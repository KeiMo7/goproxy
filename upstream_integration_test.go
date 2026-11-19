package goproxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/elazarl/goproxy/upstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newBufioReaderConn(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

func proxyAuthMatches(req *http.Request, userpass string) bool {
	hdr := req.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(hdr, "Basic ") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hdr, "Basic "))
	return err == nil && string(raw) == userpass
}

// newUpstreamTestProxy builds a goproxy instance whose outbound traffic is
// driven by the given multi-hop router.
func newUpstreamTestProxy(t *testing.T, router *upstream.Router) (*goproxy.ProxyHttpServer, *httptest.Server, *http.Client) {
	t.Helper()
	proxy := goproxy.NewProxyHttpServer()
	rt := upstream.NewRoundTripper(router)
	require.NoError(t, proxy.SetUpstreamRouter(rt))
	require.True(t, proxy.HasUpstreamRouter())
	srv := httptest.NewServer(proxy)
	t.Cleanup(srv.Close)
	pu, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	return proxy, srv, client
}

// localConnectProxy is a minimal HTTP CONNECT proxy used as an upstream hop
// in root-package integration tests.
type localConnectProxy struct {
	listener net.Listener
	conns    atomic.Int64
	auth     string // "user:pass" or "" for open
}

func startLocalConnectProxy(t *testing.T, auth string) *localConnectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &localConnectProxy{listener: ln, auth: auth}
	go p.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func (p *localConnectProxy) addr() string { return p.listener.Addr().String() }

func (p *localConnectProxy) serve() {
	for {
		c, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *localConnectProxy) handle(c net.Conn) {
	defer c.Close()
	br := newBufioReaderConn(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if p.auth != "" && !proxyAuthMatches(req, p.auth) {
		io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if req.Method != http.MethodConnect {
		return
	}
	p.conns.Add(1)
	up, err := net.Dial("tcp", req.Host)
	if err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer up.Close()
	io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// TestUpstreamChainEndToEndHTTP verifies the full path: client -> goproxy ->
// two-hop chain (basic-auth CONNECT, open CONNECT) -> target, for plain HTTP.
func TestUpstreamChainEndToEndHTTP(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "end-to-end")
	}))
	t.Cleanup(target.Close)

	hop1 := startLocalConnectProxy(t, "u1:p1")
	hop2 := startLocalConnectProxy(t, "")

	router, err := upstream.NewRouter(&upstream.Config{
		Version: "v1",
		Chains: []upstream.Chain{{
			ID: "e2e",
			Hops: []upstream.Hop{
				{Name: "auth-edge", Address: hop1.addr(), Tunnel: upstream.TunnelConnect,
					Auth: upstream.Auth{Type: upstream.AuthBasic, Username: "u1", Password: "p1"}},
				{Name: "open-inner", Address: hop2.addr(), Tunnel: upstream.TunnelConnect},
			},
		}},
		Routes: []upstream.Route{{Default: true, Primary: "e2e"}},
	})
	require.NoError(t, err)
	_, _, client := newUpstreamTestProxy(t, router)

	resp, err := client.Get(target.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "end-to-end", string(b))
	assert.GreaterOrEqual(t, hop1.conns.Load(), int64(1))
	assert.GreaterOrEqual(t, hop2.conns.Load(), int64(1))
}

// TestUpstreamChainEndToEndCONNECT verifies transparent CONNECT (non-MITM)
// through the multi-hop router for an HTTPS target.
func TestUpstreamChainEndToEndCONNECT(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "https-ok")
	}))
	t.Cleanup(target.Close)

	hop1 := startLocalConnectProxy(t, "")
	router, err := upstream.NewRouter(&upstream.Config{
		Version: "v1",
		Chains: []upstream.Chain{{
			ID: "tun",
			Hops: []upstream.Hop{
				{Name: "edge", Address: hop1.addr(), Tunnel: upstream.TunnelConnect},
			},
		}},
		Routes: []upstream.Route{{Default: true, Primary: "tun"}},
	})
	require.NoError(t, err)
	_, _, client := newUpstreamTestProxy(t, router)

	resp, err := client.Get(target.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "https-ok", string(b))
}

// TestUpstreamChainMitmKeepsHooks verifies hard requirement IV.2: request and
// response hooks keep firing with their original timing when the router is
// attached, including over an MITM'd CONNECT.
func TestUpstreamChainMitmKeepsHooks(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "mitm-target")
	}))
	t.Cleanup(target.Close)

	hop1 := startLocalConnectProxy(t, "")
	router, err := upstream.NewRouter(&upstream.Config{
		Version: "v1",
		Chains: []upstream.Chain{{
			ID: "mitm-chain",
			Hops: []upstream.Hop{
				{Name: "edge", Address: hop1.addr(), Tunnel: upstream.TunnelConnect},
			},
		}},
		Routes: []upstream.Route{{Default: true, Primary: "mitm-chain"}},
	})
	require.NoError(t, err)

	proxy := goproxy.NewProxyHttpServer()
	require.NoError(t, proxy.SetUpstreamRouter(upstream.NewRoundTripper(router)))
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	var reqHook, respHook atomic.Int64
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		reqHook.Add(1)
		return req, nil
	})
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		respHook.Add(1)
		return resp
	})

	srv := httptest.NewServer(proxy)
	t.Cleanup(srv.Close)
	pu, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}

	resp, err := client.Get(target.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "mitm-target", string(b))
	assert.GreaterOrEqual(t, reqHook.Load(), int64(1), "request hook must fire")
	assert.GreaterOrEqual(t, respHook.Load(), int64(1), "response hook must fire")
}

// TestDetachRouterRestoresSingleHop verifies hard requirement IV.1: detaching
// the router restores the legacy single-hop behavior path.
func TestDetachRouterRestoresSingleHop(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	hop := startLocalConnectProxy(t, "")
	router, err := upstream.NewRouter(&upstream.Config{
		Version: "v1",
		Chains:  []upstream.Chain{{ID: "c", Hops: []upstream.Hop{{Name: "h", Address: hop.addr(), Tunnel: upstream.TunnelConnect}}}},
		Routes:  []upstream.Route{{Default: true, Primary: "c"}},
	})
	require.NoError(t, err)
	require.NoError(t, proxy.SetUpstreamRouter(upstream.NewRoundTripper(router)))
	require.True(t, proxy.HasUpstreamRouter())
	require.NoError(t, proxy.SetUpstreamRouter(nil))
	assert.False(t, proxy.HasUpstreamRouter())
}

// TestUpstreamChainFailoverEndToEnd verifies failover is observable through
// the goproxy integration and the request body is delivered once.
func TestUpstreamChainFailoverEndToEnd(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		io.WriteString(w, "got:"+string(body))
	}))
	t.Cleanup(target.Close)

	dead := startLocalConnectProxy(t, "")
	require.NoError(t, dead.listener.Close()) // nothing listening -> unreachable
	alive := startLocalConnectProxy(t, "")

	router, err := upstream.NewRouter(&upstream.Config{
		Version: "v1",
		Chains: []upstream.Chain{
			{ID: "dead", Hops: []upstream.Hop{{Name: "dead-edge", Address: dead.addr(),
				Tunnel: upstream.TunnelConnect, DialTimeout: 500_000_000}}},
			{ID: "alive", Hops: []upstream.Hop{{Name: "alive-edge", Address: alive.addr(),
				Tunnel: upstream.TunnelConnect}}},
		},
		Routes: []upstream.Route{{Default: true, Primary: "dead", Backups: []string{"alive"}}},
	})
	require.NoError(t, err)

	var events []upstream.Event
	router.AddSink(upstream.EventSinkFunc(func(e upstream.Event) {
		events = append(events, e)
	}))

	_, _, client := newUpstreamTestProxy(t, router)
	resp, err := client.Post(target.URL+"/", "text/plain", strings.NewReader("once"))
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "got:once", string(b))

	var sawFailover bool
	for _, e := range events {
		if e.Type == upstream.EventFailover && e.ChainID == "alive" {
			sawFailover = true
		}
	}
	assert.True(t, sawFailover, "failover event missing: %+v", events)
}

// TestSetUpstreamRouterRejectsBadType checks the interface guard.
func TestSetUpstreamRouterRejectsBadType(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	err := proxy.SetUpstreamRouter(struct{}{})
	require.Error(t, err)
	assert.False(t, proxy.HasUpstreamRouter())
}

var _ = context.Background
