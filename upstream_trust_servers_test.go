package goproxy_test

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
)

// sniRecordingServer is an HTTPS server that records the SNI name it sees on
// every incoming TLS connection, keyed by connection, and returns a fixed
// body. It lets tests assert the proxy sent the correct name per hop.
type sniRecordingServer struct {
	t       *testing.T
	server  *httptest.Server
	namesMu chan string
}

func newSNIServer(t *testing.T, cert tls.Certificate) *sniRecordingServer {
	t.Helper()
	names := make(chan string, 256)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.ServerName) > 0 {
			select {
			case names <- r.TLS.ServerName:
			default:
			}
		}
		_, _ = io.WriteString(w, "ok")
	})
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &sniRecordingServer{t: t, server: srv, namesMu: names}
}

// newSNIServerOnIP starts an HTTPS test server bound to a specific loopback
// address, allowing tests to distinguish targets by IP literal rather than
// only by port.
func newSNIServerOnIP(t *testing.T, cert tls.Certificate, ip string) *sniRecordingServer {
	t.Helper()
	names := make(chan string, 256)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.ServerName) > 0 {
			select {
			case names <- r.TLS.ServerName:
			default:
			}
		}
		_, _ = io.WriteString(w, "ok")
	})
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = ln
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &sniRecordingServer{t: t, server: srv, namesMu: names}
}

func (s *sniRecordingServer) url() *url.URL {
	u, err := url.Parse(s.server.URL)
	require.NoError(s.t, err)
	return u
}

// drainNames returns all SNI values recorded so far without blocking.
func (s *sniRecordingServer) drainNames() []string {
	var out []string
	for {
		select {
		case n := <-s.namesMu:
			out = append(out, n)
		default:
			return out
		}
	}
}

// proxyClient builds an HTTP client that sends everything through proxy,
// trusting the proxy's MITM CA not at all (the test client itself uses
// InsecureSkipVerify, which only governs the client<->proxy edge).
func proxyClient(t *testing.T, proxyURL *url.URL) *http.Client {
	t.Helper()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyURL(proxyURL),
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr}
}

// startProxy runs a goproxy instance with MITM enabled and returns its base
// URL. The upstream policy starts empty (system trust everywhere).
func startProxy(t *testing.T) (*goproxy.ProxyHttpServer, *url.URL) {
	t.Helper()
	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	srv := httptest.NewServer(proxy)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return proxy, u
}

// mustReplace installs a trust policy, failing the test on configuration
// errors.
func mustReplace(t *testing.T, proxy *goproxy.ProxyHttpServer,
	groups map[string]*goproxy.TrustGroupBuilder, entries []goproxy.TrustTargetEntry) uint64 {
	t.Helper()
	v, err := proxy.ReplaceTrustPolicy(groups, entries)
	require.NoError(t, err)
	return v
}

// freePort returns an unused TCP port on loopback.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().(*net.TCPAddr)
	require.NoError(t, l.Close())
	return addr.Port
}
