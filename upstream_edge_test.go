package goproxy_test

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// connectTunnel issues a CONNECT to the proxy and returns the raw client
// connection plus the buffered reader positioned after the 200 response.
func connectTunnel(t *testing.T, proxyURL *url.URL, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(t.Context(), "tcp", proxyURL.Host)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	require.NoError(t, req.Write(conn))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
	return conn, br
}

// TestTunnelHalfCloseServerObservesEOF proves that a client CloseWrite is
// forwarded as a FIN to the origin, and that the reverse direction keeps
// working afterwards. The origin only answers once it has seen the EOF, so a
// premature full close on either side fails the test.
func TestTunnelHalfCloseServerObservesEOF(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	originResult := make(chan string, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			originResult <- "accept: " + aerr.Error()
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		if _, rerr := c.Read(buf); rerr != nil {
			originResult <- "read: " + rerr.Error()
			return
		}
		// The next read must report the propagated half-close.
		if _, rerr := c.Read(buf); rerr != nil {
			originResult <- "after-eof"
			_, _ = c.Write([]byte("after-eof"))
			return
		}
		originResult <- "no-eof"
		_, _ = c.Write([]byte("no-eof"))
	}()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Upstream = &goproxy.UpstreamConfig{TunnelIdleTimeout: 2 * time.Second}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)

	conn, br := connectTunnel(t, proxyURL, ln.Addr().String())
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	tcpConn, ok := conn.(*net.TCPConn)
	require.True(t, ok)
	require.NoError(t, tcpConn.CloseWrite())

	buf := make([]byte, len("after-eof"))
	_, err = io.ReadFull(br, buf)
	require.NoError(t, err)
	assert.Equal(t, "after-eof", string(buf))
	assert.Equal(t, "after-eof", <-originResult)
}

// TestTunnelIdleAfterHalfCloseReclaims verifies the idle watchdog still arms
// after one direction was half-closed. A tunnel whose client wrote EOF but
// whose other direction stays silent must be reclaimed instead of holding a
// connection slot forever.
func TestTunnelIdleAfterHalfCloseReclaims(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	originDone := make(chan struct{})
	defer close(originDone)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		// Drain the tunnel without ever closing the reverse direction: after
		// the client's EOF this side must stay silent, so the idle watchdog
		// is the only thing that can end the tunnel.
		buf := make([]byte, 4096)
		for {
			_, rerr := c.Read(buf)
			if rerr != nil {
				<-originDone
				return
			}
		}
	}()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Upstream = &goproxy.UpstreamConfig{TunnelIdleTimeout: 150 * time.Millisecond}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)

	conn, br := connectTunnel(t, proxyURL, ln.Addr().String())
	tcpConn, ok := conn.(*net.TCPConn)
	require.True(t, ok)
	require.NoError(t, tcpConn.CloseWrite())

	// The proxy must not keep the silent, half-closed tunnel forever.
	_, rerr := br.ReadByte()
	require.Error(t, rerr, "an idle half-closed tunnel must be reclaimed")
	assert.GreaterOrEqual(t, proxy.UpstreamStats().IdleClosed, uint64(1))
}

// TestPerHostIdleConnectionsStayReusable checks that idle connections are
// kept on the exact origin they were dialed for, so a pool with several
// origins does not lose them (a shared idle bucket would return the wrong
// origin's connection).
func TestPerHostIdleConnectionsStayReusable(t *testing.T) {
	accepted := func() (*httptest.Server, *atomic.Int64) {
		var n atomic.Int64
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "ok")
		}))
		s.Config.ConnState = func(_ net.Conn, st http.ConnState) {
			if st == http.StateNew {
				n.Add(1)
			}
		}
		s.Start()
		return s, &n
	}
	originA, countA := accepted()
	defer originA.Close()
	originB, countB := accepted()
	defer originB.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Upstream = &goproxy.UpstreamConfig{MaxIdleConnsPerHost: 4}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	client := newProxyClient(t, proxySrv.URL, nil)
	defer client.CloseIdleConnections()

	get := func(rawURL string) {
		resp, err := doGet(t, client, rawURL)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		require.NoError(t, resp.Body.Close())
	}

	for i := 0; i < 3; i++ {
		get(originA.URL)
		get(originB.URL)
	}
	assert.EqualValues(t, 1, countA.Load(), "connections to A must be reused, not evicted by B")
	assert.EqualValues(t, 1, countB.Load(), "connections to B must be reused, not evicted by A")
	assert.GreaterOrEqual(t, proxy.UpstreamStats().Hits, uint64(4))
}

// TestUpstreamCancellationDuringHandshakeAbortsConnect verifies a client
// that disappears while the upstream TLS handshake is still running aborts
// the dial instead of leaving it to finish for a client that is gone.
func TestUpstreamCancellationDuringHandshakeAbortsConnect(t *testing.T) {
	// The origin accepts TCP but never completes a TLS handshake.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		accepted <- c
	}()

	originURL := "https://" + ln.Addr().String() + "/"
	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)

	conn, _ := connectTunnel(t, proxyURL, ln.Addr().String())
	upstreamClient := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, upstreamClient.HandshakeContext(t.Context()))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, originURL, nil)
	require.NoError(t, err)
	require.NoError(t, req.Write(upstreamClient))

	// The proxy starts the TLS handshake with the origin; it must be in
	// flight when the client vanishes.
	var upstreamConn net.Conn
	select {
	case upstreamConn = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("the proxy never connected to the upstream origin")
	}
	defer upstreamConn.Close()
	_ = upstreamClient.Close()
	_ = conn.Close()

	// The aborted handshake must close the upstream connection promptly,
	// without waiting for the handshake timeout. The proxy's ClientHello may
	// already be buffered, so drain until the close.
	_ = upstreamConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	var rerr error
	for {
		if _, rerr = upstreamConn.Read(buf); rerr != nil {
			break
		}
	}
	require.Error(t, rerr, "the upstream handshake must be aborted when the client goes away")
}

// TestStreamingStaysAliveAcrossSilence proves a response body that goes
// quiet for longer than the idle timeout keeps streaming afterwards.
func TestStreamingStaysAliveAcrossSilence(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, "first\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		<-release
		_, _ = io.WriteString(w, "second\n\n")
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer origin.Close()
	defer releaseOnce.Do(func() { close(release) })

	proxy := goproxy.NewProxyHttpServer()
	proxy.Upstream = &goproxy.UpstreamConfig{IdleTimeout: 80 * time.Millisecond}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	client := newProxyClient(t, proxySrv.URL, nil)
	defer client.CloseIdleConnections()

	resp, err := doGet(t, client, origin.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	require.NoError(t, err)
	assert.Equal(t, "first\n", line)
	if rest, err := br.ReadString('\n'); err == nil {
		require.Equal(t, "\n", rest, "the event separator must arrive with the first chunk")
	}
	// Stay silent beyond the idle timeout: the active body must survive.
	time.Sleep(250 * time.Millisecond)
	releaseOnce.Do(func() { close(release) })
	line, err = br.ReadString('\n')
	require.NoError(t, err, "the body must keep streaming after a silent interval")
	assert.Equal(t, "second\n", line)
}

// TestCancelDuringHandshakeReleasesBudget proves a cancelled handshake does
// not leak a connection slot: after the client goes away, a new tunnel must
// be admitted even when the total budget is tiny.
func TestCancelDuringHandshakeReleasesBudget(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	held := make(chan net.Conn, 4)
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			held <- c // hold it without ever speaking TLS
		}
	}()
	defer func() {
		close(held)
		for c := range held {
			_ = c.Close()
		}
	}()

	originURL := "https://" + ln.Addr().String() + "/"
	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	proxy.Upstream = &goproxy.UpstreamConfig{MaxConns: 1, MaxConnsPerHost: 1, WaitQueue: -1}
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)

	// First client starts a handshake and then disappears.
	conn, _ := connectTunnel(t, proxyURL, ln.Addr().String())
	upstreamClient := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, upstreamClient.HandshakeContext(t.Context()))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, originURL, nil)
	require.NoError(t, err)
	require.NoError(t, req.Write(upstreamClient))
	require.Eventually(t, func() bool { return proxy.UpstreamStats().Active == 1 }, 3*time.Second, 5*time.Millisecond)
	_ = upstreamClient.Close()
	_ = conn.Close()

	// The aborted handshake's slot must be freed, so a second tunnel is
	// admitted instead of being rejected at the limit.
	require.Eventually(t, func() bool { return proxy.UpstreamStats().Active == 0 }, 3*time.Second, 10*time.Millisecond,
		"a cancelled handshake must release its connection slot")

	conn2, _ := connectTunnel(t, proxyURL, ln.Addr().String())
	_ = conn2.Close()
	assert.Zero(t, proxy.UpstreamStats().Rejected, "the freed slot must admit the next tunnel")
}
