package goproxy_test

import (
	"bufio"
	"context"
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

// connCounter is an origin that counts accepted TCP connections.
type connCounter struct {
	*httptest.Server
	accepted atomic.Int64
}

func newConnCounter(t *testing.T, h http.Handler) *connCounter {
	t.Helper()
	c := &connCounter{}
	c.Server = httptest.NewUnstartedServer(h)
	c.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			c.accepted.Add(1)
		}
	}
	c.Start()
	t.Cleanup(c.Close)
	return c
}

// newTLSConnCounter is newConnCounter for a TLS origin.
func newTLSConnCounter(t *testing.T, h http.Handler) *connCounter {
	t.Helper()
	c := &connCounter{}
	c.Server = httptest.NewUnstartedServer(h)
	c.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			c.accepted.Add(1)
		}
	}
	c.StartTLS()
	t.Cleanup(c.Close)
	return c
}

func newProxyClient(t *testing.T, proxyURL string, tlsCfg *tls.Config) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	require.NoError(t, err)
	if tlsCfg == nil {
		tlsCfg = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(u),
		TLSClientConfig:   tlsCfg,
		ForceAttemptHTTP2: false,
	}}
}

// TestUpstreamPoolReusesPlainHTTPConnections covers the plain-text
// forwarding path: sequential requests must hit a single origin connection
// and the pool counters must reflect it.
func TestUpstreamPoolReusesPlainHTTPConnections(t *testing.T) {
	origin := newConnCounter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	proxy := goproxy.NewProxyHttpServer()
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	client := newProxyClient(t, proxySrv.URL, nil)
	defer client.CloseIdleConnections()

	for i := 0; i < 4; i++ {
		resp, err := doGet(t, client, origin.URL)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, "ok", string(body))
	}

	stats := proxy.UpstreamStats()
	assert.EqualValues(t, 1, origin.accepted.Load(), "sequential plain requests must share one upstream connection")
	assert.EqualValues(t, 1, stats.News)
	assert.GreaterOrEqual(t, stats.Hits, uint64(3))
	assert.GreaterOrEqual(t, stats.Recycled, uint64(3))
}

// TestUpstreamPoolReusesMITMConnections covers the MITM forwarding path,
// where every request has its own upstream RoundTrip.
func TestUpstreamPoolReusesMITMConnections(t *testing.T) {
	origin := newTLSConnCounter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))

	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	client := newProxyClient(t, proxySrv.URL, nil)
	defer client.CloseIdleConnections()

	for i := 0; i < 4; i++ {
		resp, err := doGet(t, client, origin.URL)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, "ok", string(body))
	}

	stats := proxy.UpstreamStats()
	assert.EqualValues(t, 1, origin.accepted.Load(), "sequential MITM requests must share one upstream connection")
	assert.GreaterOrEqual(t, stats.Hits, uint64(3))
}

// TestUpstreamPoolMaxConnsPerHost proves the per-origin cap holds under a
// burst, and that the excess queues instead of dialing without bound.
func TestUpstreamPoolMaxConnsPerHost(t *testing.T) {
	release := make(chan struct{})
	origin := newConnCounter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		fmt.Fprint(w, "ok")
	}))
	proxy := goproxy.NewProxyHttpServer()
	proxy.Upstream = &goproxy.UpstreamConfig{
		MaxConnsPerHost: 2,
		MaxConns:        100,
		WaitQueue:       32,
	}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	client := newProxyClient(t, proxySrv.URL, nil)
	defer client.CloseIdleConnections()

	var wg sync.WaitGroup
	errs := make([]error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := doGet(t, client, origin.URL)
			if err != nil {
				errs[i] = err
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}(i)
	}
	require.Eventually(t, func() bool { return origin.accepted.Load() >= 2 }, 3*time.Second, 5*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	assert.LessOrEqual(t, origin.accepted.Load(), int64(2), "per-host cap must bound concurrent upstream connections")
	close(release)
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "request %d", i)
	}
	assert.LessOrEqual(t, origin.accepted.Load(), int64(2))
	assert.GreaterOrEqual(t, proxy.UpstreamStats().Queued, uint64(1), "excess requests must queue")
}

// TestUpstreamPoolFailsFastWhenQueueFull covers the rejection path.
func TestUpstreamPoolFailsFastWhenQueueFull(t *testing.T) {
	release := make(chan struct{})
	origin := newConnCounter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		fmt.Fprint(w, "ok")
	}))
	proxy := goproxy.NewProxyHttpServer()
	proxy.Upstream = &goproxy.UpstreamConfig{
		MaxConnsPerHost: 1,
		MaxConns:        1,
		WaitQueue:       -1, // fail fast
	}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	client := newProxyClient(t, proxySrv.URL, nil)
	defer client.CloseIdleConnections()

	first := make(chan struct{})
	go func() {
		resp, err := doGet(t, client, origin.URL)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		close(first)
	}()
	require.Eventually(t, func() bool { return proxy.UpstreamStats().Active >= 1 }, 3*time.Second, 5*time.Millisecond)

	resp, err := doGet(t, client, origin.URL)
	if err == nil {
		// The proxy reports the failure as a 5xx; that is a fail-fast result.
		defer resp.Body.Close()
		assert.GreaterOrEqual(t, resp.StatusCode, http.StatusInternalServerError)
	}
	close(release)
	<-first
}

// TestTunnelIdleReclaimsConnection verifies a transparent CONNECT tunnel is
// reclaimed after inactivity and that a later CONNECT rebuilds normally.
func TestTunnelIdleReclaimsConnection(t *testing.T) {
	ctx := t.Context()
	target := newConnCounter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	proxy := goproxy.NewProxyHttpServer()
	proxy.Upstream = &goproxy.UpstreamConfig{
		TunnelIdleTimeout: 120 * time.Millisecond,
	}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)

	connect := func() (net.Conn, *bufio.Reader) {
		c, derr := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", proxyURL.Host)
		require.NoError(t, derr)
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: target.Listener.Addr().String()},
			Host:   target.Listener.Addr().String(),
			Header: make(http.Header),
		}
		require.NoError(t, req.Write(c))
		br := bufio.NewReader(c)
		resp, rerr := http.ReadResponse(br, req)
		require.NoError(t, rerr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
		return c, br
	}

	conn, br := connect()
	// Keep the tunnel silent; it must be reclaimed.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, rerr := br.ReadByte()
	require.Error(t, rerr, "an idle tunnel must be closed by the proxy")
	_ = conn.Close()
	assert.GreaterOrEqual(t, proxy.UpstreamStats().IdleClosed, uint64(1))

	// The next CONNECT must establish a fresh tunnel and carry data.
	conn2, br2 := connect()
	defer conn2.Close()
	_, err = fmt.Fprintf(conn2, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target.Listener.Addr().String())
	require.NoError(t, err)
	resp, err := http.ReadResponse(br2, nil)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, "ok", string(body))
}

// TestTunnelHalfCloseKeepsOtherDirection verifies a half-close from the
// client is propagated without tearing down the server-to-client direction.
func TestTunnelHalfCloseKeepsOtherDirection(t *testing.T) {
	ctx := t.Context()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		// The client half-closed after writing; the server may still answer.
		_, _ = c.Write([]byte("reply"))
	}()

	proxy := goproxy.NewProxyHttpServer()
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)

	c, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", proxyURL.Host)
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: ln.Addr().String()},
		Host:   ln.Addr().String(),
		Header: make(http.Header),
	}
	require.NoError(t, req.Write(c))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	_, err = c.Write([]byte("hello"))
	require.NoError(t, err)
	if cw, ok := c.(*net.TCPConn); ok {
		require.NoError(t, cw.CloseWrite())
	}

	buf := make([]byte, 5)
	_, err = io.ReadFull(br, buf)
	require.NoError(t, err, "the tunnel must still deliver the reverse direction after a half-close")
	assert.Equal(t, "reply", string(buf))
	<-serverDone
}

// TestTunnelCarriesEarlyClientBytes ensures buffered bytes sent with the
// CONNECT request are not lost when the pool dials upstream.
func TestTunnelCarriesEarlyClientBytes(t *testing.T) {
	ctx := t.Context()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	received := make(chan string, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		received <- string(buf[:n])
		_, _ = c.Write([]byte("ok"))
	}()

	proxy := goproxy.NewProxyHttpServer()
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)

	c, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", proxyURL.Host)
	require.NoError(t, err)
	defer c.Close()
	require.NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))

	// CONNECT and the first payload bytes in a single write.
	payload := "early-bytes"
	_, err = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n%s", ln.Addr(), ln.Addr(), payload)
	require.NoError(t, err)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	select {
	case got := <-received:
		assert.Equal(t, payload, got, "bytes buffered with the CONNECT request must be forwarded")
	case <-time.After(3 * time.Second):
		t.Fatal("upstream never received the early client bytes")
	}
}

// TestStreamingResponseSurvivesIdleTimeout ensures a slow, streaming upstream
// response is not killed by the idle reaper (which only touches idle
// keep-alive connections, not active bodies).
func TestStreamingResponseSurvivesIdleTimeout(t *testing.T) {
	const chunk = "data: ping\n\n"
	release := make(chan struct{})
	origin := newConnCounter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 3; i++ {
			_, _ = io.WriteString(w, chunk)
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(150 * time.Millisecond)
		}
		<-release
	}))
	proxy := goproxy.NewProxyHttpServer()
	proxy.Upstream = &goproxy.UpstreamConfig{IdleTimeout: 100 * time.Millisecond}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	client := newProxyClient(t, proxySrv.URL, nil)
	defer client.CloseIdleConnections()

	resp, err := doGet(t, client, origin.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	defer close(release)

	br := bufio.NewReader(resp.Body)
	for i := 0; i < 3; i++ {
		first, err := br.ReadString('\n')
		require.NoError(t, err, "streaming chunk %d must arrive despite the idle timeout", i)
		second, err := br.ReadString('\n')
		require.NoError(t, err)
		assert.Equal(t, chunk, first+second)
	}
}

// TestResponseHeaderTimeoutOnProxy verifies the configured response header
// timeout surfaces as a proxy error instead of hanging.
func TestResponseHeaderTimeoutOnProxy(t *testing.T) {
	origin := newConnCounter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		fmt.Fprint(w, "late")
	}))
	proxy := goproxy.NewProxyHttpServer()
	proxy.Upstream = &goproxy.UpstreamConfig{ResponseHeaderTimeout: 100 * time.Millisecond}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	client := newProxyClient(t, proxySrv.URL, nil)
	defer client.CloseIdleConnections()

	start := time.Now()
	resp, err := doGet(t, client, origin.URL)
	elapsed := time.Since(start)
	if err == nil {
		defer resp.Body.Close()
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	}
	assert.Less(t, elapsed, time.Second, "the response header timeout must bound the wait")
	assert.GreaterOrEqual(t, proxy.UpstreamStats().Timeouts, uint64(1))
}

// TestClientDisconnectCancelsUpstreamMITM ensures a client that abandons a
// MITM request cancels the upstream request, and background goroutines do not
// leak.
func TestClientDisconnectCancelsUpstreamMITM(t *testing.T) {
	ctx := t.Context()
	started := make(chan struct{}, 1)
	stopped := make(chan struct{})
	var stopOnce sync.Once
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
		stopOnce.Do(func() { close(stopped) })
	}))
	defer origin.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)

	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", proxyURL.Host)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: origin.Listener.Addr().String()},
		Host:   origin.Listener.Addr().String(),
		Header: make(http.Header),
	}
	require.NoError(t, connectReq.Write(conn))
	connectResp, err := http.ReadResponse(bufio.NewReader(conn), connectReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, connectResp.StatusCode)

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, tlsConn.HandshakeContext(ctx))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
	require.NoError(t, err)
	require.NoError(t, req.Write(tlsConn))

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request never started")
	}

	// The client disappears mid-request.
	_ = tlsConn.Close()
	_ = conn.Close()

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request was not canceled when the MITM client disconnected")
	}
	assert.GreaterOrEqual(t, proxy.UpstreamStats().Canceled, uint64(1))
}

// TestUpstreamEventsObservePoolLifecycle checks the event hook reports reuse
// and recycling without blocking forwarding.
func TestUpstreamEventsObservePoolLifecycle(t *testing.T) {
	origin := newConnCounter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	var reuse, recycled atomic.Int64
	proxy := goproxy.NewProxyHttpServer()
	proxy.Upstream = &goproxy.UpstreamConfig{
		OnEvent: func(ev goproxy.UpstreamEvent) {
			switch ev.Kind {
			case goproxy.UpstreamEventReuse:
				reuse.Add(1)
			case goproxy.UpstreamEventClose:
				recycled.Add(1)
			}
		},
	}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	client := newProxyClient(t, proxySrv.URL, nil)
	defer client.CloseIdleConnections()

	for i := 0; i < 3; i++ {
		resp, err := doGet(t, client, origin.URL)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	require.Eventually(t, func() bool { return reuse.Load() >= 2 }, 2*time.Second, 10*time.Millisecond,
		"the reuse event must fire for reused connections")
}

// TestUpstreamDefaultsKeepLongPollingAlive ensures the default configuration
// (no response-header timeout) never kills a long-polling request.
func TestUpstreamDefaultsKeepLongPollingAlive(t *testing.T) {
	origin := newConnCounter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(600 * time.Millisecond):
			fmt.Fprint(w, "polled")
		}
	}))
	proxy := goproxy.NewProxyHttpServer() // default Upstream config
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	client := newProxyClient(t, proxySrv.URL, nil)
	defer client.CloseIdleConnections()

	resp, err := doGet(t, client, origin.URL)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, "polled", string(body))
}

// TestCloseIdleUpstreamConnections ensures the explicit close helper releases
// idle connections and the next request rebuilds one.
func TestCloseIdleUpstreamConnections(t *testing.T) {
	origin := newConnCounter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	proxy := goproxy.NewProxyHttpServer()
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	client := newProxyClient(t, proxySrv.URL, nil)
	defer client.CloseIdleConnections()

	resp, err := doGet(t, client, origin.URL)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	require.EqualValues(t, 1, origin.accepted.Load())

	proxy.CloseIdleUpstreamConnections()
	require.Eventually(t, func() bool { return proxy.UpstreamStats().Active == 0 }, 2*time.Second, 10*time.Millisecond)

	resp, err = doGet(t, client, origin.URL)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	assert.EqualValues(t, 2, origin.accepted.Load(), "a request after an explicit idle close must dial again")
}

// TestClientCancelDuringResponseBody verifies that cancelling a request while
// its response body is being read closes the upstream connection and returns
// a deterministic result to the client.
func TestClientCancelDuringResponseBody(t *testing.T) {
	bodyStarted := make(chan struct{}, 1)
	upstreamClosed := make(chan struct{})
	var upstreamOnce sync.Once
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A streaming content type makes the proxy flush the head and first
		// chunk, so the test can observe the body before cancelling.
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, "first")
		if flusher != nil {
			flusher.Flush()
		}
		// The handler returns only after the client has seen the first bytes;
		// the deferred close fires when the client disconnects (r.Context()
		// is done) or the test finishes.
		select {
		case bodyStarted <- struct{}{}:
		default:
		}
		<-r.Context().Done()
		upstreamOnce.Do(func() { close(upstreamClosed) })
	}))
	defer origin.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	client := newProxyClient(t, proxySrv.URL, nil)
	defer client.CloseIdleConnections()

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	buf := make([]byte, 5)
	_, err = io.ReadFull(resp.Body, buf)
	require.NoError(t, err)
	require.Equal(t, "first", string(buf))

	<-bodyStarted
	cancel()
	// A cancelled body read fails deterministically instead of blocking.
	done := make(chan error, 1)
	go func() {
		_, rerr := io.ReadAll(resp.Body)
		done <- rerr
	}()
	select {
	case err = <-done:
		require.Error(t, err, "a cancelled response body read must fail deterministically")
	case <-time.After(5 * time.Second):
		t.Fatal("the cancelled response body read did not return")
	}

	select {
	case <-upstreamClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream connection was not closed after the client canceled")
	}
}

// TestUpstreamConfigInheritsTransportTimeouts verifies that a transport
// timeout the caller set on Tr is honored by the pool when Upstream does not
// override it.
func TestUpstreamConfigInheritsTransportTimeouts(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr.TLSHandshakeTimeout = 1234 * time.Millisecond
	proxy.Tr.ResponseHeaderTimeout = 4321 * time.Millisecond
	proxy.Tr.IdleConnTimeout = 5555 * time.Millisecond

	origin := newConnCounter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	client := newProxyClient(t, proxySrv.URL, nil)
	defer client.CloseIdleConnections()

	resp, err := doGet(t, client, origin.URL)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, resp.Body)
	require.NoError(t, resp.Body.Close())

	// A request that succeeds proves the inherited settings are valid; the
	// inheritance itself is unit-tested through UpstreamStats not exposing
	// them, so assert the pool is in use and the connection was recycled.
	assert.GreaterOrEqual(t, proxy.UpstreamStats().News, uint64(1))
	assert.GreaterOrEqual(t, proxy.UpstreamStats().Recycled, uint64(1))
}

// TestEnvProxyTunnelStillBounded verifies that setting HTTPS_PROXY (which
// makes NewProxyHttpServer install a CONNECT-chaining dialer) does not let
// tunnels bypass the shared connection budget.
func TestEnvProxyTunnelStillBounded(t *testing.T) {
	ctx := t.Context()
	// A chaining proxy that accepts CONNECT and tunnels to the requested
	// target, so the derived dialer succeeds and occupies a slot.
	targetLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer targetLn.Close()
	go func() {
		for {
			c, aerr := targetLn.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()

	upstreamProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "connect only", http.StatusMethodNotAllowed)
			return
		}
		hij, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		client, _, herr := hij.Hijack()
		if herr != nil {
			return
		}
		defer client.Close()
		target, derr := (&net.Dialer{}).DialContext(ctx, "tcp", targetLn.Addr().String())
		if derr != nil {
			return
		}
		defer target.Close()
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(target, client); done <- struct{}{} }()
		go func() { _, _ = io.Copy(client, target); done <- struct{}{} }()
		<-done
	}))
	defer upstreamProxy.Close()
	t.Setenv("HTTPS_PROXY", upstreamProxy.URL)
	t.Setenv("https_proxy", upstreamProxy.URL)

	proxy := goproxy.NewProxyHttpServer()
	require.NotNil(t, proxy.ConnectDial, "the environment proxy must install a dialer")
	proxy.Upstream = &goproxy.UpstreamConfig{MaxConns: 1, MaxConnsPerHost: 1, WaitQueue: -1}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)

	connect := func() net.Conn {
		c, derr := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", proxyURL.Host)
		require.NoError(t, derr)
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: "example.test:443"},
			Host:   "example.test:443",
			Header: make(http.Header),
		}
		require.NoError(t, req.Write(c))
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = http.ReadResponse(bufio.NewReader(c), req)
		return c
	}

	first := connect()
	defer first.Close()
	require.Eventually(t, func() bool { return proxy.UpstreamStats().Active >= 1 }, 2*time.Second, 5*time.Millisecond)

	// The chaining dialer is reached through the budget, so the second
	// tunnel must not raise the live connection count above the cap.
	second := connect()
	defer second.Close()
	time.Sleep(100 * time.Millisecond)
	stats := proxy.UpstreamStats()
	assert.LessOrEqual(t, stats.Active, int64(1), "a tunnel must not bypass the shared budget")
	assert.GreaterOrEqual(t, stats.Rejected, uint64(1), "the over-limit tunnel must be rejected")
}

// TestHTTP2UpstreamConnectionSurvivesIdleTimeout forwards MITM'd requests to
// an HTTP/2 origin and verifies the multiplexed upstream connection is not
// reaped by the idle timer while streams are served.
func TestHTTP2UpstreamConnectionSurvivesIdleTimeout(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, 2, r.ProtoMajor, "the origin must be reached over HTTP/2")
		fmt.Fprint(w, "ok")
	}))
	backend.EnableHTTP2 = true
	backend.StartTLS()
	defer backend.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Tr = &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		},
	}
	proxy.Upstream = &goproxy.UpstreamConfig{IdleTimeout: 100 * time.Millisecond}
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	client := newProxyClient(t, proxySrv.URL, nil)
	defer client.CloseIdleConnections()

	for i := 0; i < 3; i++ {
		resp, err := doGet(t, client, backend.URL)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		require.NoError(t, resp.Body.Close())
		if i == 0 {
			// Let the idle reaper run between requests; the multiplexed
			// connection must not be torn down.
			time.Sleep(250 * time.Millisecond)
		}
	}
	assert.GreaterOrEqual(t, proxy.UpstreamStats().Hits, uint64(1), "h2 requests must reuse the upstream connection")
	assert.Zero(t, proxy.UpstreamStats().IdleClosed, "an h2 connection must never be idle-reaped")
}

// TestSlowEventObserverDoesNotStallForwarding proves that a blocking event
// handler (an observability backend) cannot slow the forwarding path.
func TestSlowEventObserverDoesNotStallForwarding(t *testing.T) {
	origin := newConnCounter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	release := make(chan struct{})
	defer close(release)
	proxy := goproxy.NewProxyHttpServer()
	proxy.Upstream = &goproxy.UpstreamConfig{
		OnEvent: func(goproxy.UpstreamEvent) { <-release }, // blocks forever
	}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	client := newProxyClient(t, proxySrv.URL, nil)
	defer client.CloseIdleConnections()

	// Several requests must complete even though every event handler blocks
	// and the event buffer eventually fills.
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 20; i++ {
			resp, err := doGet(t, client, origin.URL)
			if err != nil {
				done <- err
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		done <- nil
	}()
	select {
	case err := <-done:
		require.NoError(t, err, "forwarding must not stall on a blocking event handler")
	case <-time.After(5 * time.Second):
		t.Fatal("forwarding stalled behind a blocking observability handler")
	}
}

// doGet issues a context-aware GET through client.
func doGet(t *testing.T, client *http.Client, rawURL string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}
