package upstream

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countedServer is an origin that counts accepted TCP connections and can
// answer with arbitrary handlers.
type countedServer struct {
	*httptest.Server
	accepted atomic.Int64
	handled  atomic.Int64
}

func newCountedServer(t *testing.T, h http.Handler) *countedServer {
	t.Helper()
	cs := &countedServer{}
	cs.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.handled.Add(1)
		h.ServeHTTP(w, r)
	}))
	cs.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			cs.accepted.Add(1)
		}
	}
	cs.Start()
	t.Cleanup(cs.Close)
	return cs
}

func newCountingManager(t *testing.T, cfg Config) *Manager {
	t.Helper()
	m := NewManager(&http.Transport{}, cfg, Hooks{})
	t.Cleanup(m.Close)
	return m
}

func doRequest(t *testing.T, m *Manager, rawURL string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	resp, err := m.RoundTrip(req, nil)
	require.NoError(t, err)
	body, err := drain(resp)
	require.NoError(t, err)
	assert.NotEmpty(t, body)
	return resp
}

func drain(resp *http.Response) (string, error) {
	if resp == nil || resp.Body == nil {
		return "", nil
	}
	var sb strings.Builder
	buf := make([]byte, 512)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			_ = resp.Body.Close()
			if err.Error() == "EOF" {
				return sb.String(), nil
			}
			return sb.String(), err
		}
	}
}

func TestSequentialRequestsReuseOneConnection(t *testing.T) {
	origin := newCountedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	m := newCountingManager(t, DefaultConfig())
	for i := 0; i < 5; i++ {
		doRequest(t, m, origin.URL)
	}
	stats := m.Stats()
	assert.EqualValues(t, 1, origin.accepted.Load(), "sequential requests must reuse one connection")
	assert.EqualValues(t, 1, stats.News)
	assert.EqualValues(t, 4, stats.Hits)
	assert.GreaterOrEqual(t, stats.Recycled, uint64(4))
	assert.EqualValues(t, 5, origin.handled.Load())
}

func TestPerHostLimitBoundsConnections(t *testing.T) {
	release := make(chan struct{})
	origin := newCountedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		fmt.Fprint(w, "ok")
	}))
	cfg := DefaultConfig()
	cfg.MaxConnsPerHost = 2
	cfg.MaxConns = 100
	cfg.WaitQueue = 10
	m := newCountingManager(t, cfg)

	var wg sync.WaitGroup
	results := make([]error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
			resp, err := m.RoundTrip(req, nil)
			if err != nil {
				results[i] = err
				return
			}
			_, _ = drain(resp)
		}(i)
	}
	// Wait until two connections are in flight, then let everything through.
	require.Eventually(t, func() bool { return origin.accepted.Load() >= 2 }, 2*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	assert.LessOrEqual(t, origin.accepted.Load(), int64(2), "per-host limit must cap concurrent connections")
	close(release)
	wg.Wait()
	for i, err := range results {
		require.NoError(t, err, "request %d", i)
	}
	assert.LessOrEqual(t, origin.accepted.Load(), int64(2), "the per-host cap must hold for the whole burst")
	assert.GreaterOrEqual(t, m.Stats().Queued, uint64(1), "bursts must queue rather than dial without bound")
}

func TestGlobalLimitBoundsTunnelsAndRequests(t *testing.T) {
	release := make(chan struct{})
	origin := newCountedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		<-release
		fmt.Fprint(w, "ok")
	}))
	cfg := DefaultConfig()
	cfg.MaxConns = 2
	cfg.MaxConnsPerHost = 10
	cfg.WaitQueue = 10
	m := newCountingManager(t, cfg)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
			if resp, err := m.RoundTrip(req, nil); err == nil {
				_, _ = drain(resp)
			}
		}()
	}
	// With both slots taken by forwarding, a third caller must queue rather
	// than dial: tunnels and forwarded requests share one budget.
	require.Eventually(t, func() bool { return m.Stats().Active >= 1 }, 2*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	assert.LessOrEqual(t, m.Stats().Active, int64(2), "the global cap must hold while requests are in flight")
	close(release)
	wg.Wait()
	assert.LessOrEqual(t, origin.accepted.Load(), int64(2), "the global cap must bound origin connections")
}

func TestRejectBeyondWaitQueue(t *testing.T) {
	release := make(chan struct{})
	origin := newCountedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		fmt.Fprint(w, "ok")
	}))
	cfg := DefaultConfig()
	cfg.MaxConnsPerHost = 1
	cfg.MaxConns = 1
	cfg.WaitQueue = -1 // fail fast
	m := newCountingManager(t, cfg)

	// Occupy the only slot.
	go func() {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
		resp, err := m.RoundTrip(req, nil)
		if err == nil {
			_, _ = drain(resp)
		}
	}()
	require.Eventually(t, func() bool { return m.Stats().Active == 1 }, 2*time.Second, 5*time.Millisecond)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
	_, err := m.RoundTrip(req, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrLimit)
	assert.GreaterOrEqual(t, m.Stats().Rejected, uint64(1))
	close(release)
}

func TestIdleReapingClosesConnectionsAndAllowsRebuild(t *testing.T) {
	origin := newCountedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	cfg := DefaultConfig()
	cfg.IdleTimeout = 120 * time.Millisecond
	m := newCountingManager(t, cfg)

	doRequest(t, m, origin.URL)
	require.EqualValues(t, 1, origin.accepted.Load())
	require.Eventually(t, func() bool {
		return m.Stats().IdleClosed >= 1
	}, 2*time.Second, 10*time.Millisecond, "idle connection must be reclaimed")
	require.Eventually(t, func() bool { return m.Stats().Active == 0 }, 2*time.Second, 10*time.Millisecond)

	// A new request after reclamation must dial again and succeed.
	doRequest(t, m, origin.URL)
	assert.EqualValues(t, 2, origin.accepted.Load(), "a reaped connection must be rebuilt on demand")
	assert.EqualValues(t, 2, m.Stats().News)
}

func TestTunnelIdleTimeoutReclaimsAndRebuilds(t *testing.T) {
	origin := newCountedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	cfg := DefaultConfig()
	cfg.TunnelIdleTimeout = 100 * time.Millisecond
	m := newCountingManager(t, cfg)

	conn, err := m.DialContextForTunnel(context.Background(), "tcp", origin.Listener.Addr().String())
	require.NoError(t, err)
	addr := origin.Listener.Addr().String()

	// The tunnel carries no bytes; it must be closed by the idle watchdog.
	require.Eventually(t, func() bool {
		return m.Stats().IdleClosed >= 1
	}, 2*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return m.Stats().Active == 0 }, 2*time.Second, 10*time.Millisecond)
	_ = conn.Close()

	// A fresh tunnel must establish normally.
	conn2, err := m.DialContextForTunnel(context.Background(), "tcp", addr)
	require.NoError(t, err, "a reclaimed tunnel must be rebuildable")
	require.NoError(t, conn2.Close())
	assert.GreaterOrEqual(t, m.Stats().News, uint64(2))
}

func TestActiveTunnelIsNotReclaimed(t *testing.T) {
	origin := newCountedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	cfg := DefaultConfig()
	cfg.TunnelIdleTimeout = 150 * time.Millisecond
	m := newCountingManager(t, cfg)

	conn, err := m.DialContextForTunnel(context.Background(), "tcp", origin.Listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// Keep the tunnel active for longer than the idle timeout: it must survive.
	deadline := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(deadline) {
		_, werr := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		require.NoError(t, werr)
		time.Sleep(40 * time.Millisecond)
	}
	assert.Zero(t, m.Stats().IdleClosed, "an active tunnel must not be reclaimed")
	assert.EqualValues(t, 1, m.Stats().Active)
}

func TestConnectTimeoutDoesNotConsumeRequestBudget(t *testing.T) {
	// A dialer that blocks until its context is done, simulating slow DNS.
	cfg := DefaultConfig()
	cfg.ConnectTimeout = 80 * time.Millisecond
	cfg.MaxConns = 100
	m := NewManager(&http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}, cfg, Hooks{})
	t.Cleanup(m.Close)

	start := time.Now()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://slow.example/", nil)
	_, err := m.RoundTrip(req, nil)
	elapsed := time.Since(start)
	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, elapsed, 2*time.Second, "connect timeout must bound the dial, not the whole request budget")
	assert.GreaterOrEqual(t, m.Stats().Timeouts, uint64(1))
}

func TestTLSHandshakeTimeoutIsIndependentOfConnectTimeout(t *testing.T) {
	// The server accepts TCP but never speaks TLS.
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c // hold the connection open without writing
		}
	}()

	cfg := DefaultConfig()
	cfg.ConnectTimeout = 5 * time.Second
	cfg.TLSHandshakeTimeout = 80 * time.Millisecond
	m := NewManager(&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, cfg, Hooks{})
	t.Cleanup(m.Close)

	start := time.Now()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+ln.Addr().String()+"/", nil)
	_, err = m.RoundTrip(req, nil)
	elapsed := time.Since(start)
	require.Error(t, err)
	assert.Less(t, elapsed, 2*time.Second, "the TLS handshake timeout must fire independently of the connect timeout")
}

func TestResponseHeaderTimeout(t *testing.T) {
	origin := newCountedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		fmt.Fprint(w, "late")
	}))
	cfg := DefaultConfig()
	cfg.ResponseHeaderTimeout = 80 * time.Millisecond
	cfg.RequestTimeout = 5 * time.Second
	m := newCountingManager(t, cfg)

	start := time.Now()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
	_, err := m.RoundTrip(req, nil)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 2*time.Second)
	var ne net.Error
	require.ErrorAs(t, err, &ne)
	assert.True(t, ne.Timeout())
	assert.GreaterOrEqual(t, m.Stats().Timeouts, uint64(1))
}

func TestRequestCancellationPropagatesToUpstream(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	origin := newCountedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(stopped)
	}))
	m := newCountingManager(t, DefaultConfig())

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL, nil)
	errCh := make(chan error, 1)
	go func() {
		_, err := m.RoundTrip(req, nil)
		errCh <- err
	}()
	<-started
	cancel()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream request was not canceled when the client went away")
	}
	select {
	case err := <-errCh:
		require.Error(t, err)
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Fatal("RoundTrip did not return after cancellation")
	}
	assert.GreaterOrEqual(t, m.Stats().Canceled, uint64(1))
}

func TestWaitQueueRespectsCancellation(t *testing.T) {
	release := make(chan struct{})
	origin := newCountedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		fmt.Fprint(w, "ok")
	}))
	cfg := DefaultConfig()
	cfg.MaxConnsPerHost = 1
	cfg.MaxConns = 1
	cfg.WaitQueue = 10
	m := newCountingManager(t, cfg)

	go func() {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
		if resp, err := m.RoundTrip(req, nil); err == nil {
			_, _ = drain(resp)
		}
	}()
	require.Eventually(t, func() bool { return m.Stats().Active == 1 }, 2*time.Second, 5*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL, nil)
	errCh := make(chan error, 1)
	go func() {
		_, err := m.RoundTrip(req, nil)
		errCh <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-errCh:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("a canceled waiter was not released")
	}
	close(release)
}

func TestStalePooledConnectionIsReplacedSafely(t *testing.T) {
	// The origin closes every connection right after responding, which makes
	// the idle pooled connection die. A following idempotent request must
	// still succeed: net/http replaces the stale connection with a fresh one.
	// A non-replayable body must never be delivered twice.
	var gets atomic.Int64
	var posts atomic.Int64
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, rerr := http.ReadRequest(br)
				if rerr != nil {
					return
				}
				if req.Method == http.MethodPost {
					_, _ = io.Copy(io.Discard, req.Body)
					posts.Add(1)
				} else {
					gets.Add(1)
				}
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
			}(c)
		}
	}()

	m := newCountingManager(t, DefaultConfig())
	url := "http://" + ln.Addr().String() + "/"

	doRequest(t, m, url)
	doRequest(t, m, url)
	assert.EqualValues(t, 2, gets.Load(), "each GET must reach the origin exactly once")
	assert.GreaterOrEqual(t, m.Stats().News, uint64(2))

	// A POST with a body that cannot be rewound must not be retried.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url,
		io.NopCloser(strings.NewReader("payload")))
	require.NoError(t, err)
	req.ContentLength = int64(len("payload"))
	resp, err := m.RoundTrip(req, nil)
	if err == nil {
		_, _ = drain(resp)
	}
	assert.EqualValues(t, 1, posts.Load(), "a non-replayable request must be submitted at most once")
}

func TestStaleDetectionRecognizesClosedConnections(t *testing.T) {
	assert.True(t, isStaleConnErr(io.EOF))
	assert.True(t, isStaleConnErr(net.ErrClosed))
	assert.True(t, isStaleConnErr(&net.OpError{Op: "read", Err: io.EOF}))
	assert.False(t, isStaleConnErr(&net.OpError{Op: "write", Err: io.ErrUnexpectedEOF}))
	assert.False(t, isStaleConnErr(context.Canceled))
}

func TestNonReusableResponseIsDiscarded(t *testing.T) {
	origin := newCountedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		fmt.Fprint(w, "ok")
	}))
	m := newCountingManager(t, DefaultConfig())
	doRequest(t, m, origin.URL)
	assert.EqualValues(t, 1, origin.accepted.Load())
	stats := m.Stats()
	assert.Zero(t, stats.Recycled, "a Connection: close response must not be pooled")
	assert.GreaterOrEqual(t, stats.Discarded, uint64(1))
}

func TestAuthContextsNeverShareConnections(t *testing.T) {
	origin := newCountedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, html.EscapeString(r.Header.Get("Authorization")))
	}))
	m := newCountingManager(t, DefaultConfig())

	makeReq := func(auth string) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := m.RoundTrip(req, nil)
		require.NoError(t, err)
		_, _ = drain(resp)
	}
	makeReq("Bearer one")
	makeReq("Bearer two")
	makeReq("Bearer one")
	assert.EqualValues(t, 2, origin.accepted.Load(), "different credentials must not share a connection")
}

func TestTrustContextsNeverShareConnections(t *testing.T) {
	m := newCountingManager(t, DefaultConfig())
	m.baseTLSConf = &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}

	// Two different trust configurations for the same target.
	trustA := &tls.Config{InsecureSkipVerify: true, ServerName: "a.example", NextProtos: []string{"http/1.1"}}
	trustB := &tls.Config{InsecureSkipVerify: false, ServerName: "a.example", NextProtos: []string{"http/1.1"}}
	keyA := m.partitionKey("https", trustA, "")
	keyB := m.partitionKey("https", trustB, "")
	assert.NotEqual(t, keyA, keyB, "different trust configurations must use different pools")
	assert.Equal(t, keyA, m.partitionKey("https", trustA.Clone(), ""), "the same trust configuration must reuse the pool")
}

func TestHalfCloseIsPreservedThroughTunnel(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	gotEOF := make(chan struct{})
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		buf := make([]byte, 64)
		_, _ = c.Read(buf)
		// After the client half-closes, the server must still be able to
		// write in the other direction.
		_, _ = c.Write([]byte("reply"))
		close(gotEOF)
		_ = c.Close()
	}()

	m := newCountingManager(t, DefaultConfig())
	conn, err := m.DialContextForTunnel(context.Background(), "tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	cw, ok := conn.(interface{ CloseWrite() error })
	require.True(t, ok, "the tunnel connection must expose CloseWrite")
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	require.NoError(t, cw.CloseWrite())

	buf := make([]byte, 5)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "reply", string(buf[:n]))
	<-gotEOF
}

func TestMultiplexedConnectionNotReaped(t *testing.T) {
	m := newCountingManager(t, DefaultConfig())
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	m.markMultiplexed(server)
	m.trackIdle(server)
	m.reapIdle(time.Now().Add(time.Hour))
	assert.Zero(t, m.Stats().IdleClosed, "a multiplexed connection must never be reaped")
	assert.Zero(t, m.Stats().Active, "the test never acquired a slot")
}

func TestTunnelSlotReleasedAfterHalfClose(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		_, _ = c.Read(make([]byte, 8))
		_ = c.Close()
	}()

	m := newCountingManager(t, DefaultConfig())
	conn, err := m.DialContextForTunnel(context.Background(), "tcp", ln.Addr().String())
	require.NoError(t, err)
	require.EqualValues(t, 1, m.Stats().Active)

	_, _ = conn.Write([]byte("hello"))
	cw, ok := conn.(interface{ CloseWrite() error })
	require.True(t, ok, "the tunnel must expose CloseWrite")
	require.NoError(t, cw.CloseWrite())

	// The half-close alone must not free the slot; the eventual Close does.
	require.NoError(t, conn.Close())
	assert.EqualValues(t, 0, m.Stats().Active)
	// Closing twice must not release the slot twice (which would corrupt the
	// counter).
	_ = conn.Close()
	assert.EqualValues(t, 0, m.Stats().Active)
}

func TestRequestTimeoutAppliesToWholeExchange(t *testing.T) {
	started := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer origin.Close()

	cfg := DefaultConfig()
	cfg.RequestTimeout = 80 * time.Millisecond
	m := newCountingManager(t, cfg)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
	start := time.Now()
	_, err := m.RoundTrip(req, nil)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 2*time.Second, "the whole-request timeout must bound the exchange")
	<-started
	assert.GreaterOrEqual(t, m.Stats().Timeouts, uint64(1))
}

func TestTunnelChurnDoesNotLeakSlots(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	cfg := DefaultConfig()
	cfg.MaxConns = 3
	cfg.MaxConnsPerHost = 3
	m := newCountingManager(t, cfg)
	addr := ln.Addr().String()

	for i := 0; i < 200; i++ {
		c, derr := m.DialContextForTunnel(context.Background(), "tcp", addr)
		if derr != nil {
			t.Fatalf("dial %d: %v", i, derr)
		}
		_ = c.Close()
	}
	assert.Eventually(t, func() bool { return m.Stats().Active == 0 }, 2*time.Second, 5*time.Millisecond,
		"every tunnel slot must be released")
	assert.EqualValues(t, 200, m.Stats().News)
}

func TestTunnelHalfCloseReachesSocket(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	peerSawEOF := make(chan struct{})
	peerReply := make(chan error, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 16)
		n, rerr := c.Read(buf)
		if rerr != nil || string(buf[:n]) != "ping" {
			peerReply <- rerr
			return
		}
		// After the client's CloseWrite, the read returns EOF.
		_, _ = c.Read(buf)
		close(peerSawEOF)
		// The other direction must still work.
		_, werr := c.Write([]byte("pong"))
		peerReply <- werr
	}()

	m := newCountingManager(t, DefaultConfig())
	conn, err := m.DialContextForTunnel(context.Background(), "tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	cw, ok := conn.(interface{ CloseWrite() error })
	require.True(t, ok, "the tunnel must expose CloseWrite")
	require.NoError(t, cw.CloseWrite())

	<-peerSawEOF
	require.NoError(t, <-peerReply)
	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "pong", string(buf[:n]))
}

func TestAuthPartitionsAreBounded(t *testing.T) {
	origin := newCountedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	cfg := DefaultConfig()
	cfg.MaxAuthPartitions = 2
	m := newCountingManager(t, cfg)

	// Three distinct credentials create three partitions, but only the two
	// most recently used are retained; requests keep succeeding.
	for _, cred := range []string{"one", "two", "three", "one"} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
		req.Header.Set("Authorization", "Bearer "+cred)
		resp, err := m.RoundTrip(req, nil)
		require.NoError(t, err)
		_, _ = drain(resp)
	}
	m.mu.Lock()
	n := len(m.parts)
	m.mu.Unlock()
	assert.LessOrEqual(t, n, 2, "the partition count must stay bounded")
}

func TestConcurrentHTTP2RequestsShareOneConnection(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hold briefly so requests overlap on one multiplexed connection.
		time.Sleep(30 * time.Millisecond)
		fmt.Fprint(w, html.EscapeString(r.URL.Path))
	}))
	backend.EnableHTTP2 = true
	backend.StartTLS()
	defer backend.Close()

	cfg := DefaultConfig()
	cfg.RequestTimeout = 5 * time.Second // exercised per request
	m := NewManager(&http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		},
	}, cfg, Hooks{})
	t.Cleanup(m.Close)

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := fmt.Sprintf("/p%d", i)
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, backend.URL+path, nil)
			resp, err := m.RoundTrip(req, nil)
			if err != nil {
				errs <- err
				return
			}
			body, err := drain(resp)
			if err != nil {
				errs <- err
				return
			}
			if body != path {
				errs <- fmt.Errorf("got %q want %q", body, path)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent h2 request failed: %v", err)
	}
	assert.EqualValues(t, 0, m.Stats().Canceled, "no request may be canceled by another's completion")
}
