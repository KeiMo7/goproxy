package upstream

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// bufferedConn preserves bytes a proxy handshake left buffered in a
// bufio.Reader (e.g. early data the next-hop proxy sent together with its
// 200 reply).
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// idleTunnel is a fully established chain tunnel awaiting reuse.
type idleTunnel struct {
	conn net.Conn
	// bornAt supports basic sanity checks on very old entries.
	bornAt time.Time
}

// chainDialer establishes tunnels through one fixed chain. Instances are
// scoped to a Config snapshot; hot-reload builds new dialers and retires old
// ones after their in-flight requests finish.
type chainDialer struct {
	chain Chain
	fp    string

	// baseDial opens the raw TCP connection to the first hop. Overridable in
	// tests to inject failures.
	baseDial func(ctx context.Context, network, addr string) (net.Conn, error)
	// tlsConfig is used when a hop has TLS=true.
	tlsConfig *tls.Config
	// sink, when non-nil, receives pool/chain events (never credentials).
	sink EventSink

	mu     sync.Mutex
	pools  map[string][]*idleTunnel // target addr -> idle tunnels
	closed bool
}

func newChainDialer(cfg *Config, ch Chain, sink EventSink) *chainDialer {
	var d net.Dialer
	return &chainDialer{
		chain:    ch,
		fp:       fingerprint(cfg.Version, &ch),
		baseDial: d.DialContext,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		sink:  sink,
		pools: map[string][]*idleTunnel{},
	}
}

// poolKey deliberately includes the credential fingerprint: rotating any
// hop credential changes the key so stale tunnels can never be reused.
func (d *chainDialer) poolKey(target string) string {
	return d.chain.ID + "|" + d.fp + "|" + target
}

// CloseIdleConnections drops pooled tunnels without touching connections
// currently serving a request. Used by hot-reload and credential rotation.
func (d *chainDialer) CloseIdleConnections() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, conns := range d.pools {
		for _, t := range conns {
			_ = t.conn.Close()
		}
		delete(d.pools, k)
	}
	d.closed = true
}

func (d *chainDialer) markBroken(c net.Conn) {
	_ = c.Close()
}

// takeIdle pops a pooled tunnel for target. A tunnel whose peer has already
// gone away is discarded rather than handed out.
func (d *chainDialer) takeIdle(target string) net.Conn {
	key := d.poolKey(target)
	d.mu.Lock()
	defer d.mu.Unlock()
	for {
		conns := d.pools[key]
		if len(conns) == 0 {
			return nil
		}
		last := conns[len(conns)-1]
		d.pools[key] = conns[:len(conns)-1]
		// One-byte non-blocking liveness probe: a tunnel that already received
		// a FIN/RST must not be reused.
		if !connAlive(last.conn) {
			_ = last.conn.Close()
			continue
		}
		return last.conn
	}
}

// putIdle returns a healthy tunnel to the pool. Broken/closed conns are
// rejected and closed.
func (d *chainDialer) putIdle(target string, c net.Conn) bool {
	if c == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		_ = c.Close()
		return false
	}
	key := d.poolKey(target)
	d.pools[key] = append(d.pools[key], &idleTunnel{conn: c, bornAt: time.Now()})
	return true
}

// DialContext builds (or reuses) a tunnel through the whole chain to target.
// On failure every partially opened socket is closed; the returned *HopError
// names the exact hop that failed.
func (d *chainDialer) DialContext(ctx context.Context, target string) (net.Conn, error) {
	if c := d.takeIdle(target); c != nil {
		d.emit(Event{Type: EventTunnelReused, Target: target, ChainID: d.chain.ID})
		return c, nil
	}
	c, err := d.dialFresh(ctx, target)
	if err != nil {
		return nil, err
	}
	d.emit(Event{Type: EventTunnelCreated, Target: target, ChainID: d.chain.ID})
	return c, nil
}

// dialFresh walks the hops in order. Hop i's tunnel targets hop i+1's
// address; the final hop targets the destination.
func (d *chainDialer) dialFresh(ctx context.Context, target string) (conn net.Conn, err error) {
	hops := d.chain.Hops
	// All sockets opened along the way are tracked so any failure leaves no
	// half-open connection behind.
	opened := make([]net.Conn, 0, len(hops))
	defer func() {
		if err != nil {
			for _, c := range opened {
				_ = c.Close()
			}
		}
	}()

	for i, hop := range hops {
		nextAddr := target
		if i < len(hops)-1 {
			nextAddr = hops[i+1].Address
		}

		if i == 0 {
			dialCtx, cancel := d.dialContext(ctx, hop.DialTimeout)
			conn, err = d.baseDial(dialCtx, "tcp", hop.Address)
			cancel()
			if err != nil {
				return nil, d.classifyDialErr(i, hop, err)
			}
		}
		opened = append(opened, conn)

		if hop.TLS {
			tlsCfg := d.tlsConfig.Clone()
			serverName, _, splitErr := net.SplitHostPort(hop.Address)
			if splitErr != nil {
				serverName = hop.Address
			}
			tlsCfg.ServerName = serverName
			tlsConn := tls.Client(conn, tlsCfg)
			handshakeCtx, cancel := context.WithTimeout(ctx, effective(hop.HandshakeTimeout))
			handshakeErr := tlsConn.HandshakeContext(handshakeCtx)
			cancel()
			if handshakeErr != nil {
				err = d.wrapErr(i, hop, "tls", handshakeErr)
				return nil, err
			}
			conn = tlsConn
		}

		switch effectiveTunnel(hop.Tunnel) {
		case TunnelConnect:
			nextConn, hErr := d.doConnect(ctx, i, hop, conn, nextAddr)
			if hErr != nil {
				err = hErr
				return nil, err
			}
			conn = nextConn
		case TunnelSOCKS5:
			err = withTimeout(ctx, hop.HandshakeTimeout, func() error {
				return socks5Handshake(conn, hop.Auth, nextAddr)
			})
			if err != nil {
				err = d.attachHop(i, hop, err)
				return nil, err
			}
		case TunnelForward:
			// Forward hop: nothing to do at tunnel layer. transport.go drives
			// the HTTP exchange against this connection.
			if i != len(hops)-1 {
				err = &HopError{ChainID: d.chain.ID, HopIndex: i, HopName: hop.Name,
					Kind: FailureProtocol, Op: "forward", Err: errors.New("forward hop not terminal")}
				return nil, err
			}
		default:
			err = &HopError{ChainID: d.chain.ID, HopIndex: i, HopName: hop.Name,
				Kind: FailureProtocol, Op: "handshake", Err: errors.New("unknown tunnel type")}
			return nil, err
		}
	}
	return conn, nil
}

// doConnect performs an HTTP CONNECT handshake over conn. When the hop is
// configured ChallengeFirst the first attempt carries no credentials; a 407
// response is answered by retrying the SAME hop with credentials. Otherwise
// credentials are sent preemptively and a 407 is still retried once on the
// same connection (e.g. rotated tokens). In all cases only this hop's
// handshake is repeated — the rest of the chain is never rebuilt and no
// request body exists at this layer, so nothing downstream can be replayed.
func (d *chainDialer) doConnect(ctx context.Context, idx int, hop Hop, conn net.Conn, target string) (net.Conn, error) {
	handshake := func(withAuth bool) (*http.Response, net.Conn, error) {
		req := buildConnectRequest(target)
		if withAuth {
			applyHTTPProxyAuth(hop.Auth, req)
		}
		if err := withTimeout(ctx, hop.HandshakeTimeout, func() error {
			return req.Write(conn)
		}); err != nil {
			return nil, conn, d.wrapErr(idx, hop, "connect", err)
		}
		br := bufio.NewReader(conn)
		var resp *http.Response
		err := withTimeout(ctx, hop.HandshakeTimeout, func() error {
			var readErr error
			resp, readErr = http.ReadResponse(br, req)
			return readErr
		})
		if err != nil {
			return nil, conn, d.wrapErr(idx, hop, "connect", err)
		}
		// A successful CONNECT response has no real body — the tunnel bytes
		// follow immediately, so we must never drain it. Only consume a
		// bounded error body (407/502/…) so the socket stays reusable on 407.
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, _errBodyLimit))
		}
		_ = resp.Body.Close()
		out := &bufferedConn{Conn: conn, r: br}
		return resp, out, nil
	}

	firstResp, firstConn, err := handshake(!hop.ChallengeFirst)
	if err != nil {
		return nil, err
	}
	if firstResp.StatusCode == http.StatusOK {
		return firstConn, nil
	}
	if firstResp.StatusCode != http.StatusProxyAuthRequired {
		return nil, &HopError{ChainID: d.chain.ID, HopIndex: idx, HopName: hop.Name,
			Kind: FailureRefused, Op: "connect",
			Err: fmt.Errorf("proxy replied %d", firstResp.StatusCode)}
	}

	if hop.Auth.Type == AuthNone {
		return nil, &HopError{ChainID: d.chain.ID, HopIndex: idx, HopName: hop.Name,
			Kind: FailureAuth, Op: "connect", Err: errors.New("proxy requires authentication but no credentials configured")}
	}
	// Re-handshake on the same socket: the proxy explicitly kept the
	// connection open with the 407. If the socket died meanwhile, the second
	// write/read fails as a normal I/O error — no liveness probe is needed,
	// and a probe could steal bytes buffered by the bufio.Reader.
	resp2, out2, err := handshake(true)
	if err != nil {
		return nil, err
	}
	if resp2.StatusCode == http.StatusOK {
		return out2, nil
	}
	if resp2.StatusCode == http.StatusProxyAuthRequired {
		return nil, &HopError{ChainID: d.chain.ID, HopIndex: idx, HopName: hop.Name,
			Kind: FailureAuth, Op: "connect", Err: errors.New("proxy rejected credentials")}
	}
	return nil, &HopError{ChainID: d.chain.ID, HopIndex: idx, HopName: hop.Name,
		Kind: FailureRefused, Op: "connect", Err: fmt.Errorf("proxy replied %d after auth retry", resp2.StatusCode)}
}

const _errBodyLimit int64 = 4096

func buildConnectRequest(target string) *http.Request {
	return &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
}

// applyHTTPProxyAuth writes hop-local credentials onto a CONNECT request.
// It is the only place hop credentials touch a request, and the header is
// consumed by this single hop's proxy only.
func applyHTTPProxyAuth(a Auth, req *http.Request) {
	switch a.Type {
	case AuthNone:
		return
	case AuthBasic:
		if a.Username == "" && a.Password == "" {
			return
		}
		token := a.Username + ":" + a.Password
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(token)))
	case AuthToken:
		header := a.Header
		if header == "" {
			header = "Proxy-Authorization"
		}
		value := a.Token
		if a.Scheme != "" {
			value = a.Scheme + " " + value
		}
		req.Header.Set(header, value)
	}
}

// forwardAuthHeader returns the proxy-auth header for a forward-hop request,
// or ("", "") when the hop needs none.
func forwardAuthHeader(a Auth) (string, string) {
	switch a.Type {
	case AuthBasic:
		if a.Username == "" && a.Password == "" {
			return "", ""
		}
		token := a.Username + ":" + a.Password
		return "Proxy-Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(token))
	case AuthToken:
		header := a.Header
		if header == "" {
			header = "Proxy-Authorization"
		}
		value := a.Token
		if a.Scheme != "" {
			value = a.Scheme + " " + value
		}
		return header, value
	default:
		return "", ""
	}
}

// classifyDialErr maps raw TCP dial errors to the hop-level taxonomy.
func (d *chainDialer) classifyDialErr(idx int, hop Hop, err error) error {
	kind := FailureUnreachable
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		kind = FailureTimeout
	}
	if errors.Is(err, context.Canceled) {
		kind = FailureCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		kind = FailureTimeout
	}
	if strings.Contains(err.Error(), "connection refused") {
		kind = FailureRefused
	}
	return &HopError{ChainID: d.chain.ID, HopIndex: idx, HopName: hop.Name,
		Kind: kind, Op: "dial", Err: err}
}

// wrapErr classifies non-dial errors (TLS handshake, proxy protocol errors).
func (d *chainDialer) wrapErr(idx int, hop Hop, op string, err error) error {
	if he := (*HopError)(nil); errors.As(err, &he) {
		// SOCKS layer already produced a classified HopError; fill identity.
		return d.attachHop(idx, hop, err)
	}
	kind := FailureProtocol
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		kind = FailureTimeout
	}
	if errors.Is(err, context.Canceled) {
		kind = FailureCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		kind = FailureTimeout
	}
	return &HopError{ChainID: d.chain.ID, HopIndex: idx, HopName: hop.Name,
		Kind: kind, Op: op, Err: err}
}

// attachHop ensures an error produced deeper in the stack carries the hop
// identity of the current traversal step.
func (d *chainDialer) attachHop(idx int, hop Hop, err error) error {
	var he *HopError
	if errors.As(err, &he) {
		he.ChainID = d.chain.ID
		he.HopIndex = idx
		he.HopName = hop.Name
		return he
	}
	return d.wrapErr(idx, hop, "handshake", err)
}

func (d *chainDialer) emit(e Event) {
	if d.sink != nil {
		d.sink.Observe(e)
	}
}

func effectiveTunnel(t TunnelType) TunnelType {
	if t == "" {
		return TunnelConnect
	}
	return t
}

func effective(d time.Duration) time.Duration {
	if d <= 0 {
		return 30 * time.Second
	}
	return d
}

func (d *chainDialer) dialContext(parent context.Context, hopTimeout time.Duration) (context.Context, context.CancelFunc) {
	if hopTimeout <= 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, hopTimeout)
}

// withTimeout runs fn bounded by the per-hop handshake timeout, while still
// honoring parent cancellation.
func withTimeout(parent context.Context, hopTimeout time.Duration, fn func() error) error {
	if hopTimeout <= 0 {
		return fn()
	}
	ctx, cancel := context.WithTimeout(parent, hopTimeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		if errors.Is(parent.Err(), context.Canceled) {
			return &HopError{Kind: FailureCanceled, Op: "handshake", Err: parent.Err()}
		}
		return &HopError{Kind: FailureTimeout, Op: "handshake", Err: ctx.Err()}
	}
}

// connAlive performs a non-blocking liveness check used before reusing a
// pooled tunnel.
func connAlive(c net.Conn) bool {
	if c == nil {
		return false
	}
	_ = c.SetReadDeadline(time.Now())
	one := make([]byte, 1)
	n, err := c.Read(one)
	if n > 0 {
		// Unexpected unsolicited byte — treat as broken.
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		// Reset the deadline; no data means the connection is idle and usable.
		_ = c.SetReadDeadline(time.Time{})
		return true
	}
	return false
}
