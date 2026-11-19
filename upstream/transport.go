package upstream

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
)

// RoundTripper routes HTTP requests through the configured multi-hop chains.
// It implements http.RoundTripper and is safe for concurrent use.
type RoundTripper struct {
	router *Router
}

// NewRoundTripper wraps a Router for use as an http.RoundTripper.
func NewRoundTripper(r *Router) *RoundTripper {
	return &RoundTripper{router: r}
}

// reportKey carries the per-request FailoverReport slot.
type reportKey struct{}

// WithReport allocates a *FailoverReport slot in the context. After RoundTrip
// returns (even with an error), the slot is populated whenever routing ran.
func WithReport(ctx context.Context) (context.Context, *FailoverReport) {
	rep := &FailoverReport{}
	return context.WithValue(ctx, reportKey{}, rep), rep
}

func reportFrom(ctx context.Context) *FailoverReport {
	rep, _ := ctx.Value(reportKey{}).(*FailoverReport)
	return rep
}

// bodyGuard records whether request-body bytes have been produced. Failover
// runs strictly in the dial phase (before this body is touched), so once a
// Read has delivered data another attempt is structurally impossible. The
// guard makes this guarantee explicit and testable.
type bodyGuard struct {
	io.ReadCloser
	consumed bool
}

func (g *bodyGuard) Read(p []byte) (int, error) {
	n, err := g.ReadCloser.Read(p)
	if n > 0 {
		g.consumed = true
	}
	return n, err
}

// RoundTrip selects a chain for req.URL.Host, establishes the chain tunnel
// (with failover), then performs exactly one HTTP exchange over it.
func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil {
		return nil, errors.New("upstream: nil Request.URL")
	}
	targetHost := req.URL.Host
	host := req.URL.Hostname()

	guard := &bodyGuard{}
	if req.Body != nil && req.Body != http.NoBody {
		guard.ReadCloser = req.Body
		req.Body = guard
	}

	// Failover happens here, before a single request byte is written. Once
	// routedDial returns, no further attempt is ever made.
	chainConn, dialer, report, err := rt.router.routedDial(req.Context(), host, targetHost)
	if rep := reportFrom(req.Context()); rep != nil && report != nil {
		*rep = *report
	}
	if err != nil {
		return nil, err
	}
	if chainConn == nil || dialer == nil {
		return nil, errors.New("upstream: router returned no connection without an error")
	}
	if guard.consumed {
		// Defensive: routedDial must never consume the body. Close and refuse
		// rather than risk a duplicated request.
		_ = chainConn.Close()
		return nil, errors.New("upstream: internal error: request body consumed before tunnel was established")
	}

	hops := dialer.chain.Hops
	last := hops[len(hops)-1]
	if effectiveTunnel(last.Tunnel) == TunnelForward && req.URL.Scheme == "https" {
		_ = chainConn.Close()
		return nil, &HopError{ChainID: dialer.chain.ID, HopIndex: len(hops) - 1,
			HopName: last.Name, Kind: FailureProtocol, Op: "forward",
			Err: errors.New("forward hop cannot carry HTTPS; use a CONNECT/SOCKS terminal hop")}
	}

	resp, err := rt.exchange(req, dialer, chainConn)
	if err != nil {
		// Exchange-phase failures never trigger another attempt.
		_ = chainConn.Close()
		return nil, err
	}
	return resp, nil
}

// exchange performs the single HTTP transaction over the established chain.
func (rt *RoundTripper) exchange(req *http.Request, dialer *chainDialer, chainConn net.Conn) (*http.Response, error) {
	hops := dialer.chain.Hops
	last := hops[len(hops)-1]
	conn := net.Conn(chainConn)

	// Terminal TLS for tunneled HTTPS.
	if req.URL.Scheme == "https" && effectiveTunnel(last.Tunnel) != TunnelForward {
		tlsConn, err := terminalTLS(chainConn, req.URL.Hostname())
		if err != nil {
			return nil, &HopError{ChainID: dialer.chain.ID, HopIndex: len(hops) - 1,
				HopName: last.Name, Kind: FailureProtocol, Op: "tls", Err: err}
		}
		conn = tlsConn
	}

	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	// Any embedded userinfo must never reach a hop; hop credentials come from
	// Hop.Auth only.
	if outReq.URL.User != nil {
		outReq.URL.User = nil
	}

	if effectiveTunnel(last.Tunnel) == TunnelForward {
		// Absolute-form request line for the forwarding proxy, with hop-local
		// auth. RequestURI must be the absolute URL: a cleared RequestURI makes
		// Request.Write emit origin-form, which a forward proxy cannot route.
		outReq.RequestURI = outReq.URL.String()
		if h, v := forwardAuthHeader(last.Auth); h != "" {
			outReq.Header.Set(h, v)
		}
	} else {
		// Tunneled end-to-end: origin-form against the destination; proxy
		// headers belong to individual hop CONNECT handshakes, not this stream.
		outReq.Header.Del("Proxy-Authorization")
		outReq.Header.Del("Proxy-Connection")
	}

	bw := bufio.NewWriter(conn)
	var err error
	if effectiveTunnel(last.Tunnel) == TunnelForward {
		// WriteProxy emits the absolute-form request line required by a
		// forwarding proxy.
		err = outReq.WriteProxy(bw)
	} else {
		err = outReq.Write(bw)
	}
	if err != nil {
		return nil, &HopError{ChainID: dialer.chain.ID, HopIndex: len(hops) - 1,
			HopName: last.Name, Kind: FailureProtocol, Op: "write", Err: err}
	}
	if err := bw.Flush(); err != nil {
		return nil, &HopError{ChainID: dialer.chain.ID, HopIndex: len(hops) - 1,
			HopName: last.Name, Kind: FailureProtocol, Op: "write", Err: err}
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, outReq)
	if err != nil {
		return nil, &HopError{ChainID: dialer.chain.ID, HopIndex: len(hops) - 1,
			HopName: last.Name, Kind: FailureProtocol, Op: "read", Err: err}
	}

	reusable := !resp.Close && !outReq.Close
	resp.Body = &poolingBody{
		ReadCloser: resp.Body,
		rawConn:    chainConn,
		dialer:     dialer,
		target:     req.URL.Host,
		reusable:   reusable,
	}
	return resp, nil
}

// poolingBody returns the chain tunnel to the dialer pool once the response
// body is drained/closed. An abnormal teardown closes the tunnel so a broken
// connection is never handed back to another request.
type poolingBody struct {
	io.ReadCloser
	rawConn  net.Conn
	dialer   *chainDialer
	target   string
	reusable bool
	returned bool
}

func (b *poolingBody) Close() error {
	err := b.ReadCloser.Close()
	if b.returned {
		return err
	}
	b.returned = true
	if b.reusable && b.dialer.putIdle(b.target, b.rawConn) {
		return err
	}
	_ = b.rawConn.Close()
	return err
}

// DialContext opens a chain tunnel to addr for CONNECT-style wiring. The
// returned connection is owned by the caller and is not pooled here (the
// proxy server's copy loops own its lifecycle).
func (rt *RoundTripper) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host := hostOnly(addr)
	conn, _, _, err := rt.router.routedDial(ctx, host, addr)
	return conn, err
}

// DialContextForRequest is the goproxy integration entry point: it opens a
// chain tunnel to addr using req for route selection. The returned connection
// is owned by the caller.
func (rt *RoundTripper) DialContextForRequest(ctx context.Context, req *http.Request, network, addr string) (net.Conn, error) {
	return rt.router.DialContext(ctx, req, network, addr)
}

// Router returns the underlying router.
func (rt *RoundTripper) Router() *Router { return rt.router }
