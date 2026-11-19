package goproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/elazarl/goproxy/internal/upstreamtls"
)

// relayRoundTripper handles requests whose transport is configured with an
// encrypted (HTTPS) forward proxy. It performs the two independent hops
// explicitly:
//
//  1. a TLS handshake to the relay, verified against the relay's own name
//     and trust policy;
//  2. an HTTP CONNECT through that TLS connection, followed by a separate
//     TLS handshake to the target verified against the target's own name
//     and trust policy.
//
// The standard http.Transport cannot express this nesting through its
// DialTLSContext hook, because it assumes the dialer returns an
// end-to-end TLS connection and applies its own TLS/HTTP state to it. This
// round tripper owns the full lifecycle instead while keeping pool
// keying, cancellation and timeout semantics aligned with the rest of the
// proxy.
type relayRoundTripper struct {
	proxy *ProxyHttpServer
	mu    sync.Mutex
	pools map[relayPoolKey]*relayConnPool
}

type relayPoolKey struct {
	target string
	relay  string
	fp     policyFingerprint
}

type relayConnPool struct {
	mu    sync.Mutex
	conns []*relayConn
}

type relayConn struct {
	inner net.Conn // inner target TLS connection, carried over the relay tunnel
	br    *bufio.Reader
	busy  bool
}

func newRelayRoundTripper(proxy *ProxyHttpServer) *relayRoundTripper {
	return &relayRoundTripper{proxy: proxy, pools: map[relayPoolKey]*relayConnPool{}}
}

func (proxy *ProxyHttpServer) relayRoundTripper() *relayRoundTripper {
	proxy.relayRoundOnce.Do(func() {
		proxy.relayRT = newRelayRoundTripper(proxy)
	})
	return proxy.relayRT
}

// RoundTrip executes one HTTP/1.1 transaction over a two-hop relay
// connection. It reuses idle connections keyed by target plus trust
// fingerprint, so distinct trust configurations never share a connection.
func (rt *relayRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil {
		return nil, &upstreamtls.VerificationError{Kind: upstreamtls.FailureConfig, Reason: "nil request URL"}
	}

	name, err := upstreamtls.NormalizeName(req.URL.Host)
	if err != nil {
		return nil, err
	}
	snap := rt.proxy.trustRegistry().Current()
	policy := rt.proxy.effectiveMode(snap, name)
	fp := fingerprintOf(snap, policy)

	relayURL, err := rt.proxy.Tr.Proxy(req)
	if err != nil {
		return nil, err
	}
	if relayURL == nil || (relayURL.Scheme != "https" && relayURL.Scheme != "wss") {
		// Not an encrypted relay: defer to the normal policy transport.
		return rt.proxy.policyRoundTripper().RoundTrip(req)
	}

	key := relayPoolKey{target: name.String(), relay: relayURL.Host, fp: fp}
	pool := rt.poolForKey(key)

	rc, err := rt.getConn(req.Context(), pool, key, policy, snap, relayURL)
	if err != nil {
		return nil, err
	}

	if err := req.Write(rc.inner); err != nil {
		rt.discard(rc)
		return nil, err
	}
	resp, err := http.ReadResponse(rc.br, req)
	if err != nil {
		rt.discard(rc)
		return nil, err
	}
	// Honor connection-close semantics: a request or response asking to
	// close must not be returned to the reuse pool.
	reuse := !req.Close && !resp.Close && !headerConnClose(resp.Header)
	// Wrap the body so the connection is returned to the pool when closed.
	resp.Body = &relayBody{body: resp.Body, pool: pool, rc: rc, reusable: reuse}
	return resp, nil
}

// headerConnClose reports whether headers carry "Connection: close".
func headerConnClose(h http.Header) bool {
	for _, v := range h.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "close") {
				return true
			}
		}
	}
	return false
}

func (rt *relayRoundTripper) poolForKey(key relayPoolKey) *relayConnPool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	pool, ok := rt.pools[key]
	if !ok {
		pool = &relayConnPool{}
		rt.pools[key] = pool
	}
	return pool
}

func (rt *relayRoundTripper) getConn(
	ctx context.Context,
	pool *relayConnPool,
	key relayPoolKey,
	policy *upstreamtls.TargetPolicy,
	snap *upstreamtls.Snapshot,
	relayURL *url.URL,
) (*relayConn, error) {
	pool.mu.Lock()
	for len(pool.conns) > 0 {
		c := pool.conns[len(pool.conns)-1]
		pool.conns = pool.conns[:len(pool.conns)-1]
		if !c.busy {
			c.busy = true
			pool.mu.Unlock()
			return c, nil
		}
	}
	pool.mu.Unlock()

	inner, err := rt.dialTwoHop(ctx, key, policy, snap, relayURL)
	if err != nil {
		return nil, err
	}
	return &relayConn{inner: inner, br: bufio.NewReader(inner), busy: true}, nil
}

// dialTwoHop establishes the outer relay TLS connection, the CONNECT tunnel
// and the inner target TLS connection, each with its own name and policy.
func (rt *relayRoundTripper) dialTwoHop(
	ctx context.Context,
	key relayPoolKey,
	targetPolicy *upstreamtls.TargetPolicy,
	snap *upstreamtls.Snapshot,
	relayURL *url.URL,
) (net.Conn, error) {
	proxy := rt.proxy

	// Hop 1: TCP + TLS to the relay using the relay's own name.
	relayName, err := upstreamtls.NormalizeName(key.relay)
	if err != nil {
		return nil, err
	}
	relayAddr := withDefaultPort(key.relay, "443")
	rawToRelay, err := proxy.dialRaw(ctx, "tcp", relayAddr)
	if err != nil {
		return nil, err
	}
	relaySnap := proxy.trustRegistry().Current()
	relayPolicy := proxy.effectiveMode(relaySnap, relayName)
	req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+key.relay, nil)
	relayConn, err := proxy.initializeRelayTLS(&ProxyCtx{Req: req}, rawToRelay, key.relay, relayName, relaySnap, relayPolicy)
	if err != nil {
		return nil, err
	}

	// CONNECT through the relay to the target.
	targetAddr := withDefaultPort(key.target, "443")
	tunnel, err := proxy.connectThrough(ctx, relayConn, targetAddr, relayURL)
	if err != nil {
		_ = relayConn.Close()
		return nil, err
	}

	// Hop 2: independent TLS to the target over the tunnel, with the
	// target's own name and trust policy.
	baseCfg := proxy.Tr.TLSClientConfig
	if baseCfg == nil {
		baseCfg = &tls.Config{}
	}
	targetName, err := upstreamtls.NormalizeName(targetAddr)
	if err != nil {
		return nil, err
	}
	hop := upstreamtls.Hop{
		Name:       targetName,
		Snapshot:   snap,
		Label:      "target",
		BaseConfig: baseCfg,
	}
	cfg, report, err := upstreamtls.ConfigForPolicy(hop, targetPolicy)
	if err != nil {
		_ = tunnel.Close()
		return nil, err
	}
	tlsConn := tls.Client(tunnel, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tunnel.Close()
		return nil, upstreamtls.HandshakeError("target", targetName, err)
	}
	if report.Skipped {
		state := tlsConn.ConnectionState()
		report.TLSVersion = state.Version
		if len(state.PeerCertificates) > 0 {
			report.PeerFingerprint = fingerprintLeaf(state.PeerCertificates[0])
		}
	}
	if box := reportBoxFromCtx(ctx); box != nil {
		box.add(reportFromInternal(report))
	}
	return tlsConn, nil
}

func (rt *relayRoundTripper) discard(rc *relayConn) {
	_ = rc.inner.Close()
}

// relayBody returns a connection to its pool once the response body is fully
// consumed and closed, preserving keep-alive semantics. A connection marked
// non-reusable (Connection: close) is torn down instead.
type relayBody struct {
	body     io.ReadCloser
	pool     *relayConnPool
	rc       *relayConn
	reusable bool
	once     sync.Once
}

func (b *relayBody) Read(p []byte) (int, error) { return b.body.Read(p) }

func (b *relayBody) Close() error {
	err := b.body.Close()
	b.once.Do(func() {
		if !b.reusable {
			_ = b.rc.inner.Close()
			return
		}
		b.rc.busy = false
		b.pool.mu.Lock()
		b.pool.conns = append(b.pool.conns, b.rc)
		b.pool.mu.Unlock()
	})
	return err
}
