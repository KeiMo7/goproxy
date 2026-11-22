package goproxy

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/elazarl/goproxy/internal/upstream"
)

// UpstreamEventKind identifies an upstream connection lifecycle event.
type UpstreamEventKind int

// Upstream lifecycle event kinds.
const (
	// UpstreamEventReuse is reported when a request is served on a reused
	// upstream connection.
	UpstreamEventReuse UpstreamEventKind = iota
	// UpstreamEventNew is reported when a new upstream connection is
	// established.
	UpstreamEventNew
	// UpstreamEventClose is reported when an upstream connection is closed.
	UpstreamEventClose
	// UpstreamEventTimeout is reported when an upstream operation times
	// out (connect, TLS handshake, response headers or idle expiry).
	UpstreamEventTimeout
	// UpstreamEventQueued is reported when a caller has to wait for a
	// connection slot.
	UpstreamEventQueued
	// UpstreamEventRejected is reported when a caller is rejected because
	// the wait queue is full.
	UpstreamEventRejected
	// UpstreamEventRetry is reported when a stale pooled connection is
	// replaced and the request retried once.
	UpstreamEventRetry
	// UpstreamEventDiscarded is reported when a connection is not returned
	// to the pool because it is not reusable.
	UpstreamEventDiscarded
	// UpstreamEventCanceled is reported when a request or tunnel is
	// canceled.
	UpstreamEventCanceled
)

// UpstreamEvent describes an upstream connection lifecycle event. Target is
// the origin host:port and never carries credentials.
type UpstreamEvent struct {
	Kind   UpstreamEventKind
	Target string
	// Tunnel is true for events on the CONNECT tunnel path.
	Tunnel bool
}

// UpstreamStats is a snapshot of a proxy's upstream connection counters.
type UpstreamStats struct {
	// Hits is the number of requests served on a reused connection.
	Hits uint64
	// News is the number of upstream connections newly established.
	News uint64
	// Recycled is the number of connections returned to the idle pool.
	Recycled uint64
	// Timeouts is the number of upstream operations that timed out.
	Timeouts uint64

	// IdleClosed is the number of connections reclaimed for being idle.
	IdleClosed uint64
	// Queued is the number of callers that had to wait for a slot.
	Queued uint64
	// Rejected is the number of callers rejected at a limit.
	Rejected uint64
	// Retried is the number of requests retried after a stale connection.
	Retried uint64
	// Discarded is the number of connections dropped as non-reusable.
	Discarded uint64
	// Canceled is the number of canceled requests or tunnels.
	Canceled uint64
	// Active is the number of live upstream connections.
	Active int64
}

// UpstreamConfig controls upstream connection reuse, resource limits and
// timeouts. A zero field selects the package default; a negative duration or
// limit disables the corresponding feature.
//
// The defaults bound total and per-origin connections (1024 and 64), the TCP
// connect (15s), the TLS handshake (10s) and idle keep-alive lifetime (90s).
// The response-header and whole-request timeouts are disabled by default so
// that long-polling and streaming responses keep working unchanged.
type UpstreamConfig struct {
	// MaxConns bounds the total number of live upstream connections
	// (forwarding and tunnelling combined). Negative means unlimited.
	MaxConns int
	// MaxConnsPerHost bounds the live upstream connections of a single
	// origin (host:port). Negative means unlimited.
	MaxConnsPerHost int
	// MaxIdleConnsPerHost bounds the idle keep-alive connections retained
	// per origin. Negative disables idle retention.
	MaxIdleConnsPerHost int
	// WaitQueue is the number of callers that may wait for a connection
	// slot once a limit is reached; further callers fail fast. Negative
	// disables waiting entirely.
	WaitQueue int

	// ConnectTimeout bounds name resolution plus the TCP connect of one
	// upstream connection, independently of the request deadline.
	ConnectTimeout time.Duration
	// TLSHandshakeTimeout bounds the TLS handshake to an upstream server,
	// independently of ConnectTimeout.
	TLSHandshakeTimeout time.Duration
	// ResponseHeaderTimeout bounds the wait for response headers after the
	// request has been written. Zero disables it.
	ResponseHeaderTimeout time.Duration
	// IdleTimeout bounds how long an idle keep-alive connection is retained
	// before being reclaimed.
	IdleTimeout time.Duration
	// TunnelIdleTimeout bounds how long a CONNECT tunnel may carry no bytes
	// in either direction before being reclaimed. Defaults to IdleTimeout.
	TunnelIdleTimeout time.Duration
	// TunnelConnectTimeout bounds establishing the upstream side of a
	// tunnel. Defaults to ConnectTimeout.
	TunnelConnectTimeout time.Duration
	// RequestTimeout bounds a whole upstream exchange (connect, TLS
	// handshake, response headers and body). Zero disables it; the caller's
	// context always applies.
	RequestTimeout time.Duration
	// MaxAuthPartitions bounds the number of distinct authentication
	// contexts for which separate pools are kept.
	MaxAuthPartitions int

	// OnEvent receives upstream lifecycle events from a background
	// goroutine. Events are dropped rather than blocking forwarding when
	// the handler falls behind.
	OnEvent func(UpstreamEvent)
}

func (c *UpstreamConfig) internal() upstream.Config {
	if c == nil {
		return upstream.DefaultConfig()
	}
	cfg := upstream.Config{
		MaxConns:              c.MaxConns,
		MaxConnsPerHost:       c.MaxConnsPerHost,
		MaxIdleConnsPerHost:   c.MaxIdleConnsPerHost,
		WaitQueue:             c.WaitQueue,
		ConnectTimeout:        c.ConnectTimeout,
		TLSHandshakeTimeout:   c.TLSHandshakeTimeout,
		ResponseHeaderTimeout: c.ResponseHeaderTimeout,
		IdleTimeout:           c.IdleTimeout,
		TunnelIdleTimeout:     c.TunnelIdleTimeout,
		TunnelConnectTimeout:  c.TunnelConnectTimeout,
		RequestTimeout:        c.RequestTimeout,
		MaxAuthPartitions:     c.MaxAuthPartitions,
	}
	if c.OnEvent != nil {
		handler := c.OnEvent
		cfg.OnEvent = func(ev upstream.Event) {
			handler(UpstreamEvent{Kind: UpstreamEventKind(ev.Kind), Target: ev.Target, Tunnel: ev.Tunnel})
		}
	}
	return cfg
}

// inheritTransportTimeouts seeds the pool configuration from a transport the
// caller configured explicitly, so tuning proxy.Tr keeps working. It only
// applies when no UpstreamConfig was supplied: an explicit UpstreamConfig is
// authoritative, and its zero fields select the package defaults.
func inheritTransportTimeouts(tr *http.Transport) upstream.Config {
	cfg := upstream.DefaultConfig()
	if tr.IdleConnTimeout != 0 {
		cfg.IdleTimeout = tr.IdleConnTimeout
	}
	if tr.TLSHandshakeTimeout != 0 {
		cfg.TLSHandshakeTimeout = tr.TLSHandshakeTimeout
	}
	if tr.ResponseHeaderTimeout != 0 {
		cfg.ResponseHeaderTimeout = tr.ResponseHeaderTimeout
	}
	if tr.MaxIdleConnsPerHost != 0 {
		cfg.MaxIdleConnsPerHost = tr.MaxIdleConnsPerHost
	}
	if tr.MaxConnsPerHost > 0 {
		cfg.MaxConnsPerHost = tr.MaxConnsPerHost
	}
	return cfg
}

// upstreamManager returns the manager for the proxy's current transport,
// creating (or replacing) it when the transport or configuration changed.
func (proxy *ProxyHttpServer) upstreamManager() *upstream.Manager {
	proxy.upstreamMu.Lock()
	defer proxy.upstreamMu.Unlock()
	if proxy.Tr == nil {
		return nil
	}
	if proxy.upstreamMgr != nil && proxy.upstreamTr == proxy.Tr && proxy.upstreamCfg == proxy.Upstream {
		return proxy.upstreamMgr
	}
	if proxy.upstreamMgr != nil {
		proxy.upstreamMgr.Close()
	}
	var cfg upstream.Config
	if proxy.Upstream != nil {
		cfg = proxy.Upstream.internal()
	} else {
		cfg = inheritTransportTimeouts(proxy.Tr)
	}
	mgr := upstream.NewManager(proxy.Tr, cfg, upstream.Hooks{})
	proxy.upstreamMgr = mgr
	proxy.upstreamTr = proxy.Tr
	proxy.upstreamCfg = proxy.Upstream
	return mgr
}

// roundTripUpstream forwards req through the upstream pool. It is the
// default path used by ProxyCtx.RoundTrip.
func (proxy *ProxyHttpServer) roundTripUpstream(ctx *ProxyCtx, req *http.Request) (*http.Response, error) {
	mgr := proxy.upstreamManager()
	if mgr == nil {
		return nil, upstream.ErrClosed
	}
	return mgr.RoundTrip(req, ctx)
}

// UpstreamStats returns a snapshot of the upstream connection counters.
func (proxy *ProxyHttpServer) UpstreamStats() UpstreamStats {
	mgr := proxy.upstreamManager()
	if mgr == nil {
		return UpstreamStats{}
	}
	return fromInternalStats(mgr.Stats())
}

// CloseIdleUpstreamConnections closes every idle upstream connection. Useful
// to release resources promptly, for example on configuration reload. In-use
// connections are unaffected.
func (proxy *ProxyHttpServer) CloseIdleUpstreamConnections() {
	mgr := proxy.upstreamManager()
	if mgr == nil {
		return
	}
	mgr.CloseIdle()
}

func fromInternalStats(s upstream.Stats) UpstreamStats {
	return UpstreamStats{
		Hits:       s.Hits,
		News:       s.News,
		Recycled:   s.Recycled,
		Timeouts:   s.Timeouts,
		IdleClosed: s.IdleClosed,
		Queued:     s.Queued,
		Rejected:   s.Rejected,
		Retried:    s.Retried,
		Discarded:  s.Discarded,
		Canceled:   s.Canceled,
		Active:     s.Active,
	}
}

// upstreamTunnelDial establishes the upstream side of a CONNECT tunnel
// through the shared connection budget.
func (proxy *ProxyHttpServer) upstreamTunnelDial(ctx *ProxyCtx, network, addr string) (net.Conn, error) {
	mgr := proxy.upstreamManager()
	if mgr == nil {
		return nil, upstream.ErrClosed
	}
	var dial upstream.DialFunc
	switch {
	case ctx.Dialer != nil:
		// A per-request dialer overrides everything else.
		d := ctx.Dialer
		reqCtx := ctx.Req.Context()
		dial = func(_ context.Context, network, addr string) (net.Conn, error) {
			return d(reqCtx, network, addr)
		}
	case proxy.dialFromEnv && proxy.ConnectDial != nil:
		cd := proxy.ConnectDial
		dial = func(_ context.Context, network, addr string) (net.Conn, error) {
			return cd(network, addr)
		}
	}
	return mgr.DialContextForTunnelWith(ctx.Req.Context(), network, addr, dial)
}
