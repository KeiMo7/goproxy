package goproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
)

var errNotUpstreamRouter = errors.New("goproxy: argument does not implement the upstream router interfaces")

// upstreamRoundTripper is the optional multi-hop chain integration. It is
// satisfied by *upstream.RoundTripper (see subpackage upstream); the root
// package depends only on these minimal interfaces so there is no import
// cycle. When both fields are nil, every code path behaves exactly as it did
// before multi-hop support existed.
type upstreamChainRoundTripper interface {
	http.RoundTripper
}

type upstreamChainDialer interface {
	// DialContextForRequest establishes a multi-hop tunnel to addr, honoring
	// req for route selection.
	DialContextForRequest(ctx context.Context, req *http.Request, network, addr string) (net.Conn, error)
}

// SetUpstreamRouter attaches a multi-hop upstream router built from the
// upstream subpackage. Passing nil detaches it and restores single-hop
// behavior. The argument must implement http.RoundTripper and expose
//
//	DialContextForRequest(ctx context.Context, req *http.Request, network, addr string) (net.Conn, error)
//
// which *upstream.RoundTripper does. Existing single-hop configuration
// (Tr.Proxy, ConnectDial/ConnectDialWithReq, env-var dialer) is left
// untouched and only takes effect again once the router is detached.
func (proxy *ProxyHttpServer) SetUpstreamRouter(r any) error {
	if r == nil {
		proxy.upstreamRT = nil
		proxy.upstreamDialer = nil
		return nil
	}
	rt, ok := r.(upstreamChainRoundTripper)
	if !ok {
		return errNotUpstreamRouter
	}
	d, ok := r.(upstreamChainDialer)
	if !ok {
		return errNotUpstreamRouter
	}
	proxy.upstreamRT = rt
	proxy.upstreamDialer = d
	return nil
}

// HasUpstreamRouter reports whether a multi-hop router is currently attached.
func (proxy *ProxyHttpServer) HasUpstreamRouter() bool {
	return proxy.upstreamRT != nil && proxy.upstreamDialer != nil
}
