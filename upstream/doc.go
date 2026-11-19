// Package upstream provides multi-hop upstream proxy chains for goproxy.
//
// A Chain is an ordered list of Hop values. Each hop uses its own tunnel
// type (HTTP CONNECT, SOCKS5, or HTTP forwarding) and its own credentials.
// A Router selects a chain per destination using hostname suffixes, exact
// hostnames, or IP CIDRs, and supports ordered backup chains with typed,
// hop-attributed failover.
//
// # Credential isolation
//
// A hop's Auth is only serialized toward that hop. Credentials are never
// copied onto requests to later hops, never written to the destination, and
// never included in logs, events, or error strings. HopError.Error contains
// only the hop index, hop name, operation, and failure kind.
//
// # Failure semantics
//
// Failures are classified into FailureKind values (unreachable, timeout,
// auth, refused, protocol, canceled) and wrapped in *HopError naming the
// exact hop. When every allowed chain fails, *RouteError aggregates the
// per-hop reasons of every attempt. A 407 challenge is retried against the
// challenged hop only; failover happens strictly before any request byte is
// written, so a request body can never be transmitted twice.
//
// # Reuse and hot-reload
//
// Tunnels are pooled per (chain, credential fingerprint, target). Rotating
// credentials or replacing the Config changes the fingerprint, forcing new
// tunnels. Router.Replace is atomic: in-flight requests keep their old
// dialers and connections; only idle tunnels of the retired snapshot close.
//
// # Wiring into goproxy
//
//	router, err := upstream.NewRouter(cfg)
//	// ...
//	proxy.SetUpstreamRouter(upstream.NewRoundTripper(router))
//
// With no router attached, goproxy behaves exactly as it did before this
// package existed.
package upstream
