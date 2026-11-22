# Upstream connection reuse, limits and cancellation

This document describes how goproxy manages connections to upstream origins:
reuse, bounded pooling, layered timeouts, idle reclamation and end-to-end
cancellation.

The default configuration bounds total and per-origin connections and applies
connect, TLS-handshake and idle timeouts. Every other behaviour is unchanged
unless you opt in through `ProxyHttpServer.Upstream`.

## Configuration

```go
proxy := goproxy.NewProxyHttpServer()
proxy.Upstream = &goproxy.UpstreamConfig{
    MaxConns:            1024,             // total live upstream connections
    MaxConnsPerHost:     64,               // per origin (host:port)
    MaxIdleConnsPerHost: 16,               // idle keep-alive connections kept
    WaitQueue:           1024,             // callers allowed to wait for a slot
    ConnectTimeout:      15 * time.Second, // resolve + TCP connect
    TLSHandshakeTimeout: 10 * time.Second, // TLS handshake, counted separately
    ResponseHeaderTimeout: 0,              // disabled: long-polling unaffected
    IdleTimeout:           90 * time.Second,
    TunnelIdleTimeout:     5 * time.Minute,
    RequestTimeout:        0,              // disabled by default
}
```

A zero field selects the package default. A negative duration or limit
disables that feature (for example `WaitQueue: -1` makes every caller over a
limit fail fast, and `IdleTimeout: -1` keeps idle connections forever).

When `Upstream` is nil, the pool inherits whatever the caller set on
`proxy.Tr` (`IdleConnTimeout`, `TLSHandshakeTimeout`,
`ResponseHeaderTimeout`, `MaxIdleConnsPerHost`, `MaxConnsPerHost`) so that
tuning the transport keeps working. An explicit `UpstreamConfig` is
authoritative.

## Observability

```go
stats := proxy.UpstreamStats()
// Hits      — requests served on a reused connection
// News      — connections newly established
// Recycled  — connections returned to the idle pool
// Timeouts  — connect/handshake/response-header/idle timeouts
// plus IdleClosed, Queued, Rejected, Retried, Discarded, Canceled, Active
```

`UpstreamConfig.OnEvent` receives lifecycle events from a background goroutine;
events are dropped rather than blocking forwarding when the handler falls
behind. `proxy.CloseIdleUpstreamConnections()` releases idle capacity
immediately.

## Connection identity

A pooled connection is keyed by everything that decides whether it may carry
a request:

* scheme, canonical host and port;
* SNI;
* a digest of every TLS trust input (verification mode, root CAs, client
  certificates, ALPN, versions, cipher suites, renegotiation);
* a digest of the request's authentication context
  (`Proxy-Authorization` / `Authorization` by default).

Connections are therefore never shared between different trust configurations
or different credential sets.

## Timeouts

Timeouts are independent, so a slow DNS resolution cannot consume the TLS
handshake budget, and neither can consume the response-header budget:

| Timeout                | Bounds                                             |
|------------------------|----------------------------------------------------|
| `ConnectTimeout`       | name resolution + TCP connect                      |
| `TLSHandshakeTimeout`  | TLS handshake after the connect                    |
| `ResponseHeaderTimeout`| wait for response headers after writing the request|
| `IdleTimeout`          | idle keep-alive connection retention               |
| `TunnelIdleTimeout`    | inactivity inside a CONNECT tunnel                 |
| `RequestTimeout`       | whole exchange, opt-in                             |

Streaming and long-polling responses are not affected by `IdleTimeout`: it
only reclaims connections that are idle between requests. Multiplexed HTTP/2
connections are excluded from idle reaping entirely, because net/http returns
them to its pool while streams are still in flight.

## Limits and queueing

`MaxConns` and `MaxConnsPerHost` are hard bounds enforced by one shared
budget that covers both forwarded requests and CONNECT tunnels. While a limit
is reached, up to `WaitQueue` callers wait (bounded by their request context);
beyond that they fail fast with a limit error instead of dialing without
bound. When the global limit is hit, idle connections are reclaimed first so
idle capacity cannot starve a new origin.

## Cancellation

* **Client → upstream.** Cancelling the request context cancels the upstream
  request and its response body, and aborts an in-flight dial or TLS
  handshake. net/http runs the dial and handshake on a context detached from
  the request, so the pool watches the request context itself and closes the
  connection (releasing its slot) if the dialing client goes away. For
  MITM'd HTTP/1.1 clients, a hijacked connection has no net/http server
  watching it, so a non-destructive probe on the socket's descriptor detects
  the client's FIN and cancels the request.
* **Upstream → client.** An upstream failure propagates back as the
  request's error, and a canceled response body read returns a deterministic
  error instead of blocking.
* No background goroutine survives a completed request beyond the bounded
  event-delivery and reaper loops, which stop when the manager closes.

## Failures and degradation

* A response that is not reusable (`Connection: close`, a protocol switch, or
  a response the transport declines to pool) is discarded instead of returned
  to the pool.
* If a pooled connection is found closed by the peer, net/http retries once
  on a fresh connection. It only does so for replayable requests (no body, a
  rewindable body, or an idempotent method), so a non-idempotent request is
  never submitted twice.
* Cancel during body read closes the upstream connection.
* Events and metrics are delivered off the forwarding path and are dropped
  under backpressure.

## Compatibility

* Request and response interceptors keep their order and semantics.
* Tunnel byte streams are forwarded unchanged, including early bytes buffered
  with the CONNECT request and half-close propagation.
* Certificate verification and SNI handling are unchanged.
* Apart from the explicit resource bounds, the default configuration behaves
  like earlier releases.
