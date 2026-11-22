package upstream

import "time"

// Configuration defaults. Each can be overridden per ProxyHttpServer through
// Config. A zero field selects the default; a negative duration or limit
// disables the corresponding feature.
const (
	// DefaultMaxConns is the default total live upstream connection budget.
	DefaultMaxConns = 1024
	// DefaultMaxConnsPerHost is the default live connection budget of one origin.
	DefaultMaxConnsPerHost = 64
	// DefaultMaxIdleConnsPerHost is the default number of idle connections kept
	// per origin for reuse.
	DefaultMaxIdleConnsPerHost = 16
	// DefaultWaitQueue is the default number of callers allowed to wait for a
	// connection slot after a limit is reached.
	DefaultWaitQueue = 1024
	// DefaultConnectTimeout bounds name resolution plus the TCP connect.
	DefaultConnectTimeout = 15 * time.Second
	// DefaultTLSHandshakeTimeout bounds the TLS handshake.
	DefaultTLSHandshakeTimeout = 10 * time.Second
	// DefaultIdleTimeout bounds the lifetime of an idle keep-alive connection.
	DefaultIdleTimeout = 90 * time.Second
	// DefaultTunnelIdleTimeout bounds the inactivity of a CONNECT tunnel.
	DefaultTunnelIdleTimeout = 5 * time.Minute
	// DefaultMaxAuthPartitions bounds the number of authentication pools kept.
	DefaultMaxAuthPartitions = 64
)

// Config controls upstream connection reuse, limits and timeouts.
type Config struct {
	// MaxConns bounds the total number of live upstream connections owned
	// by the proxy (forwarding and tunnelling combined). Negative means
	// unlimited.
	MaxConns int
	// MaxConnsPerHost bounds the live upstream connections of a single
	// origin (host:port). Negative means unlimited.
	MaxConnsPerHost int
	// MaxIdleConnsPerHost bounds how many idle keep-alive connections are
	// retained per origin. Negative disables idle retention.
	MaxIdleConnsPerHost int
	// WaitQueue is the number of callers that may wait for a connection
	// slot after a limit is reached. Further callers fail fast with
	// ErrLimit. Negative disables waiting entirely (every caller over a
	// limit fails fast).
	WaitQueue int

	// ConnectTimeout bounds name resolution plus the TCP connect of one
	// upstream connection, independently of the request deadline.
	ConnectTimeout time.Duration
	// TLSHandshakeTimeout bounds the TLS handshake to an upstream server,
	// independently of ConnectTimeout.
	TLSHandshakeTimeout time.Duration
	// ResponseHeaderTimeout bounds the wait for response headers after the
	// request has been written.
	ResponseHeaderTimeout time.Duration
	// IdleTimeout bounds how long a forwarded keep-alive connection may sit
	// unused before it is reclaimed.
	IdleTimeout time.Duration
	// TunnelIdleTimeout is the inactivity interval after which a CONNECT
	// tunnel is reclaimed. Defaults to IdleTimeout.
	TunnelIdleTimeout time.Duration
	// TunnelConnectTimeout bounds establishing the upstream side of a
	// tunnel. Defaults to ConnectTimeout.
	TunnelConnectTimeout time.Duration
	// RequestTimeout bounds a whole upstream exchange (connect, TLS
	// handshake, response headers and body). Zero disables it; the
	// request's own context always applies.
	RequestTimeout time.Duration
	// MaxAuthPartitions bounds the number of distinct authentication
	// contexts for which separate pools are kept. Connections are never
	// shared across authentication contexts.
	MaxAuthPartitions int

	// OnEvent receives upstream lifecycle events. It is invoked from a
	// background goroutine; events are dropped rather than blocking
	// forwarding when the handler falls behind.
	OnEvent func(Event)
}

// DefaultConfig returns the configuration applied when
// ProxyHttpServer.Upstream is nil.
func DefaultConfig() Config {
	return Config{
		MaxConns:              DefaultMaxConns,
		MaxConnsPerHost:       DefaultMaxConnsPerHost,
		MaxIdleConnsPerHost:   DefaultMaxIdleConnsPerHost,
		WaitQueue:             DefaultWaitQueue,
		ConnectTimeout:        DefaultConnectTimeout,
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: 0,
		IdleTimeout:           DefaultIdleTimeout,
		TunnelIdleTimeout:     DefaultTunnelIdleTimeout,
		MaxAuthPartitions:     DefaultMaxAuthPartitions,
	}
}

// normalize fills zero-valued fields with defaults while keeping negative
// values as "disabled". It never mutates its receiver.
func normalize(c Config) Config {
	d := DefaultConfig()
	if c.MaxConns == 0 {
		c.MaxConns = d.MaxConns
	}
	if c.MaxConnsPerHost == 0 {
		c.MaxConnsPerHost = d.MaxConnsPerHost
	}
	if c.MaxIdleConnsPerHost == 0 {
		c.MaxIdleConnsPerHost = d.MaxIdleConnsPerHost
	}
	if c.WaitQueue == 0 {
		c.WaitQueue = d.WaitQueue
	}
	if c.MaxAuthPartitions == 0 {
		c.MaxAuthPartitions = d.MaxAuthPartitions
	}
	c.ConnectTimeout = effectiveDuration(c.ConnectTimeout, d.ConnectTimeout)
	c.TLSHandshakeTimeout = effectiveDuration(c.TLSHandshakeTimeout, d.TLSHandshakeTimeout)
	c.ResponseHeaderTimeout = effectiveDuration(c.ResponseHeaderTimeout, 0)
	c.IdleTimeout = effectiveDuration(c.IdleTimeout, d.IdleTimeout)
	c.TunnelIdleTimeout = effectiveDuration(c.TunnelIdleTimeout, c.IdleTimeout)
	c.TunnelConnectTimeout = effectiveDuration(c.TunnelConnectTimeout, c.ConnectTimeout)
	c.RequestTimeout = effectiveDuration(c.RequestTimeout, 0)
	return c
}

// effectiveDuration maps zero to def, negatives to zero (disabled), and
// positive values through unchanged.
func effectiveDuration(v, def time.Duration) time.Duration {
	if v < 0 {
		return 0
	}
	if v == 0 {
		return def
	}
	return v
}
