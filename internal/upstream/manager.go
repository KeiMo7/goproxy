package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DialFunc establishes a connection. It must honour ctx.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Hooks carries the per-request selection functions supplied by the proxy.
type Hooks struct {
	// TLSConfigForRequest, when set and returning non-nil, replaces the
	// base TLS configuration for that request's upstream connection. The
	// returned configuration is part of the connection identity, so
	// connections are never shared across trust configurations.
	TLSConfigForRequest func(req *http.Request, hookCtx any) *tls.Config
	// AuthKeyForRequest, when set, returns the authentication fingerprint
	// of the request. Requests with different fingerprints never share a
	// connection. When nil, the fingerprint is derived from the request's
	// proxy and origin authorization headers.
	AuthKeyForRequest func(req *http.Request, hookCtx any) string
}

// Manager owns the upstream connection lifecycle of one proxy: the shared
// connection budget, the per-identity transport partitions, the layered
// timeouts and the observability counters.
type Manager struct {
	cfg    Config
	stats  counters
	events *eventSink
	gate   *gate
	hooks  Hooks

	base        *http.Transport
	baseDial    DialFunc
	baseTLSDial DialFunc
	baseTLSConf *tls.Config
	maxParts    int

	mu     sync.Mutex
	parts  map[string]*partition
	order  []*partition // least recently used first
	closed bool
	idle   map[net.Conn]idleEntry
	// h2 marks multiplexed connections. net/http re-adds an HTTP/2
	// connection to its pool as soon as each response's headers arrive, so
	// "put idle" does not mean the connection is unused; reaping it on the
	// idle timer could kill a live stream. Such connections are left to
	// net/http's own idle management.
	h2        map[net.Conn]struct{}
	reaperWG  sync.WaitGroup
	done      chan struct{}
	closeOnce sync.Once
}

type partition struct {
	key string
	tr  *http.Transport
}

// idleEntry records when a connection became idle.
type idleEntry struct {
	since time.Time
}

// NewManager builds a manager on top of base. base may be nil, in which case
// a default http.Transport is used. The manager clones base rather than
// mutating it. cfg is normalized, so callers may pass a partially filled
// Config.
func NewManager(base *http.Transport, cfg Config, hooks Hooks) *Manager {
	cfg = normalize(cfg)
	if base == nil {
		base = &http.Transport{}
	}
	m := &Manager{
		cfg:      cfg,
		hooks:    hooks,
		base:     base,
		parts:    make(map[string]*partition),
		idle:     make(map[net.Conn]idleEntry),
		h2:       make(map[net.Conn]struct{}),
		maxParts: cfg.MaxAuthPartitions,
		baseDial: dialerOf(base),
		done:     make(chan struct{}),
	}
	m.baseTLSDial = tlsDialerOf(base)
	if base.TLSClientConfig != nil {
		m.baseTLSConf = base.TLSClientConfig.Clone()
	}
	m.events = newEventSink(cfg.OnEvent)
	m.gate = newGate(cfg, &m.stats, m.events, m.evictIdle)
	if cfg.IdleTimeout > 0 {
		m.reaperWG.Add(1)
		go m.reapLoop()
	}
	return m
}

// dialerOf extracts the effective plain-text dialer of base.
func dialerOf(base *http.Transport) DialFunc {
	if base.DialContext != nil {
		return base.DialContext
	}
	//nolint:staticcheck // Dial is the only dialer a caller may have set.
	if base.Dial != nil {
		d := base.Dial
		return func(_ context.Context, network, addr string) (net.Conn, error) {
			return d(network, addr)
		}
	}
	return (&net.Dialer{}).DialContext
}

// tlsDialerOf extracts a custom TLS dialer of base, if any.
func tlsDialerOf(base *http.Transport) DialFunc {
	if base.DialTLSContext != nil {
		return base.DialTLSContext
	}
	//nolint:staticcheck // DialTLS is the only TLS dialer some callers set.
	if base.DialTLS != nil {
		d := base.DialTLS
		return func(_ context.Context, network, addr string) (net.Conn, error) {
			return d(network, addr)
		}
	}
	return nil
}

// Stats returns a snapshot of the manager's counters.
func (m *Manager) Stats() Stats { return m.stats.snapshot() }

// Config returns the normalized configuration in use.
func (m *Manager) Config() Config { return m.cfg }

// CloseIdle closes every idle upstream connection of every partition.
// In-flight requests are not interrupted.
func (m *Manager) CloseIdle() {
	m.mu.Lock()
	parts := make([]*partition, 0, len(m.parts))
	for _, p := range m.parts {
		parts = append(parts, p)
	}
	m.mu.Unlock()
	for _, p := range parts {
		p.tr.CloseIdleConnections()
	}
}

// Close stops the manager. Idle connections are closed; in-flight requests
// continue on their own.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.mu.Unlock()
	m.closeOnce.Do(func() { close(m.done) })
	m.reaperWG.Wait()
	m.gate.close()
	m.CloseIdle()
	m.mu.Lock()
	m.idle = make(map[net.Conn]idleEntry)
	m.h2 = make(map[net.Conn]struct{})
	m.mu.Unlock()
	m.events.close()
}

// partitionFor returns (creating if needed) the transport partition for key.
func (m *Manager) partitionFor(key string, tlsCfg *tls.Config) *partition {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.parts[key]; ok {
		m.touchLocked(p)
		return p
	}
	if m.closed {
		return nil
	}
	tr := m.base.Clone()
	// Idle reclamation is owned by the manager's reaper so that it is
	// deterministic and observable (idle-close counters). net/http's own
	// timeout is disabled to avoid racing it.
	tr.IdleConnTimeout = 0
	tr.TLSHandshakeTimeout = m.cfg.TLSHandshakeTimeout
	tr.ResponseHeaderTimeout = m.cfg.ResponseHeaderTimeout
	if m.cfg.MaxIdleConnsPerHost > 0 {
		tr.MaxIdleConnsPerHost = m.cfg.MaxIdleConnsPerHost
	} else {
		tr.MaxIdleConnsPerHost = -1 // no idle retention
	}
	if m.cfg.MaxConns > 0 {
		tr.MaxIdleConns = m.cfg.MaxConns
	}
	// Per-host and global caps are enforced by the shared gate, which also
	// covers tunnels, instead of by this transport alone.
	tr.MaxConnsPerHost = 0
	tr.DialContext = m.gatedDial
	if m.baseTLSDial != nil {
		tr.DialTLSContext = m.gatedTLSDial
		//nolint:staticcheck // both fields are cleared/handled explicitly.
		tr.DialTLS = nil
	}
	if tlsCfg != nil {
		tr.TLSClientConfig = tlsCfg.Clone()
	}
	p := &partition{key: key, tr: tr}
	m.parts[key] = p
	m.order = append(m.order, p)
	m.evictPartitionsLocked()
	return p
}

// touchLocked moves p to the most-recently-used end of the LRU list.
func (m *Manager) touchLocked(p *partition) {
	for i, q := range m.order {
		if q == p {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	m.order = append(m.order, p)
}

// evictPartitionsLocked drops the least recently used partitions while the
// number of partitions exceeds the cap. Only their idle connections close.
func (m *Manager) evictPartitionsLocked() {
	if m.maxParts <= 0 {
		return
	}
	for len(m.order) > m.maxParts {
		old := m.order[0]
		m.order = m.order[1:]
		delete(m.parts, old.key)
		go old.tr.CloseIdleConnections()
	}
}

// evictIdle releases one reclaimable idle connection, preferring conns owned
// by target so a per-origin limit can make progress. It reports whether a
// connection was closed.
func (m *Manager) evictIdle(target string) bool {
	m.mu.Lock()
	var chosen net.Conn
	var chosenSince time.Time
	chosenTarget := ""
	for conn, e := range m.idle {
		// Prefer a connection to the same target, otherwise take the oldest
		// idle connection so the global budget makes progress.
		t := connTarget(conn)
		same := t == target
		chosenSame := chosenTarget == target
		switch {
		case chosen == nil:
		case same && !chosenSame:
		case same == chosenSame && e.since.Before(chosenSince):
		default:
			continue
		}
		chosen, chosenSince, chosenTarget = conn, e.since, t
	}
	if chosen == nil {
		m.mu.Unlock()
		return false
	}
	delete(m.idle, chosen)
	m.mu.Unlock()
	_ = chosen.Close()
	m.stats.idleClose.Add(1)
	if chosenTarget != "" {
		m.emit(Event{Kind: EventTimeout, Target: chosenTarget})
	}
	return true
}

// connTarget best-effort extracts the origin address of a connection.
func connTarget(conn net.Conn) string {
	if ra := conn.RemoteAddr(); ra != nil {
		return ra.String()
	}
	return ""
}

// authKey returns the authentication fingerprint of req.
func (m *Manager) authKey(req *http.Request, hookCtx any) string {
	if m.hooks.AuthKeyForRequest != nil {
		return m.hooks.AuthKeyForRequest(req, hookCtx)
	}
	return AuthDigest(
		req.Header.Get("Proxy-Authorization"),
		req.Header.Get("Authorization"),
	)
}

// partitionKey derives the transport partition for one request. The key
// covers the scheme, TLS identity (SNI and trust digest) and the
// authentication context.
func (m *Manager) partitionKey(scheme string, tlsCfg *tls.Config, auth string) string {
	if scheme != "https" || tlsCfg == nil {
		return "http\x00auth=" + auth
	}
	return "https\x00sni=" + tlsCfg.ServerName + "\x00trust=" + TrustDigest(tlsCfg) + "\x00auth=" + auth
}

// canonicalConn maps a connection reported by net/http's trace hooks back to
// the connection this package dialed. For HTTPS, net/http wraps the dialed
// connection in a *tls.Conn and reports that wrapper; the pool tracks
// connections by their underlying dialed connection so that idle bookkeeping
// and closure notifications refer to the same key.
func canonicalConn(conn net.Conn) net.Conn {
	seen := 0
	for conn != nil && seen < 8 {
		switch c := conn.(type) {
		case *tls.Conn:
			conn = c.NetConn()
		case interface{ NetConn() net.Conn }:
			conn = c.NetConn()
		default:
			return conn
		}
		seen++
	}
	return conn
}

// TrackIdle records that conn was just returned to the idle pool. net/http
// owns the connection from then on; the manager only remembers when it went
// idle so that IdleTimeout can be enforced and counted.
func (m *Manager) trackIdle(conn net.Conn) {
	conn = canonicalConn(conn)
	if conn == nil || m.cfg.IdleTimeout <= 0 {
		return
	}
	m.mu.Lock()
	_, multiplexed := m.h2[conn]
	if !m.closed && !multiplexed {
		m.idle[conn] = idleEntry{since: time.Now()}
	}
	m.mu.Unlock()
}

// markMultiplexed records conn as an HTTP/2 connection so the idle reaper
// never touches it. Multiplexed connections are reclaimed by net/http once
// they have no active streams.
func (m *Manager) markMultiplexed(conn net.Conn) {
	conn = canonicalConn(conn)
	if conn == nil {
		return
	}
	m.mu.Lock()
	if !m.closed {
		m.h2[conn] = struct{}{}
		delete(m.idle, conn)
	}
	m.mu.Unlock()
}

// forgetConn drops every record kept for conn when the connection is
// closed, so the tracking maps stay bounded over a long-lived proxy.
func (m *Manager) forgetConn(conn net.Conn) {
	conn = canonicalConn(conn)
	if conn == nil {
		return
	}
	m.mu.Lock()
	_, wasIdle := m.idle[conn]
	delete(m.idle, conn)
	delete(m.h2, conn)
	m.mu.Unlock()
	if wasIdle {
		m.emit(Event{Kind: EventClose, Target: connTarget(conn)})
	}
}

// noteConnUsed forgets a connection's idle record: it is about to carry a
// request again.
func (m *Manager) noteConnUsed(conn net.Conn) {
	conn = canonicalConn(conn)
	if conn == nil {
		return
	}
	m.mu.Lock()
	delete(m.idle, conn)
	m.mu.Unlock()
}

// reapLoop enforces IdleTimeout on idle keep-alive connections. net/http
// silently closes its own idle connections after IdleConnTimeout; closing
// them here as well gives the proxy a deterministic, observable reclamation
// (and lets a shorter manager timeout win).
func (m *Manager) reapLoop() {
	defer m.reaperWG.Done()
	interval := m.cfg.IdleTimeout / 4
	if interval < 20*time.Millisecond {
		interval = 20 * time.Millisecond
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			return
		case now := <-t.C:
			m.reapIdle(now)
		}
	}
}

func (m *Manager) reapIdle(now time.Time) {
	cutoff := now.Add(-m.cfg.IdleTimeout)
	var expired []net.Conn
	m.mu.Lock()
	for conn, e := range m.idle {
		if e.since.Before(cutoff) {
			expired = append(expired, conn)
			delete(m.idle, conn)
		}
	}
	m.mu.Unlock()
	for _, conn := range expired {
		_ = conn.Close()
		m.stats.idleClose.Add(1)
		m.stats.timeouts.Add(1)
		if target := connTarget(conn); target != "" {
			m.emit(Event{Kind: EventTimeout, Target: target})
		}
	}
}

// RoundTrip forwards req upstream through the pool that matches its
// identity. hookCtx is handed back to the configured hooks.
func (m *Manager) RoundTrip(req *http.Request, hookCtx any) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, &Error{Kind: FailureOther, Err: errors.New("nil request URL")}
	}
	scheme := strings.ToLower(req.URL.Scheme)
	var tlsCfg *tls.Config
	if scheme == "https" {
		tlsCfg = m.baseTLSConf
		if m.hooks.TLSConfigForRequest != nil {
			if c := m.hooks.TLSConfigForRequest(req, hookCtx); c != nil {
				tlsCfg = c
			}
		}
	}
	key := m.partitionKey(scheme, tlsCfg, m.authKey(req, hookCtx))
	part := m.partitionFor(key, tlsCfg)
	if part == nil {
		return nil, ErrClosed
	}

	ctx := req.Context()
	var cancel context.CancelFunc
	if m.cfg.RequestTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, m.cfg.RequestTimeout)
	}

	// The watch set is stopped as soon as the connection is available: from
	// then on net/http propagates request cancellation itself. The dial
	// context carries the original request context, because net/http detaches
	// the dial from request cancellation.
	ws := &watchSet{}
	defer ws.stopAll()

	var (
		mu       sync.Mutex
		gotConns int
		// discarded records that a response was not reusable, either because
		// it announced Connection: close, switched protocols, or because the
		// transport explicitly declined to pool the connection.
		discarded bool
		// conn is the connection the request is currently using, if any.
		// It is recorded so PutIdleConn can remember when it went idle.
		// GotConn runs on the request goroutine and PutIdleConn on the
		// transport's read loop, hence the mutex.
		conn net.Conn
		// negotiatedH2 records that the TLS handshake settled on HTTP/2.
		negotiatedH2 bool
		// gotConnSeen records that at least one connection was delivered.
		gotConnSeen bool
	)
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			ws.stopAll()
			m.noteConnUsed(info.Conn)
			mu.Lock()
			conn = info.Conn
			gotConns++
			first := gotConns == 1
			if first {
				gotConnSeen = true
			}
			multiplexed := negotiatedH2
			mu.Unlock()
			if multiplexed {
				m.markMultiplexed(info.Conn)
			}
			if !first {
				// net/http retried on a fresh connection after the pooled
				// one turned out to be closed. This only happens for
				// replayable requests and never resubmits a body.
				m.stats.retried.Add(1)
				m.emit(Event{Kind: EventRetry, Target: req.URL.Host})
				return
			}
			if info.Reused {
				m.stats.hits.Add(1)
				m.emit(Event{Kind: EventReuse, Target: req.URL.Host})
			}
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, _ error) {
			ws.stopAll()
			// The connection itself is only available in GotConn, which
			// fires after this hook; remember the negotiated protocol so
			// GotConn can mark the connection as multiplexed.
			mu.Lock()
			negotiatedH2 = cs.NegotiatedProtocol == "h2"
			mu.Unlock()
		},
		PutIdleConn: func(err error) {
			if err == nil {
				m.stats.recycled.Add(1)
				mu.Lock()
				idleConn := conn
				mu.Unlock()
				m.trackIdle(idleConn)
				return
			}
			mu.Lock()
			discarded = true
			mu.Unlock()
		},
	}
	ctx = httptrace.WithClientTrace(ctx, trace)
	ctx = context.WithValue(ctx, requestCtxKey{}, req.Context())
	ctx = context.WithValue(ctx, watchKey{}, ws)
	out := req.Clone(ctx)

	resp, err := part.tr.RoundTrip(out)
	if err != nil {
		m.classify(req, err)
		if cancel != nil {
			cancel()
		}
		return nil, err
	}
	if resp.ProtoMajor == 2 {
		mu.Lock()
		c := conn
		mu.Unlock()
		m.markMultiplexed(c)
	}
	mu.Lock()
	if resp.Close || resp.StatusCode == http.StatusSwitchingProtocols {
		discarded = true
	} else if !gotConnSeen {
		// A response but no GotConn hook: the transport served it without
		// handing out a tracked connection, so nothing was pooled.
		discarded = true
	}
	wasDiscarded := discarded
	mu.Unlock()
	if wasDiscarded {
		m.stats.discarded.Add(1)
		m.emit(Event{Kind: EventDiscarded, Target: req.URL.Host})
	}
	if cancel != nil {
		resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
	}
	return resp, nil
}

// classify updates the counters from a failed RoundTrip.
func (m *Manager) classify(req *http.Request, err error) {
	switch Classify(err) {
	case FailureCanceled:
		m.stats.canceled.Add(1)
		m.emit(Event{Kind: EventCanceled, Target: req.URL.Host})
	case FailureLimit:
		m.stats.rejected.Add(1)
		m.emit(Event{Kind: EventRejected, Target: req.URL.Host})
	case FailureIdle:
		m.stats.idleClose.Add(1)
		m.stats.timeouts.Add(1)
		m.emit(Event{Kind: EventTimeout, Target: req.URL.Host})
	case FailureResponseHeader:
		m.stats.timeouts.Add(1)
		m.emit(Event{Kind: EventTimeout, Target: req.URL.Host})
	case FailureConnect, FailureHandshake:
		m.stats.timeouts.Add(1)
		m.emit(Event{Kind: EventTimeout, Target: req.URL.Host})
	}
}

func (m *Manager) emit(ev Event) {
	if m.events != nil {
		m.events.emit(ev)
	}
}

// cancelOnClose cancels the whole-request timeout once the body is closed.
type cancelOnClose struct {
	ReadCloser interface {
		Read([]byte) (int, error)
		Close() error
	}
	cancel   context.CancelFunc
	canceled atomic.Bool
}

func (b *cancelOnClose) Read(p []byte) (int, error) { return b.ReadCloser.Read(p) }

func (b *cancelOnClose) Close() error {
	if b.canceled.CompareAndSwap(false, true) {
		b.cancel()
	}
	return b.ReadCloser.Close()
}
