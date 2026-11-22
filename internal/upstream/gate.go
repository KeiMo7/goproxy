package upstream

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// gate enforces the total and per-origin connection limits and the bounded
// wait queue. Every live upstream connection (busy, idle, being dialed, or
// tunnelled) holds one slot until it is closed.
type gate struct {
	cfg    Config
	stats  *counters
	events *eventSink
	evict  func(target string) bool

	mu      sync.Mutex
	total   int
	perHost map[string]int
	waiting map[string]int
	queued  int
	closed  bool
	// generation is closed and replaced on every release, waking every
	// waiter so that no eligible caller can be left behind by a token
	// consumed by a caller that could not proceed.
	generation chan struct{}
}

func newGate(cfg Config, stats *counters, events *eventSink, evict func(string) bool) *gate {
	return &gate{
		cfg:        cfg,
		stats:      stats,
		events:     events,
		evict:      evict,
		perHost:    make(map[string]int),
		waiting:    make(map[string]int),
		generation: make(chan struct{}),
	}
}

func (g *gate) emit(ev Event) {
	if g.events != nil {
		g.events.emit(ev)
	}
}

// acquire reserves one connection slot for target. When a limit is reached
// it reclaims idle capacity, then waits, bounded by WaitQueue and by ctx.
func (g *gate) acquire(ctx context.Context, target string) error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return ErrClosed
	}
	if g.hasCapacityLocked(target) {
		g.takeLocked(target)
		g.mu.Unlock()
		return nil
	}
	g.mu.Unlock()

	// Under pressure, reclaim idle connections before making the caller
	// wait: idle capacity must not starve a new request. Each successful
	// eviction frees a slot for a connection the caller can replace; the
	// loop is bounded by the number of reclaimable idle connections.
	if g.evict != nil {
		for {
			g.mu.Lock()
			if g.closed {
				g.mu.Unlock()
				return ErrClosed
			}
			if g.hasCapacityLocked(target) {
				g.takeLocked(target)
				g.mu.Unlock()
				return nil
			}
			atTotal := g.atTotalLimitLocked()
			g.mu.Unlock()
			if !atTotal || !g.evict(target) {
				break
			}
		}
	}

	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return ErrClosed
	}
	if g.hasCapacityLocked(target) {
		g.takeLocked(target)
		g.mu.Unlock()
		return nil
	}

	// A negative WaitQueue disables waiting: callers fail fast instead of
	// queueing, so the proxy never builds an unbounded backlog. The bound
	// applies globally and per origin, so many origins cannot add up to an
	// unbounded backlog either.
	if g.cfg.WaitQueue < 0 || g.queued >= g.cfg.WaitQueue || g.waiting[target] >= g.cfg.WaitQueue {
		g.mu.Unlock()
		g.stats.rejected.Add(1)
		g.emit(Event{Kind: EventRejected, Target: target})
		return ErrLimit
	}
	g.stats.queued.Add(1)
	g.emit(Event{Kind: EventQueued, Target: target})
	g.waiting[target]++
	g.queued++
	g.mu.Unlock()

	for {
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			g.leaveWait(target)
			return ErrClosed
		}
		if g.hasCapacityLocked(target) {
			g.takeLocked(target)
			g.mu.Unlock()
			g.leaveWait(target)
			return nil
		}
		gen := g.generation
		g.mu.Unlock()

		select {
		case <-gen:
		case <-ctx.Done():
			g.leaveWait(target)
			return ctx.Err()
		}
	}
}

func (g *gate) leaveWait(target string) {
	g.mu.Lock()
	if n := g.waiting[target] - 1; n <= 0 {
		delete(g.waiting, target)
	} else {
		g.waiting[target] = n
	}
	if g.queued > 0 {
		g.queued--
	}
	g.mu.Unlock()
}

func (g *gate) atTotalLimitLocked() bool {
	return g.cfg.MaxConns >= 0 && g.total >= g.cfg.MaxConns
}

func (g *gate) hasCapacityLocked(target string) bool {
	if g.cfg.MaxConns >= 0 && g.total >= g.cfg.MaxConns {
		return false
	}
	if g.cfg.MaxConnsPerHost >= 0 && g.perHost[target] >= g.cfg.MaxConnsPerHost {
		return false
	}
	return true
}

func (g *gate) takeLocked(target string) {
	g.total++
	g.perHost[target]++
	g.stats.active.Add(1)
}

// release frees one slot for target and wakes the waiters.
func (g *gate) release(target string) {
	g.mu.Lock()
	g.total--
	g.stats.active.Add(-1)
	if n := g.perHost[target] - 1; n <= 0 {
		delete(g.perHost, target)
	} else {
		g.perHost[target] = n
	}
	if !g.closed {
		close(g.generation)
		g.generation = make(chan struct{})
	}
	g.mu.Unlock()
}

func (g *gate) close() {
	g.mu.Lock()
	if !g.closed {
		g.closed = true
		close(g.generation)
		g.generation = make(chan struct{})
	}
	g.mu.Unlock()
}

// gatedConn pairs a connection with the gate slot it holds and reports
// closing so the slot is released exactly once.
type gatedConn struct {
	net.Conn
	gate   *gate
	target string
	once   sync.Once
}

func (c *gatedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.gate.release(c.target) })
	return err
}

// Release frees the slot without closing the connection.
func (c *gatedConn) Release() {
	c.once.Do(func() { c.gate.release(c.target) })
}

// gatedHalfConn additionally forwards half-close operations. It is returned
// only when the underlying connection supports them, so callers can keep
// distinguishing full from half-close capable tunnels.
type gatedHalfConn struct {
	*gatedConn
}

// CloseWrite half-closes the write direction.
func (c *gatedHalfConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// CloseRead half-closes the read direction.
func (c *gatedHalfConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// wrapGated wraps conn in the narrowest gating wrapper that preserves the
// underlying half-close capabilities.
func wrapGated(conn net.Conn, g *gate, target string) net.Conn {
	base := &gatedConn{Conn: conn, gate: g, target: target}
	if _, ok := conn.(interface{ CloseWrite() error }); ok {
		return &gatedHalfConn{gatedConn: base}
	}
	return base
}

// requestCtxKey carries the caller's request context into net/http's dial
// context. net/http detaches the dial context from request cancellation so
// that a pooled dial may outlive one request, but the proxy still has to
// abandon a dial or TLS handshake when the client that asked for it has gone
// away. The value survives the detachment, so the dialer can watch it.
type requestCtxKey struct{}

// watchKey carries the per-request watch set into the dialer.
type watchKey struct{}

// watchSet is the set of cancellation watches installed by the dialer for
// one request. They are stopped as soon as the connection is handed to the
// request (GotConn) or its TLS handshake completes, because from then on
// net/http itself propagates request cancellation. Stopping them is what
// prevents a later request's cancellation from aborting a connection that is
// already shared or idle.
type watchSet struct {
	mu     sync.Mutex
	stops  []func()
	closed bool
}

func (w *watchSet) add(stop func()) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		stop()
		return
	}
	w.stops = append(w.stops, stop)
	w.mu.Unlock()
}

func (w *watchSet) stopAll() {
	w.mu.Lock()
	stops := w.stops
	w.stops = nil
	w.closed = true
	w.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
}

// dialWatch derives a dial context that is cancelled when the requesting
// client goes away, and returns a function that stops watching.
//
// net/http runs the dial (and the TLS handshake that follows it) on a context
// detached from the request's cancellation, so that a connection dialed for
// one request can be reused by another. The proxy still must not keep dialing
// for a client that is gone, so the request context is watched separately and
// cancels the derived context. The watch is released once the dial returns;
// from then on the connection itself is watched (see watchConn), because the
// TLS handshake that net/http performs next does not use this context.
func dialWatch(ctx context.Context) (context.Context, func()) {
	reqCtx, _ := requestContext(ctx)
	if reqCtx == nil || reqCtx.Done() == nil {
		return ctx, func() {}
	}
	dialCtx, cancel := context.WithCancel(ctx)
	stopAfter := context.AfterFunc(reqCtx, cancel)
	return dialCtx, func() {
		stopAfter()
		cancel()
	}
}

// watchConn closes conn if the requesting client goes away before the
// connection is handed to the request (GotConn) or its TLS handshake
// completes. net/http performs the TLS handshake on a detached context, so
// closing the connection is the only way to abort a handshake for a client
// that has disconnected. The returned stop function is registered with the
// request's watch set, which GotConn stops, so an established or pooled
// connection is never closed by a previous request's context.
func watchConn(ctx context.Context, conn net.Conn) func() {
	reqCtx, ws := requestContext(ctx)
	if reqCtx == nil || reqCtx.Done() == nil {
		return func() {}
	}
	if reqCtx.Err() != nil {
		_ = conn.Close()
		return func() {}
	}
	stopAfter := context.AfterFunc(reqCtx, func() { _ = conn.Close() })
	stop := func() { stopAfter() }
	if ws != nil {
		ws.add(stop)
	}
	return stop
}

// requestContext extracts the request context and watch set carried by a
// dial context.
func requestContext(ctx context.Context) (context.Context, *watchSet) {
	reqCtx, _ := ctx.Value(requestCtxKey{}).(context.Context)
	ws, _ := ctx.Value(watchKey{}).(*watchSet)
	return reqCtx, ws
}

// gatedDial is the DialContext of every partition: it enforces the shared
// budget, applies the independent connect timeout and aborts a dial whose
// requesting client went away.
func (m *Manager) gatedDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return m.dialWithBudget(ctx, network, addr, m.baseDial, m.cfg.ConnectTimeout)
}

// gatedTLSDial is the DialTLSContext used when the base transport had a
// custom TLS dialer. The base dialer performs the handshake; the slot, the
// connect timeout and the request cancellation watch are still enforced.
func (m *Manager) gatedTLSDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return m.dialWithBudget(ctx, network, addr, m.baseTLSDial, m.cfg.ConnectTimeout)
}

func (m *Manager) dialWithBudget(
	ctx context.Context, network, addr string, dial DialFunc, timeout time.Duration,
) (net.Conn, error) {
	if err := m.gate.acquire(ctx, addr); err != nil {
		return nil, err
	}
	dialCtx, stopWatch := dialWatch(ctx)
	dialCtxv := dialCtx
	var cancel context.CancelFunc
	if timeout > 0 {
		dialCtxv, cancel = context.WithTimeout(dialCtx, timeout)
		defer cancel()
	}
	if dial == nil {
		dial = m.baseDial
	}
	conn, err := dial(dialCtxv, network, addr)
	stopWatch()
	if err != nil {
		m.gate.release(addr)
		m.noteDialFailure(ctx, addr, err)
		return nil, err
	}
	// The TLS handshake that net/http performs next does not use dialCtx, so
	// watch the connection itself until GotConn/TLSHandshakeDone releases the
	// watch. A client that disconnects during the handshake closes it. The
	// watch closes the gated wrapper, not the raw socket, so the connection
	// slot is released too.
	wc := &watchedConn{Conn: wrapGated(conn, m.gate, addr), onClose: m.forgetConn}
	wc.stop = watchConn(ctx, wc)
	m.stats.news.Add(1)
	m.emit(Event{Kind: EventNew, Target: addr})
	return wc, nil
}

// watchedConn releases the dial-time cancellation watch and forgets the
// connection's idle bookkeeping when it is closed. The watch itself is
// stopped earlier, at GotConn or TLSHandshakeDone, so that an established
// connection shared by later requests is never aborted by a previous
// request's context.
type watchedConn struct {
	net.Conn
	stop    func()
	onClose func(net.Conn)
	once    sync.Once
	stopped atomic.Bool
}

func (c *watchedConn) Close() error {
	if c.stopped.CompareAndSwap(false, true) {
		c.stop()
	}
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose(c)
		}
	})
	return c.Conn.Close()
}

// noteDialFailure counts a connect or TLS-handshake timeout, distinctly from
// caller cancellation.
func (m *Manager) noteDialFailure(ctx context.Context, addr string, err error) {
	if reqCtx, _ := requestContext(ctx); reqCtx != nil && reqCtx.Err() != nil {
		return
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		m.stats.timeouts.Add(1)
		m.emit(Event{Kind: EventTimeout, Target: addr})
	}
}

// DialContextForTunnel establishes the upstream side of a CONNECT tunnel
// through the shared budget. The returned connection owns a slot; closing
// it releases the slot. The connection also enforces TunnelIdleTimeout: if
// it carries no bytes in either direction for that long, it is closed so the
// tunnel cannot occupy capacity indefinitely.
func (m *Manager) DialContextForTunnel(ctx context.Context, network, addr string) (net.Conn, error) {
	return m.DialContextForTunnelWith(ctx, network, addr, nil)
}

// DialContextForTunnelWith is DialContextForTunnel using dial instead of the
// manager's default dialer (for example a proxy-chaining dialer derived from
// the environment). The connection still counts against the shared budget.
func (m *Manager) DialContextForTunnelWith(
	ctx context.Context, network, addr string, dial DialFunc,
) (net.Conn, error) {
	if err := m.gate.acquire(ctx, addr); err != nil {
		return nil, err
	}
	dialCtx := ctx
	var cancel context.CancelFunc
	if m.cfg.TunnelConnectTimeout > 0 {
		dialCtx, cancel = context.WithTimeout(ctx, m.cfg.TunnelConnectTimeout)
		defer cancel()
	}
	if dial == nil {
		dial = m.baseDial
	}
	conn, err := dial(dialCtx, network, addr)
	if err != nil {
		m.gate.release(addr)
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			m.stats.timeouts.Add(1)
			m.emit(Event{Kind: EventTimeout, Target: addr, Tunnel: true})
		}
		return nil, err
	}
	m.stats.news.Add(1)
	m.emit(Event{Kind: EventNew, Target: addr, Tunnel: true})
	gated := wrapGated(conn, m.gate, addr)
	if m.cfg.TunnelIdleTimeout <= 0 {
		return gated, nil
	}
	onIdle := func() {
		m.stats.idleClose.Add(1)
		m.stats.timeouts.Add(1)
		m.emit(Event{Kind: EventTimeout, Target: addr, Tunnel: true})
	}
	return newIdleConn(gated, m.cfg.TunnelIdleTimeout, onIdle), nil
}

// idleConn closes a tunnel that carries no bytes in either direction for a
// configured interval, so an abandoned tunnel cannot hold a connection slot
// forever. Any successful read or write resets the timer.
type idleConn struct {
	net.Conn
	timeout time.Duration
	onIdle  func()

	last   atomic.Int64 // unix nanos of the last activity
	closed atomic.Bool
	done   chan struct{}
	once   sync.Once
}

// idleHalfConn additionally forwards half-close operations, which the tunnel
// relay uses to propagate a half-close instead of tearing down both
// directions.
type idleHalfConn struct {
	*idleConn
}

// CloseWrite half-closes the write direction and keeps the idle timer
// running for the remaining direction.
func (c *idleHalfConn) CloseWrite() error {
	c.touch()
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// CloseRead half-closes the read direction.
func (c *idleHalfConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func newIdleConn(conn net.Conn, timeout time.Duration, onIdle func()) net.Conn {
	c := &idleConn{Conn: conn, timeout: timeout, onIdle: onIdle, done: make(chan struct{})}
	c.touch()
	go c.watch()
	if _, ok := conn.(interface{ CloseWrite() error }); ok {
		return &idleHalfConn{idleConn: c}
	}
	return c
}

func (c *idleConn) touch() { c.last.Store(time.Now().UnixNano()) }

func (c *idleConn) watch() {
	interval := c.timeout / 4
	if interval < 20*time.Millisecond {
		interval = 20 * time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			idle := time.Since(time.Unix(0, c.last.Load()))
			if idle >= c.timeout {
				c.idleClose()
				return
			}
		}
	}
}

func (c *idleConn) idleClose() {
	if c.closed.CompareAndSwap(false, true) {
		if c.onIdle != nil {
			c.onIdle()
		}
		_ = c.Conn.Close()
	}
}

func (c *idleConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *idleConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *idleConn) Close() error {
	c.closed.Store(true)
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}
