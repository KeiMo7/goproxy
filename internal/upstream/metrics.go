package upstream

import (
	"sync"
	"sync/atomic"
)

// EventKind identifies an upstream connection lifecycle event.
type EventKind int

// Upstream connection lifecycle events.
const (
	// EventReuse is emitted when a request is served on an existing
	// upstream connection.
	EventReuse EventKind = iota
	// EventNew is emitted when a new upstream connection is established.
	EventNew
	// EventClose is emitted when an upstream connection is torn down.
	EventClose
	// EventTimeout is emitted when an upstream operation times out (connect,
	// TLS handshake, response headers, or idle expiry).
	EventTimeout
	// EventQueued is emitted when a caller has to wait for a connection
	// slot because a limit was reached.
	EventQueued
	// EventRejected is emitted when a caller is rejected because the wait
	// queue is full.
	EventRejected
	// EventRetry is emitted when a stale pooled connection is replaced and
	// the request is retried once on a fresh connection.
	EventRetry
	// EventDiscarded is emitted when a connection is not returned to the
	// pool because the response marked it non-reusable.
	EventDiscarded
	// EventCanceled is emitted when a request or tunnel is canceled.
	EventCanceled
)

// String returns a stable, log-friendly event name.
func (k EventKind) String() string {
	switch k {
	case EventReuse:
		return "reuse"
	case EventNew:
		return "new"
	case EventClose:
		return "close"
	case EventTimeout:
		return "timeout"
	case EventQueued:
		return "queued"
	case EventRejected:
		return "rejected"
	case EventRetry:
		return "retry"
	case EventDiscarded:
		return "discarded"
	case EventCanceled:
		return "canceled"
	default:
		return "unknown"
	}
}

// Event describes one upstream connection lifecycle event. Target is the
// origin host:port; it never carries credentials or request data.
type Event struct {
	Kind   EventKind
	Target string
	// Tunnel is true for events on the CONNECT tunnel path.
	Tunnel bool
}

// Stats is a snapshot of the counters exposed by a ProxyHttpServer.
//
// Hits, News, Recycled and Timeouts are the four stable counters required
// for observability; the remaining fields give finer-grained detail.
type Stats struct {
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

// counters holds the atomic counters for one proxy.
type counters struct {
	hits      atomic.Uint64
	news      atomic.Uint64
	recycled  atomic.Uint64
	timeouts  atomic.Uint64
	idleClose atomic.Uint64
	queued    atomic.Uint64
	rejected  atomic.Uint64
	retried   atomic.Uint64
	discarded atomic.Uint64
	canceled  atomic.Uint64
	active    atomic.Int64
}

// snapshot returns the current counter values.
func (c *counters) snapshot() Stats {
	return Stats{
		Hits:       c.hits.Load(),
		News:       c.news.Load(),
		Recycled:   c.recycled.Load(),
		Timeouts:   c.timeouts.Load(),
		IdleClosed: c.idleClose.Load(),
		Queued:     c.queued.Load(),
		Rejected:   c.rejected.Load(),
		Retried:    c.retried.Load(),
		Discarded:  c.discarded.Load(),
		Canceled:   c.canceled.Load(),
		Active:     c.active.Load(),
	}
}

// eventBuffer is the number of events that may queue before delivery starts
// dropping them.
const eventBuffer = 512

// eventSink serialises event delivery onto a background goroutine so a slow
// observer never blocks the forwarding path.
type eventSink struct {
	mu   sync.Mutex
	ch   chan Event
	done chan struct{}
	// closed guards against sending on a closed channel: emit and close
	// both take mu, so a concurrent emit either delivers or is dropped.
	closed bool
}

func newEventSink(handler func(Event)) *eventSink {
	if handler == nil {
		return nil
	}
	s := &eventSink{ch: make(chan Event, eventBuffer), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		for ev := range s.ch {
			handler(ev)
		}
	}()
	return s
}

// emit hands an event to the delivery goroutine without blocking. When the
// buffer is full the event is dropped: an observability backend must never
// slow the data path.
func (s *eventSink) emit(ev Event) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	select {
	case s.ch <- ev:
	default:
	}
}

// close stops event delivery. It never blocks the caller: if the handler is
// stuck, the delivery goroutine is left to finish on its own once it
// returns, rather than delaying proxy shutdown.
func (s *eventSink) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	close(s.ch)
}
