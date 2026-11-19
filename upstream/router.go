package upstream

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
)

// Router picks an upstream chain per destination, drives failover and holds
// the hot-swappable Config. The zero value is not usable; use NewRouter.
type Router struct {
	state   atomic.Pointer[routerState]
	sinksMu sync.RWMutex
	sinks   []EventSink
}

type routerState struct {
	cfg     *Config
	dialers map[string]*chainDialer // chain ID -> dialer
	routes  []Route
	def     *Route
}

// NewRouter validates cfg and builds the initial snapshot.
func NewRouter(cfg *Config) (*Router, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	r := &Router{}
	if err := r.replace(cfg); err != nil {
		return nil, err
	}
	return r, nil
}

// AddSink attaches an observability sink. Safe to call at any time.
func (r *Router) AddSink(s EventSink) {
	r.sinksMu.Lock()
	r.sinks = append(r.sinks, s)
	r.sinksMu.Unlock()
}

// Observe implements EventSink so chain dialers can report pool events into
// the router's fan-out.
func (r *Router) Observe(e Event) { r.emit(e) }

func (r *Router) emit(e Event) {
	r.sinksMu.RLock()
	sinks := r.sinks
	r.sinksMu.RUnlock()
	for _, s := range sinks {
		s.Observe(e)
	}
}

// Replace atomically swaps the configuration. Requests already in flight keep
// using the old dialers (and therefore their established tunnels); only idle
// pooled tunnels of the old snapshot are closed, so no active connection is
// ever cut. New requests observe the new config.
func (r *Router) Replace(cfg *Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	return r.replace(cfg)
}

func (r *Router) replace(cfg *Config) error {
	st := &routerState{
		cfg:     cfg,
		dialers: make(map[string]*chainDialer, len(cfg.Chains)),
		routes:  cfg.Routes,
	}
	for i := range cfg.Chains {
		ch := cfg.Chains[i]
		st.dialers[ch.ID] = newChainDialer(cfg, ch, r)
	}
	for i := range cfg.Routes {
		if cfg.Routes[i].Default {
			rt := cfg.Routes[i]
			st.def = &rt
		}
	}
	old := r.state.Swap(st)
	if old != nil {
		// Retire old dialers: close idle tunnels only; in-flight conns remain
		// owned by the requests using them and are closed when those finish.
		for _, d := range old.dialers {
			d.CloseIdleConnections()
		}
	}
	r.emit(Event{Type: EventConfigReplaced})
	return nil
}

// CurrentConfig returns the active snapshot (read-only view; do not mutate).
func (r *Router) CurrentConfig() *Config {
	return r.state.Load().cfg
}

// matchRoute finds the first route whose selectors match host. Explicit
// routes win over the default regardless of order.
func (r *Router) matchRoute(host string) *Route {
	st := r.state.Load()
	var fallback *Route
	for i := range st.routes {
		rt := &st.routes[i]
		if rt.Default {
			fallback = rt
			continue
		}
		if rt.matchesHost(host) {
			return rt
		}
	}
	if fallback != nil {
		return fallback
	}
	if st.def != nil {
		return st.def
	}
	return nil
}

// chainOrder returns the ordered list of chain IDs allowed for host:
// primary first, then backups.
func (r *Router) chainOrder(host string) ([]string, *Route) {
	rt := r.matchRoute(host)
	if rt == nil {
		return nil, nil
	}
	order := make([]string, 0, 1+len(rt.Backups))
	order = append(order, rt.Primary)
	order = append(order, rt.Backups...)
	return order, rt
}

// dialChain establishes a tunnel through one chain. Failover bookkeeping is
// handled by the caller.
func (r *Router) dialChain(ctx context.Context, chainID, target string) (net.Conn, *chainDialer, error) {
	st := r.state.Load()
	d, ok := st.dialers[chainID]
	if !ok {
		return nil, nil, &HopError{ChainID: chainID, Kind: FailureProtocol, Op: "route",
			HopName: "(unknown)", Err: errUnknownChain(chainID)}
	}
	conn, err := d.DialContext(ctx, target)
	if err != nil {
		return nil, d, err
	}
	return conn, d, nil
}

func errUnknownChain(id string) error {
	return &simpleErr{msg: "unknown chain " + id}
}

type simpleErr struct{ msg string }

func (e *simpleErr) Error() string { return "upstream: " + e.msg }

// routedDial is the shared core of DialContext/RoundTrip: try the primary,
// then each allowed backup, collecting per-hop errors. Failover happens only
// before any request byte is written, so a request body can never be sent
// twice.
func (r *Router) routedDial(ctx context.Context, host, target string) (net.Conn, *chainDialer, *FailoverReport, error) {
	order, route := r.chainOrder(host)
	if len(order) == 0 {
		return nil, nil, nil, &simpleErr{msg: "no upstream route for " + host}
	}
	report := &FailoverReport{}
	var attempts []ChainAttempt
	var prevChain string

	for i, chainID := range order {
		if i == 0 {
			r.emit(Event{Type: EventChainSelected, Target: target, ChainID: chainID})
		} else {
			r.emit(Event{Type: EventFailover, Target: target, ChainID: chainID, FromChain: prevChain})
		}
		conn, d, dialErr := r.dialChain(ctx, chainID, target)
		if dialErr == nil && conn != nil {
			report.Trail = append(report.Trail, FailoverTrailEntry{ChainID: chainID})
			report.UsedChain = chainID
			report.FellBack = i > 0
			r.emit(Event{Type: EventChainSucceeded, Target: target, ChainID: chainID})
			return conn, d, report, nil
		}

		he := AsHopError(dialErr)
		entry := FailoverTrailEntry{ChainID: chainID}
		var hopErrs []*HopError
		if he != nil {
			entry.Kind = he.Kind
			entry.Hop = he.HopIndex
			entry.HopName = he.HopName
			hopErrs = append(hopErrs, he)
		}
		report.Trail = append(report.Trail, entry)
		attempts = append(attempts, ChainAttempt{ChainID: chainID, HopErrors: hopErrs})

		// Decide whether failover is allowed for this kind.
		kind := FailureProtocol
		if he != nil {
			kind = he.Kind
			r.emit(Event{Type: EventFailover, Target: target, ChainID: chainID,
				FromChain: prevChain, Reason: he.Error(), HopIndex: he.HopIndex,
				HopName: he.HopName, Kind: he.Kind})
		} else {
			r.emit(Event{Type: EventFailover, Target: target, ChainID: chainID,
				FromChain: prevChain, Reason: dialErr.Error(), Kind: kind})
		}
		if route == nil || !route.Policy.allows(kind) {
			return nil, nil, report, &RouteError{Target: target, Attempts: attempts}
		}
		prevChain = chainID
	}

	r.emit(Event{Type: EventAllChainsFailed, Target: target})
	return nil, nil, report, &RouteError{Target: target, Attempts: attempts}
}

// DialContext returns a tunneled net.Conn to target (host:port), selecting
// the chain based on host (port stripped internally for route matching).
// It is the entry point used for CONNECT-style traffic.
func (r *Router) DialContext(ctx context.Context, req *http.Request, network, target string) (net.Conn, error) {
	host := hostOnly(target)
	if req != nil && req.URL != nil && req.URL.Hostname() != "" {
		host = req.URL.Hostname()
	}
	conn, _, _, err := r.routedDial(ctx, host, target)
	return conn, err
}

// hostOnly strips the port from a host:port address, tolerating bracketed
// IPv6 literals such as "[::1]:8080".
func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
