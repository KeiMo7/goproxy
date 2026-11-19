package upstream

import (
	"errors"
	"fmt"
	"strings"
)

// HopError describes a failure at one specific hop of a chain.
//
// The Error() string deliberately contains only the hop index, hop name and
// the failure kind/classification — never credentials, challenge bodies or
// request headers.
type HopError struct {
	// ChainID is the chain being established.
	ChainID string
	// HopIndex is the zero-based index of the failing hop.
	HopIndex int
	// HopName is the label of the failing hop.
	HopName string
	// Kind classifies the failure.
	Kind FailureKind
	// Op is the operation that failed ("dial", "handshake", "connect", "socks").
	Op string
	// Err is the wrapped underlying error (also credential-free).
	Err error
}

func (e *HopError) Error() string {
	label := e.HopName
	if label == "" {
		label = "hop"
	}
	return fmt.Sprintf("upstream: chain %q hop %d (%s) %s failed: %s: %v",
		e.ChainID, e.HopIndex, label, e.Op, e.Kind, e.Err)
}

func (e *HopError) Unwrap() error { return e.Err }

// Is supports errors.Is against sentinel kinds via FailureKind values.
func (e *HopError) Is(target error) bool {
	k, ok := target.(FailureKind)
	if !ok {
		return false
	}
	return e.Kind == k
}

// Error implements the error interface for FailureKind so callers can use
// errors.Is(err, upstream.FailureTimeout) etc.
func (k FailureKind) Error() string { return "upstream failure: " + string(k) }

// ChainAttempt records the outcome of trying one chain, either success or a
// per-hop error list.
type ChainAttempt struct {
	ChainID string
	// HopErrors holds the failures collected while trying this chain.
	// Normally exactly one entry; more when a failover chain itself fails
	// after some partial progress.
	HopErrors []*HopError
}

func (a ChainAttempt) failed() bool { return len(a.HopErrors) > 0 }

// RouteError is returned when every chain allowed for a route has failed.
// It carries the per-hop failure of every attempt so operators can locate
// the broken hop without reproducing the request.
type RouteError struct {
	// Target is the destination address that was being reached.
	Target string
	// Attempts lists every chain tried, in order.
	Attempts []ChainAttempt
}

func (e *RouteError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "upstream: all chains failed for %s:", e.Target)
	for _, a := range e.Attempts {
		b.WriteString("\n  - chain ")
		b.WriteString(a.ChainID)
		b.WriteString(": ")
		for _, he := range a.HopErrors {
			fmt.Fprintf(&b, "hop %d (%s) %s/%s: %v; ",
				he.HopIndex, he.HopName, he.Op, he.Kind, he.Err)
		}
	}
	return b.String()
}

// AsHopError extracts the first HopError from err, walking RouteError if
// needed. Returns nil when err contains no hop error.
func AsHopError(err error) *HopError {
	var he *HopError
	if errors.As(err, &he) {
		return he
	}
	var re *RouteError
	if errors.As(err, &re) {
		for _, a := range re.Attempts {
			if len(a.HopErrors) > 0 {
				return a.HopErrors[0]
			}
		}
	}
	return nil
}

// EventType enumerates observable router events. Credentials never appear in
// event fields.
type EventType string

const (
	// EventChainSelected: a route matched and the primary chain was chosen.
	EventChainSelected EventType = "chain_selected"
	// EventFailover: the current chain failed and the router switched to a
	// backup chain. Reason carries the HopError summary (no credentials).
	EventFailover EventType = "failover"
	// EventChainSucceeded: a chain produced a working tunnel.
	EventChainSucceeded EventType = "chain_succeeded"
	// EventAllChainsFailed: every allowed chain failed.
	EventAllChainsFailed EventType = "all_chains_failed"
	// EventTunnelReused: an idle pooled tunnel served a new request.
	EventTunnelReused EventType = "tunnel_reused"
	// EventTunnelCreated: a fresh tunnel was built.
	EventTunnelCreated EventType = "tunnel_created"
	// EventConfigReplaced: the router config was hot-swapped.
	EventConfigReplaced EventType = "config_replaced"
)

// Event is one observability record. All strings are credential-free.
type Event struct {
	Type      EventType
	Target    string
	ChainID   string
	FromChain string
	Reason    string
	HopIndex  int
	HopName   string
	Kind      FailureKind
}

// EventSink receives router events. Implementations must be safe for
// concurrent use.
type EventSink interface {
	Observe(Event)
}

// EventSinkFunc adapts a function to EventSink.
type EventSinkFunc func(Event)

func (f EventSinkFunc) Observe(e Event) { f(e) }

// FailoverReport is the structured result of a routed dial: whether failover
// happened and which chain ultimately served the request.
type FailoverReport struct {
	// UsedChain is the chain ID that produced the tunnel.
	UsedChain string
	// FellBack is true when the primary chain was not used.
	FellBack bool
	// Trail lists every chain tried, in order, with the failure kind of the
	// failed ones.
	Trail []FailoverTrailEntry
}

// FailoverTrailEntry is one chain attempt in a FailoverReport.
type FailoverTrailEntry struct {
	ChainID string
	Kind    FailureKind // empty for the successful attempt
	Hop     int
	HopName string
}
