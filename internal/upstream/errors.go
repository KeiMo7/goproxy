package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// FailureKind classifies an upstream failure without relying on string
// matching, so callers can distinguish caller cancellation from a timeout
// from a plain connection failure.
type FailureKind string

// Sentinel errors shared across the package.
var (
	// ErrLimit is returned when a connection limit is reached and the wait
	// queue is full (or waiting is disabled).
	ErrLimit = errors.New("goproxy: upstream connection limit reached")
	// ErrIdle marks errors caused by a connection or tunnel that was
	// reclaimed for being idle.
	ErrIdle = errors.New("goproxy: upstream connection idle-expired")
	// ErrClosed is returned by pool operations after the pool is closed.
	ErrClosed = errors.New("goproxy: upstream pool closed")
)

// Failure kinds reported by Classify.
const (
	// FailureConnect means the TCP connection could not be established.
	FailureConnect FailureKind = "connect"
	// FailureHandshake means the TLS handshake to the origin failed.
	FailureHandshake FailureKind = "handshake"
	// FailureResponseHeader means the origin did not send response headers
	// within ResponseHeaderTimeout.
	FailureResponseHeader FailureKind = "response-header"
	// FailureIdle means an idle connection or tunnel was reclaimed.
	FailureIdle FailureKind = "idle"
	// FailureLimit means a connection limit was reached.
	FailureLimit FailureKind = "limit"
	// FailureCanceled means the caller canceled or disconnected.
	FailureCanceled FailureKind = "canceled"
	// FailureStale means a pooled connection was found closed by the peer.
	FailureStale FailureKind = "stale"
	// FailureNotReplayable means a stale connection was detected but the
	// request may not be retried because it is not replayable.
	FailureNotReplayable FailureKind = "not-replayable"
	// FailureOther is any unclassified failure.
	FailureOther FailureKind = "other"
)

// Error is a classified upstream failure. It unwraps to the underlying
// error, so errors.Is(err, context.Canceled) keeps working through it.
type Error struct {
	Kind   FailureKind
	Target string
	Err    error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("goproxy upstream %s: %s", e.Kind, e.Target)
	}
	return fmt.Sprintf("goproxy upstream %s %s: %v", e.Kind, e.Target, e.Err)
}

// Unwrap exposes the underlying cause.
func (e *Error) Unwrap() error { return e.Err }

// Timeout reports whether the failure was a timeout.
func (e *Error) Timeout() bool {
	var ne net.Error
	return errors.As(e.Err, &ne) && ne.Timeout()
}

// Classify maps err onto a FailureKind.
func Classify(err error) FailureKind {
	if err == nil {
		return FailureOther
	}
	var ee *Error
	if errors.As(err, &ee) {
		return ee.Kind
	}
	switch {
	case errors.Is(err, ErrLimit):
		return FailureLimit
	case errors.Is(err, context.Canceled):
		return FailureCanceled
	case errors.Is(err, ErrIdle):
		return FailureIdle
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		// Distinguish the wait-for-headers timeout from connect/handshake
		// timeouts by its message, which net/http defines and does not
		// otherwise expose as a type.
		if strings.Contains(err.Error(), "timeout awaiting response headers") {
			return FailureResponseHeader
		}
		return FailureConnect
	}
	return FailureOther
}

// isStaleConnErr reports whether err indicates that a connection taken from
// the idle pool was already closed by the peer, or that a connection had to
// be abandoned before the request was fully written.
func isStaleConnErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrIdle) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "read" {
		return true
	}
	return false
}
