//go:build !linux

package goproxy

import "net"

// readableProbe reports whether a connection's read side has reached
// end-of-file without consuming any payload.
type readableProbe interface {
	// PeerGone reports whether the peer has closed its write direction.
	PeerGone() bool
}

// newReadableProbe returns nil on platforms without a non-destructive
// liveness probe; disconnect detection then falls back to write errors.
func newReadableProbe(net.Conn) readableProbe { return nil }

// releaseProbe exists for symmetry with the Linux implementation.
func releaseProbe(readableProbe) {}
