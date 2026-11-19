package upstreamtls

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
)

func certFingerprint(cert *x509.Certificate) [32]byte {
	return sha256.Sum256(cert.Raw)
}

// classifyHandshakeError maps transport-level handshake errors (everything
// outside the certificate verify callback) onto the stable failure
// taxonomy. String matching is used only as a last resort for protocol
// alerts whose concrete error type is unexported in crypto/tls; typed
// errors and net.OpError are handled structurally first.
func classifyHandshakeError(err error) (FailureKind, string) {
	// A clean EOF or connection reset during the handshake means the peer
	// (or a middlebox) hung up before verification completed.
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return FailurePeerClosed, "peer closed the connection during the handshake"
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, net.ErrClosed) {
		return FailurePeerClosed, "peer closed the connection during the handshake"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.ECONNRESET) ||
			errors.Is(opErr.Err, net.ErrClosed) ||
			isReset(opErr) ||
			strings.Contains(opErr.Err.Error(), "connection reset") {
			return FailurePeerClosed, "peer closed the connection during the handshake"
		}
	}

	// Protocol-version rejections are surfaced as alert strings by
	// crypto/tls.
	msg := err.Error()
	if strings.Contains(msg, "protocol version") ||
		strings.Contains(msg, "unsupported versions") ||
		strings.Contains(msg, "handshake failure") && strings.Contains(msg, "version") {
		return FailureProtocolVersion, "no mutually acceptable TLS protocol version"
	}

	// Certificate alerts that escaped the callback still carry the
	// underlying x509 reason in their message.
	if strings.Contains(msg, "certificate") {
		if kind, reason := classifyX509(err); kind != FailureHandshake {
			return kind, reason
		}
	}

	return FailureHandshake, "TLS handshake failed"
}

func isReset(err error) bool {
	type resetter interface{ Reset() bool }
	var r resetter
	if errors.As(err, &r) {
		return r.Reset()
	}
	return false
}
