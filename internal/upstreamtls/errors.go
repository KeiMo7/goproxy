// Package upstreamtls implements per-target TLS trust policies for the
// proxy's upstream connections. Every upstream TLS handshake (to a target
// server or to an encrypted upstream relay) is verified against the trust
// policy registered for the name used on that specific hop, never against a
// shared mutable configuration.
//
// The package only depends on the Go standard library.
package upstreamtls

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// FailureKind is the structured category of an upstream TLS failure.
// Upper layers can count and aggregate failures by kind without parsing
// free-form error strings.
type FailureKind string

const (
	// FailureNameMismatch means the verified certificate does not carry a
	// name (DNS or IP) matching the name requested for this hop.
	FailureNameMismatch FailureKind = "name_mismatch"

	// FailureUntrustedIssuer means the certificate chain does not chain to
	// the system roots, nor to any issuer registered for the target.
	FailureUntrustedIssuer FailureKind = "untrusted_issuer"

	// FailureExpired means the peer certificate is expired or not yet valid
	// at verification time.
	FailureExpired FailureKind = "expired"

	// FailureProtocolVersion means the peer only offered TLS protocol
	// versions that the configured policy forbids.
	FailureProtocolVersion FailureKind = "protocol_version"

	// FailurePeerClosed means the peer closed the connection during the
	// handshake before a certificate could be verified.
	FailurePeerClosed FailureKind = "peer_closed"

	// FailureConfig means the trust policy itself could not be applied:
	// unreadable or malformed trust material, or no name available to
	// verify against. The connection fails rather than falling back to
	// trusting everything.
	FailureConfig FailureKind = "config"

	// FailureHandshake covers handshake failures not attributable to one of
	// the specific categories above (cipher mismatch, malformed messages,
	// I/O timeouts other than a clean peer close, ...).
	FailureHandshake FailureKind = "handshake"
)

// VerificationError is the structured error returned for every failed
// upstream TLS verification or handshake. It implements the standard
// error interface and unwraps to the underlying library error, so existing
// errors.Is/errors.As checks keep working.
type VerificationError struct {
	// Kind is the stable, machine-readable failure category.
	Kind FailureKind
	// Target is the normalized name (without port) the failing hop was
	// supposed to present.
	Target string
	// Hop identifies which independent hop failed, e.g. "target" or the
	// host name of an encrypted upstream relay.
	Hop string
	// Reason is a short human-readable explanation.
	Reason string
	// Err is the underlying standard-library error, if any.
	Err error
}

func (e *VerificationError) Error() string {
	base := fmt.Sprintf("upstream tls: hop %q target %q: %s", e.Hop, e.Target, e.Reason)
	if e.Err != nil {
		return base + ": " + e.Err.Error()
	}
	return base
}

// Unwrap exposes the underlying error to errors.Is/errors.As.
func (e *VerificationError) Unwrap() error { return e.Err }

// AsVerificationError extracts a *VerificationError from err, returning nil
// if err does not wrap one.
func AsVerificationError(err error) *VerificationError {
	var ve *VerificationError
	if errors.As(err, &ve) {
		return ve
	}
	return nil
}

// classifyX509 maps a standard-library certificate verification error to the
// corresponding FailureKind. x509.Verify may return compound errors
// (CertPoolError wrapping several leaf errors); the most specific,
// security-relevant category wins deterministically.
func classifyX509(err error) (FailureKind, string) {
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return FailureNameMismatch, "certificate name does not match the requested host"
	}

	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		switch invalidErr.Reason {
		case x509.Expired:
			return FailureExpired, "certificate has expired or is not yet valid"
		case x509.CANotAuthorizedForThisName:
			return FailureNameMismatch, "CA is not authorized for the requested name"
		default:
			return FailureUntrustedIssuer, "certificate is invalid: " + invalidErr.Error()
		}
	}

	var unknownAuthErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthErr) {
		return FailureUntrustedIssuer, "certificate signed by an untrusted issuer"
	}

	var systemRootsErr x509.SystemRootsError
	if errors.As(err, &systemRootsErr) {
		return FailureConfig, "system root certificate pool unavailable"
	}

	// Recurse into compound errors (e.g. x509.CertPoolError).
	type multiErr interface{ Unwrap() []error }
	if me, ok := err.(multiErr); ok {
		for _, sub := range me.Unwrap() {
			if kind, reason := classifyX509(sub); kind != FailureHandshake {
				return kind, reason
			}
		}
	}
	if wrapped := errors.Unwrap(err); wrapped != nil && wrapped != err {
		if kind, reason := classifyX509(wrapped); kind != FailureHandshake {
			return kind, reason
		}
	}

	return FailureHandshake, "certificate verification failed"
}
