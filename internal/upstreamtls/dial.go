package upstreamtls

import (
	"context"
	"crypto/tls"
	"net"
)

// Dialer performs one independent upstream TLS hop. Each call builds a fresh
// tls.Config from the hop's own name and the given policy snapshot, so
// concurrent dials never share a mutable ServerName, root pool or version
// bound, and SNI cannot leak from a previous connection.
type Dialer struct{}

// NewDialer returns the package dialer. It holds no mutable state.
func NewDialer() *Dialer { return &Dialer{} }

// Dial runs the TLS client handshake over rawConn according to hop. On
// success the returned net.Conn is the established TLS connection and the
// Report describes what was verified (including explicit bypasses). On
// failure the error is a *VerificationError with a stable FailureKind;
// rawConn is closed by Dial.
//
// Cancellation and deadlines follow ctx, matching tls.Conn.HandshakeContext.
func (d *Dialer) Dial(ctx context.Context, rawConn net.Conn, hop Hop) (net.Conn, *Report, error) {
	cfg, _, report, err := configForHop(hop)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}

	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, nil, HandshakeError(hop.Label, hop.Name, err)
	}

	// For an explicit bypass the verify callback was not installed, so fill
	// the report from the completed connection state directly. The bypass
	// fact itself stays visible via report.Skipped.
	if report.Skipped {
		state := tlsConn.ConnectionState()
		report.TLSVersion = state.Version
		if len(state.PeerCertificates) > 0 {
			report.PeerFingerprint = certFingerprint(state.PeerCertificates[0])
		}
	}

	return tlsConn, report, nil
}

// ConfigForHop exposes the per-hop tls.Config construction for callers that
// drive the handshake themselves (e.g. an http.Transport's DialTLSContext).
// The returned config is freshly cloned and must not be shared across hops.
func ConfigForHop(hop Hop) (*tls.Config, *Report, error) {
	cfg, _, report, err := configForHop(hop)
	return cfg, report, err
}

// ConfigForPolicy is ConfigForHop with the effective policy supplied
// explicitly by the caller, for cases where the applied policy differs from
// the raw registry entry (narrowed legacy bypass, synthetic entries).
func ConfigForPolicy(hop Hop, policy *TargetPolicy) (*tls.Config, *Report, error) {
	cfg, _, report, err := configForPolicy(hop, policy)
	return cfg, report, err
}
