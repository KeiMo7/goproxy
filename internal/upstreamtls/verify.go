package upstreamtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
)

// Hop describes one independent TLS handshake inside a proxy connection.
// A plain target connection has one hop ("target"); an encrypted relay has
// a relay hop (verified against the relay's own name and trust) followed,
// when the tunneled traffic is itself TLS, by a separate target hop.
type Hop struct {
	// Name is the normalized name this hop must present in its certificate.
	// It comes from the request target for a target hop and from the
	// relay URL for a relay hop — never inherited from another connection.
	Name NormalizedName
	// Snapshot is the trust-configuration generation this hop is decided
	// under. It is captured at connection time and held for the
	// connection's lifetime, so a concurrent reload cannot change an
	// established connection's policy.
	Snapshot *Snapshot
	// Label identifies the hop in structured errors and reports, e.g.
	// "target" or "relay".
	Label string
	// BaseConfig supplies hop-independent settings (cipher suites, client
	// certificates, ALPN, ...) from the proxy's configured transport. It is
	// cloned, never mutated, so concurrent hops cannot pollute each other.
	BaseConfig *tls.Config
}

// Report is the structured result of one hop's verification. On success it
// is attached to the connection context; on failure the same information is
// carried inside VerificationError.
type Report struct {
	// Hop is the hop label.
	Hop string
	// Target is the normalized name that was verified.
	Target string
	// PolicyVersion is Snapshot.Version at connection time.
	PolicyVersion uint64
	// Mode is the verification mode that was applied.
	Mode TargetMode
	// Skipped is true only for an explicitly registered per-target bypass.
	Skipped bool
	// ServerName is the exact SNI value sent on the wire.
	ServerName string
	// TLSVersion is the negotiated protocol version.
	TLSVersion uint16
	// PeerFingerprint carries the SHA-256 of the peer leaf certificate's
	// raw bytes, allowing callers to detect certificate rotation between
	// requests.
	PeerFingerprint [32]byte
}

// configForHop builds a fresh tls.Config for one hop. The returned config is
// never shared with another hop: it is a clone with this hop's ServerName,
// root pool, version bounds and verification callback installed.
func configForHop(hop Hop) (*tls.Config, *TargetPolicy, *Report, error) {
	return configForPolicy(hop, hop.Snapshot.Lookup(hop.Name))
}

// configForPolicy builds a hop config from a policy already resolved by the
// caller. This is required when the effective policy differs from the raw
// registry entry (e.g. the narrowed legacy bypass switch): the pool key and
// the handshake must be derived from one and the same policy.
func configForPolicy(hop Hop, policy *TargetPolicy) (*tls.Config, *TargetPolicy, *Report, error) {
	name := hop.Name
	if name.String() == "" {
		return nil, nil, nil, &VerificationError{
			Kind:   FailureConfig,
			Hop:    hop.Label,
			Reason: "no name available to verify against",
		}
	}

	base := hop.BaseConfig
	if base == nil {
		base = &tls.Config{}
	}
	cfg := base.Clone()

	// The single source of the wire SNI: this hop's own normalized name.
	// Never inherited from BaseConfig (which another hop may have set).
	cfg.ServerName = name.String()

	if policy.MinTLSVersion != 0 {
		cfg.MinVersion = policy.MinTLSVersion
	}
	if policy.MaxTLSVersion != 0 {
		cfg.MaxVersion = policy.MaxTLSVersion
	}

	report := &Report{
		Hop:           hop.Label,
		Target:        name.String(),
		PolicyVersion: hop.Snapshot.Version,
		Mode:          policy.Mode,
		ServerName:    name.String(),
	}

	switch policy.Mode {
	case ModePrivateCA:
		// Scope trust to the issuers registered for this target. The system
		// pool is deliberately not mixed in here.
		cfg.RootCAs = policy.Roots
		cfg.InsecureSkipVerify = false
	case ModeSkipVerify:
		// Explicit per-target bypass. Verification is skipped, but recorded
		// on the report instead of happening silently.
		report.Skipped = true
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = nil
		cfg.VerifyPeerCertificate = nil
	default: // ModeSystemTrust
		// Honor a caller-provided root pool from the base config (the
		// equivalent of http.Transport.TLSClientConfig.RootCAs); a nil pool
		// makes crypto/tls use the system roots, matching a plain tls.Dial
		// against the target.
		cfg.RootCAs = base.RootCAs
		cfg.InsecureSkipVerify = false
	}

	if policy.Mode != ModeSkipVerify {
		// We run verification ourselves so that every failure gets a stable
		// category. InsecureSkipVerify suppresses the library's built-in
		// check; VerifyConnection still runs and performs the equivalent
		// chain + name + validity verification.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = nil
		cfg.VerifyConnection = makeVerifyFunc(hop, policy, report)
	}

	return cfg, policy, report, nil
}

// makeVerifyFunc returns a tls.Config.VerifyConnection callback that
// verifies the peer chain against the policy's roots (or system/caller
// roots) and the hop name, converting every failure into a structured
// VerificationError.
func makeVerifyFunc(hop Hop, policy *TargetPolicy, report *Report) func(tls.ConnectionState) error {
	label := hop.Label
	name := hop.Name
	return func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return &VerificationError{
				Kind:   FailureConfig,
				Hop:    label,
				Target: name.String(),
				Reason: "peer presented no certificate",
			}
		}
		leaf := state.PeerCertificates[0]

		roots := policy.Roots
		if policy.Mode == ModeSystemTrust {
			// Prefer a caller-configured pool from the base TLS config;
			// only fall back to the system roots when none was supplied.
			if hop.BaseConfig != nil && hop.BaseConfig.RootCAs != nil {
				roots = hop.BaseConfig.RootCAs
			} else {
				systemPool, err := x509.SystemCertPool()
				if err != nil || systemPool == nil {
					return &VerificationError{
						Kind:   FailureConfig,
						Hop:    label,
						Target: name.String(),
						Reason: "system root certificate pool unavailable",
						Err:    err,
					}
				}
				roots = systemPool
			}
		}

		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}

		// Chain and validity verification. DNSName is left empty so that a
		// chain failure (unknown issuer, expiry) is reported on its own
		// merits; name comparison is performed separately below to keep the
		// two failure categories distinguishable.
		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if _, err := leaf.Verify(opts); err != nil {
			kind, reason := classifyX509(err)
			return &VerificationError{
				Kind:   kind,
				Hop:    label,
				Target: name.String(),
				Reason: reason,
				Err:    err,
			}
		}

		// Name verification against the hop's own normalized name. IP
		// literals compare against IP SANs only — there is no fallback to
		// DNS matching or to skipping the check.
		if name.IsIP() {
			ip := net.ParseIP(name.String())
			if !ipInCert(ip, leaf) {
				return &VerificationError{
					Kind:   FailureNameMismatch,
					Hop:    label,
					Target: name.String(),
					Reason: "certificate has no IP SAN matching the target address",
				}
			}
		} else {
			if err := leaf.VerifyHostname(name.String()); err != nil {
				return &VerificationError{
					Kind:   FailureNameMismatch,
					Hop:    label,
					Target: name.String(),
					Reason: "certificate name does not match the requested host",
					Err:    err,
				}
			}
		}

		report.TLSVersion = state.Version
		report.PeerFingerprint = certFingerprint(leaf)
		return nil
	}
}

func ipInCert(ip net.IP, leaf *x509.Certificate) bool {
	for _, san := range leaf.IPAddresses {
		if san.Equal(ip) {
			return true
		}
	}
	return false
}

// HandshakeError converts an error returned while establishing a hop into a
// structured VerificationError of the right category. Errors that are
// already *VerificationError (e.g. produced by the verify callback) pass
// through unchanged.
func HandshakeError(label string, name NormalizedName, err error) error {
	if err == nil {
		return nil
	}
	var ve *VerificationError
	if errors.As(err, &ve) {
		return err
	}

	kind, reason := classifyHandshakeError(err)
	return &VerificationError{
		Kind:   kind,
		Hop:    label,
		Target: name.String(),
		Reason: reason,
		Err:    err,
	}
}
