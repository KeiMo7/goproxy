package upstreamtls

import (
	"crypto/x509"
	"sort"
	"sync"
	"sync/atomic"
)

// TargetMode states how a single registered target is to be verified.
type TargetMode int

const (
	// ModeSystemTrust (the implicit default) verifies the peer against the
	// system root store and the requested name. Nothing registered.
	ModeSystemTrust TargetMode = iota

	// ModePrivateCA verifies the peer against one of the explicitly
	// registered issuer certificates (plus the name). Targets without a
	// matching registration never fall into this mode.
	ModePrivateCA

	// ModeSkipVerify is an explicit per-target bypass: certificate chain
	// and name checks are skipped only for this target, and every such
	// bypass is recorded in the hop's verification report. It is never
	// inferred from a global switch.
	ModeSkipVerify
)

// TargetPolicy is the immutable trust decision for one normalized target.
type TargetPolicy struct {
	// Name is the normalized target name the policy was registered for.
	Name NormalizedName
	// Mode selects system trust, a registered private CA, or an explicit
	// per-target bypass.
	Mode TargetMode
	// Roots holds the trusted issuer certificates for ModePrivateCA. The
	// pool is owned by the policy and must not be mutated after
	// registration.
	Roots *x509.CertPool
	// MinTLSVersion optionally forbids TLS versions below the given
	// crypto/tls version constant (e.g. tls.VersionTLS12). Zero means the
	// library default applies.
	MinTLSVersion uint16
	// MaxTLSVersion optionally forbids TLS versions above the given
	// crypto/tls version constant. Zero means no upper bound.
	MaxTLSVersion uint16
}

// Snapshot is an immutable point-in-time view of the whole trust
// configuration. Connections established while a snapshot is current keep
// using it for their whole lifetime; reloading the registry only affects
// subsequently established connections.
type Snapshot struct {
	// Version is incremented on every registry replacement. It lets
	// callers tell which policy generation an established connection used.
	Version uint64
	targets map[NormalizedName]*TargetPolicy
	groups  map[string]*x509.CertPool
	// poolID assigns a stable identity to each distinct root pool for
	// connection-cache keying. Pool pointers themselves must not escape the
	// package's abstraction.
	poolID map[*x509.CertPool]uint64
}

// PoolID returns the stable identity of a snapshot's root pool, or zero if
// the pool is not part of this snapshot.
func (s *Snapshot) PoolID(pool *x509.CertPool) uint64 {
	if s == nil || pool == nil {
		return 0
	}
	return s.poolID[pool]
}

// Lookup returns the effective policy for a normalized target name.
// Unregistered targets get an immutable ModeSystemTrust policy, so the
// default verification strength is never weakened by merely having a
// registry. The returned pointer must not be modified.
func (s *Snapshot) Lookup(name NormalizedName) *TargetPolicy {
	if s != nil {
		if p, ok := s.targets[name]; ok {
			return p
		}
	}
	return &TargetPolicy{Name: name, Mode: ModeSystemTrust}
}

// LookupEntry reports whether a policy was explicitly registered for name
// in this snapshot (as opposed to the implicit system-trust default).
func (s *Snapshot) LookupEntry(name NormalizedName) (*TargetPolicy, bool) {
	if s == nil {
		return nil, false
	}
	p, ok := s.targets[name]
	return p, ok
}

// Registry holds the trust configuration and serves immutable snapshots.
// The zero value is a valid, empty registry (system trust for everyone).
//
// All methods are safe for concurrent use. Update replaces the whole
// configuration atomically; in-flight connections retain the snapshot they
// were built from.
type Registry struct {
	snap atomic.Pointer[Snapshot]
	// history retains every installed snapshot by version so callers can
	// later inspect or reuse a policy generation still held by established
	// connections. Entries are append-only and never mutated.
	historyMu sync.RWMutex
	history   map[uint64]*Snapshot
}

// SnapshotAt returns the snapshot with the given version, or the current
// snapshot if the requested version is unknown.
func (r *Registry) SnapshotAt(version uint64) *Snapshot {
	r.historyMu.RLock()
	snap, ok := r.history[version]
	r.historyMu.RUnlock()
	if ok {
		return snap
	}
	return r.Current()
}

// NewRegistry returns an empty registry. An empty registry changes nothing
// about verification behavior: every target is verified with system trust.
func NewRegistry() *Registry {
	r := &Registry{history: map[uint64]*Snapshot{}}
	initial := &Snapshot{
		Version: 0,
		targets: map[NormalizedName]*TargetPolicy{},
		groups:  map[string]*x509.CertPool{},
		poolID:  map[*x509.CertPool]uint64{},
	}
	r.history[0] = initial
	r.snap.Store(initial)
	return r
}

// Current returns the immutable snapshot currently in effect.
func (r *Registry) Current() *Snapshot {
	s := r.snap.Load()
	if s == nil {
		// Tolerate a Registry obtained without NewRegistry.
		return &Snapshot{
			Version: 0,
			targets: map[NormalizedName]*TargetPolicy{},
			groups:  map[string]*x509.CertPool{},
			poolID:  map[*x509.CertPool]uint64{},
		}
	}
	return s
}

// GroupBuilder accumulates the issuer certificates trusted for a named
// target group.
type GroupBuilder struct {
	pool *x509.CertPool
}

// NewGroupBuilder starts a group whose first issuer is the given PEM- or
// DER-encoded certificate. More issuers can be added with AddCertPEM.
func NewGroupBuilder(firstPEM []byte) (*GroupBuilder, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(firstPEM) {
		return nil, &VerificationError{
			Kind:   FailureConfig,
			Reason: "no valid issuer certificate found in group PEM data",
		}
	}
	return &GroupBuilder{pool: pool}, nil
}

// NewGroupBuilderFromCert starts a group trusting the given parsed
// certificate (typically a CA certificate).
func NewGroupBuilderFromCert(cert *x509.Certificate) *GroupBuilder {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &GroupBuilder{pool: pool}
}

// AddCertPEM trusts an additional issuer for the group. A parse failure
// returns an error instead of silently dropping the certificate.
func (b *GroupBuilder) AddCertPEM(pem []byte) error {
	if !b.pool.AppendCertsFromPEM(pem) {
		return &VerificationError{
			Kind:   FailureConfig,
			Reason: "no valid issuer certificate found in group PEM data",
		}
	}
	return nil
}

// TargetEntry is one entry of a full registry replacement.
type TargetEntry struct {
	// Host is the target as written by the operator; it is normalized the
	// same way request names are normalized, so equivalent spellings
	// collapse onto one entry.
	Host string
	// Mode selects private-CA verification or an explicit bypass.
	Mode TargetMode
	// Group names the issuer group trusted for ModePrivateCA. Required for
	// ModePrivateCA and forbidden otherwise.
	Group string
	// MinTLSVersion / MaxTLSVersion optionally bound the accepted TLS
	// protocol versions (crypto/tls VersionTLSxx constants).
	MinTLSVersion uint16
	MaxTLSVersion uint16
}

// Replace atomically installs a new configuration built from the given
// issuer groups and target entries. The result is fully validated before the
// swap: any malformed entry makes Replace fail and leaves the previously
// installed configuration untouched — a bad config never degrades to
// trusting everything.
//
// Determinism: entries are keyed by normalized name. If the same target
// appears more than once, the later entry in entries wins, and the decision
// never depends on map iteration order. If the same target is meant to be
// both allowed and rejected, callers resolve that before calling Replace;
// the last explicit registration is the installed answer and is observable
// via Snapshot.Version.
func (r *Registry) Replace(groups map[string]*GroupBuilder, entries []TargetEntry) (*Snapshot, error) {
	newSnap := &Snapshot{
		Version: r.Current().Version + 1,
		targets: make(map[NormalizedName]*TargetPolicy, len(entries)),
		groups:  make(map[string]*x509.CertPool, len(groups)),
		poolID:  make(map[*x509.CertPool]uint64, len(groups)),
	}

	// Deterministic pool IDs: sort group names so the same logical
	// configuration always produces the same key components, independent of
	// map traversal order.
	groupNames := make([]string, 0, len(groups))
	for name := range groups {
		groupNames = append(groupNames, name)
	}
	sort.Strings(groupNames)
	for i, name := range groupNames {
		b := groups[name]
		if name == "" {
			return nil, &VerificationError{Kind: FailureConfig, Reason: "issuer group has an empty name"}
		}
		if b == nil || b.pool == nil {
			return nil, &VerificationError{
				Kind:   FailureConfig,
				Reason: "issuer group " + name + " has no certificates",
			}
		}
		newSnap.groups[name] = b.pool
		newSnap.poolID[b.pool] = uint64(i + 1)
	}

	for _, e := range entries {
		name, err := NormalizeName(e.Host)
		if err != nil {
			return nil, err
		}
		policy := &TargetPolicy{
			Name:          name,
			Mode:          e.Mode,
			MinTLSVersion: e.MinTLSVersion,
			MaxTLSVersion: e.MaxTLSVersion,
		}
		switch e.Mode {
		case ModePrivateCA:
			pool, ok := newSnap.groups[e.Group]
			if !ok {
				return nil, &VerificationError{
					Kind:   FailureConfig,
					Target: name.String(),
					Reason: "target references unknown issuer group: " + e.Group,
				}
			}
			policy.Roots = pool
		case ModeSkipVerify:
			if e.Group != "" {
				return nil, &VerificationError{
					Kind:   FailureConfig,
					Target: name.String(),
					Reason: "skip-verify target must not name an issuer group",
				}
			}
		case ModeSystemTrust:
			if e.Group != "" {
				return nil, &VerificationError{
					Kind:   FailureConfig,
					Target: name.String(),
					Reason: "system-trust target must not name an issuer group",
				}
			}
		default:
			return nil, &VerificationError{
				Kind:   FailureConfig,
				Target: name.String(),
				Reason: "unknown target verification mode",
			}
		}
		if e.MinTLSVersion != 0 && e.MaxTLSVersion != 0 && e.MinTLSVersion > e.MaxTLSVersion {
			return nil, &VerificationError{
				Kind:   FailureConfig,
				Target: name.String(),
				Reason: "min TLS version is greater than max TLS version",
			}
		}
		// Explicit, order-independent overwrite: slice order decides, never
		// map traversal.
		newSnap.targets[name] = policy
	}

	r.historyMu.Lock()
	r.history[newSnap.Version] = newSnap
	r.historyMu.Unlock()
	r.snap.Store(newSnap)
	return newSnap, nil
}
