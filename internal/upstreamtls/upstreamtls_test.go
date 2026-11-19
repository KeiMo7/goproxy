package upstreamtls

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
)

func TestNormalizeName(t *testing.T) {
	cases := []struct {
		in   string
		want string
		err  bool
	}{
		{"example.com", "example.com", false},
		{"Example.COM", "example.com", false},
		{"example.com.", "example.com", false},
		{"example.com:8443", "example.com", false},
		{"[2001:db8::1]:443", "2001:db8::1", false},
		{"127.0.0.1:9443", "127.0.0.1", false},
		{"bücher.example", "xn--bcher-kva.example", false},
		{"BÜCHER.EXAMPLE.:443", "xn--bcher-kva.example", false},
		{"", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeName(c.in)
		if c.err {
			if err == nil {
				t.Errorf("NormalizeName(%q) expected error, got %q", c.in, got)
			}
			var ve *VerificationError
			if !errors.As(err, &ve) || ve.Kind != FailureConfig {
				t.Errorf("NormalizeName(%q) error not classified as config: %v", c.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeName(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("NormalizeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizedNameIsIP(t *testing.T) {
	n, err := NormalizeName("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !n.IsIP() {
		t.Error("127.0.0.1 should be detected as IP")
	}
	dns, err := NormalizeName("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if dns.IsIP() {
		t.Error("example.com should not be detected as IP")
	}
}

func TestRegistryDefaultsToSystemTrust(t *testing.T) {
	r := NewRegistry()
	snap := r.Current()
	p := snap.Lookup(NormalizedName("anything.example"))
	if p.Mode != ModeSystemTrust {
		t.Fatalf("default mode = %v, want system trust", p.Mode)
	}
	if _, ok := snap.LookupEntry(NormalizedName("anything.example")); ok {
		t.Error("unregistered target must not appear as an entry")
	}
}

func TestReplaceFailsClosedOnUnknownGroup(t *testing.T) {
	r := NewRegistry()
	before := r.Current().Version
	_, err := r.Replace(nil, []TargetEntry{
		{Host: "x.example", Mode: ModePrivateCA, Group: "missing"},
	})
	if err == nil {
		t.Fatal("expected error for unknown group")
	}
	if r.Current().Version != before {
		t.Fatal("failed replacement must not change the active version")
	}
}

func TestReplaceFailsClosedOnBadPEM(t *testing.T) {
	if _, err := NewGroupBuilder([]byte("not a certificate")); err == nil {
		t.Fatal("expected error for malformed PEM")
	}
}

func TestConflictingEntriesLastWinsDeterministically(t *testing.T) {
	r := NewRegistry()
	g, err := NewGroupBuilder(caPEMForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	entries := []TargetEntry{
		{Host: "dup.example", Mode: ModePrivateCA, Group: "g"},
		{Host: "dup.example.", Mode: ModeSkipVerify},
	}
	snap, err := r.Replace(map[string]*GroupBuilder{"g": g}, entries)
	if err != nil {
		t.Fatal(err)
	}
	// Lookup by a normalized spelling equivalent to both registered forms.
	norm, err := NormalizeName("DUP.Example")
	if err != nil {
		t.Fatal(err)
	}
	p := snap.Lookup(norm)
	if p.Mode != ModeSkipVerify {
		t.Fatalf("conflict resolution = %v, want skip-verify", p.Mode)
	}
}

func TestSnapshotHistoryPreservesGenerations(t *testing.T) {
	r := NewRegistry()
	g, err := NewGroupBuilder(caPEMForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.Replace(map[string]*GroupBuilder{"g": g},
		[]TargetEntry{{Host: "a.example", Mode: ModePrivateCA, Group: "g"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.Replace(map[string]*GroupBuilder{"g": g},
		[]TargetEntry{{Host: "b.example", Mode: ModePrivateCA, Group: "g"}})
	if err != nil {
		t.Fatal(err)
	}
	if second.Version <= first.Version {
		t.Fatal("versions must increase")
	}
	old := r.SnapshotAt(first.Version)
	if old.Version != first.Version {
		t.Fatal("SnapshotAt did not return the requested generation")
	}
	if _, ok := old.LookupEntry(NormalizedName("a.example")); !ok {
		t.Fatal("old snapshot must retain its original entries")
	}
}

func TestHandshakeErrorClassifiesPeerReset(t *testing.T) {
	// A plain EOF during a handshake is a peer close.
	err := HandshakeError("target", NormalizedName("x.example"), errEOFShim{})
	ve, ok := err.(*VerificationError)
	if !ok {
		t.Fatalf("expected *VerificationError, got %T", err)
	}
	if ve.Kind != FailurePeerClosed {
		t.Fatalf("kind = %v, want peer_closed", ve.Kind)
	}
}

func TestHandshakeErrorPassesThroughVerificationError(t *testing.T) {
	original := &VerificationError{Kind: FailureNameMismatch, Target: "x.example", Hop: "target"}
	got := HandshakeError("target", NormalizedName("x.example"), original)
	if got != original {
		t.Fatal("existing VerificationError must pass through unchanged")
	}
}

func TestPoolIDStableAcrossLookup(t *testing.T) {
	r := NewRegistry()
	g, err := NewGroupBuilder(caPEMForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := r.Replace(map[string]*GroupBuilder{"g": g},
		[]TargetEntry{{Host: "a.example", Mode: ModePrivateCA, Group: "g"}})
	if err != nil {
		t.Fatal(err)
	}
	p := snap.Lookup(NormalizedName("a.example"))
	id1 := snap.PoolID(p.Roots)
	id2 := snap.PoolID(p.Roots)
	if id1 == 0 || id1 != id2 {
		t.Fatalf("pool ID must be stable and non-zero: %d %d", id1, id2)
	}
}

func TestMinMaxTLSVersionValidation(t *testing.T) {
	r := NewRegistry()
	g, err := NewGroupBuilder(caPEMForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Replace(map[string]*GroupBuilder{"g": g}, []TargetEntry{{
		Host: "a.example", Mode: ModePrivateCA, Group: "g",
		MinTLSVersion: tls.VersionTLS13, MaxTLSVersion: tls.VersionTLS12,
	}})
	if err == nil {
		t.Fatal("min > max must be rejected")
	}
}

func TestNormalizeIPLiteral(t *testing.T) {
	// IPv4 canonicalization.
	n, err := NormalizeName("127.0.0.1")
	if err != nil || n.String() != "127.0.0.1" {
		t.Fatalf("ipv4 normalize: %q %v", n, err)
	}
	if !n.IsIP() {
		t.Fatal("should report IP")
	}
	// Bracket IPv6.
	n6, err := NormalizeName(net.JoinHostPort("::1", "443"))
	if err != nil {
		t.Fatal(err)
	}
	if n6.String() != "::1" || !n6.IsIP() {
		t.Fatalf("ipv6 normalize: %q", n6)
	}
}
