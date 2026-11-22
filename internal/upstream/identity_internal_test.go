package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
)

func TestCanonicalHostPort(t *testing.T) {
	for _, tc := range []struct {
		in       string
		def      string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{in: "Example.COM:443", def: "80", wantHost: "example.com", wantPort: "443"},
		{in: "example.com", def: "80", wantHost: "example.com", wantPort: "80"},
		{in: "example.com", def: "443", wantHost: "example.com", wantPort: "443"},
		{in: "127.0.0.1:8080", def: "80", wantHost: "127.0.0.1", wantPort: "8080"},
		{in: "[::1]:443", def: "80", wantHost: "::1", wantPort: "443"},
		{in: "::1", def: "80", wantHost: "::1", wantPort: "80"},
		{in: "example.com:0", def: "80", wantErr: true},
		{in: "example.com:99999", def: "80", wantErr: true},
		{in: "example.com:abc", def: "80", wantErr: true},
		{in: "", def: "80", wantErr: true},
	} {
		host, port, err := CanonicalHostPort(tc.in, tc.def)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%q: expected error, got %q:%q", tc.in, host, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error: %v", tc.in, err)
			continue
		}
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("%q: got %q:%q, want %q:%q", tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

func TestIdentityKeySeparatesEveryField(t *testing.T) {
	base := Identity{Scheme: "https", Host: "example.com", Port: "443", SNI: "example.com", Trust: "t1", Auth: "a1"}
	variants := []Identity{
		{Scheme: "http", Host: "example.com", Port: "443", SNI: "example.com", Trust: "t1", Auth: "a1"},
		{Scheme: "https", Host: "example.org", Port: "443", SNI: "example.com", Trust: "t1", Auth: "a1"},
		{Scheme: "https", Host: "example.com", Port: "8443", SNI: "example.com", Trust: "t1", Auth: "a1"},
		{Scheme: "https", Host: "example.com", Port: "443", SNI: "other.example", Trust: "t1", Auth: "a1"},
		{Scheme: "https", Host: "example.com", Port: "443", SNI: "example.com", Trust: "t2", Auth: "a1"},
		{Scheme: "https", Host: "example.com", Port: "443", SNI: "example.com", Trust: "t1", Auth: "a2"},
	}
	seen := map[string]bool{base.Key(): true}
	for _, v := range variants {
		k := v.Key()
		if seen[k] {
			t.Errorf("identity %+v collides with an earlier key", v)
		}
		seen[k] = true
	}
}

func TestTrustDigestChangesWithEveryTrustInput(t *testing.T) {
	poolA := x509.NewCertPool()
	poolA.AddCert(GoproxyCaForTest(t))
	poolB := x509.NewCertPool()
	poolB.AddCert(GoproxyCaForTest(t))
	poolB.AddCert(GoproxyCaForTest(t))

	base := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
		RootCAs:            poolA,
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
	}
	baseDigest := TrustDigest(base)
	if TrustDigest(base.Clone()) != baseDigest {
		t.Fatal("identical configs must produce identical digests")
	}
	baseCfg := func() *tls.Config {
		return &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "example.com",
			RootCAs:            poolA,
			NextProtos:         []string{"http/1.1"},
			MinVersion:         tls.VersionTLS12,
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*tls.Config)
	}{
		{"insecure", func(c *tls.Config) { c.InsecureSkipVerify = false }},
		{"sni", func(c *tls.Config) { c.ServerName = "other.example" }},
		{"roots", func(c *tls.Config) { c.RootCAs = poolB }},
		{"alpn", func(c *tls.Config) { c.NextProtos = []string{"h2"} }},
		{"minver", func(c *tls.Config) { c.MinVersion = tls.VersionTLS13 }},
		{"nil roots", func(c *tls.Config) { c.RootCAs = nil }},
	} {
		cfg := baseCfg()
		tc.mutate(cfg)
		if TrustDigest(cfg) == baseDigest {
			t.Errorf("%s: digest did not change", tc.name)
		}
	}
}

func TestAuthDigest(t *testing.T) {
	if AuthDigest("", "") != "" {
		t.Error("no credentials must yield the empty digest")
	}
	if AuthDigest("user", "pass") == AuthDigest("user", "other") {
		t.Error("different credentials must yield different digests")
	}
	if AuthDigest("ab", "c") == AuthDigest("a", "bc") {
		t.Error("part boundaries must be significant")
	}
	if AuthDigest("secret") == "secret" {
		t.Error("digest must not contain the cleartext")
	}
}

func TestCanonicalConnUnwrapsTLSAndWrappers(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	tlsConn := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
	})
	if got := canonicalConn(tlsConn); got != client {
		t.Fatalf("canonicalConn must unwrap the TLS layer, got %T", got)
	}
	if got := canonicalConn(nil); got != nil {
		t.Fatalf("canonicalConn(nil) = %v, want nil", got)
	}
}
