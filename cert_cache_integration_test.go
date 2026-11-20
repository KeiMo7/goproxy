package goproxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mitmProxyWithCache builds a MITM proxy backed by cache, using the default
// built-in CA (AlwaysMitm). It returns the proxy and its test server.
func mitmProxyWithCache(t *testing.T, cache CertStorage) (*ProxyHttpServer, *httptest.Server) {
	t.Helper()
	proxy := NewProxyHttpServer()
	proxy.CertStore = cache
	proxy.OnRequest().HandleConnect(AlwaysMitm)
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)
	return proxy, server
}

// mitmLeafViaTunnel drives a TLS handshake to sni through the proxy over a
// CONNECT tunnel and returns the presented leaf certificate fingerprint.
func mitmLeafViaTunnel(t *testing.T, server *httptest.Server, sni string) ([32]byte, error) {
	t.Helper()
	pu, _ := url.Parse(server.URL)
	raw, err := net.Dial("tcp", pu.Host)
	if err != nil {
		return [32]byte{}, err
	}
	t.Cleanup(func() { raw.Close() })
	if _, err := raw.Write([]byte("CONNECT " + sni + ":443 HTTP/1.1\r\nHost: " + sni + ":443\r\n\r\n")); err != nil {
		return [32]byte{}, err
	}
	buf := make([]byte, 1024)
	n, err := raw.Read(buf)
	if err != nil {
		return [32]byte{}, err
	}
	if !bytes.Contains(buf[:n], []byte(" 200 ")) {
		return [32]byte{}, errors.New("CONNECT rejected: " + string(buf[:n]))
	}
	tconn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: sni})
	if err := tconn.Handshake(); err != nil {
		return [32]byte{}, err
	}
	defer tconn.Close()
	return sha256.Sum256(tconn.ConnectionState().PeerCertificates[0].Raw), nil
}

// mustLeaf is the fatal-on-error form of mitmLeafViaTunnel.
func mustLeaf(t *testing.T, server *httptest.Server, sni string) [32]byte {
	t.Helper()
	fp, err := mitmLeafViaTunnel(t, server, sni)
	if err != nil {
		t.Fatalf("MITM handshake for %s failed: %v", sni, err)
	}
	return fp
}

// TestIntegrationConcurrentHandshakeOneSigning is acceptance case 1 end to
// end: N concurrent handshakes through a real MITM proxy trigger one signing.
func TestIntegrationConcurrentHandshakeOneSigning(t *testing.T) {
	var signs atomic.Int32
	cache := &countingCache{
		inner: NewCertCache(),
		onGen: func() { signs.Add(1) },
	}
	_, server := mitmProxyWithCache(t, cache)

	const n = 16
	var wg sync.WaitGroup
	fps := make([][32]byte, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			fps[i], errs[i] = mitmLeafViaTunnel(t, server, "concurrent.example")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("handshake %d failed: %v", i, err)
		}
	}
	if got := signs.Load(); got != 1 {
		t.Fatalf("expected 1 signing for %d handshakes, got %d", n, got)
	}
	want := fps[0]
	for i := 1; i < n; i++ {
		if fps[i] != want {
			t.Fatalf("handshake %d presented a different certificate", i)
		}
	}
}

// TestIntegrationStableFingerprintAcrossHandshakes is acceptance case 3 end
// to end: repeated handshakes see identical leaf DER.
func TestIntegrationStableFingerprintAcrossHandshakes(t *testing.T) {
	cache := NewCertCache()
	_, server := mitmProxyWithCache(t, cache)

	first := mustLeaf(t, server, "stable.integration.example")
	second := mustLeaf(t, server, "stable.integration.example")
	if first != second {
		t.Fatal("leaf certificate changed between handshakes")
	}
}

// TestIntegrationIssuerRotation is acceptance case 4 end to end: rotating the
// CA makes the proxy present a certificate from the new issuer.
func TestIntegrationIssuerRotation(t *testing.T) {
	ca1 := GoproxyCa
	ca2 := mustTestCA(t)
	cache := NewCertCache()

	proxy := NewProxyHttpServer()
	proxy.CertStore = cache
	// Switch issuer per CONNECT: first CA for the first two connections,
	// then a different CA.
	var useSecond atomic.Bool
	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *ProxyCtx) (*ConnectAction, string) {
		action := &ConnectAction{Action: ConnectMitm}
		if useSecond.Load() {
			action.TLSConfig = TLSConfigFromCA(&ca2)
		} else {
			action.TLSConfig = TLSConfigFromCA(&ca1)
		}
		return action, host
	})
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)

	leaf1 := mustLeaf(t, server, "rotate.integration.example")
	useSecond.Store(true)
	leaf2 := mustLeaf(t, server, "rotate.integration.example")
	if leaf1 == leaf2 {
		t.Fatal("issuer rotation did not change the presented certificate")
	}
	if stats := cache.Stats(); stats.Discards < 1 {
		t.Fatalf("expected an issuer-mismatch discard, got %+v", stats)
	}
}

// TestIntegrationSignerFailureSharedAndRetried is acceptance case 6 end to
// end: a failing signer is not amplified, the error is shared, and after the
// negative TTL the target recovers.
func TestIntegrationSignerFailureSharedAndRetried(t *testing.T) {
	ca := GoproxyCa
	boom := errors.New("signer down")
	var attempts atomic.Int32
	var failMode atomic.Bool
	failMode.Store(true)

	cache := NewCertCache(WithNegativeTTL(60 * time.Millisecond))
	proxy := NewProxyHttpServer()
	proxy.CertStore = cache
	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *ProxyCtx) (*ConnectAction, string) {
		return &ConnectAction{
			Action: ConnectMitm,
			TLSConfig: func(h string, c *ProxyCtx) (*tls.Config, error) {
				id, _ := IssuerIDFromCertificate(&ca)
				_, err := cache.FetchCert(CertRequest{
					Host: h, IssuerID: id, Purpose: CertPurposeServerTLS,
					Generate: func() (*tls.Certificate, error) {
						n := attempts.Add(1)
						if failMode.Load() {
							return nil, boom
						}
						_ = n
						return signHostShim(ca, stripPort(h))
					},
				})
				if err != nil {
					return nil, err
				}
				// Reuse the normal config builder once the cache accepted.
				return TLSConfigFromCA(&ca)(h, c)
			},
		}, host
	})
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)

	const n = 8
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := mitmLeafViaTunnel(t, server, "failing.integration.example")
			if err == nil {
				t.Error("expected handshake failure while signer is down")
			}
		}()
	}
	wg.Wait()
	if got := attempts.Load(); got != 1 {
		t.Fatalf("signer failure amplified: %d attempts", got)
	}

	// Recover: once the negative entry expires, a handshake succeeds.
	failMode.Store(false)
	time.Sleep(80 * time.Millisecond)
	if _, err := mitmLeafViaTunnel(t, server, "failing.integration.example"); err != nil {
		t.Fatalf("retry after recovery failed: %v", err)
	}
}

// TestIntegrationNoCacheSignsEveryTime is acceptance case 9: with no cache,
// each handshake independently signs (the pre-existing behavior).
func TestIntegrationNoCacheSignsEveryTime(t *testing.T) {
	ca := GoproxyCa
	var signs atomic.Int32
	proxy := NewProxyHttpServer()
	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *ProxyCtx) (*ConnectAction, string) {
		return &ConnectAction{
			Action: ConnectMitm,
			TLSConfig: func(h string, c *ProxyCtx) (*tls.Config, error) {
				signs.Add(1)
				return TLSConfigFromCA(&ca)(h, c)
			},
		}, host
	})
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)

	mustLeaf(t, server, "nocache.integration.example")
	mustLeaf(t, server, "nocache.integration.example")
	if got := signs.Load(); got != 2 {
		t.Fatalf("without a cache each handshake must sign; got %d signings", got)
	}
}

// TestIntegrationLegacyStoreUnaffected ensures a pre-existing CertStorage
// implementation keeps working through the legacy Fetch path.
func TestIntegrationLegacyStoreUnaffected(t *testing.T) {
	legacy := &legacyMapStore{m: map[string]*tls.Certificate{}}
	proxy := NewProxyHttpServer()
	proxy.CertStore = legacy
	proxy.OnRequest().HandleConnect(AlwaysMitm)
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)

	fp1 := mustLeaf(t, server, "legacy.integration.example")
	fp2 := mustLeaf(t, server, "legacy.integration.example")
	if fp1 != fp2 {
		t.Fatal("legacy store did not reuse its cached certificate")
	}
	if legacy.genCalls.Load() != 1 {
		t.Fatalf("legacy store generator called %d times", legacy.genCalls.Load())
	}
}

// TestNoCacheCertificateShapeUnchanged pins the pre-existing signing shape
// when no cache is configured: DNS name/CN from the stripped host, ServerAuth
// EKU and the -30d/+365d validity window are all preserved.
func TestNoCacheCertificateShapeUnchanged(t *testing.T) {
	ca := GoproxyCa
	cfg, err := TLSConfigFromCA(&ca)("WWW.Example.org:8443", &ProxyCtx{Proxy: NewProxyHttpServer()})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 1 || cfg.Certificates[0].Leaf == nil {
		t.Fatal("expected exactly one leaf certificate")
	}
	leaf := cfg.Certificates[0].Leaf

	// The signer receives the stripped host (port removed) but otherwise
	// unchanged; it must appear verbatim in the SAN/CN.
	found := false
	for _, dns := range leaf.DNSNames {
		if dns == "WWW.Example.org" {
			found = true
		}
	}
	if !found || leaf.Subject.CommonName != "WWW.Example.org" {
		t.Fatalf("host writing rule changed: DNSNames=%v CN=%q", leaf.DNSNames, leaf.Subject.CommonName)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("EKU changed: %v", leaf.ExtKeyUsage)
	}
	now := time.Now()
	if leaf.NotBefore.After(now.Add(-29*24*time.Hour)) || leaf.NotBefore.Before(now.Add(-31*24*time.Hour)) {
		t.Fatalf("NotBefore window changed: %v", leaf.NotBefore)
	}
	if leaf.NotAfter.Before(now.Add(364*24*time.Hour)) || leaf.NotAfter.After(now.Add(366*24*time.Hour)) {
		t.Fatalf("NotAfter window changed: %v", leaf.NotAfter)
	}
	if err := leaf.CheckSignatureFrom(ca.Leaf); err != nil {
		t.Fatalf("leaf not signed by CA: %v", err)
	}
}

// ---- test doubles ----

type countingCache struct {
	inner *CertCache
	onGen func()
}

func (c *countingCache) Fetch(host string, gen func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	return c.inner.Fetch(host, func() (*tls.Certificate, error) {
		c.onGen()
		return gen()
	})
}

func (c *countingCache) FetchCert(req CertRequest) (*tls.Certificate, error) {
	wrapped := req
	wrapped.Generate = func() (*tls.Certificate, error) {
		c.onGen()
		return req.Generate()
	}
	return c.inner.FetchCert(wrapped)
}

type legacyMapStore struct {
	mu       sync.Mutex
	m        map[string]*tls.Certificate
	genCalls atomic.Int32
}

func (s *legacyMapStore) Fetch(hostname string, gen func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	s.mu.Lock()
	if c, ok := s.m[hostname]; ok {
		s.mu.Unlock()
		return c, nil
	}
	s.mu.Unlock()
	s.genCalls.Add(1)
	c, err := gen()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.m[hostname] = c
	s.mu.Unlock()
	return c, nil
}

func mustTestCA(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "integration-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
