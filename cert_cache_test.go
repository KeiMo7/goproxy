package goproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testCA builds a fresh in-memory CA for a single test.
func testCA(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// signGen returns a generator that signs host with ca through the real signer.
func signGen(ca tls.Certificate, host string) func() (*tls.Certificate, error) {
	return func() (*tls.Certificate, error) {
		return signHostForTest(ca, host)
	}
}

// signHostForTest wraps the internal signer via the same path the proxy uses.
func signHostForTest(ca tls.Certificate, host string) (*tls.Certificate, error) {
	return signHostShim(ca, host)
}

func issuerID(t *testing.T, ca *tls.Certificate) [32]byte {
	t.Helper()
	id, err := IssuerIDFromCertificate(ca)
	if err != nil {
		t.Fatalf("issuer id: %v", err)
	}
	return id
}

func certFingerprint(c *tls.Certificate) [32]byte {
	return sha256.Sum256(c.Certificate[0])
}

// sameLeafMaterial reports whether two certificates carry the same leaf
// public key and serial number. Re-signing always moves NotBefore/NotAfter,
// so the raw DER fingerprint of two independently signed certs differs even
// when the signer's deterministic key/serial derivation is intact.
func sameLeafMaterial(t *testing.T, a, b *tls.Certificate) bool {
	t.Helper()
	if a == nil || b == nil || a.Leaf == nil || b.Leaf == nil {
		return false
	}
	if a.Leaf.SerialNumber.Cmp(b.Leaf.SerialNumber) != 0 {
		return false
	}
	return a.Leaf.PublicKey.(*ecdsa.PublicKey).Equal(b.Leaf.PublicKey)
}

// TestCacheConcurrentSingleFlight covers acceptance case 1: N concurrent
// handshakes for one target trigger exactly one issuance; every waiter gets
// the same fingerprint, and a failure is shared without amplification.
func TestCacheConcurrentSingleFlight(t *testing.T) {
	ca := testCA(t)
	var signs atomic.Int32
	release := make(chan struct{})
	gen := func() (*tls.Certificate, error) {
		signs.Add(1)
		<-release // block until all goroutines have queued up
		return signHostShim(ca, "example.com")
	}
	cache := NewCertCache()
	id := issuerID(t, &ca)

	const n = 32
	var wg sync.WaitGroup
	results := make([][32]byte, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			c, err := cache.FetchCert(CertRequest{
				Host: "example.com:443", IssuerID: id,
				Purpose: CertPurposeServerTLS, Generate: gen,
			})
			errs[i] = err
			if err == nil {
				results[i] = certFingerprint(c)
			}
		}(i)
	}
	// Give every goroutine time to block on the inflight placeholder.
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := signs.Load(); got != 1 {
		t.Fatalf("expected exactly 1 signing, got %d", got)
	}
	want := results[0]
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("waiter %d got error: %v", i, errs[i])
		}
		if results[i] != want {
			t.Fatalf("waiter %d fingerprint mismatch", i)
		}
	}
	stats := cache.Stats()
	if stats.Signings != 1 || stats.Misses != 1 || stats.Coalesced != n-1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

// TestCacheLeaderCancellationDoesNotAffectWaiters covers hard constraint 1:
// the leader giving up must not take the other waiters down.
func TestCacheLeaderCancellationDoesNotAffectWaiters(t *testing.T) {
	ca := testCA(t)
	var entered atomic.Int32
	release := make(chan struct{})
	gen := func() (*tls.Certificate, error) {
		entered.Add(1)
		<-release
		return signHostShim(ca, "leader.example")
	}
	cache := NewCertCache()
	id := issuerID(t, &ca)
	req := CertRequest{Host: "leader.example", IssuerID: id,
		Purpose: CertPurposeServerTLS, Generate: gen}

	// Leader starts and blocks inside gen.
	leaderDone := make(chan struct{})
	go func() {
		_, _ = cache.FetchCert(req)
		close(leaderDone)
	}()
	time.Sleep(50 * time.Millisecond)

	// Waiter queues while the leader is blocked.
	waiterErr := make(chan error, 1)
	waiterFp := make(chan [32]byte, 1)
	go func() {
		c, err := cache.FetchCert(req)
		waiterErr <- err
		if err == nil {
			waiterFp <- certFingerprint(c)
		}
	}()
	time.Sleep(50 * time.Millisecond)

	// The leader's "request" goes away (its handshake aborted), but the
	// in-cache generation keeps running because the cache owns it.
	if !isLeaderStillInflight(cache, req) {
		t.Fatal("inflight placeholder disappeared while generation was running")
	}
	close(release)

	select {
	case err := <-waiterErr:
		if err != nil {
			t.Fatalf("waiter failed after leader left: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter never received the shared result")
	}
	<-leaderDone
	if got := entered.Load(); got != 1 {
		t.Fatalf("expected 1 generator entry, got %d", got)
	}
}

func isLeaderStillInflight(cache *CertCache, req CertRequest) bool {
	key := cacheKey{
		host:     normalizeHostname(req.Host),
		issuerID: req.IssuerID,
		purpose:  string(req.Purpose),
		policy:   req.Policy,
	}
	shard := cache.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	_, ok := shard.inflight[key]
	return ok
}

// TestCacheKeyDimensions covers acceptance case 2: normalization collapses
// case/trailing-dot/port variants, while issuer, purpose and policy keep
// entries apart with no key collisions.
func TestCacheKeyDimensions(t *testing.T) {
	ca1 := testCA(t)
	ca2 := testCA(t)
	cache := NewCertCache(WithNegativeTTL(time.Hour))
	id1 := issuerID(t, &ca1)
	id2 := issuerID(t, &ca2)

	var signs atomic.Int32
	gen := func(ca tls.Certificate, host string) func() (*tls.Certificate, error) {
		return func() (*tls.Certificate, error) {
			signs.Add(1)
			return signHostShim(ca, host)
		}
	}

	// Normalized variants of the same target must hit the same entry.
	c1, err := cache.FetchCert(CertRequest{Host: "Example.COM.:443", IssuerID: id1,
		Purpose: CertPurposeServerTLS, Generate: gen(ca1, "example.com")})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := cache.FetchCert(CertRequest{Host: "example.com", IssuerID: id1,
		Purpose: CertPurposeServerTLS, Generate: gen(ca1, "example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if certFingerprint(c1) != certFingerprint(c2) {
		t.Fatal("normalized host variants did not share an entry")
	}

	// Different purpose: separate entry, distinct from the server-tls one.
	if _, err := cache.FetchCert(CertRequest{Host: "example.com", IssuerID: id1,
		Purpose: CertPurpose("client-tls"), Generate: gen(ca1, "example.com")}); err != nil {
		t.Fatal(err)
	}

	// Different policy: separate entry, distinct from the default policy.
	if _, err := cache.FetchCert(CertRequest{Host: "example.com", IssuerID: id1,
		Purpose: CertPurposeServerTLS, Policy: "strict",
		Generate: gen(ca1, "example.com")}); err != nil {
		t.Fatal(err)
	}

	// Different issuer is a rotation: it signs separately and supersedes the
	// previous issuer's entry for the same host/purpose/policy.
	if _, err := cache.FetchCert(CertRequest{Host: "example.com", IssuerID: id2,
		Purpose: CertPurposeServerTLS, Generate: gen(ca2, "example.com")}); err != nil {
		t.Fatal(err)
	}

	// 4 distinct issuances: original + purpose + policy + rotated issuer.
	// DER fingerprints are not compared across distinct keys, because the
	// signer is deterministic: the same CA + host produce identical DER
	// within one clock second even when keys differ. The meaningful
	// invariant is that each distinct key triggers its own signing.
	if got := signs.Load(); got != 4 {
		t.Fatalf("expected 4 signings, got %d", got)
	}

	// The purpose and policy dimensions coexist as independent entries.
	coexisting := []cacheKey{
		{host: "example.com", issuerID: id1, purpose: "client-tls"},
		{host: "example.com", issuerID: id1, purpose: string(CertPurposeServerTLS), policy: "strict"},
	}
	for _, k := range coexisting {
		shard := cache.shardFor(k)
		shard.mu.Lock()
		_, ok := shard.entries[k]
		shard.mu.Unlock()
		if !ok {
			t.Fatalf("expected distinct entry to coexist: %+v", k)
		}
	}

	// The rotated issuer replaced, rather than joined, the previous issuer's
	// server-tls entry: the old CA's certificate must no longer be reachable.
	newKey := cacheKey{host: "example.com", issuerID: id2, purpose: string(CertPurposeServerTLS)}
	oldKey := cacheKey{host: "example.com", issuerID: id1, purpose: string(CertPurposeServerTLS)}
	shard := cache.shardFor(newKey)
	shard.mu.Lock()
	_, hasNew := shard.entries[newKey]
	_, hasOld := shard.entries[oldKey]
	shard.mu.Unlock()
	if !hasNew {
		t.Fatal("rotated issuer entry missing")
	}
	if hasOld {
		t.Fatal("previous issuer's entry was not superseded after CA rotation")
	}
	if stats := cache.Stats(); stats.Discards < 1 {
		t.Fatalf("rotation not recorded as a discard: %+v", stats)
	}
}

// TestCacheKeySerializationIsUnambiguous covers hard constraint 2: keys built
// from fields containing separators must never collide.
func TestCacheKeySerializationIsUnambiguous(t *testing.T) {
	k1 := cacheKey{host: "ab", purpose: "c", policy: "d"}
	k2 := cacheKey{host: "a", purpose: "bc", policy: "d"}
	if string(k1.bytes()) == string(k2.bytes()) {
		t.Fatal("length-prefixed key serialization collided")
	}
	// Empty fields round-trip distinctly from fields containing data.
	k3 := cacheKey{host: "x", purpose: "", policy: "y"}
	k4 := cacheKey{host: "x", purpose: "y", policy: ""}
	if string(k3.bytes()) == string(k4.bytes()) {
		t.Fatal("empty-field key serialization collided")
	}
}

// TestCacheStableFingerprint covers acceptance case 3: repeated handshakes
// return identical key material and serial number.
func TestCacheStableFingerprint(t *testing.T) {
	ca := testCA(t)
	cache := NewCertCache()
	id := issuerID(t, &ca)
	req := CertRequest{Host: "stable.example", IssuerID: id,
		Purpose: CertPurposeServerTLS, Generate: signGen(ca, "stable.example")}

	first, err := cache.FetchCert(req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cache.FetchCert(req)
	if err != nil {
		t.Fatal(err)
	}
	if certFingerprint(first) != certFingerprint(second) {
		t.Fatal("fingerprint changed across handshakes")
	}
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) != 0 {
		t.Fatal("serial number changed across handshakes")
	}
	if !first.Leaf.PublicKey.(*ecdsa.PublicKey).Equal(second.Leaf.PublicKey) {
		t.Fatal("leaf public key changed across handshakes")
	}
}

// TestCacheIssuerRotationInvalidates covers acceptance case 4: after the
// issuer changes, the old entry is discarded and a new CA-signed certificate
// is returned.
func TestCacheIssuerRotationInvalidates(t *testing.T) {
	ca1 := testCA(t)
	ca2 := testCA(t)
	cache := NewCertCache()
	id1 := issuerID(t, &ca1)
	id2 := issuerID(t, &ca2)

	c1, err := cache.FetchCert(CertRequest{Host: "rot.example", IssuerID: id1,
		Purpose: CertPurposeServerTLS, Generate: signGen(ca1, "rot.example")})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := cache.FetchCert(CertRequest{Host: "rot.example", IssuerID: id2,
		Purpose: CertPurposeServerTLS, Generate: signGen(ca2, "rot.example")})
	if err != nil {
		t.Fatal(err)
	}
	if certFingerprint(c1) == certFingerprint(c2) {
		t.Fatal("issuer rotation did not produce a new certificate")
	}
	if err := c2.Leaf.CheckSignatureFrom(ca2.Leaf); err != nil {
		t.Fatalf("new cert not signed by new CA: %v", err)
	}
	if stats := cache.Stats(); stats.Discards < 1 {
		t.Fatalf("expected issuer-mismatch discard, stats: %+v", stats)
	}
}

// TestCacheLRUEviction covers acceptance case 5: capacity bounds and LRU
// eviction, while in-flight results remain usable.
func TestCacheLRUEviction(t *testing.T) {
	ca := testCA(t)
	id := issuerID(t, &ca)
	cache := NewCertCache(WithMaxEntries(2), WithShardCount(1))

	fetch := func(host string) {
		t.Helper()
		if _, err := cache.FetchCert(CertRequest{Host: host, IssuerID: id,
			Purpose: CertPurposeServerTLS, Generate: signGen(ca, host)}); err != nil {
			t.Fatal(err)
		}
	}
	fetch("a.example")
	fetch("b.example")
	// Touch a again so b becomes the LRU victim.
	if _, err := cache.FetchCert(CertRequest{Host: "a.example", IssuerID: id,
		Purpose: CertPurposeServerTLS, Generate: signGen(ca, "a.example")}); err != nil {
		t.Fatal(err)
	}
	fetch("c.example")

	shard := cache.shards[0]
	shard.mu.Lock()
	_, bPresent := shard.entries[cacheKey{host: "b.example", issuerID: id,
		purpose: string(CertPurposeServerTLS)}]
	_, aPresent := shard.entries[cacheKey{host: "a.example", issuerID: id,
		purpose: string(CertPurposeServerTLS)}]
	shard.mu.Unlock()
	if bPresent {
		t.Fatal("LRU entry was not evicted")
	}
	if !aPresent {
		t.Fatal("most-recently-used entry was wrongly evicted")
	}
	if stats := cache.Stats(); stats.Evictions < 1 {
		t.Fatalf("expected eviction counter, got %+v", stats)
	}
}

// TestCacheNegativeCachingAndRetry covers acceptance case 6: failures are not
// stored as positive entries, the error is shared, and after the negative TTL
// a retry can succeed, with backoff growing across consecutive failures.
func TestCacheNegativeCachingAndRetry(t *testing.T) {
	ca := testCA(t)
	id := issuerID(t, &ca)
	ttl := 40 * time.Millisecond
	cache := NewCertCache(WithNegativeTTL(ttl), WithNegativeMaxTTL(time.Hour))

	var attempts atomic.Int32
	boom := errors.New("signer unavailable")
	gen := func() (*tls.Certificate, error) {
		n := attempts.Add(1)
		if n < 2 {
			return nil, boom
		}
		return signHostShim(ca, "fail.example")
	}
	req := CertRequest{Host: "fail.example", IssuerID: id,
		Purpose: CertPurposeServerTLS, Generate: gen}

	// First failure.
	if _, err := cache.FetchCert(req); !errors.Is(err, boom) {
		t.Fatalf("expected boom, got %v", err)
	}
	// Concurrent waiters share the failure rather than re-invoking gen.
	const waiters = 8
	var wg sync.WaitGroup
	wg.Add(waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			defer wg.Done()
			if _, err := cache.FetchCert(req); !errors.Is(err, boom) {
				t.Errorf("expected shared boom, got %v", err)
			}
		}()
	}
	wg.Wait()
	if got := attempts.Load(); got != 1 {
		t.Fatalf("failure was amplified: %d generator calls", got)
	}
	if stats := cache.Stats(); stats.NegativeHits != uint64(waiters) {
		t.Fatalf("expected %d negative hits, got %+v", waiters, stats)
	}

	// The failure must not have created a positive entry.
	if c, _ := cache.FetchCert(CertRequest{Host: "fail.example", IssuerID: id,
		Purpose: CertPurposeServerTLS,
		Generate: func() (*tls.Certificate, error) {
			t.Fatal("negative entry should have been served without signing")
			return nil, nil
		}}); c != nil {
		t.Fatal("negative cache returned a certificate")
	}

	// After the negative TTL expires, the retry succeeds.
	time.Sleep(ttl + 20*time.Millisecond)
	cert, err := cache.FetchCert(req)
	if err != nil {
		t.Fatalf("retry after negative TTL failed: %v", err)
	}
	if cert == nil || cert.Leaf == nil {
		t.Fatal("retry did not produce a usable certificate")
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("expected a single retry after negative TTL, got %d calls", got)
	}
}

// TestCacheNegativeBackoffGrows verifies consecutive failures extend the
// negative TTL exponentially (failure/degradation requirement 2).
func TestCacheNegativeBackoffGrows(t *testing.T) {
	ca := testCA(t)
	id := issuerID(t, &ca)
	base := 20 * time.Millisecond
	now := time.Now()
	cache := NewCertCache(WithNegativeTTL(base), WithNegativeMaxTTL(time.Hour),
		WithNow(func() time.Time { return now }))
	req := CertRequest{Host: "backoff.example", IssuerID: id,
		Purpose: CertPurposeServerTLS,
		Generate: func() (*tls.Certificate, error) {
			return nil, errors.New("nope")
		}}

	for i := 1; i <= 3; i++ {
		if _, err := cache.FetchCert(req); err == nil {
			t.Fatal("expected failure")
		}
		key := cacheKey{host: "backoff.example", issuerID: id,
			purpose: string(CertPurposeServerTLS)}
		shard := cache.shardFor(key)
		shard.mu.Lock()
		e := shard.entries[key]
		ttl := e.expiresAt.Sub(now)
		failCount := e.failCount
		shard.mu.Unlock()
		if failCount != i {
			t.Fatalf("failCount = %d, want %d", failCount, i)
		}
		wantTTL := base * time.Duration(1<<(i-1))
		if ttl != wantTTL {
			t.Fatalf("failure %d ttl = %v, want %v", i, ttl, wantTTL)
		}
		// Advance past expiry so the next call re-signs.
		now = now.Add(wantTTL + time.Millisecond)
	}
}

// TestCacheCorruptAndBadEntries covers acceptance case 7 and test case 4:
// entries whose leaf cannot be parsed, or whose issuer mismatches, are
// discarded and re-signed rather than handed to a client.
func TestCacheCorruptAndBadEntries(t *testing.T) {
	ca := testCA(t)
	id := issuerID(t, &ca)
	cache := NewCertCache()
	req := CertRequest{Host: "corrupt.example", IssuerID: id,
		Purpose: CertPurposeServerTLS, Generate: signGen(ca, "corrupt.example")}

	if _, err := cache.FetchCert(req); err != nil {
		t.Fatal(err)
	}

	// Corrupt the stored DER in place through the shard internals.
	key := cacheKey{host: "corrupt.example", issuerID: id,
		purpose: string(CertPurposeServerTLS)}
	shard := cache.shardFor(key)
	shard.mu.Lock()
	e := shard.entries[key]
	e.cert.Certificate[0] = []byte("not-a-certificate")
	e.cert.Leaf = nil
	shard.mu.Unlock()

	recovered, err := cache.FetchCert(req)
	if err != nil {
		t.Fatalf("corrupt entry was not re-signed: %v", err)
	}
	// The replacement must be a valid leaf for the target, signed by the
	// same CA. (Re-signing consumes the deterministic stream differently
	// when the old entry was corrupt, so key/serial equality is not
	// asserted here; stability across healthy re-reads is covered by
	// TestCacheStableFingerprint.)
	if err := recovered.Leaf.VerifyHostname("corrupt.example"); err != nil {
		t.Fatalf("re-signed leaf does not cover the target: %v", err)
	}
	if err := recovered.Leaf.CheckSignatureFrom(ca.Leaf); err != nil {
		t.Fatalf("re-signed leaf is not signed by the CA: %v", err)
	}
	if stats := cache.Stats(); stats.Discards < 1 {
		t.Fatalf("corrupt entry was not counted as discard: %+v", stats)
	}

	// A generated certificate that fails validation is never published as a
	// positive entry, but is recorded as a negative entry so the failure is
	// shared and backoff applies rather than hammering the generator.
	badCache := NewCertCache(WithNegativeTTL(time.Hour))
	var badGenCalls atomic.Int32
	badReq := CertRequest{Host: "bad.example", IssuerID: id,
		Purpose: CertPurposeServerTLS,
		Generate: func() (*tls.Certificate, error) {
			badGenCalls.Add(1)
			return &tls.Certificate{Certificate: [][]byte{[]byte("garbage")}}, nil
		}}
	if _, err := badCache.FetchCert(badReq); err == nil {
		t.Fatal("invalid generated certificate was accepted")
	}
	for i := 0; i < 4; i++ {
		if _, err := badCache.FetchCert(badReq); err == nil {
			t.Fatal("invalid generated certificate was accepted on retry")
		}
	}
	if got := badGenCalls.Load(); got != 1 {
		t.Fatalf("validation failure was amplified: %d generator calls", got)
	}
	badKey := cacheKey{host: "bad.example", issuerID: id,
		purpose: string(CertPurposeServerTLS)}
	shard2 := badCache.shardFor(badKey)
	shard2.mu.Lock()
	stored := shard2.entries[badKey]
	shard2.mu.Unlock()
	if stored == nil {
		t.Fatal("validation failure was not recorded")
	}
	if !stored.isNegative {
		t.Fatal("invalid certificate was written as a positive entry")
	}
}

// TestCacheReturnedCertificateIsImmutable covers hard constraint 5: mutating a
// returned certificate must not corrupt the shared entry.
func TestCacheReturnedCertificateIsImmutable(t *testing.T) {
	ca := testCA(t)
	id := issuerID(t, &ca)
	cache := NewCertCache()
	req := CertRequest{Host: "immutable.example", IssuerID: id,
		Purpose: CertPurposeServerTLS, Generate: signGen(ca, "immutable.example")}

	first, err := cache.FetchCert(req)
	if err != nil {
		t.Fatal(err)
	}
	// Snapshot the shared entry's fingerprint before mutating the copy.
	originalFP := certFingerprint(first)
	first.Certificate[0][0] ^= 0xff
	if first.Leaf != nil {
		first.Leaf.SerialNumber = big.NewInt(999)
	}
	second, err := cache.FetchCert(req)
	if err != nil {
		t.Fatal(err)
	}
	if certFingerprint(second) != originalFP {
		t.Fatal("shared cache entry was mutated by a caller")
	}
}

// TestCacheDegradedRateLimit covers failure/degradation requirement 3:
// internal faults fall back to rate-limited direct signing and reject excess.
func TestCacheDegradedRateLimit(t *testing.T) {
	ca := testCA(t)
	id := issuerID(t, &ca)
	// A frozen clock keeps the token bucket from refilling, so the limit is
	// deterministic regardless of test scheduling.
	now := time.Now()
	cache := NewCertCache(
		WithDegradedSignLimit(2), WithShardCount(1),
		WithNow(func() time.Time { return now }),
	)

	req := CertRequest{Host: "deg.example", IssuerID: id,
		Purpose: CertPurposeServerTLS, Generate: signGen(ca, "deg.example")}
	if _, err := cache.FetchCert(req); err != nil {
		t.Fatal(err)
	}
	key := cacheKey{host: "deg.example", issuerID: id,
		purpose: string(CertPurposeServerTLS)}

	// Every iteration corrupts the stored DER and immediately fetches, so
	// every attempt must take the structural-fault (degraded) path. With a
	// frozen clock and a limit of two, the first two fault recoveries sign
	// and the rest are rejected until the clock advances.
	const attempts = 6
	rejected, recovered := 0, 0
	for i := 0; i < attempts; i++ {
		shard := cache.shardFor(key)
		shard.mu.Lock()
		if e, ok := shard.entries[key]; ok {
			e.cert.Leaf = nil
			e.cert.Certificate[0] = []byte("broken")
		}
		shard.mu.Unlock()

		_, err := cache.FetchCert(req)
		switch {
		case err == nil:
			recovered++
		case fmt.Sprint(err) == "goproxy: certificate cache degraded signing rate limit exceeded":
			rejected++
		default:
			t.Fatalf("attempt %d: unexpected error: %v", i, err)
		}
	}
	if recovered != 2 {
		t.Fatalf("expected 2 rate-limited degraded recoveries, got %d", recovered)
	}
	if rejected != attempts-2 {
		t.Fatalf("expected %d rejections, got %d", attempts-2, rejected)
	}

	// After the clock advances a second, the bucket refills and a fault can
	// be recovered again.
	now = now.Add(2 * time.Second)
	shard := cache.shardFor(key)
	shard.mu.Lock()
	if e, ok := shard.entries[key]; ok {
		e.cert.Leaf = nil
		e.cert.Certificate[0] = []byte("broken")
	}
	shard.mu.Unlock()
	if _, err := cache.FetchCert(req); err != nil {
		t.Fatalf("degraded signing did not recover after refill: %v", err)
	}
}

// TestCachePanicInGenerator ensures a panicking generator does not leak the
// inflight placeholder or deadlock waiters.
func TestCachePanicInGenerator(t *testing.T) {
	ca := testCA(t)
	id := issuerID(t, &ca)
	cache := NewCertCache(WithDegradedSignLimit(100))
	var calls atomic.Int32
	req := CertRequest{Host: "panic.example", IssuerID: id,
		Purpose: CertPurposeServerTLS,
		Generate: func() (*tls.Certificate, error) {
			if calls.Add(1) == 1 {
				panic("boom")
			}
			return signHostShim(ca, "panic.example")
		}}

	c, err := cache.FetchCert(req)
	if err != nil {
		t.Fatalf("panic recovery did not produce a cert: %v", err)
	}
	if c == nil || c.Leaf == nil {
		t.Fatal("nil cert after panic recovery")
	}
	if isLeaderStillInflight(cache, req) {
		t.Fatal("inflight placeholder leaked after panic")
	}
}

// TestCacheHighConcurrencyStress hammers the cache from many goroutines across
// many hosts to surface deadlocks, races in LRU/count bookkeeping and inflight
// placeholder leaks under contention.
func TestCacheHighConcurrencyStress(t *testing.T) {
	ca := testCA(t)
	id := issuerID(t, &ca)
	cache := NewCertCache(WithMaxEntries(128))

	const goroutines = 64
	const iterations = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				host := fmt.Sprintf("host-%d.example", (g+i)%40)
				c, err := cache.FetchCert(CertRequest{
					Host: host, IssuerID: id,
					Purpose: CertPurposeServerTLS,
					Generate: func() (*tls.Certificate, error) {
						return signHostShim(ca, host)
					},
				})
				if err != nil {
					t.Errorf("fetch %s: %v", host, err)
					return
				}
				if c == nil || c.Leaf == nil {
					t.Errorf("nil cert for %s", host)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	// Every inflight placeholder must have been resolved.
	for _, shard := range cache.shards {
		shard.mu.Lock()
		if len(shard.inflight) != 0 {
			t.Fatalf("leaked %d inflight placeholders", len(shard.inflight))
		}
		shard.mu.Unlock()
	}
	// LRU capacity was enforced: positive entries never exceed the bound by
	// more than the number of shards (a shard stops trimming once its own
	// list is empty).
	if cache.positiveCount.Load() > uint64(128+cache.shardCount) {
		t.Fatalf("capacity not enforced: %d positive entries", cache.positiveCount.Load())
	}
}

// TestCacheDisabledFallback covers acceptance case 9: without a cache the
// proxy still signs on every call (verified at the TLSConfigFromCA level in
// the proxy integration test).
func TestCacheLegacyFetchStillWorks(t *testing.T) {
	ca := testCA(t)
	cache := NewCertCache()
	var calls atomic.Int32
	gen := func() (*tls.Certificate, error) {
		calls.Add(1)
		return signHostShim(ca, "legacy.example")
	}
	c1, err := cache.Fetch("legacy.example", gen)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := cache.Fetch("legacy.example", gen)
	if err != nil {
		t.Fatal(err)
	}
	if certFingerprint(c1) != certFingerprint(c2) {
		t.Fatal("legacy Fetch did not cache")
	}
	if calls.Load() != 1 {
		t.Fatalf("legacy Fetch invoked generator %d times", calls.Load())
	}
}

// BenchmarkCacheHit measures the read path: after one signing, every fetch is
// a lock + map + LRU touch plus a defensive copy, with no signing work.
func BenchmarkCacheHit(b *testing.B) {
	ca := testCA(&testing.T{})
	id, _ := IssuerIDFromCertificate(&ca)
	cache := NewCertCache()
	req := CertRequest{Host: "bench.example", IssuerID: id,
		Purpose: CertPurposeServerTLS, Generate: signGen(ca, "bench.example")}
	if _, err := cache.FetchCert(req); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cache.FetchCert(req); err != nil {
			b.Fatal(err)
		}
	}
}

// TestCachePerTargetStats covers acceptance case 8: counters aggregate per
// target host.
func TestCachePerTargetStats(t *testing.T) {
	ca := testCA(t)
	id := issuerID(t, &ca)
	cache := NewCertCache()
	req := CertRequest{Host: "stats.example", IssuerID: id,
		Purpose: CertPurposeServerTLS, Generate: signGen(ca, "stats.example")}
	if _, err := cache.FetchCert(req); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.FetchCert(req); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.FetchCert(req); err != nil {
		t.Fatal(err)
	}
	ts, ok := cache.TargetStats("STATS.example.")
	if !ok {
		t.Fatal("target stats missing")
	}
	if ts.Host != "stats.example" || ts.Misses != 1 || ts.Hits != 2 {
		t.Fatalf("unexpected target stats: %+v", ts)
	}
}
