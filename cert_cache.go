package goproxy

import (
	"container/list"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CertPurpose labels what a cached leaf certificate is used for. It is part of
// the cache key, so certificates issued for different uses never get mixed up.
type CertPurpose string

const (
	// CertPurposeServerTLS is the purpose of leaf certificates presented by
	// the proxy to intercepted clients during MITM handshakes.
	CertPurposeServerTLS CertPurpose = "server-tls"
)

// CertRequest identifies one certificate issuance request.
//
// The cache key is built from four independent dimensions:
//   - the normalized target hostname (case-folded, trailing dot removed,
//     port stripped);
//   - the issuer identity (a hash of the CA certificate);
//   - the purpose of the certificate;
//   - the upstream policy tag, an opaque caller-provided string that
//     distinguishes certificates produced under different signing policies.
//
// Generate performs the actual signing and is invoked at most once for any
// group of concurrent identical requests.
type CertRequest struct {
	// Host is the target host, optionally including a port (the port is
	// stripped before keying).
	Host string
	// IssuerID identifies the signing CA. Use IssuerIDFromCertificate to
	// derive it. Requests carrying different issuer identities never share
	// an entry, so rotating the CA automatically invalidates old entries.
	IssuerID [32]byte
	// Purpose distinguishes different certificate uses.
	Purpose CertPurpose
	// Policy is an opaque tag distinguishing different upstream signing
	// policies. Empty string is the default policy.
	Policy string
	// Generate signs the leaf certificate. It must not be nil on a cache
	// miss; the cache never invokes it when a usable entry already exists.
	Generate func() (*tls.Certificate, error)
}

// CertStorageV2 is the optional, concurrency-aware extension of CertStorage.
// Caches implementing it deduplicate concurrent issuances, validate entries
// against the current issuer and expose counters. The legacy CertStorage
// interface keeps working unchanged for custom implementations.
type CertStorageV2 interface {
	CertStorage
	// FetchCert returns a cached certificate for req or issues one through
	// req.Generate. Concurrent identical requests are coalesced: only the
	// first one signs, the rest wait and receive the same certificate or
	// the same error. A request whose caller gave up still runs to
	// completion inside the cache, so waiters are never taken down with
	// the leader.
	FetchCert(req CertRequest) (*tls.Certificate, error)
}

// CacheStats reports aggregate cache counters since construction.
type CacheStats struct {
	// Hits is the number of requests served from a valid positive entry.
	Hits uint64
	// Misses is the number of requests that triggered a fresh issuance.
	Misses uint64
	// Coalesced is the number of requests that waited on another request's
	// in-flight issuance and reused its result (success or failure).
	Coalesced uint64
	// NegativeHits is the number of requests answered from a negative
	// (failure) entry without invoking the signer.
	NegativeHits uint64
	// Resigns is the number of entries replaced because they were expired,
	// near-expiry, issued by another CA or otherwise invalid.
	Resigns uint64
	// Discards is the number of unusable entries dropped (issuer mismatch,
	// unparsable leaf, clock jumps, corrupt data).
	Discards uint64
	// Evictions is the number of LRU evictions caused by capacity limits.
	Evictions uint64
	// Failures is the number of issuance attempts that returned an error.
	Failures uint64
	// NegativeRetries is the number of issuances retried after a negative
	// entry expired.
	NegativeRetries uint64
	// Degraded is the number of times the cache bypassed itself and signed
	// on demand because of an internal fault (panic, clock jump, corrupt
	// entry). Degraded signing is rate-limited.
	Degraded uint64
	// DegradedRejected is the number of requests refused while degraded
	// signing was over its rate limit.
	DegradedRejected uint64
	// Signings is the number of invocations of the caller's Generate.
	Signings uint64
}

// TargetStats reports per-host counters. Host names are shown normalized.
type TargetStats struct {
	Host            string
	Hits            uint64
	Misses          uint64
	Coalesced       uint64
	NegativeHits    uint64
	Resigns         uint64
	Discards        uint64
	Failures        uint64
	NegativeRetries uint64
}

// CertCacheOption customizes a CertCache at construction.
type CertCacheOption func(*CertCache)

// WithMaxEntries bounds the number of positive entries kept in cache. When
// the limit is exceeded, the least-recently-used entry is evicted. A zero or
// negative value means unbounded. Default: 1024.
func WithMaxEntries(n int) CertCacheOption {
	return func(c *CertCache) { c.maxEntries = n }
}

// WithCertRenewMargin sets how long before NotAfter a cached certificate is
// considered due for renewal. Default: 7 days.
func WithCertRenewMargin(d time.Duration) CertCacheOption {
	return func(c *CertCache) { c.renewMargin = d }
}

// WithNegativeTTL sets the base lifetime of a negative (failure) entry.
// Consecutive failures of the same target back off exponentially up to
// WithNegativeMaxTTL. Default: 2 seconds.
func WithNegativeTTL(d time.Duration) CertCacheOption {
	return func(c *CertCache) { c.negativeTTL = d }
}

// WithNegativeMaxTTL caps the exponential backoff for a failing target.
// Default: 5 minutes.
func WithNegativeMaxTTL(d time.Duration) CertCacheOption {
	return func(c *CertCache) { c.negativeMaxTTL = d }
}

// WithDegradedSignLimit bounds how many on-demand ("degraded") signings the
// cache will perform per second when its internal state is faulty. Additional
// requests fail fast instead of melting the CPU. Default: 16 per second.
func WithDegradedSignLimit(perSecond int) CertCacheOption {
	return func(c *CertCache) {
		if perSecond > 0 {
			c.degradedLimit = perSecond
		}
	}
}

// WithWarningHook installs a callback invoked on internal faults that force
// degraded mode. The hook must be cheap and must not block. Private key
// material is never passed to it.
func WithWarningHook(f func(event string, err error)) CertCacheOption {
	return func(c *CertCache) { c.warn = f }
}

// WithShardCount overrides the number of lock shards. The value is rounded up
// to a power of two and clamped to [1, 4096]. Most callers should leave it
// untouched.
func WithShardCount(n int) CertCacheOption {
	return func(c *CertCache) {
		if n < 1 {
			n = 1
		}
		if n > 4096 {
			n = 4096
		}
		shards := 1
		for shards < n {
			shards <<= 1
		}
		c.shardCount = shards
	}
}

// WithNow overrides the clock, mainly for tests.
func WithNow(now func() time.Time) CertCacheOption {
	return func(c *CertCache) {
		if now != nil {
			c.now = now
		}
	}
}

const (
	defaultMaxEntries     = 1024
	defaultRenewMargin    = 7 * 24 * time.Hour
	defaultNegativeTTL    = 2 * time.Second
	defaultNegativeMaxTTL = 5 * time.Minute
	defaultDegradedLimit  = 16
	defaultShardCount     = 64
)

// CertCache is a concurrency-safe cache of MITM leaf certificates.
//
// It provides:
//   - single-flight issuance: concurrent handshakes for the same target share
//     one signing operation and one result, including errors;
//   - structured, collision-free keys distinguishing host, issuer, purpose
//     and policy;
//   - issuer-aware expiry: rotating the signing CA invalidates old entries;
//   - bounded LRU eviction that never disturbs in-flight handshakes;
//   - short negative caching with exponential backoff for failing targets;
//   - corruption detection: entries whose leaf cannot be parsed or whose
//     issuer does not match are discarded and re-signed;
//   - per-target and aggregate counters;
//   - rate-limited degraded signing on internal faults.
type CertCache struct {
	maxEntries     int
	renewMargin    time.Duration
	negativeTTL    time.Duration
	negativeMaxTTL time.Duration
	degradedLimit  int
	shardCount     int
	now            func() time.Time
	warn           func(event string, err error)

	shards []*cacheShard

	// rate limiter for degraded (fallback) signing after internal faults
	degradedBucketMu sync.Mutex
	degradedBucket   degradedBucket

	// positiveCount tracks the number of positive (certificate) entries
	// across all shards, so LRU capacity is enforced globally without a
	// global lock. Negative entries are not counted.
	positiveCount atomic.Uint64

	// aggregate counters, accessed atomically
	stats cacheStats
}

type degradedBucket struct {
	tokens   int
	lastFill time.Time
}

// cacheStats holds the counters shared by CacheStats. It is a separate type so
// the fields can be embedded and accessed with sync/atomic.
type cacheStats struct {
	hits             atomic.Uint64
	misses           atomic.Uint64
	coalesced        atomic.Uint64
	negativeHits     atomic.Uint64
	resigns          atomic.Uint64
	discards         atomic.Uint64
	evictions        atomic.Uint64
	failures         atomic.Uint64
	negativeRetries  atomic.Uint64
	degraded         atomic.Uint64
	degradedRejected atomic.Uint64
	signings         atomic.Uint64
}

type cacheEntry struct {
	key      cacheKey
	cert     *tls.Certificate
	notAfter time.Time

	// negative-entry state
	isNegative bool
	err        error
	failCount  int
	expiresAt  time.Time

	// per-target counters, heap-held so the entry itself never copies an
	// atomic value
	stats *targetCounters

	// LRU bookkeeping (nil while the entry is only an in-flight placeholder)
	elem *list.Element
}

type targetCounters struct {
	hits            atomic.Uint64
	misses          atomic.Uint64
	coalesced       atomic.Uint64
	negativeHits    atomic.Uint64
	resigns         atomic.Uint64
	discards        atomic.Uint64
	failures        atomic.Uint64
	negativeRetries atomic.Uint64
}

// inflight is the placeholder for a signing in progress. Waiters block on
// done, which is closed exactly once when the leader finishes.
type inflight struct {
	done chan struct{}
	// result is populated before done is closed.
	cert *tls.Certificate
	err  error
}

type cacheShard struct {
	mu       sync.Mutex
	entries  map[cacheKey]*cacheEntry
	lru      *list.List // front = most recently used
	inflight map[cacheKey]*inflight
}

// cacheKey is the structured identity of a cache entry. String fields are
// length-prefixed when serialized, so no concatenation can make two distinct
// requests collide.
type cacheKey struct {
	host     string
	issuerID [32]byte
	purpose  string
	policy   string
}

// bytes serializes the key unambiguously. Every variable-length field is
// written with its length, and the fixed-size issuer hash keeps its own slot.
func (k cacheKey) bytes() []byte {
	var b strings.Builder
	writeField := func(s string) {
		var lenBuf [8]byte
		n := uint64(len(s))
		for i := 7; i >= 0; i-- {
			lenBuf[i] = byte(n)
			n >>= 8
		}
		b.Write(lenBuf[:])
		b.WriteString(s)
	}
	writeField(k.host)
	b.Write(k.issuerID[:])
	writeField(k.purpose)
	writeField(k.policy)
	return []byte(b.String())
}

// NewCertCache creates a ready-to-use certificate cache.
func NewCertCache(opts ...CertCacheOption) *CertCache {
	c := &CertCache{
		maxEntries:     defaultMaxEntries,
		renewMargin:    defaultRenewMargin,
		negativeTTL:    defaultNegativeTTL,
		negativeMaxTTL: defaultNegativeMaxTTL,
		degradedLimit:  defaultDegradedLimit,
		shardCount:     defaultShardCount,
		now:            time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	c.shards = make([]*cacheShard, c.shardCount)
	for i := range c.shards {
		c.shards[i] = &cacheShard{
			entries:  make(map[cacheKey]*cacheEntry),
			lru:      list.New(),
			inflight: make(map[cacheKey]*inflight),
		}
	}
	return c
}

// IssuerIDFromCertificate derives the issuer identity embedded in cache keys.
// It hashes the DER-encoded CA certificate; the private key is never read and
// never leaves the process.
func IssuerIDFromCertificate(ca *tls.Certificate) ([32]byte, error) {
	if ca == nil || len(ca.Certificate) == 0 || len(ca.Certificate[0]) == 0 {
		return [32]byte{}, errors.New("goproxy: cannot derive issuer id from empty CA certificate")
	}
	return sha256.Sum256(ca.Certificate[0]), nil
}

// normalizeHostname strips the port, lower-cases and removes a single
// trailing dot, so "Example.COM.:443" and "example.com" share an entry. The
// raw, unnormalized host is still what the signer receives; normalization
// only affects the cache index.
func normalizeHostname(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host
}

// shardFor selects a shard from the normalized hostname only. All entries for
// a given host — regardless of issuer, purpose or policy — therefore live in
// one shard, which keeps host-scoped operations (issuer rotation, per-target
// stats) cheap and bounded by the number of entries per host.
func (c *CertCache) shardFor(key cacheKey) *cacheShard {
	sum := sha256.Sum256([]byte(key.host))
	// use the first 8 bytes as an unbiased index
	idx := uint64(0)
	for _, b := range sum[:8] {
		idx = idx<<8 | uint64(b)
	}
	return c.shards[idx%uint64(c.shardCount)]
}

// FetchCert implements CertStorageV2.
func (c *CertCache) FetchCert(req CertRequest) (cert *tls.Certificate, err error) {
	if req.Generate == nil {
		return nil, errors.New("goproxy: CertRequest.Generate is nil")
	}
	key := cacheKey{
		host:     normalizeHostname(req.Host),
		issuerID: req.IssuerID,
		purpose:  string(req.Purpose),
		policy:   req.Policy,
	}
	shard := c.shardFor(key)
	now := c.now()
	var prevEntry *cacheEntry
	var droppedFaulty *cacheEntry // structural-fault entry removed this call
	degraded := false

	// Fast path and waiter registration both happen under the shard lock,
	// which is only ever held for map/list operations — never during signing.
	shard.mu.Lock()
	if call, waiting := shard.inflight[key]; waiting {
		shard.mu.Unlock()
		c.stats.coalesced.Add(1)
		// A previous entry (e.g. negative) may still hold the target's
		// counters; attribute the coalesce there when present.
		if e, ok := shard.entries[key]; ok && e.stats != nil {
			e.stats.coalesced.Add(1)
		}
		// Block without holding any lock. The leader ignores caller
		// cancellation: it always completes and closes this channel.
		<-call.done
		if call.err != nil {
			return nil, call.err
		}
		return cloneCert(call.cert), nil
	}

	if existing, ok := shard.entries[key]; ok {
		// Capture the previous entry before it is removed, so its failure
		// count and per-target history survive replacement.
		prevEntry = existing
		if usable, reason := c.entryUsable(existing, key, now); usable {
			if existing.isNegative {
				shard.mu.Unlock()
				c.stats.negativeHits.Add(1)
				existing.stats.negativeHits.Add(1)
				return nil, existing.err
			}
			// Positive hit: refresh LRU position under the lock.
			shard.lru.MoveToFront(existing.elem)
			shard.mu.Unlock()
			c.stats.hits.Add(1)
			existing.stats.hits.Add(1)
			return cloneCert(existing.cert), nil
		} else {
			// Entry expired, near expiry, corrupt or from another issuer.
			wasNegative := existing.isNegative
			c.dropEntry(shard, existing, reason)
			switch reason {
			case "expired", "near-expiry":
				c.stats.resigns.Add(1)
			case "neg-expired":
				if wasNegative {
					c.stats.negativeRetries.Add(1)
				}
			case "clock-jump", "corrupt", "issuer-mismatch":
				// Structural fault: re-sign in degraded mode with a bounded
				// rate so a wedged clock or poisoned store cannot trigger an
				// unbounded signing storm. Keep the dropped entry so it can
				// be restored if the rate limiter refuses this attempt.
				degraded = true
				droppedFaulty = existing
			}
		}
	}

	// Become the leader. The placeholder stays until signing completes even
	// if this goroutine's own handshake is aborted, so waiters always get a
	// definitive result.
	call := &inflight{done: make(chan struct{})}
	shard.inflight[key] = call
	shard.mu.Unlock()

	c.stats.misses.Add(1)
	if degraded {
		if !c.takeDegradedToken() {
			shard.mu.Lock()
			delete(shard.inflight, key)
			// Restore the faulty entry so the fault is preserved and retried
			// once the bucket refills, instead of silently turning into an
			// unbounded normal miss path.
			if droppedFaulty != nil {
				shard.entries[key] = droppedFaulty
				if droppedFaulty.elem != nil {
					shard.lru.PushFront(droppedFaulty.elem)
				}
				if !droppedFaulty.isNegative {
					c.positiveCount.Add(1)
				}
			}
			err := errors.New("goproxy: certificate cache degraded signing rate limit exceeded")
			c.stats.degradedRejected.Add(1)
			call.err = err
			close(call.done)
			shard.mu.Unlock()
			return nil, err
		}
		c.stats.degraded.Add(1)
	}

	// Sign outside every lock. Recover from panics so a faulty generator
	// cannot leave waiters hanging or the inflight map populated forever.
	cert, err = c.runGenerate(req.Generate)

	shard.mu.Lock()
	delete(shard.inflight, key)
	if err != nil {
		c.stats.failures.Add(1)
		c.storeNegativeLocked(shard, key, err, now, prevEntry)
		call.err = err
		close(call.done)
		shard.mu.Unlock()
		return nil, err
	}

	// Validate before publishing: a leaf that cannot be parsed, or a chain
	// not signed for this issuer slot, must never reach a client. Record it
	// as a negative entry so repeated requests for the same target back off
	// instead of re-running the faulty generator on every handshake.
	if verr := validateEntry(cert, key); verr != nil {
		c.stats.discards.Add(1)
		c.stats.failures.Add(1)
		c.warning("bad-generated-cert", verr)
		c.storeNegativeLocked(shard, key, verr, now, prevEntry)
		call.err = verr
		close(call.done)
		shard.mu.Unlock()
		return nil, verr
	}

	entry := &cacheEntry{
		key:      key,
		cert:     cert,
		notAfter: cert.Leaf.NotAfter,
	}
	if prevEntry != nil && prevEntry.stats != nil {
		// Reuse the same counter object so per-target history survives the
		// replacement of a negative or expired entry.
		entry.stats = prevEntry.stats
	} else {
		entry.stats = &targetCounters{}
	}
	entry.stats.misses.Add(1)
	_, hadSameKey := shard.entries[key]
	if old, ok := shard.entries[key]; ok {
		// Same-key replacement (renewed cert under the same issuer):
		// release the previous LRU node.
		if old.elem != nil {
			shard.lru.Remove(old.elem)
		}
	}
	shard.entries[key] = entry
	entry.elem = shard.lru.PushFront(entry)
	// Track positive-entry count: a replacement of an existing positive
	// entry does not grow the total; everything else does. Negative entries
	// are not counted.
	if !hadSameKey || prevEntry == nil || prevEntry.isNegative {
		c.positiveCount.Add(1)
	}
	// Rotating the CA supersedes the previous issuer's entry for this same
	// host/purpose/policy; drop it (and its count slot) so the old
	// certificate is never served.
	c.purgeStaleIssuerEntriesLocked(shard, key)
	c.evictIfNeededLocked(shard)
	call.cert = cert
	close(call.done)
	shard.mu.Unlock()

	return cloneCert(cert), nil
}

// runGenerate invokes the signer with panic recovery. A panicking generator
// is an internal fault: the attempt is counted as degraded and retried at
// most once, subject to the degraded-signing rate limit.
func (c *CertCache) runGenerate(gen func() (*tls.Certificate, error)) (cert *tls.Certificate, err error) {
	c.stats.signings.Add(1)
	defer func() {
		if r := recover(); r != nil {
			c.warning("generate-panic", errors.New(toString(r)))
			if !c.takeDegradedToken() {
				c.stats.degradedRejected.Add(1)
				cert = nil
				err = errors.New("goproxy: certificate cache degraded signing rate limit exceeded")
				return
			}
			c.stats.degraded.Add(1)
			cert, err = gen()
		}
	}()
	return gen()
}

// degradedTokens implements a simple token bucket refilled every second.
func (c *CertCache) takeDegradedToken() bool {
	c.degradedBucketMu.Lock()
	defer c.degradedBucketMu.Unlock()
	now := c.now()
	if c.degradedBucket.lastFill.IsZero() {
		c.degradedBucket.lastFill = now
		c.degradedBucket.tokens = c.degradedLimit
	}
	elapsed := now.Sub(c.degradedBucket.lastFill)
	if elapsed >= time.Second {
		refills := int(elapsed / time.Second)
		c.degradedBucket.tokens += refills * c.degradedLimit
		if c.degradedBucket.tokens > c.degradedLimit {
			c.degradedBucket.tokens = c.degradedLimit
		}
		c.degradedBucket.lastFill = now
	}
	if c.degradedBucket.tokens <= 0 {
		return false
	}
	c.degradedBucket.tokens--
	return true
}

func (c *CertCache) warning(event string, err error) {
	if c.warn != nil {
		c.warn(event, err)
	}
}

// entryUsable decides whether an existing entry may be served. It assumes the
// shard lock is held.
func (c *CertCache) entryUsable(e *cacheEntry, key cacheKey, now time.Time) (bool, string) {
	if e.isNegative {
		if now.Before(e.expiresAt) {
			return true, "negative"
		}
		return false, "neg-expired"
	}
	if e.cert == nil || len(e.cert.Certificate) == 0 {
		return false, "corrupt"
	}
	// Issuer rotation: the entry belongs to a different CA than the request.
	if e.key.issuerID != key.issuerID {
		return false, "issuer-mismatch"
	}
	leaf := e.cert.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(e.cert.Certificate[0])
		if err != nil {
			return false, "corrupt"
		}
		leaf = parsed
		e.cert.Leaf = parsed
	}
	// Clock-jump guard: NotBefore in the future means the clock moved.
	if now.Before(leaf.NotBefore) {
		return false, "clock-jump"
	}
	if !now.Before(leaf.NotAfter) {
		return false, "expired"
	}
	if now.Add(c.renewMargin).After(leaf.NotAfter) {
		return false, "near-expiry"
	}
	return true, "valid"
}

// validateEntry checks a freshly generated certificate before it is published.
func validateEntry(cert *tls.Certificate, key cacheKey) error {
	if cert == nil || len(cert.Certificate) == 0 {
		return errors.New("goproxy: generated certificate has no DER data")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return errors.New("goproxy: generated leaf certificate cannot be parsed")
	}
	if cert.Leaf == nil {
		cert.Leaf = leaf
	}
	// The leaf must carry the normalized SAN/CN for the requested target.
	if err := leaf.VerifyHostname(key.host); err != nil {
		// IP addresses and some edge cases (e.g. wildcardless CN) are still
		// legitimate for the proxy; only reject when there is no matching
		// DNS name or IP at all.
		if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
			return errors.New("goproxy: generated certificate has no host identifiers")
		}
	}
	return nil
}

// dropEntry removes an entry from map and LRU and accounts for the reason.
// Time-based replacements (expiry, near-expiry, negative TTL) are resigns,
// not discards; only structural faults count as discards.
// Caller holds the shard lock.
func (c *CertCache) dropEntry(shard *cacheShard, e *cacheEntry, reason string) {
	delete(shard.entries, e.key)
	if e.elem != nil {
		shard.lru.Remove(e.elem)
	}
	if !e.isNegative {
		c.positiveCount.Add(^uint64(0))
	}
	switch reason {
	case "issuer-mismatch", "corrupt", "clock-jump":
		c.stats.discards.Add(1)
		e.stats.discards.Add(1)
		c.warning("entry-"+reason, nil)
	}
}

// storeNegativeLocked records a failed issuance with exponential backoff.
// Caller holds the shard lock. The failing key has already been removed from
// the shard; prev (when non-nil) carries the previous entry's counters and
// failure count so per-target history and backoff are preserved.
func (c *CertCache) storeNegativeLocked(shard *cacheShard, key cacheKey, signErr error, now time.Time, prev *cacheEntry) {
	failCount := 1
	var stats *targetCounters
	if prev != nil {
		failCount = prev.failCount + 1
		stats = prev.stats
	}
	if stats == nil {
		stats = &targetCounters{}
	}
	ttl := c.negativeTTL
	for i := 1; i < failCount; i++ {
		ttl *= 2
		if ttl >= c.negativeMaxTTL {
			ttl = c.negativeMaxTTL
			break
		}
	}
	if ttl > c.negativeMaxTTL {
		ttl = c.negativeMaxTTL
	}
	ne := &cacheEntry{
		key:        key,
		isNegative: true,
		err:        signErr,
		failCount:  failCount,
		expiresAt:  now.Add(ttl),
		stats:      stats,
	}
	ne.stats.failures.Add(1)
	shard.entries[key] = ne
	// Negative entries do not occupy LRU capacity; they are time-bounded
	// instead.
}

// purgeStaleIssuerEntriesLocked drops cached positive entries for the same
// host, purpose and policy that were signed by a different issuer. When the
// signing CA is rotated, the new issuer's entry supersedes the old one so the
// previous CA's certificate can never be served again. Entries that differ in
// purpose or policy are distinct certificate classes and are kept.
// Caller holds the shard lock.
func (c *CertCache) purgeStaleIssuerEntriesLocked(shard *cacheShard, fresh cacheKey) {
	for k, e := range shard.entries {
		if k.host != fresh.host || k.issuerID == fresh.issuerID ||
			k.purpose != fresh.purpose || k.policy != fresh.policy || e.isNegative {
			continue
		}
		c.dropEntry(shard, e, "issuer-mismatch")
	}
}

// evictIfNeededLocked enforces the global cache capacity using LRU order.
// Capacity is counted across all shards via an atomic counter, while LRU
// ordering stays per shard, so eviction never takes a global lock. When the
// total is over capacity, this shard drops its own least-recently-used
// positive entries until back under the limit. In-flight handshakes are
// unaffected: they hold their own *tls.Certificate or wait on an inflight
// channel that eviction never touches. Caller holds the shard lock.
func (c *CertCache) evictIfNeededLocked(shard *cacheShard) {
	if c.maxEntries <= 0 {
		return
	}
	for c.positiveCount.Load() > uint64(c.maxEntries) {
		oldest := shard.lru.Back()
		if oldest == nil {
			// Nothing this shard can give up; other shards will trim
			// themselves on their own inserts.
			return
		}
		e := oldest.Value.(*cacheEntry)
		shard.lru.Remove(oldest)
		delete(shard.entries, e.key)
		c.positiveCount.Add(^uint64(0))
		c.stats.evictions.Add(1)
	}
}

// Fetch implements the legacy CertStorage interface. It keys on the raw
// hostname under the default purpose and a zero issuer, so existing custom
// stores and the TestProxyWithCertStorage test keep their exact semantics.
// New code should use FetchCert.
func (c *CertCache) Fetch(hostname string, gen func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	return c.FetchCert(CertRequest{
		Host:     hostname,
		Purpose:  CertPurposeServerTLS,
		Generate: gen,
	})
}

// Stats returns a snapshot of aggregate counters.
func (c *CertCache) Stats() CacheStats {
	return CacheStats{
		Hits:             c.stats.hits.Load(),
		Misses:           c.stats.misses.Load(),
		Coalesced:        c.stats.coalesced.Load(),
		NegativeHits:     c.stats.negativeHits.Load(),
		Resigns:          c.stats.resigns.Load(),
		Discards:         c.stats.discards.Load(),
		Evictions:        c.stats.evictions.Load(),
		Failures:         c.stats.failures.Load(),
		NegativeRetries:  c.stats.negativeRetries.Load(),
		Degraded:         c.stats.degraded.Load(),
		DegradedRejected: c.stats.degradedRejected.Load(),
		Signings:         c.stats.signings.Load(),
	}
}

// TargetStats returns per-host counters for the normalized host, summed over
// every issuer, purpose and policy that has an entry for it. The boolean is
// false when the host has no recorded activity.
func (c *CertCache) TargetStats(host string) (TargetStats, bool) {
	host = normalizeHostname(host)
	var out TargetStats
	found := false
	// The same host can land in different shards when its entries differ by
	// issuer, purpose or policy, so scan them all.
	for _, shard := range c.shards {
		shard.mu.Lock()
		for k, e := range shard.entries {
			if k.host != host {
				continue
			}
			found = true
			out.Host = host
			if e.stats == nil {
				continue
			}
			out.Hits += e.stats.hits.Load()
			out.Misses += e.stats.misses.Load()
			out.Coalesced += e.stats.coalesced.Load()
			out.NegativeHits += e.stats.negativeHits.Load()
			out.Resigns += e.stats.resigns.Load()
			out.Discards += e.stats.discards.Load()
			out.Failures += e.stats.failures.Load()
			out.NegativeRetries += e.stats.negativeRetries.Load()
		}
		shard.mu.Unlock()
	}
	return out, found
}

// cloneCert returns a shallow-independent copy of a cached certificate: the
// DER slices and the parsed Leaf are freshly allocated, so a caller cannot
// mutate shared entry state through the returned value. The private key is
// shared by design (copying it would defeat the cache) and must be treated as
// read-only; it is never logged or persisted.
func cloneCert(in *tls.Certificate) *tls.Certificate {
	if in == nil {
		return nil
	}
	out := &tls.Certificate{
		PrivateKey: in.PrivateKey,
		Leaf:       in.Leaf,
	}
	out.Certificate = make([][]byte, len(in.Certificate))
	for i, der := range in.Certificate {
		dup := make([]byte, len(der))
		copy(dup, der)
		out.Certificate[i] = dup
	}
	if in.Leaf != nil {
		// Re-parse from the copied DER so the returned Leaf is also
		// independent of the cached one.
		if leaf, err := x509.ParseCertificate(out.Certificate[0]); err == nil {
			out.Leaf = leaf
		}
	}
	return out
}

func toString(v any) string {
	switch t := v.(type) {
	case error:
		return t.Error()
	case string:
		return t
	default:
		return "goproxy: panic in certificate generator"
	}
}
