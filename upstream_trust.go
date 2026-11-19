package goproxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/elazarl/goproxy/internal/upstreamtls"
)

// Re-exported policy types so callers can configure trust without importing
// the internal package.

// TLSFailureKind is the structured category of an upstream TLS failure.
type TLSFailureKind = upstreamtls.FailureKind

// Structured failure categories, stable for counting and aggregation.
const (
	TLSFailureNameMismatch    = upstreamtls.FailureNameMismatch
	TLSFailureUntrustedIssuer = upstreamtls.FailureUntrustedIssuer
	TLSFailureExpired         = upstreamtls.FailureExpired
	TLSFailureProtocolVersion = upstreamtls.FailureProtocolVersion
	TLSFailurePeerClosed      = upstreamtls.FailurePeerClosed
	TLSFailureConfig          = upstreamtls.FailureConfig
	TLSFailureHandshake       = upstreamtls.FailureHandshake
)

// TLSVerificationError is the structured error returned when an upstream
// TLS hop fails. Use errors.As to extract it and aggregate by Kind.
type TLSVerificationError = upstreamtls.VerificationError

// TrustGroupBuilder accumulates the issuer certificates trusted for a named
// target group.
type TrustGroupBuilder = upstreamtls.GroupBuilder

// NewTrustGroup starts an issuer group from a PEM-encoded CA certificate.
func NewTrustGroup(pem []byte) (*TrustGroupBuilder, error) {
	return upstreamtls.NewGroupBuilder(pem)
}

// NewTrustGroupFromCert starts an issuer group trusting a parsed CA
// certificate.
func NewTrustGroupFromCert(cert *x509.Certificate) *TrustGroupBuilder {
	return upstreamtls.NewGroupBuilderFromCert(cert)
}

// TrustTargetEntry is one target registration in a full policy replacement.
type TrustTargetEntry = upstreamtls.TargetEntry

// Verification modes for TrustTargetEntry.Mode.
const (
	TrustModeSystemTrust = upstreamtls.ModeSystemTrust
	TrustModePrivateCA   = upstreamtls.ModePrivateCA
	TrustModeSkipVerify  = upstreamtls.ModeSkipVerify
)

// UpstreamTLSReport is the observable, structured outcome of one upstream
// TLS hop. Adding it changes nothing about existing proxy behavior.
type UpstreamTLSReport struct {
	// Hop labels which independent handshake this reports: "target" for the
	// destination, "relay" for an encrypted upstream proxy.
	Hop string
	// Target is the normalized name this hop verified.
	Target string
	// PolicyVersion is the trust-configuration generation in force when the
	// connection was established. Established connections keep their
	// original version after a reload, which makes old-vs-new policy
	// behavior observable.
	PolicyVersion uint64
	// Mode is the verification mode that was applied.
	Mode int
	// Skipped is true only when this target had an explicit per-target
	// bypass registered. Every bypass is therefore attributable rather
	// than silent.
	Skipped bool
	// ServerName is the exact SNI value sent on this hop.
	ServerName string
	// TLSVersion is the negotiated protocol version.
	TLSVersion uint16
	// PeerFingerprint is the SHA-256 of the peer leaf certificate, allowing
	// certificate rotation between requests to be detected.
	PeerFingerprint [32]byte
}

func reportFromInternal(r *upstreamtls.Report) UpstreamTLSReport {
	return UpstreamTLSReport{
		Hop:             r.Hop,
		Target:          r.Target,
		PolicyVersion:   r.PolicyVersion,
		Mode:            int(r.Mode),
		Skipped:         r.Skipped,
		ServerName:      r.ServerName,
		TLSVersion:      r.TLSVersion,
		PeerFingerprint: r.PeerFingerprint,
	}
}

func fingerprintLeaf(cert *x509.Certificate) [32]byte {
	return sha256.Sum256(cert.Raw)
}

// trustRegistry returns the proxy's concurrency-safe trust registry,
// initializing it lazily to an empty registry (system trust for every
// target, identical to the default verification strength).
func (proxy *ProxyHttpServer) trustRegistry() *upstreamtls.Registry {
	proxy.trustOnce.Do(func() {
		if proxy.trustReg == nil {
			proxy.trustReg = upstreamtls.NewRegistry()
		}
	})
	return proxy.trustReg
}

// TrustRegistry returns the upstream trust registry. It is safe to call
// concurrently and to reconfigure while requests are in flight.
func (proxy *ProxyHttpServer) TrustRegistry() *upstreamtls.Registry {
	return proxy.trustRegistry()
}

// ReplaceTrustPolicy atomically installs a new upstream trust configuration.
// Groups map group names to issuer pools; entries register individual
// targets against those groups or as explicit, annotated bypasses.
//
// The whole replacement is validated before it becomes effective: malformed
// trust material or unknown group references fail the call and leave the
// previous configuration in place. A failed policy load therefore never
// degrades into trusting everything.
func (proxy *ProxyHttpServer) ReplaceTrustPolicy(
	groups map[string]*TrustGroupBuilder,
	entries []TrustTargetEntry,
) (version uint64, err error) {
	snap, err := proxy.trustRegistry().Replace(groups, entries)
	if err != nil {
		return 0, err
	}
	return snap.Version, nil
}

// reportKey is the context key under which per-request TLS reports travel.
type reportKey struct{}

type reportBox struct {
	mu      sync.Mutex
	reports []UpstreamTLSReport
}

func withReportBox(ctx context.Context) context.Context {
	if _, ok := ctx.Value(reportKey{}).(*reportBox); ok {
		return ctx
	}
	return context.WithValue(ctx, reportKey{}, &reportBox{})
}

// WithUpstreamReportContext returns a context that collects structured
// upstream TLS verification reports, retrievable with UpstreamTLSReports.
// Requests handled by the proxy already carry such a context; callers
// driving DefaultRoundTrip or RoundTripWithPolicyVersion directly use this
// to obtain the same observability.
func WithUpstreamReportContext(ctx context.Context) context.Context {
	return withReportBox(ctx)
}

func reportBoxFromCtx(ctx context.Context) *reportBox {
	box, _ := ctx.Value(reportKey{}).(*reportBox)
	return box
}

func (b *reportBox) add(r UpstreamTLSReport) {
	b.mu.Lock()
	b.reports = append(b.reports, r)
	b.mu.Unlock()
}

func (b *reportBox) snapshot() []UpstreamTLSReport {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]UpstreamTLSReport, len(b.reports))
	copy(out, b.reports)
	return out
}

// UpstreamTLSReports returns the structured TLS verification reports
// collected for a request (target hop, and relay hop when an encrypted
// upstream proxy is in use). It is the only addition to the request's
// observable surface; existing handlers and logs are untouched.
func UpstreamTLSReports(ctx context.Context) []UpstreamTLSReport {
	if box := reportBoxFromCtx(ctx); box != nil {
		return box.snapshot()
	}
	return nil
}

// NormalizeHostName canonicalizes a host exactly as the proxy does before
// policy lookup and certificate comparison: ports are removed, trailing dots
// are trimmed, letters are lowercased, internationalized names are converted
// to punycode, and IP literals are canonicalized. An unparseable
// internationalized name returns a TLSFailureConfig error.
func NormalizeHostName(host string) (string, error) {
	name, err := upstreamtls.NormalizeName(host)
	if err != nil {
		return "", err
	}
	return name.String(), nil
}

// RoundTripWithPolicyVersion forces a request onto the connection pool of a
// specific trust-configuration generation. It exists so callers (and tests)
// can observe that connections established under an older snapshot keep
// using that snapshot's policy after a reload. Requests normally route
// through the current snapshot via ProxyCtx.RoundTrip.
func (proxy *ProxyHttpServer) RoundTripWithPolicyVersion(req *http.Request, version uint64) (*http.Response, error) {
	name, err := upstreamtls.NormalizeName(req.URL.Host)
	if err != nil {
		return nil, err
	}
	snap := proxy.trustRegistry().SnapshotAt(version)
	policy := proxy.effectiveMode(snap, name)
	fp := fingerprintOf(snap, policy)
	return proxy.policyTransports().transportFor(fp).RoundTrip(req)
}

// policyFingerprint identifies an effective per-target policy inside one
// snapshot. Transports are keyed by this fingerprint so that two requests to
// the same host under different trust configurations can never reuse each
// other's pooled connections, while identical policies still reuse.
type policyFingerprint struct {
	version        uint64
	mode           int
	minVer, maxVer uint16
	// rootsID distinguishes distinct registered root pools via the
	// snapshot's stable pool IDs.
	rootsID uint64
	skip    bool
}

func fingerprintOf(snap *upstreamtls.Snapshot, p *upstreamtls.TargetPolicy) policyFingerprint {
	return policyFingerprint{
		version: snap.Version,
		mode:    int(p.Mode),
		minVer:  p.MinTLSVersion,
		maxVer:  p.MaxTLSVersion,
		rootsID: snap.PoolID(p.Roots),
		skip:    p.Mode == upstreamtls.ModeSkipVerify,
	}
}

// policyTransportPool maintains one http.Transport per distinct effective
// policy. Each member transport is derived from the proxy's configured
// transport, so proxy routing, dialers, timeouts and compression semantics
// are preserved; only connection-cache keying and TLS construction are
// specialized per policy.
type policyTransportPool struct {
	proxy *ProxyHttpServer

	mu         sync.Mutex
	transports map[policyFingerprint]*http.Transport
}

func newPolicyTransportPool(proxy *ProxyHttpServer) *policyTransportPool {
	return &policyTransportPool{proxy: proxy, transports: map[policyFingerprint]*http.Transport{}}
}

func (pool *policyTransportPool) transportFor(fp policyFingerprint) *http.Transport {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if tr, ok := pool.transports[fp]; ok {
		return tr
	}
	tr := pool.buildTransport(fp)
	pool.transports[fp] = tr
	return tr
}

func (pool *policyTransportPool) buildTransport(fp policyFingerprint) *http.Transport {
	base := pool.proxy.Tr
	tr := base.Clone()

	// The shared transport's TLS config must not be used as-is: it carries
	// no per-target ServerName and historically InsecureSkipVerify. Each
	// dial builds a fresh, hop-specific config instead.
	tr.TLSClientConfig = &tls.Config{}

	// Clone copies DialContext/DialTLSContext from the base transport. Our
	// TLS dialer below must own the TLS edge, but the raw dialer (custom
	// dialers, SOCKS, test host mapping) must be preserved exactly.
	tr.DialContext = base.DialContext
	tr.DialTLSContext = nil
	tr.DialTLS = nil
	// TLSNextProto (e.g. HTTP/2 upgrade) is intentionally inherited from
	// the base transport via Clone. The custom dialer returns a fully
	// handshaken *tls.Conn, so the transport's follow-up HandshakeContext is
	// a no-op and ALPN-based upgrades keep working. Encrypted-relay
	// nesting is handled separately by relayRoundTripper, not here.

	// Capture the snapshot generation this pool belongs to. Even if the
	// registry later reloads, connections established here keep using the
	// policy captured in fp; the new generation gets a new fingerprint and
	// therefore a new pool.
	snap := pool.proxy.trustRegistry().Current()
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return pool.proxy.dialPolicyTLS(ctx, network, addr, snap, fp, "target")
	}
	return tr
}

// legacySkipVerify reports whether the proxy's pre-existing global switch is
// set. Its semantics are narrowed: it now only applies to targets listed in
// legacySkipTargets, and every application of it is recorded on the report.
func (proxy *ProxyHttpServer) legacySkipVerify() bool {
	return proxy.Tr != nil && proxy.Tr.TLSClientConfig != nil && proxy.Tr.TLSClientConfig.InsecureSkipVerify
}

// SetLegacySkipVerifyTargets narrows the pre-existing
// Tr.TLSClientConfig.InsecureSkipVerify switch to the listed targets. Host
// spellings are normalized exactly like request targets (ports, trailing
// dots, case, IDN), so equivalent names always match.
//
// With an empty target list (the default) the legacy switch keeps its
// original blanket scope for backward compatibility, but every bypass now
// appears in the request's UpstreamTLSReport instead of happening silently.
// Passing targets makes the switch apply to those targets only; all other
// targets fall back to system trust.
func (proxy *ProxyHttpServer) SetLegacySkipVerifyTargets(hosts []string) error {
	normalized := make(map[upstreamtls.NormalizedName]struct{}, len(hosts))
	for _, h := range hosts {
		name, err := upstreamtls.NormalizeName(h)
		if err != nil {
			return err
		}
		normalized[name] = struct{}{}
	}
	proxy.legacySkipMu.Lock()
	proxy.legacySkipTargets = normalized
	proxy.legacySkipMu.Unlock()
	return nil
}

// legacySkipAllows reports whether the narrowed legacy switch applies to
// name. An empty allow-list means "all" for backward compatibility.
func (proxy *ProxyHttpServer) legacySkipAllows(name upstreamtls.NormalizedName) bool {
	proxy.legacySkipMu.RLock()
	defer proxy.legacySkipMu.RUnlock()
	if len(proxy.legacySkipTargets) == 0 {
		return true
	}
	_, ok := proxy.legacySkipTargets[name]
	return ok
}

// effectiveMode resolves the mode actually applied to a target: an explicit
// registry policy always wins; otherwise the legacy global switch applies
// only to targets explicitly listed for it, and everything else stays on
// system trust.
func (proxy *ProxyHttpServer) effectiveMode(snap *upstreamtls.Snapshot, name upstreamtls.NormalizedName) *upstreamtls.TargetPolicy {
	policy := snap.Lookup(name)
	if _, registered := snap.LookupEntry(name); registered {
		return policy
	}
	if proxy.legacySkipVerify() && proxy.legacySkipAllows(name) {
		clone := *policy
		clone.Mode = upstreamtls.ModeSkipVerify
		return &clone
	}
	return policy
}

// dialPolicyTLS establishes one TLS hop with a freshly built config. The
// same function backs target hops and encrypted-relay hops; only the hop
// label, snapshot and policy resolution differ, so the two handshakes of a
// tunneled connection stay fully independent.
//
// When the transport is configured with an HTTP(S) forward proxy, the
// CONNECT tunnel to that proxy is established first, exactly as the standard
// transport would do, and only then is the target TLS handshake run over the
// tunnel with the target's own name and trust policy.
func (proxy *ProxyHttpServer) dialPolicyTLS(
	ctx context.Context,
	network, addr string,
	snap *upstreamtls.Snapshot,
	fp policyFingerprint,
	label string,
) (net.Conn, error) {
	// With a custom TLS dialer the standard library passes the proxy
	// address as addr; the true target is carried in the request context.
	targetAddr := addr
	if dt, ok := ctx.Value(dialTargetKey{}).(dialTarget); ok && dt.targetAddr != "" {
		targetAddr = dt.targetAddr
	}

	rawName, err := upstreamtls.NormalizeName(targetAddr)
	if err != nil {
		return nil, err
	}

	policy := proxy.effectiveMode(snap, rawName)
	if got := fingerprintOf(snap, policy); got != fp {
		// The pool was built under an older snapshot or the legacy switch
		// narrows the mode: route through the pool matching the effective
		// policy instead of handshaking with the wrong trust set.
		tr := proxy.policyTransports().transportFor(got)
		return tr.DialTLSContext(ctx, network, addr)
	}

	// The pool key already encodes the effective mode; ConfigForHop must
	// see that same mode. Re-resolve through the registry view by building
	// the hop from the effective policy's mode directly.
	baseCfg := proxy.Tr.TLSClientConfig
	if baseCfg == nil {
		baseCfg = &tls.Config{}
	}
	hop := upstreamtls.Hop{
		Name:       rawName,
		Snapshot:   snap,
		Label:      label,
		BaseConfig: baseCfg,
	}
	cfg, report, err := upstreamtls.ConfigForPolicy(hop, policy)
	if err != nil {
		return nil, err
	}

	// Establish the underlying stream. When a forward proxy is configured
	// this is a CONNECT tunnel (itself over TLS for an https proxy), and
	// the TLS handshake below is the independent inner target hop.
	rawConn, err := proxy.dialUnderlying(ctx, network, targetAddr)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, upstreamtls.HandshakeError(label, rawName, err)
	}

	if report.Skipped {
		state := tlsConn.ConnectionState()
		report.TLSVersion = state.Version
		if len(state.PeerCertificates) > 0 {
			report.PeerFingerprint = fingerprintLeaf(state.PeerCertificates[0])
		}
	}
	if box := reportBoxFromCtx(ctx); box != nil {
		box.add(reportFromInternal(report))
	}
	return tlsConn, nil
}

// dialUnderlying returns a raw stream to targetAddr, transparently
// establishing a CONNECT tunnel when the configured transport routes
// through an HTTP(S) forward proxy. It mirrors the standard http.Transport
// behavior: a proxy request carries Proxy-Authorization from the proxy URL,
// and a successful tunnel leaves the connection ready for the target's TLS
// ClientHello.
func (proxy *ProxyHttpServer) dialUnderlying(ctx context.Context, network, targetAddr string) (net.Conn, error) {
	var proxyURL *url.URL
	if dt, ok := ctx.Value(dialTargetKey{}).(dialTarget); ok {
		proxyURL = dt.proxyURL
	}
	if proxyURL == nil && proxy.Tr != nil && proxy.Tr.Proxy != nil {
		req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+targetAddr, nil)
		if err != nil {
			return nil, err
		}
		proxyURL, err = proxy.Tr.Proxy(req)
		if err != nil {
			return nil, err
		}
	}
	if proxyURL == nil {
		return proxy.dialRaw(ctx, network, targetAddr)
	}

	// SOCKS proxies are handled entirely by the configured dialer: by the
	// time DialTLSContext runs, the socks connection already reaches the
	// target.
	if proxyURL.Scheme == "socks5" || proxyURL.Scheme == "socks5h" {
		return proxy.dialRaw(ctx, network, targetAddr)
	}

	proxyAddr := proxyURL.Host
	if proxyURL.Scheme == "https" || proxyURL.Scheme == "wss" {
		// An encrypted forward proxy is itself an independent TLS hop:
		// verify it with its own name and policy before tunneling the
		// target through it.
		relayName, err := upstreamtls.NormalizeName(proxyAddr)
		if err != nil {
			return nil, err
		}
		relaySnap := proxy.trustRegistry().Current()
		relayPolicy := proxy.effectiveMode(relaySnap, relayName)
		rawToRelay, err := proxy.dialRaw(ctx, network, withDefaultPort(proxyAddr, "443"))
		if err != nil {
			return nil, err
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+proxyAddr, nil)
		relayConn, err := proxy.initializeRelayTLS(&ProxyCtx{Req: req}, rawToRelay, proxyAddr, relayName, relaySnap, relayPolicy)
		if err != nil {
			return nil, err
		}
		return proxy.connectThrough(ctx, relayConn, targetAddr, proxyURL)
	}

	rawToProxy, err := proxy.dialRaw(ctx, network, withDefaultPort(proxyAddr, "80"))
	if err != nil {
		return nil, err
	}
	return proxy.connectThrough(ctx, rawToProxy, targetAddr, proxyURL)
}

// dialRaw opens a TCP connection using the transport's configured dialer
// when present, so custom dialing (mocks, timeouts, socks) is preserved.
func (proxy *ProxyHttpServer) dialRaw(ctx context.Context, network, addr string) (net.Conn, error) {
	if proxy.Tr != nil && proxy.Tr.DialContext != nil {
		return proxy.Tr.DialContext(ctx, network, addr)
	}
	d := &net.Dialer{}
	return d.DialContext(ctx, network, addr)
}

// connectThrough sends an HTTP CONNECT over an established connection to the
// forward proxy and waits for the 200 response, returning the tunneled
// connection. It is intentionally small and standard: proxy authentication
// comes from the proxy URL, as in net/http.
func (proxy *ProxyHttpServer) connectThrough(ctx context.Context, conn net.Conn, target string, proxyURL *url.URL) (net.Conn, error) {
	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if user := proxyURL.User; user != nil {
		connectReq.Header.Set("Proxy-Authorization", "Basic "+basicAuth(user))
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := connectReq.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	// Read the CONNECT response through a size-limited reader, exactly as
	// net/http does. The inner TLS handshake has not sent a ClientHello at
	// this point, so a well-behaved relay returns no tunnel bytes ahead of
	// the response; the limited reader therefore cannot strand them.
	br := bufio.NewReader(&io.LimitedReader{R: conn, N: 1 << 20})
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, &upstreamtls.VerificationError{
			Kind:   upstreamtls.FailureHandshake,
			Target: target,
			Hop:    "relay",
			Reason: "forward proxy refused CONNECT: " + resp.Status,
		}
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func withDefaultPort(host, port string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, port)
}

func base64StdEncode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func basicAuth(user *url.Userinfo) string {
	pass, _ := user.Password()
	return base64StdEncode(user.Username() + ":" + pass)
}

func (proxy *ProxyHttpServer) policyTransports() *policyTransportPool {
	proxy.transportOnce.Do(func() {
		proxy.policyPool = newPolicyTransportPool(proxy)
	})
	return proxy.policyPool
}

// dialTargetKey carries the request's connect-method information into the
// DialTLSContext closure. The standard transport, when a custom TLS dialer
// is set, calls it with the proxy address; the actual target address and
// the forward-proxy URL travel through the request context instead.
type dialTargetKey struct{}

type dialTarget struct {
	targetAddr string
	proxyURL   *url.URL
}

// policyRoundTripper routes each request to a connection pool keyed by the
// effective trust policy for its target, then delegates the actual HTTP
// transaction to the standard library transport. Request cancellation,
// timeouts and keep-alive semantics are therefore exactly those of
// http.Transport; only pool selection and TLS config construction change.
type policyRoundTripper struct {
	proxy *ProxyHttpServer
}

func (rt *policyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" {
		// Plain HTTP has no TLS hop: preserve the pre-existing path exactly.
		return rt.proxy.Tr.RoundTrip(req)
	}

	// Encrypted forward proxies require two independent TLS hops, which the
	// standard transport cannot model through DialTLSContext. Route those
	// through the dedicated relay round tripper.
	if rt.proxy.Tr != nil && rt.proxy.Tr.Proxy != nil {
		if proxyURL, err := rt.proxy.Tr.Proxy(req); err == nil && proxyURL != nil &&
			(proxyURL.Scheme == "https" || proxyURL.Scheme == "wss") {
			return rt.proxy.relayRoundTripper().RoundTrip(req)
		}
	}

	name, err := upstreamtls.NormalizeName(req.URL.Host)
	if err != nil {
		return nil, err
	}
	snap := rt.proxy.trustRegistry().Current()
	policy := rt.proxy.effectiveMode(snap, name)
	fp := fingerprintOf(snap, policy)
	tr := rt.proxy.policyTransports().transportFor(fp)

	// Ensure the DialTLSContext callback has somewhere to record this hop's
	// structured report, and knows the real target plus any forward proxy:
	// with a custom TLS dialer the standard library only passes the proxy
	// address as addr.
	var proxyURL *url.URL
	if tr.Proxy != nil {
		proxyURL, err = tr.Proxy(req)
		if err != nil {
			return nil, err
		}
	}
	ctx := withReportBox(req.Context())
	ctx = context.WithValue(ctx, dialTargetKey{}, dialTarget{
		targetAddr: canonicalTargetAddr(req.URL),
		proxyURL:   proxyURL,
	})
	return tr.RoundTrip(req.WithContext(ctx))
}

// canonicalTargetAddr returns host:port for the target URL, filling the
// default HTTPS port when none is given.
func canonicalTargetAddr(u *url.URL) string {
	if _, _, err := net.SplitHostPort(u.Host); err == nil {
		return u.Host
	}
	return net.JoinHostPort(u.Host, "443")
}
