package goproxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Scenario 1: direct target, publicly-style issued certificate. The
// outbound handshake must carry the requested hostname and verify strictly.
// The CA is installed as a trusted root (equivalent to a publicly trusted
// issuer for this test); name checking stays strict and policy-driven.
func TestUpstreamScenario1_PublicStyleStrictName(t *testing.T) {
	ca := newTestCA(t, "public-style-ca")
	goodLeaf := ca.issue(t, leafSpec{dnsNames: []string{"good.example"}})
	badLeaf := ca.issue(t, leafSpec{dnsNames: []string{"other.example"}})

	goodSrv := newSNIServer(t, goodLeaf)
	badSrv := newSNIServer(t, badLeaf)

	proxy, proxyURL := startProxy(t)
	cap := newErrorCapture(proxy)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.certPEM)
	proxy.Tr.TLSClientConfig.RootCAs = pool

	client := proxyClient(t, proxyURL)
	hostMap := map[string]string{
		"good.example":  goodSrv.server.Listener.Addr().String(),
		"wrong.example": badSrv.server.Listener.Addr().String(),
	}
	installHostMapDialer(t, proxy, hostMap)

	kind := requestKind(t, client, "https://good.example/bobo", cap)
	require.Empty(t, kind, "correct name must verify")
	require.Contains(t, goodSrv.drainNames(), "good.example")

	kind = requestKind(t, client, "https://wrong.example/bobo", cap)
	require.Equal(t, goproxy.TLSFailureNameMismatch, kind)
}

// Scenario 2: private/self-signed CA. Only targets registered against the
// issuer are allowed; every other target still uses system trust and fails.
func TestUpstreamScenario2_PrivateCATargetScoped(t *testing.T) {
	privateCA := newTestCA(t, "private-ca")
	otherCA := newTestCA(t, "other-ca")
	leaf := privateCA.issue(t, leafSpec{dnsNames: []string{"svn.internal"}})
	otherLeaf := otherCA.issue(t, leafSpec{dnsNames: []string{"svn.internal"}})

	srv := newSNIServer(t, leaf)
	otherSrv := newSNIServer(t, otherLeaf)

	proxy, proxyURL := startProxy(t)
	cap := newErrorCapture(proxy)
	group, err := goproxy.NewTrustGroup(privateCA.certPEM)
	require.NoError(t, err)
	mustReplace(t, proxy,
		map[string]*goproxy.TrustGroupBuilder{"private": group},
		[]goproxy.TrustTargetEntry{{Host: "svn.internal", Mode: goproxy.TrustModePrivateCA, Group: "private"}})

	installHostMapDialer(t, proxy, map[string]string{
		"svn.internal":          srv.server.Listener.Addr().String(),
		"unregistered.internal": otherSrv.server.Listener.Addr().String(),
	})
	client := proxyClient(t, proxyURL)

	kind := requestKind(t, client, "https://svn.internal/", cap)
	require.Empty(t, kind, "registered private CA should verify")

	kind = requestKind(t, client, "https://unregistered.internal/", cap)
	require.Equal(t, goproxy.TLSFailureUntrustedIssuer, kind)
}

// Scenario 3: the same target appearing in conflicting entries resolves
// deterministically: keyed by normalized name, last explicit registration
// wins regardless of any map iteration order.
func TestUpstreamScenario3_ConflictingEntriesDeterministic(t *testing.T) {
	ca := newTestCA(t, "ca3")
	leaf := ca.issue(t, leafSpec{dnsNames: []string{"dup.example"}})
	srv := newSNIServer(t, leaf)
	proxy, proxyURL := startProxy(t)
	cap := newErrorCapture(proxy)
	installHostMapDialer(t, proxy, map[string]string{"dup.example": srv.server.Listener.Addr().String()})
	client := proxyClient(t, proxyURL)

	group, err := goproxy.NewTrustGroup(ca.certPEM)
	require.NoError(t, err)

	entries := []goproxy.TrustTargetEntry{
		{Host: "dup.example", Mode: goproxy.TrustModePrivateCA, Group: "g"},
		{Host: "DUP.Example.", Mode: goproxy.TrustModeSkipVerify},
	}
	version := mustReplace(t, proxy,
		map[string]*goproxy.TrustGroupBuilder{"g": group}, entries)
	require.Greater(t, version, uint64(0))

	kind := requestKind(t, client, "https://dup.example/", cap)
	require.Empty(t, kind)

	reports := reportsViaCapture(t, client, "https://dup.example/", cap)
	require.NotEmpty(t, reports)
	assert.True(t, reports[len(reports)-1].Skipped, "conflict must resolve to the explicit, annotated bypass")
	assert.Equal(t, "dup.example", reports[len(reports)-1].ServerName)
}

// Scenario 6: target addressed by IP with an IP-only certificate. Matching
// is by address; a certificate without an IP SAN fails name matching rather
// than falling back to no verification.
func TestUpstreamScenario6_IPLiteralAndIPSAN(t *testing.T) {
	ca := newTestCA(t, "ip-ca")
	// Two distinct loopback addresses so the targets differ by normalized
	// name (IP literal) and therefore never share a connection pool.
	ipGood := net.ParseIP("127.0.0.1")
	ipLeaf := ca.issue(t, leafSpec{ips: []net.IP{ipGood}})
	dnsOnlyLeaf := ca.issue(t, leafSpec{dnsNames: []string{"localhost"}})

	ipSrv := newSNIServerOnIP(t, ipLeaf, "127.0.0.1")
	dnsSrv := newSNIServerOnIP(t, dnsOnlyLeaf, "127.0.0.2")

	proxy, proxyURL := startProxy(t)
	cap := newErrorCapture(proxy)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.certPEM)
	proxy.Tr.TLSClientConfig.RootCAs = pool
	client := proxyClient(t, proxyURL)

	ipPort := ipSrv.server.Listener.Addr().(*net.TCPAddr).Port
	require.Empty(t, requestKind(t, client, fmt.Sprintf("https://127.0.0.1:%d/", ipPort), cap))

	dnsPort := dnsSrv.server.Listener.Addr().(*net.TCPAddr).Port
	require.Equal(t, goproxy.TLSFailureNameMismatch,
		requestKind(t, client, fmt.Sprintf("https://127.0.0.2:%d/", dnsPort), cap))
}

// Scenario 7: ports, trailing dots, mixed case and IDN-equivalent spellings
// are normalized before comparison and policy lookup.
func TestUpstreamScenario7_NameNormalization(t *testing.T) {
	ca := newTestCA(t, "norm-ca")
	leaf := ca.issue(t, leafSpec{dnsNames: []string{"xn--bcher-kva.example", "host.example"}})
	srv := newSNIServer(t, leaf)

	proxy, proxyURL := startProxy(t)
	cap := newErrorCapture(proxy)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.certPEM)
	proxy.Tr.TLSClientConfig.RootCAs = pool
	installHostMapDialer(t, proxy, map[string]string{
		"host.example":          srv.server.Listener.Addr().String(),
		"xn--bcher-kva.example": srv.server.Listener.Addr().String(),
	})
	client := proxyClient(t, proxyURL)

	cases := []string{
		"https://host.example:8443/",
		"https://host.example./",
		"https://HOST.Example/",
		"https://bücher.example/",
	}
	for _, target := range cases {
		require.Empty(t, requestKind(t, client, target, cap), "target %q", target)
	}
	seen := srv.drainNames()
	require.Contains(t, seen, "host.example")
	require.Contains(t, seen, "xn--bcher-kva.example")
	for _, n := range seen {
		assert.NotContains(t, n, "bücher", "wire SNI must be ASCII: %q", n)
	}
}

// Scenario 10: each constructed failure lands in exactly its category and is
// not swallowed by another one.
func TestUpstreamScenario10_FailureCategories(t *testing.T) {
	ca := newTestCA(t, "cat-ca")
	otherCA := newTestCA(t, "other-cat-ca")
	// Each certificate carries the name the client will request, except
	// "wrong", which deliberately carries a different name. This isolates
	// one failure category per server.
	good := ca.issue(t, leafSpec{dnsNames: []string{"good.example"}})
	expired := ca.issue(t, leafSpec{dnsNames: []string{"expired.example"}, expired: true})
	notYet := ca.issue(t, leafSpec{dnsNames: []string{"notyet.example"}, notYetValid: true})
	wrongName := ca.issue(t, leafSpec{dnsNames: []string{"else.example"}})
	foreign := otherCA.issue(t, leafSpec{dnsNames: []string{"foreign.example"}})

	addrs := map[string]string{}
	for tag, cert := range map[string]tls.Certificate{
		"good": good, "expired": expired, "notyet": notYet, "wrong": wrongName, "foreign": foreign,
	} {
		s := newSNIServer(t, cert)
		addrs[tag] = s.server.Listener.Addr().String()
	}

	proxy, proxyURL := startProxy(t)
	cap := newErrorCapture(proxy)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.certPEM)
	proxy.Tr.TLSClientConfig.RootCAs = pool
	installHostMapDialer(t, proxy, map[string]string{
		"good.example":    addrs["good"],
		"expired.example": addrs["expired"],
		"notyet.example":  addrs["notyet"],
		"wrong.example":   addrs["wrong"],
		"foreign.example": addrs["foreign"],
	})
	client := proxyClient(t, proxyURL)

	expect := map[string]goproxy.TLSFailureKind{
		"https://good.example/":    "",
		"https://expired.example/": goproxy.TLSFailureExpired,
		"https://notyet.example/":  goproxy.TLSFailureExpired,
		"https://wrong.example/":   goproxy.TLSFailureNameMismatch,
		"https://foreign.example/": goproxy.TLSFailureUntrustedIssuer,
	}
	for target, want := range expect {
		require.Equal(t, want, requestKind(t, client, target, cap), "target %s", target)
	}
}

// Hard constraint 2: the legacy global switch, narrowed to listed targets,
// skips only those and annotates every skip. Unlisted targets keep strict
// verification.
func TestLegacySwitchNarrowedAndAnnotated(t *testing.T) {
	ca := newTestCA(t, "legacy-ca")
	srv := newSNIServer(t, ca.issue(t, leafSpec{dnsNames: []string{"listed.example"}}))
	other := newSNIServer(t, ca.issue(t, leafSpec{dnsNames: []string{"unlisted.example"}}))

	proxy, proxyURL := startProxy(t)
	cap := newErrorCapture(proxy)
	proxy.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	require.NoError(t, proxy.SetLegacySkipVerifyTargets([]string{"listed.example"}))
	installHostMapDialer(t, proxy, map[string]string{
		"listed.example":   srv.server.Listener.Addr().String(),
		"unlisted.example": other.server.Listener.Addr().String(),
	})
	client := proxyClient(t, proxyURL)

	require.Empty(t, requestKind(t, client, "https://listed.example/", cap))
	reports := reportsViaCapture(t, client, "https://listed.example/", cap)
	require.NotEmpty(t, reports)
	last := reports[len(reports)-1]
	assert.True(t, last.Skipped)
	assert.Equal(t, "listed.example", last.Target)

	require.Equal(t, goproxy.TLSFailureUntrustedIssuer,
		requestKind(t, client, "https://unlisted.example/", cap))
}

// Failure/degradation 1: malformed trust registration fails the
// configuration call and never falls back to trusting everything.
func TestMalformedPolicyFailsClosed(t *testing.T) {
	proxy, _ := startProxy(t)

	_, err := proxy.ReplaceTrustPolicy(nil, []goproxy.TrustTargetEntry{
		{Host: "x.example", Mode: goproxy.TrustModePrivateCA, Group: "missing"},
	})
	require.Error(t, err)
	var ve *goproxy.TLSVerificationError
	require.True(t, errors.As(err, &ve))
	assert.Equal(t, goproxy.TLSFailureConfig, ve.Kind)

	_, err = goproxy.NewTrustGroup([]byte("not a certificate"))
	require.Error(t, err)
}

// Scenario 8: concurrent access to many distinct targets over repeated
// rounds must never mix up names or trust sets.
func TestUpstreamScenario8_ConcurrentNoCrossTalk(t *testing.T) {
	const targets = 200
	const rounds = 10

	privateCA := newTestCA(t, "concurrent-ca")
	group, err := goproxy.NewTrustGroup(privateCA.certPEM)
	require.NoError(t, err)
	foreignCA := newTestCA(t, "foreign-ca")

	// One virtual-host server presents the correct, matching leaf per SNI.
	// Even-numbered hosts get certs from the registered private CA;
	// odd-numbered hosts get equally valid certs from an unregistered CA.
	certs := make(map[string]tls.Certificate, targets)
	entries := make([]goproxy.TrustTargetEntry, 0, targets/2+1)
	hostMap := make(map[string]string, targets)
	for i := 0; i < targets; i++ {
		host := fmt.Sprintf("t%03d.internal", i)
		if i%2 == 0 {
			certs[host] = privateCA.issue(t, leafSpec{dnsNames: []string{host}})
			entries = append(entries, goproxy.TrustTargetEntry{
				Host: host, Mode: goproxy.TrustModePrivateCA, Group: "grp",
			})
		} else {
			certs[host] = foreignCA.issue(t, leafSpec{dnsNames: []string{host}})
		}
	}
	vhost := newSNICertServer(t, certs, certs["t000.internal"])
	proxy, proxyURL := startProxy(t)
	cap := newErrorCapture(proxy)
	for i := 0; i < targets; i++ {
		hostMap[fmt.Sprintf("t%03d.internal", i)] = vhost.server.Listener.Addr().String()
	}
	mustReplace(t, proxy,
		map[string]*goproxy.TrustGroupBuilder{"grp": group}, entries)
	installHostMapDialer(t, proxy, hostMap)
	client := proxyClient(t, proxyURL)

	for round := 0; round < rounds; round++ {
		var wg sync.WaitGroup
		kinds := make([]goproxy.TLSFailureKind, targets)
		for i := 0; i < targets; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				host := fmt.Sprintf("t%03d.internal", i)
				kinds[i] = getThroughProxy(t, client, "https://"+host+"/", cap)
			}(i)
		}
		wg.Wait()
		for i, kind := range kinds {
			want := goproxy.TLSFailureKind("")
			if i%2 != 0 {
				want = goproxy.TLSFailureUntrustedIssuer
			}
			require.Equal(t, want, kind, "target %d round %d", i, round)
		}
		// Explicit host-keyed cross-check: no target's outcome may have
		// been overwritten by another concurrent target.
		for i := 0; i < targets; i++ {
			host := fmt.Sprintf("t%03d.internal", i)
			want := goproxy.TLSFailureKind("")
			if i%2 != 0 {
				want = goproxy.TLSFailureUntrustedIssuer
			}
			require.Equal(t, want, cap.kindFor(host), "keyed result target %d round %d", i, round)
		}
	}

	seen := vhost.drainNames()
	require.NotEmpty(t, seen)
	for _, name := range seen {
		assert.Contains(t, name, ".internal")
	}
}

// Scenario 9: certificate rotation between requests. Pooled connections keep
// working with the original certificate; fresh connections see the new one.
// The peer fingerprint makes the difference observable.
func TestUpstreamScenario9_RotationObservable(t *testing.T) {
	ca := newTestCA(t, "rot-ca")
	leaf1 := ca.issue(t, leafSpec{dnsNames: []string{"rot.example"}})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf1}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	proxy, proxyURL := startProxy(t)
	cap := newErrorCapture(proxy)
	group, err := goproxy.NewTrustGroup(ca.certPEM)
	require.NoError(t, err)
	installHostMapDialer(t, proxy, map[string]string{"rot.example": srv.Listener.Addr().String()})
	installRotPolicy := func() uint64 {
		return mustReplace(t, proxy,
			map[string]*goproxy.TrustGroupBuilder{"g": group},
			[]goproxy.TrustTargetEntry{{Host: "rot.example", Mode: goproxy.TrustModePrivateCA, Group: "g"}})
	}
	installRotPolicy()
	client := proxyClient(t, proxyURL)

	firstReports := reportsViaCapture(t, client, "https://rot.example/", cap)
	require.NotEmpty(t, firstReports)
	fp1 := firstReports[len(firstReports)-1].PeerFingerprint
	versionAtFirst := firstReports[len(firstReports)-1].PolicyVersion

	leafExpired := ca.issue(t, leafSpec{dnsNames: []string{"rot.example"}, expired: true})
	srv.TLS.Certificates = []tls.Certificate{leafExpired}

	// Reload the trust configuration. New connections are decided under the
	// new snapshot and therefore land in a different connection pool,
	// forcing a fresh handshake against the now-expired certificate.
	newVersion := installRotPolicy()
	require.Greater(t, newVersion, versionAtFirst)

	require.Equal(t, goproxy.TLSFailureExpired,
		getThroughProxy(t, client, "https://rot.example/", cap))

	// The connection established under the old snapshot remains pooled and
	// reusable: reloads do not tear down or re-verify established
	// connections. Re-driving the request through the old generation's pool
	// succeeds against the now-expired server certificate, proving the
	// cached connection (and only the cached connection) is reused.
	oldReq, err := http.NewRequestWithContext(goproxy.WithUpstreamReportContext(context.Background()),
		http.MethodGet, "https://rot.example/", nil)
	require.NoError(t, err)
	oldResp, err := proxy.RoundTripWithPolicyVersion(oldReq, versionAtFirst)
	require.NoError(t, err, "old-policy pooled connection must remain usable after reload")
	require.NoError(t, oldResp.Body.Close())

	// The original handshake report still identifies the generation and
	// certificate the pooled connection was built with.
	require.NotEmpty(t, firstReports)
	first := firstReports[0]
	assert.Equal(t, fp1, first.PeerFingerprint)
	assert.Equal(t, versionAtFirst, first.PolicyVersion)
}

// Hard constraint 1: with no policy registered, an unknown private
// certificate is rejected.
func TestDefaultNeverWeakens(t *testing.T) {
	privateCA := newTestCA(t, "default-ca")
	srv := newSNIServer(t, privateCA.issue(t, leafSpec{dnsNames: []string{"plain.example"}}))
	proxy, proxyURL := startProxy(t)
	cap := newErrorCapture(proxy)
	installHostMapDialer(t, proxy, map[string]string{"plain.example": srv.server.Listener.Addr().String()})
	client := proxyClient(t, proxyURL)

	require.Equal(t, goproxy.TLSFailureUntrustedIssuer,
		getThroughProxy(t, client, "https://plain.example/", cap))
}

// Failure/degradation 3: no usable name to compare against fails with a
// config error rather than silently passing.
func TestEmptyNameFailsClosed(t *testing.T) {
	_, err := goproxy.NormalizeHostName("")
	require.Error(t, err)
	var ve *goproxy.TLSVerificationError
	require.True(t, errors.As(err, &ve))
	assert.Equal(t, goproxy.TLSFailureConfig, ve.Kind)

	// End-to-end: a request without a host is rejected before any dial.
	_, proxyURL := startProxy(t)
	client := proxyClient(t, proxyURL)
	req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, "https:///path", nil)
	require.NoError(t, reqErr)
	_, doErr := client.Transport.RoundTrip(req)
	require.Error(t, doErr)
}
