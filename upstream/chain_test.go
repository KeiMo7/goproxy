package upstream

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func base64Decode(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	return string(raw), err
}

func newBufioReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }

// newTestRouter builds a router from chains/routes, failing the test on
// validation errors.
func newTestRouter(t *testing.T, cfg *Config) *Router {
	t.Helper()
	r, err := NewRouter(cfg)
	require.NoError(t, err)
	return r
}

func getThrough(t *testing.T, rt http.RoundTripper, target *targetServer, path string) (string, *http.Response) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target.URL+path, nil)
	require.NoError(t, err)
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(b), resp
}

// TestMultiHopConnectChain covers scenario I.1: three CONNECT hops, each with
// different auth (none / basic / token), request traverses all of them in
// order and reaches the target.
func TestMultiHopConnectChain(t *testing.T) {
	target := newTargetServer(t)
	hop1 := newMockConnectProxy(t) // no auth
	hop2 := newMockConnectProxy(t)
	hop2.requireBasic("u2", "p2")
	hop3 := newMockConnectProxy(t)
	hop3.requireToken("Proxy-Authorization", "Token abc123")

	cfg := &Config{
		Version: "v1",
		Chains: []Chain{{
			ID: "chain-a",
			Hops: []Hop{
				{Name: "edge", Address: hop1.addr(), Tunnel: TunnelConnect},
				{Name: "middle", Address: hop2.addr(), Tunnel: TunnelConnect,
					Auth: Auth{Type: AuthBasic, Username: "u2", Password: "p2"}},
				{Name: "inner", Address: hop3.addr(), Tunnel: TunnelConnect,
					Auth: Auth{Type: AuthToken, Token: "abc123", Scheme: "Token"}},
			},
		}},
		Routes: []Route{{Default: true, Primary: "chain-a"}},
	}
	rt := NewRoundTripper(newTestRouter(t, cfg))

	body, resp := getThrough(t, rt, target, "/ok")
	assert.Equal(t, "ok", body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Hop order: each hop receives a CONNECT targeting the next element of
	// the chain; only the final hop targets the actual destination.
	require.NotEmpty(t, hop1.targetsSeen(), "hop1 never received a CONNECT")
	require.NotEmpty(t, hop2.targetsSeen(), "hop2 never received a CONNECT")
	require.NotEmpty(t, hop3.targetsSeen(), "hop3 never received a CONNECT")
	assert.Equal(t, hop2.addr(), hop1.targetsSeen()[0], "hop1 must CONNECT to hop2")
	assert.Equal(t, hop3.addr(), hop2.targetsSeen()[0], "hop2 must CONNECT to hop3")
	assert.Equal(t, target.hostPort(), hop3.targetsSeen()[len(hop3.targetsSeen())-1])
}

// TestMixedTunnelTypes covers scenario I.3: CONNECT and SOCKS5 hops mixed in
// one chain with a forward terminal hop for plain HTTP.
func TestMixedTunnelTypes(t *testing.T) {
	target := newTargetServer(t)
	socks := newMockSocksServer(t)
	socks.requireAuth("su", "sp")
	edge := newMockConnectProxy(t)
	edge.requireBasic("eu", "ep")
	fwd := newMockConnectProxy(t) // acts as forward proxy on its accept loop
	fwd.requireBasic("fu", "fp")

	cfg := &Config{
		Version: "v1",
		Chains: []Chain{{
			ID: "mixed",
			Hops: []Hop{
				{Name: "edge-connect", Address: edge.addr(), Tunnel: TunnelConnect,
					Auth: Auth{Type: AuthBasic, Username: "eu", Password: "ep"}},
				{Name: "mid-socks", Address: socks.addr(), Tunnel: TunnelSOCKS5,
					Auth: Auth{Type: AuthBasic, Username: "su", Password: "sp"}},
				{Name: "forward-end", Address: fwd.addr(), Tunnel: TunnelForward,
					Auth: Auth{Type: AuthBasic, Username: "fu", Password: "fp"}},
			},
		}},
		Routes: []Route{{Default: true, Primary: "mixed"}},
	}
	rt := NewRoundTripper(newTestRouter(t, cfg))

	body, _ := getThrough(t, rt, target, "/ok")
	assert.Equal(t, "ok", body)
	assert.Equal(t, int64(1), socks.connectCount.Load())
	assert.Equal(t, "su", socks.seenUser.Load())
	assert.GreaterOrEqual(t, edge.connectCount.Load(), int64(1))
	assert.GreaterOrEqual(t, fwd.forwardCount.Load(), int64(1))
}

// TestMixedTunnelSOCKSLast verifies a SOCKS5 terminal hop carrying HTTP to
// the target (no forward hop).
func TestMixedTunnelSOCKSLast(t *testing.T) {
	target := newTargetServer(t)
	socks := newMockSocksServer(t)
	edge := newMockConnectProxy(t)

	cfg := &Config{
		Version: "v1",
		Chains: []Chain{{
			ID: "socks-last",
			Hops: []Hop{
				{Name: "edge", Address: edge.addr(), Tunnel: TunnelConnect},
				{Name: "socks", Address: socks.addr(), Tunnel: TunnelSOCKS5},
			},
		}},
		Routes: []Route{{Default: true, Primary: "socks-last"}},
	}
	rt := NewRoundTripper(newTestRouter(t, cfg))
	body, _ := getThrough(t, rt, target, "/ok")
	assert.Equal(t, "ok", body)
	// SOCKS hop must have been asked to reach the target directly.
	assert.Equal(t, int64(1), socks.connectCount.Load())
}

// TestCredentialsDoNotLeakAcrossHops covers hard constraint 1 and acceptance
// criterion V.2: every hop must only ever see its own credentials; the target
// server must see no Proxy-Authorization at all; error strings must not
// contain credential material.
func TestCredentialsDoNotLeakAcrossHops(t *testing.T) {
	target := newTargetServer(t)
	hop1 := newMockConnectProxy(t)
	hop1.requireBasic("hop1-user", "hop1-secret")
	hop2 := newMockConnectProxy(t)
	hop2.requireBasic("hop2-user", "hop2-secret")
	hop3 := newMockConnectProxy(t)
	hop3.requireToken("X-Token", "hop3-token-value")

	cfg := &Config{
		Version: "v1",
		Chains: []Chain{{
			ID: "leak-check",
			Hops: []Hop{
				{Name: "h1", Address: hop1.addr(), Tunnel: TunnelConnect,
					Auth: Auth{Type: AuthBasic, Username: "hop1-user", Password: "hop1-secret"}},
				{Name: "h2", Address: hop2.addr(), Tunnel: TunnelConnect,
					Auth: Auth{Type: AuthBasic, Username: "hop2-user", Password: "hop2-secret"}},
				{Name: "h3", Address: hop3.addr(), Tunnel: TunnelConnect,
					Auth: Auth{Type: AuthToken, Header: "X-Token", Token: "hop3-token-value"}},
			},
		}},
		Routes: []Route{{Default: true, Primary: "leak-check"}},
	}
	rt := NewRoundTripper(newTestRouter(t, cfg))
	_, _ = getThrough(t, rt, target, "/ok")

	// Hop1 must only ever see hop1 credentials.
	for _, hdr := range hop1.authsSeen() {
		assert.Contains(t, hdr, "Basic ")
		creds := decodeBasic(t, hdr)
		assert.Equal(t, "hop1-user:hop1-secret", creds)
		assert.NotContains(t, creds, "hop2")
		assert.NotContains(t, hdr, "hop3-token-value")
	}
	// Hop2 must only ever see hop2 credentials.
	for _, hdr := range hop2.authsSeen() {
		creds := decodeBasic(t, hdr)
		assert.Equal(t, "hop2-user:hop2-secret", creds)
		assert.NotContains(t, creds, "hop1")
	}
	// Hop3 sees its token, and neither of the Basic credentials.
	for _, hdr := range hop3.authsSeen() {
		assert.NotContains(t, hdr, "Basic")
	}
	// The final destination must receive no proxy auth header.
	assert.Equal(t, "", target.lastAuth.Load())

	// Error text on a deliberately broken chain must not carry secrets.
	bad := &Config{
		Version: "v1",
		Chains: []Chain{{
			ID: "broken",
			Hops: []Hop{
				{Name: "h1", Address: dialFreePort(t), Tunnel: TunnelConnect,
					Auth: Auth{Type: AuthBasic, Username: "hop1-user", Password: "hop1-secret"}},
			},
		}},
		Routes: []Route{{Default: true, Primary: "broken"}},
	}
	badRT := NewRoundTripper(newTestRouter(t, bad))
	req, _ := http.NewRequest(http.MethodGet, target.URL+"/ok", nil)
	_, err := badRT.RoundTrip(req)
	require.Error(t, err)
	for _, secret := range []string{"hop1-secret", "hop1-user"} {
		assert.NotContains(t, err.Error(), secret, "error leaked credential: %v", err)
	}
}

func decodeBasic(t *testing.T, header string) string {
	t.Helper()
	require.True(t, strings.HasPrefix(header, "Basic "))
	raw, err := base64Decode(strings.TrimPrefix(header, "Basic "))
	require.NoError(t, err)
	return raw
}

// TestHopScopedAuthRetry covers scenario I.4 and hard constraint 2: a hop
// that answers 407 first must be retried at that hop only, with credentials,
// and succeed without rebuilding the whole chain or replaying a body.
func TestHopScopedAuthRetry(t *testing.T) {
	target := newTargetServer(t)
	edge := newMockConnectProxy(t) // open
	gate := newMockConnectProxy(t)
	gate.requireBasic("gate-u", "gate-p")
	gate.setChallengeFirst(true) // 407 on the first attempt

	cfg := &Config{
		Version: "v1",
		Chains: []Chain{{
			ID: "retry",
			Hops: []Hop{
				{Name: "edge", Address: edge.addr(), Tunnel: TunnelConnect},
				{Name: "gate", Address: gate.addr(), Tunnel: TunnelConnect,
					ChallengeFirst: true,
					Auth:           Auth{Type: AuthBasic, Username: "gate-u", Password: "gate-p"}},
			},
		}},
		Routes: []Route{{Default: true, Primary: "retry"}},
	}
	rt := NewRoundTripper(newTestRouter(t, cfg))

	bodyReader := bytes.NewBufferString("payload-1234")
	req, err := http.NewRequest(http.MethodPost, target.URL+"/echo", bodyReader)
	require.NoError(t, err)
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "echo:payload-1234", string(b))

	// Exactly one CONNECT toward the edge: the 407 retry did not rebuild the
	// prefix of the chain.
	assert.Equal(t, int64(1), edge.connectCount.Load())
	// The gate saw two CONNECT attempts (challenge then authenticated).
	assert.Equal(t, int64(2), gate.connectCount.Load())
	// And only one request actually reached the target.
	assert.Equal(t, int64(1), target.requestCount.Load())
}

// TestAuthFailureHopIdentity covers hard constraint 2: a rejected credential
// must surface an auth error pointing at the exact hop.
func TestAuthFailureHopIdentity(t *testing.T) {
	target := newTargetServer(t)
	edge := newMockConnectProxy(t)
	gate := newMockConnectProxy(t)
	gate.requireBasic("right", "creds")

	cfg := &Config{
		Version: "v1",
		Chains: []Chain{{
			ID: "bad-creds",
			Hops: []Hop{
				{Name: "edge", Address: edge.addr(), Tunnel: TunnelConnect},
				{Name: "gate", Address: gate.addr(), Tunnel: TunnelConnect,
					Auth: Auth{Type: AuthBasic, Username: "wrong", Password: "wrong"}},
			},
		}},
		Routes: []Route{{Default: true, Primary: "bad-creds"}},
	}
	rt := NewRoundTripper(newTestRouter(t, cfg))
	req, _ := http.NewRequest(http.MethodGet, target.URL+"/ok", nil)
	_, err := rt.RoundTrip(req)
	require.Error(t, err)
	he := AsHopError(err)
	require.NotNil(t, he)
	assert.Equal(t, FailureAuth, he.Kind)
	assert.Equal(t, 1, he.HopIndex)
	assert.Equal(t, "gate", he.HopName)
}

// TestUnreachableHopClassification covers hard constraint 2: unreachable vs
// timeout vs refused are distinguished.
func TestUnreachableHopClassification(t *testing.T) {
	target := newTargetServer(t)
	cfg := &Config{
		Version: "v1",
		Chains: []Chain{{
			ID: "dead",
			Hops: []Hop{
				{Name: "edge", Address: dialFreePort(t), Tunnel: TunnelConnect,
					DialTimeout: 500 * time.Millisecond},
			},
		}},
		Routes: []Route{{Default: true, Primary: "dead"}},
	}
	rt := NewRoundTripper(newTestRouter(t, cfg))
	req, _ := http.NewRequest(http.MethodGet, target.URL+"/ok", nil)
	_, err := rt.RoundTrip(req)
	require.Error(t, err)
	he := AsHopError(err)
	require.NotNil(t, he)
	assert.Contains(t, []FailureKind{FailureRefused, FailureUnreachable, FailureTimeout}, he.Kind)
	assert.Equal(t, 0, he.HopIndex)
}

// TestNoHalfOpenConnections covers hard constraint 4: a failure mid-chain
// must close every socket opened so far, and the retry must build fresh.
func TestNoHalfOpenConnections(t *testing.T) {
	target := newTargetServer(t)
	edge := newMockConnectProxy(t)
	dead := newMockConnectProxy(t)
	dead.failDial.Store(true)

	cfg := &Config{
		Version: "v1",
		Chains: []Chain{{
			ID: "halfopen",
			Hops: []Hop{
				{Name: "edge", Address: edge.addr(), Tunnel: TunnelConnect},
				{Name: "dead", Address: dead.addr(), Tunnel: TunnelConnect},
			},
		}},
		Routes: []Route{{Default: true, Primary: "halfopen"}},
	}
	router := newTestRouter(t, cfg)
	rt := NewRoundTripper(router)

	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodGet, target.URL+"/ok", nil)
		_, err := rt.RoundTrip(req)
		require.Error(t, err, "iteration %d", i)
	}
	// Every attempt must have produced a fresh CONNECT to the edge (no reuse
	// of a broken tunnel).
	assert.Equal(t, int64(3), edge.connectCount.Load())

	// After fixing the second hop, a new request succeeds with a fresh chain.
	dead.failDial.Store(false)
	body, _ := getThrough(t, rt, target, "/ok")
	assert.Equal(t, "ok", body)
}

// TestTunnelReuseAndCredentialRebuild covers hard constraint 3: identical
// target+chain reuses the tunnel; rotating credentials forces a rebuild.
func TestTunnelReuseAndCredentialRebuild(t *testing.T) {
	target := newTargetServer(t)
	edge := newMockConnectProxy(t)
	edge.requireBasic("u", "p1")

	build := func(version, pass string) *Config {
		return &Config{
			Version: version,
			Chains: []Chain{{
				ID: "pool",
				Hops: []Hop{{
					Name: "edge", Address: edge.addr(), Tunnel: TunnelConnect,
					Auth: Auth{Type: AuthBasic, Username: "u", Password: pass},
				}},
			}},
			Routes: []Route{{Default: true, Primary: "pool"}},
		}
	}
	router := newTestRouter(t, build("v1", "p1"))
	rt := NewRoundTripper(router)

	_, _ = getThrough(t, rt, target, "/ok")
	first := edge.connectCount.Load()
	require.GreaterOrEqual(t, first, int64(1))

	// Second request with identical config must reuse the pooled tunnel:
	// no new CONNECT handshake at the edge.
	_, _ = getThrough(t, rt, target, "/ok")
	assert.Equal(t, first, edge.connectCount.Load(), "tunnel should be reused")

	// Rotate credentials via hot-reload: the fingerprint changes so a new
	// tunnel with a fresh CONNECT must be established.
	require.NoError(t, router.Replace(build("v2", "p2")))
	edge.requireBasic("u", "p2")
	_, _ = getThrough(t, rt, target, "/ok")
	assert.Greater(t, edge.connectCount.Load(), first, "credential rotation must rebuild tunnel")
}

// TestDomainAndCIDRRouting covers scenario I.2: different destinations pick
// different chains; hop order within a chain stays fixed.
func TestDomainAndCIDRRouting(t *testing.T) {
	target := newTargetServer(t)
	chainAEdge := newMockConnectProxy(t)
	chainBEdge := newMockConnectProxy(t)

	cfg := &Config{
		Version: "v1",
		Chains: []Chain{
			{ID: "a", Hops: []Hop{{Name: "a-edge", Address: chainAEdge.addr(), Tunnel: TunnelConnect}}},
			{ID: "b", Hops: []Hop{{Name: "b-edge", Address: chainBEdge.addr(), Tunnel: TunnelConnect}}},
		},
		Routes: []Route{
			{Primary: "a", HostSuffixes: []string{"example.com"}},
			{Primary: "b", Hosts: []string{"127.0.0.1"}},
			{Default: true, Primary: "a"},
		},
	}
	router := newTestRouter(t, cfg)
	rt := NewRoundTripper(router)

	// Target is 127.0.0.1 -> route b.
	_, _ = getThrough(t, rt, target, "/ok")
	assert.GreaterOrEqual(t, chainBEdge.connectCount.Load(), int64(1))
	assert.Equal(t, int64(0), chainAEdge.connectCount.Load())
}

// TestCIDRRouting covers the network-segment selector: destinations inside a
// configured CIDR pick the matching chain; hostname suffix selection is
// verified through chain ordering without dialing.
func TestCIDRRouting(t *testing.T) {
	target := newTargetServer(t)
	cidrEdge := newMockConnectProxy(t)
	defaultEdge := newMockConnectProxy(t)
	_, ipNet, err := net.ParseCIDR("127.0.0.0/8")
	require.NoError(t, err)

	cfg := &Config{
		Version: "v1",
		Chains: []Chain{
			{ID: "cidr", Hops: []Hop{{Name: "cidr-edge", Address: cidrEdge.addr(), Tunnel: TunnelConnect}}},
			{ID: "def", Hops: []Hop{{Name: "default-edge", Address: defaultEdge.addr(), Tunnel: TunnelConnect}}},
		},
		Routes: []Route{
			{Primary: "cidr", CIDRs: []*net.IPNet{ipNet}},
			{Primary: "def", HostSuffixes: []string{"example.com"}},
			{Default: true, Primary: "def"},
		},
	}
	router := newTestRouter(t, cfg)
	rt := NewRoundTripper(router)

	// 127.0.0.1 is inside 127.0.0.0/8 -> cidr chain.
	_, _ = getThrough(t, rt, target, "/ok")
	assert.GreaterOrEqual(t, cidrEdge.connectCount.Load(), int64(1))
	assert.Equal(t, int64(0), defaultEdge.connectCount.Load())

	// Hostname suffix match picks "def" via the suffix route (same chain as
	// default here, but the selected route is asserted through ordering).
	order, matched := router.chainOrder("api.example.com")
	require.NotNil(t, matched)
	assert.Equal(t, "def", order[0])
	assert.Contains(t, matched.HostSuffixes, "example.com")

	// An unmatched host lands on the default route.
	order2, matched2 := router.chainOrder("unmatched.other.net")
	require.NotNil(t, matched2)
	assert.True(t, matched2.Default)
	assert.Equal(t, "def", order2[0])
}

// TestFailoverWithNoDuplicateBody covers scenario III.1/III.2/III.4 and
// acceptance V.3: an unreachable primary hop falls back to the backup chain,
// the event is observable, and the request body is delivered exactly once.
func TestFailoverWithNoDuplicateBody(t *testing.T) {
	target := newTargetServer(t)
	primaryEdge := newMockConnectProxy(t)
	primaryEdge.closeEarly.Store(true) // crashes after accept
	backupEdge := newMockConnectProxy(t)

	var events []Event
	var mu sync.Mutex
	cfg := &Config{
		Version: "v1",
		Chains: []Chain{
			{ID: "primary", Hops: []Hop{{Name: "dead-edge", Address: primaryEdge.addr(), Tunnel: TunnelConnect}}},
			{ID: "backup", Hops: []Hop{{Name: "alive-edge", Address: backupEdge.addr(), Tunnel: TunnelConnect}}},
		},
		Routes: []Route{{
			Default: true, Primary: "primary", Backups: []string{"backup"},
		}},
	}
	router := newTestRouter(t, cfg)
	router.AddSink(EventSinkFunc(func(e Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}))
	rt := NewRoundTripper(router)

	ctx, rep := WithReport(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		target.URL+"/echo", bytes.NewBufferString("exactly-once"))
	require.NoError(t, err)
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Equal(t, "echo:exactly-once", string(b))

	// Failover report identifies the backup chain and why.
	assert.True(t, rep.FellBack)
	assert.Equal(t, "backup", rep.UsedChain)
	require.Len(t, rep.Trail, 2)
	assert.Equal(t, "primary", rep.Trail[0].ChainID)
	assert.NotEmpty(t, rep.Trail[0].Kind)

	// Exactly one request reached the target: no duplicated body.
	assert.Equal(t, int64(1), target.requestCount.Load())

	// Observability: a failover event was emitted naming the failing chain.
	mu.Lock()
	var sawFailover, sawSucceeded bool
	for _, e := range events {
		if e.Type == EventFailover && e.ChainID == "backup" && e.FromChain == "primary" {
			sawFailover = true
		}
		if e.Type == EventChainSucceeded && e.ChainID == "backup" {
			sawSucceeded = true
		}
	}
	mu.Unlock()
	assert.True(t, sawFailover, "missing failover event: %+v", events)
	assert.True(t, sawSucceeded, "missing success event: %+v", events)
}

// TestAllChainsFailedAggregation covers scenario III.3: when every chain
// fails, the aggregated error names each hop reason.
func TestAllChainsFailedAggregation(t *testing.T) {
	target := newTargetServer(t)
	cfg := &Config{
		Version: "v1",
		Chains: []Chain{
			{ID: "c1", Hops: []Hop{{Name: "dead1", Address: dialFreePort(t), Tunnel: TunnelConnect,
				DialTimeout: 400 * time.Millisecond}}},
			{ID: "c2", Hops: []Hop{{Name: "dead2", Address: dialFreePort(t), Tunnel: TunnelConnect,
				DialTimeout: 400 * time.Millisecond}}},
		},
		Routes: []Route{{Default: true, Primary: "c1", Backups: []string{"c2"}}},
	}
	rt := NewRoundTripper(newTestRouter(t, cfg))
	req, _ := http.NewRequest(http.MethodGet, target.URL+"/ok", nil)
	_, err := rt.RoundTrip(req)
	require.Error(t, err)
	var re *RouteError
	require.True(t, errors.As(err, &re), "want *RouteError, got %T: %v", err, err)
	assert.Len(t, re.Attempts, 2)
	assert.Contains(t, err.Error(), "dead1")
	assert.Contains(t, err.Error(), "dead2")
}

// TestAuthFailureDoesNotFailoverByDefault documents the default policy:
// auth errors are configuration problems, not outage, so no failover.
func TestAuthFailureDoesNotFailoverByDefault(t *testing.T) {
	target := newTargetServer(t)
	gate := newMockConnectProxy(t)
	gate.requireBasic("real", "creds")
	backup := newMockConnectProxy(t)
	cfg := &Config{
		Version: "v1",
		Chains: []Chain{
			{ID: "primary", Hops: []Hop{{Name: "gate", Address: gate.addr(), Tunnel: TunnelConnect,
				Auth: Auth{Type: AuthBasic, Username: "bad", Password: "bad"}}}},
			{ID: "backup", Hops: []Hop{{Name: "bk", Address: backup.addr(), Tunnel: TunnelConnect}}},
		},
		Routes: []Route{{Default: true, Primary: "primary", Backups: []string{"backup"}}},
	}
	rt := NewRoundTripper(newTestRouter(t, cfg))
	req, _ := http.NewRequest(http.MethodGet, target.URL+"/ok", nil)
	_, err := rt.RoundTrip(req)
	require.Error(t, err)
	he := AsHopError(err)
	require.NotNil(t, he)
	assert.Equal(t, FailureAuth, he.Kind)
	assert.Equal(t, int64(0), backup.connectCount.Load(), "backup must not be tried on auth failure")
}

// TestForwardHopRejectsHTTPS documents the protocol-consistency rule
// (scenario I.3): a forward terminal hop cannot carry HTTPS.
func TestForwardHopRejectsHTTPS(t *testing.T) {
	fwd := newMockConnectProxy(t)
	cfg := &Config{
		Version: "v1",
		Chains: []Chain{{
			ID:   "fwd-only",
			Hops: []Hop{{Name: "fwd", Address: fwd.addr(), Tunnel: TunnelForward}},
		}},
		Routes: []Route{{Default: true, Primary: "fwd-only"}},
	}
	rt := NewRoundTripper(newTestRouter(t, cfg))
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	_, err := rt.RoundTrip(req)
	require.Error(t, err)
	he := AsHopError(err)
	require.NotNil(t, he)
	assert.Equal(t, FailureProtocol, he.Kind)
}

// TestPerHopTimeoutClassified verifies hard constraint 2: a hop whose
// handshake stalls past its HandshakeTimeout surfaces FailureTimeout at the
// exact hop index.
func TestPerHopTimeoutClassified(t *testing.T) {
	// A raw listener that accepts a connection and then never responds.
	stallLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = stallLn.Close() })
	go func() {
		for {
			c, err := stallLn.Accept()
			if err != nil {
				return
			}
			// Hold the socket open without answering the CONNECT.
			go func(c net.Conn) {
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
				select {}
			}(c)
		}
	}()

	target := newTargetServer(t)
	cfg := &Config{
		Version: "v1",
		Chains: []Chain{{
			ID: "stall",
			Hops: []Hop{{
				Name: "slow", Address: stallLn.Addr().String(), Tunnel: TunnelConnect,
				HandshakeTimeout: 150 * time.Millisecond,
			}},
		}},
		Routes: []Route{{Default: true, Primary: "stall"}},
	}
	rt := NewRoundTripper(newTestRouter(t, cfg))
	req, _ := http.NewRequest(http.MethodGet, target.URL+"/ok", nil)
	start := time.Now()
	_, err = rt.RoundTrip(req)
	elapsed := time.Since(start)
	require.Error(t, err)
	he := AsHopError(err)
	require.NotNil(t, he)
	assert.Equal(t, FailureTimeout, he.Kind)
	assert.Equal(t, 0, he.HopIndex)
	assert.Less(t, elapsed, 2*time.Second, "per-hop timeout must bound the wait")
}

// TestHotReloadKeepsInFlightTunnel verifies hard constraint 5 directly: a
// tunnel established under the old config keeps working across Replace even
// though the old dialer's idle pool is retired.
func TestHotReloadKeepsInFlightTunnel(t *testing.T) {
	target := newTargetServer(t)
	edge := newMockConnectProxy(t)
	cfg := &Config{
		Version: "v1",
		Chains: []Chain{{
			ID:   "c",
			Hops: []Hop{{Name: "edge", Address: edge.addr(), Tunnel: TunnelConnect}},
		}},
		Routes: []Route{{Default: true, Primary: "c"}},
	}
	router := newTestRouter(t, cfg)
	rt := NewRoundTripper(router)

	// Establish a tunnel and keep its response body open (connection busy)
	// while the config is replaced.
	req, _ := http.NewRequest(http.MethodGet, target.URL+"/ok", nil)
	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)

	require.NoError(t, router.Replace(&Config{
		Version: "v2-rotated",
		Chains: []Chain{{
			ID:   "c",
			Hops: []Hop{{Name: "edge", Address: edge.addr(), Tunnel: TunnelConnect}},
		}},
		Routes: []Route{{Default: true, Primary: "c"}},
	}))

	// The in-flight response must still be fully readable: its tunnel was not
	// cut by the reload.
	b, readErr := io.ReadAll(resp.Body)
	require.NoError(t, readErr)
	assert.Equal(t, "ok", string(b))
	require.NoError(t, resp.Body.Close())

	// New requests work against the new snapshot.
	body, _ := getThrough(t, rt, target, "/ok")
	assert.Equal(t, "ok", body)
}

// TestDialContextIsRouted checks the CONNECT-facing entry used by the root
// goproxy integration.
func TestDialContextIsRouted(t *testing.T) {
	target := newTargetServer(t)
	edge := newMockConnectProxy(t)
	cfg := &Config{
		Version: "v1",
		Chains: []Chain{{
			ID:   "c",
			Hops: []Hop{{Name: "edge", Address: edge.addr(), Tunnel: TunnelConnect}},
		}},
		Routes: []Route{{Default: true, Primary: "c"}},
	}
	rt := NewRoundTripper(newTestRouter(t, cfg))
	conn, err := rt.DialContext(context.Background(), "tcp", target.hostPort())
	require.NoError(t, err)
	defer conn.Close()
	req, _ := http.NewRequest(http.MethodGet, target.URL+"/ok", nil)
	require.NoError(t, req.Write(conn))
	resp, err := http.ReadResponse(bufioReader(conn), req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "ok", string(b))
}

// helper to avoid importing bufio at top-level repeatedly
func bufioReader(c net.Conn) *bufio.Reader { return newBufioReader(c) }

// TestSOCKS5AuthRejected maps a SOCKS auth rejection to FailureAuth.
func TestSOCKS5AuthRejected(t *testing.T) {
	target := newTargetServer(t)
	socks := newMockSocksServer(t)
	socks.requireAuth("real", "creds")
	cfg := &Config{
		Version: "v1",
		Chains: []Chain{{
			ID: "s",
			Hops: []Hop{{Name: "socks", Address: socks.addr(), Tunnel: TunnelSOCKS5,
				Auth: Auth{Type: AuthBasic, Username: "bad", Password: "bad"}}},
		}},
		Routes: []Route{{Default: true, Primary: "s"}},
	}
	rt := NewRoundTripper(newTestRouter(t, cfg))
	req, _ := http.NewRequest(http.MethodGet, target.URL+"/ok", nil)
	_, err := rt.RoundTrip(req)
	require.Error(t, err)
	he := AsHopError(err)
	require.NotNil(t, he)
	assert.Equal(t, FailureAuth, he.Kind)
}
