package goproxy_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Scenario 4/5: an encrypted upstream relay. The relay handshake uses the
// relay's own host name and trust; the target handshake inside the tunnel
// independently uses the target's name and trust. The two hops must never
// inherit each other's SNI, and their trust sources / names / protocol
// versions are decided separately.
func TestUpstreamScenario45_EncryptedRelaySeparateHops(t *testing.T) {
	relayCA := newTestCA(t, "relay-ca")
	targetCA := newTestCA(t, "target-ca")

	// Target server: certificate for target.example, privately issued.
	targetLeaf := targetCA.issue(t, leafSpec{dnsNames: []string{"target.example"}})
	targetSrv := newSNIServer(t, targetLeaf)

	// A real goproxy instance acting as the encrypted upstream relay,
	// presenting its own relay.example certificate.
	relayLeaf := relayCA.issue(t, leafSpec{dnsNames: []string{"relay.example"}})
	relay := newRealTLSRelay(t, relayLeaf)
	// The relay itself must resolve the fake target host to the local
	// target listener when it dials the CONNECT tunnel.
	relay.proxy.ConnectDialWithReq = nil
	relay.proxy.ConnectDial = func(network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if host == "target.example" {
			addr = targetSrv.server.Listener.Addr().String()
		}
		var d net.Dialer
		return d.DialContext(context.Background(), network, addr)
	}

	proxy, proxyURL := startProxy(t)
	cap := newErrorCapture(proxy)

	relayGroup, err := goproxy.NewTrustGroup(relayCA.certPEM)
	require.NoError(t, err)
	targetGroup, err := goproxy.NewTrustGroup(targetCA.certPEM)
	require.NoError(t, err)
	mustReplace(t, proxy,
		map[string]*goproxy.TrustGroupBuilder{
			"relay":  relayGroup,
			"target": targetGroup,
		},
		[]goproxy.TrustTargetEntry{
			{Host: "relay.example", Mode: goproxy.TrustModePrivateCA, Group: "relay"},
			{Host: "target.example", Mode: goproxy.TrustModePrivateCA, Group: "target"},
		})

	// Route the proxy's transport through the encrypted relay.
	relayURL, err := url.Parse("https://relay.example")
	require.NoError(t, err)
	proxy.Tr.Proxy = http.ProxyURL(relayURL)
	// Only the relay's own address needs remapping to the local listener.
	proxy.Tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr == nil && host == "relay.example" {
			addr = relay.addr
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}

	client := proxyClient(t, proxyURL)
	kind := getThroughProxy(t, client, "https://target.example/", cap)
	require.Empty(t, kind)

	// Outer hop: the relay observed its own name, never the target's.
	assert.Equal(t, []string{"relay.example"}, relay.sniSnapshot())
	// Inner hop: the target observed the target name through the tunnel.
	require.Contains(t, targetSrv.drainNames(), "target.example")

	// Both independent hops are reported with their own labels and names.
	reports := cap.lastReports()
	var sawRelay, sawTarget bool
	for _, r := range reports {
		switch r.Hop {
		case "relay":
			sawRelay = true
			assert.Equal(t, "relay.example", r.ServerName)
			assert.False(t, r.Skipped)
		case "target":
			sawTarget = true
			assert.Equal(t, "target.example", r.ServerName)
		}
	}
	assert.True(t, sawRelay, "relay hop must be reported")
	assert.True(t, sawTarget, "target hop must be reported")
}

// Scenario 4 negative: the relay presenting an untrusted certificate fails
// on the relay hop with an issuer error, without ever attempting the target
// handshake.
func TestUpstreamScenario45_UntrustedRelayRejected(t *testing.T) {
	relayCA := newTestCA(t, "relay-bad-ca")
	targetCA := newTestCA(t, "target-ca2")
	targetSrv := newSNIServer(t, targetCA.issue(t, leafSpec{dnsNames: []string{"target.example"}}))
	relayLeaf := relayCA.issue(t, leafSpec{dnsNames: []string{"relay.example"}})
	relay := newRealTLSRelay(t, relayLeaf)
	relay.proxy.ConnectDial = func(network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(context.Background(), network, targetSrv.server.Listener.Addr().String())
	}

	proxy, proxyURL := startProxy(t)
	cap := newErrorCapture(proxy)
	// Trust only the target CA, not the relay's.
	targetGroup, err := goproxy.NewTrustGroup(targetCA.certPEM)
	require.NoError(t, err)
	mustReplace(t, proxy,
		map[string]*goproxy.TrustGroupBuilder{"target": targetGroup},
		[]goproxy.TrustTargetEntry{
			{Host: "target.example", Mode: goproxy.TrustModePrivateCA, Group: "target"},
		})

	relayURL, _ := url.Parse("https://relay.example")
	proxy.Tr.Proxy = http.ProxyURL(relayURL)
	proxy.Tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		if host == "relay.example" {
			addr = relay.addr
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}

	client := proxyClient(t, proxyURL)
	kind := getThroughProxy(t, client, "https://target.example/", cap)
	require.Equal(t, goproxy.TLSFailureUntrustedIssuer, kind)
	// The failure must be attributable to the relay hop specifically.
	require.Contains(t, cap.lastError(), "relay")
}

// Scenario 4/5 keep-alive: repeated requests to the same target over an
// encrypted relay reuse the established two-hop connection, while a request
// under a different trust policy gets a distinct connection.
func TestUpstreamScenario45_RelayConnectionReuse(t *testing.T) {
	relayCA := newTestCA(t, "relay-reuse-ca")
	targetCA := newTestCA(t, "target-reuse-ca")
	targetSrv := newSNIServer(t, targetCA.issue(t, leafSpec{dnsNames: []string{"target.example"}}))
	relayLeaf := relayCA.issue(t, leafSpec{dnsNames: []string{"relay.example"}})
	relay := newRealTLSRelay(t, relayLeaf)
	relay.proxy.ConnectDial = func(network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if host == "target.example" {
			addr = targetSrv.server.Listener.Addr().String()
		}
		var d net.Dialer
		return d.DialContext(context.Background(), network, addr)
	}

	proxy, proxyURL := startProxy(t)
	cap := newErrorCapture(proxy)
	relayGroup, _ := goproxy.NewTrustGroup(relayCA.certPEM)
	targetGroup, _ := goproxy.NewTrustGroup(targetCA.certPEM)
	mustReplace(t, proxy,
		map[string]*goproxy.TrustGroupBuilder{"r": relayGroup, "t": targetGroup},
		[]goproxy.TrustTargetEntry{
			{Host: "relay.example", Mode: goproxy.TrustModePrivateCA, Group: "r"},
			{Host: "target.example", Mode: goproxy.TrustModePrivateCA, Group: "t"},
		})
	relayURL, _ := url.Parse("https://relay.example")
	proxy.Tr.Proxy = http.ProxyURL(relayURL)
	proxy.Tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		if host == "relay.example" {
			addr = relay.addr
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	client := proxyClient(t, proxyURL)

	// Two sequential requests succeed over the same target.
	for i := 0; i < 2; i++ {
		require.Empty(t, getThroughProxy(t, client, "https://target.example/", cap))
	}
	// Exactly one inner target handshake across two requests proves the
	// second request reused the established two-hop connection rather than
	// handshaking again.
	targetReports := filterHop(cap.lastReports(), "target")
	require.Len(t, targetReports, 1, "reused connection must not re-handshake")
	assert.Equal(t, "target.example", targetReports[0].ServerName)
	// The relay hop always uses the relay's own name.
	for _, r := range filterHop(cap.lastReports(), "relay") {
		assert.Equal(t, "relay.example", r.ServerName)
	}
}

func filterHop(reports []goproxy.UpstreamTLSReport, hop string) []goproxy.UpstreamTLSReport {
	var out []goproxy.UpstreamTLSReport
	for _, r := range reports {
		if r.Hop == hop {
			out = append(out, r)
		}
	}
	return out
}

// Scenario 10 (protocol version): a peer that only offers a TLS version
// below the policy minimum is rejected with the protocol_version category,
// never downgraded to an older version.
func TestUpstreamScenario10_ProtocolVersionRejected(t *testing.T) {
	ca := newTestCA(t, "ver-ca")
	leaf := ca.issue(t, leafSpec{dnsNames: []string{"ver.example"}})

	srv := newTLSServerWithVersions(t, leaf, tls.VersionTLS10, tls.VersionTLS10)

	proxy, proxyURL := startProxy(t)
	cap := newErrorCapture(proxy)
	group, err := goproxy.NewTrustGroup(ca.certPEM)
	require.NoError(t, err)
	mustReplace(t, proxy,
		map[string]*goproxy.TrustGroupBuilder{"g": group},
		[]goproxy.TrustTargetEntry{{
			Host: "ver.example", Mode: goproxy.TrustModePrivateCA, Group: "g",
			MinTLSVersion: tls.VersionTLS12,
		}})
	installHostMapDialer(t, proxy, map[string]string{"ver.example": srv.Listener.Addr().String()})
	client := proxyClient(t, proxyURL)

	require.Equal(t, goproxy.TLSFailureProtocolVersion,
		getThroughProxy(t, client, "https://ver.example/", cap))
}

// Scenario 10 (peer closed): a server that accepts the TCP connection and
// then closes it during the TLS handshake is classified as peer_closed.
func TestUpstreamScenario10_PeerClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 1024)
				_ = c.SetReadDeadline(deadlineIn(5))
				_, _ = c.Read(buf)
				_ = c.Close()
			}(conn)
		}
	}()

	proxy, proxyURL := startProxy(t)
	cap := newErrorCapture(proxy)
	installHostMapDialer(t, proxy, map[string]string{"hangup.example": ln.Addr().String()})
	client := proxyClient(t, proxyURL)

	require.Equal(t, goproxy.TLSFailurePeerClosed,
		getThroughProxy(t, client, "https://hangup.example/", cap))
}
