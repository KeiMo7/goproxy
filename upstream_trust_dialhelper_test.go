package goproxy_test

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
)

// installHostMapDialer makes the proxy resolve the given logical host names
// to concrete loopback listener addresses. It replaces the transport's
// DialContext; DialTLSContext then dials through this mapping, so tests can
// request https://good.example/ without real DNS.
func installHostMapDialer(t *testing.T, proxy *goproxy.ProxyHttpServer, hostMap map[string]string) {
	t.Helper()
	var mu sync.RWMutex
	proxy.Tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		// Equivalent spellings (trailing dot, case, IDN punycode) must hit
		// the same mapping entry as the normalized name.
		key, normErr := goproxy.NormalizeHostName(host)
		if normErr == nil {
			host = key
		}
		mu.RLock()
		mapped, ok := hostMap[host]
		mu.RUnlock()
		dialAddr := addr
		if ok {
			// The mapped value already carries the test listener's full
			// host:port; redirect there regardless of the requested port.
			dialAddr = mapped
		}
		var d net.Dialer
		return d.DialContext(ctx, network, dialAddr)
	}
}

// reportsViaCapture performs a GET and returns the structured reports
// collected by cap, which wraps the default round tripper and therefore
// sees every hop regardless of whether the upstream call succeeded.
func reportsViaCapture(t *testing.T, client *http.Client, target string, cap *errorCapture) []goproxy.UpstreamTLSReport {
	t.Helper()
	resp, err := client.Get(target)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	return cap.lastReports()
}

var _ = url.Parse // keep import stable across helper edits
