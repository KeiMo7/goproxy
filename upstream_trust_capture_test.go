package goproxy_test

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
)

// errorCapture records structured upstream TLS errors and reports observed
// on the proxy side by wrapping the default round tripper. In MITM mode an
// upstream failure aborts the request before any response handler runs, so
// the round tripper is the only place that sees every outcome.
//
// Results are keyed by request host so concurrent requests cannot make
// per-target outcomes ambiguous.
type errorCapture struct {
	mu      sync.Mutex
	kinds   map[string]goproxy.TLSFailureKind
	lastErr error
	reports []goproxy.UpstreamTLSReport
}

func newErrorCapture(proxy *goproxy.ProxyHttpServer) *errorCapture {
	c := &errorCapture{kinds: map[string]goproxy.TLSFailureKind{}}
	proxy.RoundTripperOverride = goproxy.RoundTripperFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
			resp, err := proxy.DefaultRoundTrip(req)
			var kind goproxy.TLSFailureKind
			if err != nil {
				var ve *goproxy.TLSVerificationError
				if errors.As(err, &ve) {
					kind = ve.Kind
				} else {
					kind = goproxy.TLSFailureKind("unstructured:" + err.Error())
				}
			}
			c.mu.Lock()
			c.kinds[req.URL.Host] = kind
			c.lastErr = err
			c.reports = append(c.reports, goproxy.UpstreamTLSReports(req.Context())...)
			c.mu.Unlock()
			return resp, err
		})
	return c
}

func (c *errorCapture) lastError() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastErr == nil {
		return ""
	}
	return c.lastErr.Error()
}

// kindFor returns the last recorded outcome for the given host.
func (c *errorCapture) kindFor(host string) goproxy.TLSFailureKind {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kinds[host]
}

func (c *errorCapture) lastReports() []goproxy.UpstreamTLSReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]goproxy.UpstreamTLSReport, len(c.reports))
	copy(out, c.reports)
	return out
}

// getThroughProxy performs one GET and returns the structured failure kind
// seen on the proxy side ("" when the upstream verified successfully).
func getThroughProxy(t *testing.T, client *http.Client, target string, cap *errorCapture) goproxy.TLSFailureKind {
	t.Helper()
	parsed, err := url.Parse(target)
	require.NoError(t, err)
	host, err := goproxy.NormalizeHostName(parsed.Host)
	require.NoError(t, err)
	resp, err := client.Get(target)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if kind, ok := cap.lookup(host); ok {
		return kind
	}
	// Non-MITM paths surface the structured error directly to the client.
	if err != nil {
		var ve *goproxy.TLSVerificationError
		if errors.As(err, &ve) {
			return ve.Kind
		}
		require.NoError(t, err, "unexpected non-TLS error")
	}
	return ""
}

// lookup returns the recorded kind for host using either its normalized or
// port-bearing spelling.
func (c *errorCapture) lookup(host string) (goproxy.TLSFailureKind, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if kind, ok := c.kinds[host]; ok {
		return kind, true
	}
	for h, kind := range c.kinds {
		if n, err := goproxy.NormalizeHostName(h); err == nil && n == host {
			return kind, true
		}
	}
	return "", false
}

// requestKind is the short alias used by the scenario tests.
func requestKind(t *testing.T, client *http.Client, target string, cap *errorCapture) goproxy.TLSFailureKind {
	t.Helper()
	return getThroughProxy(t, client, target, cap)
}
