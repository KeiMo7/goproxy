//go:build linux

package goproxy_test

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
)

// countFDs returns the number of open file descriptors of this process.
func countFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	return len(entries)
}

// TestTunnelConnectionsDoNotLeakFDs reproduces the original symptom: many
// client connections, each opening an upstream tunnel, must not accumulate
// descriptors once the tunnels are closed.
func TestTunnelConnectionsDoNotLeakFDs(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer target.Close()
	targetURL, err := url.Parse(target.URL)
	require.NoError(t, err)

	proxy := goproxy.NewProxyHttpServer()
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)

	one := func() {
		c, derr := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(t.Context(), "tcp", proxyURL.Host)
		require.NoError(t, derr)
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: targetURL.Host},
			Host:   targetURL.Host,
			Header: make(http.Header),
		}
		require.NoError(t, req.Write(c))
		resp, rerr := http.ReadResponse(bufio.NewReader(c), req)
		require.NoError(t, rerr)
		require.NoError(t, resp.Body.Close())
		_ = c.Close()
	}
	for i := 0; i < 5; i++ {
		one()
	}
	time.Sleep(200 * time.Millisecond)
	before := countFDs(t)
	for i := 0; i < 40; i++ {
		one()
	}
	time.Sleep(400 * time.Millisecond)
	after := countFDs(t)
	if after > before+8 {
		t.Fatalf("file descriptors grew from %d to %d over 40 tunnels", before, after)
	}
	_ = tls.VersionTLS12
	_ = io.Discard
}
