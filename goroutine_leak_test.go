package goproxy_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
)

// TestUpstreamRequestsDoNotLeakGoroutines runs many sequential requests and
// checks the goroutine count returns to a stable baseline.
func TestUpstreamRequestsDoNotLeakGoroutines(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Upstream = &goproxy.UpstreamConfig{IdleTimeout: 200 * time.Millisecond}
	proxySrv := httptest.NewServer(proxy)
	defer proxySrv.Close()
	client := newProxyClient(t, proxySrv.URL, nil)
	defer client.CloseIdleConnections()

	doOne := func() {
		resp, err := doGet(t, client, origin.URL)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		require.NoError(t, resp.Body.Close())
	}
	for i := 0; i < 5; i++ {
		doOne()
	}
	runtime.GC()
	time.Sleep(300 * time.Millisecond)
	runtime.GC()
	before := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		doOne()
	}
	proxy.CloseIdleUpstreamConnections()
	time.Sleep(400 * time.Millisecond)
	runtime.GC()
	after := runtime.NumGoroutine()
	if after > before+10 {
		t.Fatalf("goroutines grew from %d to %d over 50 requests", before, after)
	}
}
