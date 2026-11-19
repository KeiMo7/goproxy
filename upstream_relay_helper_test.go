package goproxy_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
)

// realTLSRelay is an encrypted upstream proxy built from a real goproxy
// instance, rather than a hand-written byte pump. It terminates a TLS
// listener with the relay's own certificate and transparently CONNECTs to
// targets, exactly like a production encrypted relay. It also records the
// SNI presented on its outer TLS listener.
type realTLSRelay struct {
	t       *testing.T
	server  *httptest.Server
	proxy   *goproxy.ProxyHttpServer
	addr    string
	mu      sync.Mutex
	sniSeen []string
}

func newRealTLSRelay(t *testing.T, cert tls.Certificate) *realTLSRelay {
	t.Helper()
	relayProxy := goproxy.NewProxyHttpServer()
	// Default ConnectAccept: the relay tunnels CONNECT requests without
	// MITM, so the inner target TLS handshake passes through untouched.
	relay := &realTLSRelay{t: t, proxy: relayProxy}

	server := httptest.NewUnstartedServer(relayProxy)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			relay.mu.Lock()
			relay.sniSeen = append(relay.sniSeen, hello.ServerName)
			relay.mu.Unlock()
			return nil, nil
		},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	relay.server = server
	relay.addr = server.Listener.Addr().String()
	return relay
}

func (r *realTLSRelay) url() *url.URL {
	u, err := url.Parse(r.server.URL)
	require.NoError(r.t, err)
	return u
}

func (r *realTLSRelay) sniSnapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.sniSeen))
	copy(out, r.sniSeen)
	return out
}

// newTLSServerWithVersions starts an HTTPS server constrained to the given
// TLS version range, used to test protocol-version policy enforcement.
func newTLSServerWithVersions(t *testing.T, cert tls.Certificate, min, max uint16) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: min, MaxVersion: max}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func deadlineIn(d time.Duration) time.Time { return time.Now().Add(d) }
