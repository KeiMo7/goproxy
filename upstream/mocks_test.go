package upstream

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// ---- mock HTTP CONNECT / forward proxy -------------------------------------

type mockConnectProxy struct {
	listener net.Listener
	server   *httptest.Server

	mu          sync.Mutex
	connectAuth map[string]string // expected "user:pass" -> true (Basic)
	tokenHeader string
	tokenValue  string
	challenge   bool // force 407 on the first CONNECT without auth
	forwardAuth map[string]string

	connectCount atomic.Int64
	forwardCount atomic.Int64
	// seenAuth records every Proxy-Authorization header received, per CONNECT.
	seenAuth   []string
	seenAuthMu sync.Mutex
	// seenTargets records every CONNECT target.
	seenTargets   []string
	seenTargetsMu sync.Mutex
	// failDial makes the proxy accept TCP but refuse every CONNECT.
	failDial atomic.Bool
	// closeEarly closes the socket right after accepting, simulating an
	// unreachable/crashing hop.
	closeEarly atomic.Bool
}

func newMockConnectProxy(t *testing.T) *mockConnectProxy {
	t.Helper()
	p := &mockConnectProxy{
		connectAuth: map[string]string{},
		forwardAuth: map[string]string{},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p.listener = ln
	go p.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func (p *mockConnectProxy) addr() string { return p.listener.Addr().String() }

func (p *mockConnectProxy) requireBasic(user, pass string) {
	p.mu.Lock()
	p.connectAuth[user+":"+pass] = ""
	p.forwardAuth[user+":"+pass] = ""
	p.mu.Unlock()
}

func (p *mockConnectProxy) requireToken(header, value string) {
	p.mu.Lock()
	p.tokenHeader, p.tokenValue = header, value
	p.mu.Unlock()
}

func (p *mockConnectProxy) setChallengeFirst(b bool) { p.challenge = b }

func (p *mockConnectProxy) authsSeen() []string {
	p.seenAuthMu.Lock()
	defer p.seenAuthMu.Unlock()
	out := make([]string, len(p.seenAuth))
	copy(out, p.seenAuth)
	return out
}

func (p *mockConnectProxy) targetsSeen() []string {
	p.seenTargetsMu.Lock()
	defer p.seenTargetsMu.Unlock()
	out := make([]string, len(p.seenTargets))
	copy(out, p.seenTargets)
	return out
}

func (p *mockConnectProxy) serve() {
	for {
		c, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(c)
	}
}

func (p *mockConnectProxy) handle(c net.Conn) {
	defer c.Close()
	if p.closeEarly.Load() {
		return
	}
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		p.handleConnect(c, br, req)
		return
	}
	// Forward-proxy style absolute-form request: validate hop auth and proxy
	// the request to the target server over a fresh TCP connection.
	p.forwardCount.Add(1)
	if !p.checkForwardAuth(req) {
		fmt.Fprintf(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\nContent-Length: 0\r\n\r\n")
		return
	}
	p.forwardRequest(c, br, req)
}

func (p *mockConnectProxy) handleConnect(c net.Conn, br *bufio.Reader, req *http.Request) {
	// Count every CONNECT attempt, including the unauthenticated challenge.
	p.connectCount.Add(1)
	p.seenTargetsMu.Lock()
	p.seenTargets = append(p.seenTargets, req.Host)
	p.seenTargetsMu.Unlock()
	p.seenAuthMu.Lock()
	p.seenAuth = append(p.seenAuth, req.Header.Get("Proxy-Authorization"))
	p.seenAuthMu.Unlock()

	authOK := p.checkConnectAuth(req)
	if !authOK {
		fmt.Fprintf(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\nContent-Length: 0\r\n\r\n")
		// Keep the socket open so the client can retry on the same connection;
		// the test harness drives exactly one retry then closes.
		retry, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		p.connectCount.Add(1)
		p.seenTargetsMu.Lock()
		p.seenTargets = append(p.seenTargets, retry.Host)
		p.seenTargetsMu.Unlock()
		p.seenAuthMu.Lock()
		p.seenAuth = append(p.seenAuth, retry.Header.Get("Proxy-Authorization"))
		p.seenAuthMu.Unlock()
		if !p.checkConnectAuth(retry) {
			fmt.Fprintf(c, "HTTP/1.1 407 Proxy Authentication Required\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
			_ = c.Close()
			return
		}
	}
	if p.failDial.Load() {
		fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	upstream, err := net.Dial("tcp", req.Host)
	if err != nil {
		fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()
	fmt.Fprintf(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
	<-done
}

func (p *mockConnectProxy) checkConnectAuth(req *http.Request) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.connectAuth) == 0 && p.tokenValue == "" {
		return true
	}
	hdr := req.Header.Get("Proxy-Authorization")
	if p.tokenValue != "" {
		header := p.tokenHeader
		if header == "" {
			header = "Proxy-Authorization"
		}
		return req.Header.Get(header) == p.tokenValue
	}
	if !strings.HasPrefix(hdr, "Basic ") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hdr, "Basic "))
	if err != nil {
		return false
	}
	_, ok := p.connectAuth[string(raw)]
	return ok
}

func (p *mockConnectProxy) checkForwardAuth(req *http.Request) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.forwardAuth) == 0 {
		return true
	}
	hdr := req.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(hdr, "Basic ") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hdr, "Basic "))
	if err != nil {
		return false
	}
	_, ok := p.forwardAuth[string(raw)]
	return ok
}

func (p *mockConnectProxy) forwardRequest(c net.Conn, br *bufio.Reader, req *http.Request) {
	// A proxy request arrives in absolute-form: http.ReadRequest puts the
	// absolute URL into RequestURI rather than populating URL.
	if parsed, perr := url.Parse(req.RequestURI); perr == nil && parsed.Host != "" {
		req.URL = parsed
	}
	host := req.URL.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	up, err := net.Dial("tcp", host)
	if err != nil {
		fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer up.Close()
	// Rewrite the absolute-form proxy request into origin-form for the
	// origin server.
	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	if err := outReq.Write(up); err != nil {
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(up), req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if err := resp.Write(c); err != nil {
		return
	}
}

// ---- mock SOCKS5 server ----------------------------------------------------

type mockSocksServer struct {
	listener net.Listener

	user string
	pass string // empty = no auth required

	connectCount atomic.Int64
	seenUser     atomic.Value // string
	refuseAll    atomic.Bool
}

func newMockSocksServer(t *testing.T) *mockSocksServer {
	t.Helper()
	s := &mockSocksServer{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.listener = ln
	s.seenUser.Store("")
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *mockSocksServer) addr() string { return s.listener.Addr().String() }

func (s *mockSocksServer) requireAuth(user, pass string) { s.user, s.pass = user, pass }

func (s *mockSocksServer) serve() {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *mockSocksServer) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if s.user != "" {
		if !containsByte(methods, 0x01) {
			c.Write([]byte{0x05, 0xFF})
			return
		}
		c.Write([]byte{0x05, 0x01})
		// RFC 1929 sub-negotiation.
		head := make([]byte, 2)
		if _, err := io.ReadFull(br, head); err != nil {
			return
		}
		uLen := int(head[1])
		user := make([]byte, uLen+1)
		if _, err := io.ReadFull(br, user); err != nil {
			return
		}
		pLen := int(user[uLen])
		pass := make([]byte, pLen)
		if _, err := io.ReadFull(br, pass); err != nil {
			return
		}
		username := string(user[:uLen])
		if username != s.user || string(pass) != s.pass {
			c.Write([]byte{0x01, 0x01})
			return
		}
		s.seenUser.Store(username)
		c.Write([]byte{0x01, 0x00})
	} else {
		if !containsByte(methods, 0x00) {
			c.Write([]byte{0x05, 0xFF})
			return
		}
		c.Write([]byte{0x05, 0x00})
	}

	// CONNECT request: VER CMD RSV ATYP DST.ADDR DST.PORT
	front := make([]byte, 4)
	if _, err := io.ReadFull(br, front); err != nil {
		return
	}
	var host string
	switch front[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	portB := make([]byte, 2)
	if _, err := io.ReadFull(br, portB); err != nil {
		return
	}
	port := int(portB[0])<<8 | int(portB[1])
	target := net.JoinHostPort(host, strconv.Itoa(port))
	s.connectCount.Add(1)

	if s.refuseAll.Load() {
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	up, err := net.Dial("tcp", target)
	if err != nil {
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

func containsByte(xs []byte, b byte) bool {
	for _, x := range xs {
		if x == b {
			return true
		}
	}
	return false
}

// ---- test target HTTP server ----------------------------------------------

type targetServer struct {
	*httptest.Server
	requestCount atomic.Int64
	lastAuth     atomic.Value // string
}

func newTargetServer(t *testing.T) *targetServer {
	t.Helper()
	ts := &targetServer{}
	ts.lastAuth.Store("")
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		ts.requestCount.Add(1)
		ts.lastAuth.Store(r.Header.Get("Proxy-Authorization"))
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "echo:%s", string(body))
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		ts.requestCount.Add(1)
		io.WriteString(w, "ok")
	})
	ts.Server = httptest.NewServer(mux)
	t.Cleanup(ts.Server.Close)
	return ts
}

func (ts *targetServer) hostPort() string {
	return strings.TrimPrefix(ts.URL, "http://")
}

// dialFreePort returns a host:port nothing listens on, for unreachable-hop
// tests. It works by opening and immediately closing a listener (the port
// may in theory be recycled, but the kernel keeps it unavailable long enough
// for a test run).
func dialFreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}
