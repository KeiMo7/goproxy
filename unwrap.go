package goproxy

import (
	"crypto/tls"
	"net"
)

// connUnwrapper is implemented by proxy connection wrappers that can expose
// the connection they wrap.
type connUnwrapper interface {
	NetConn() net.Conn
}

// unwrapConn strips the wrappers the proxy puts around a hijacked client
// connection (buffered readers and TLS) so a probe can reach the underlying
// socket without disturbing buffered state.
func unwrapConn(conn net.Conn) net.Conn {
	seen := 0
	for conn != nil && seen < 8 {
		switch c := conn.(type) {
		case *tls.Conn:
			conn = c.NetConn()
		case connUnwrapper:
			conn = c.NetConn()
		default:
			return conn
		}
		seen++
	}
	return conn
}
