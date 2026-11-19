package upstream

import (
	"crypto/tls"
	"net"
)

// terminalTLS wraps an end-to-end chain tunnel with TLS toward the final
// destination. goproxy's default transport also skips verification; callers
// needing verification can post-process via a request handler.
func terminalTLS(conn net.Conn, serverName string) (net.Conn, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
	}
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}
