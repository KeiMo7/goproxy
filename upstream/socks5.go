package upstream

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SOCKS5 protocol constants (RFC 1928, RFC 1929).
const (
	socks5Version    = 0x05
	socks5UserPass   = 0x01 // username/password
	socks5NoAuth     = 0x00 // no authentication
	socks5NoneAcc    = 0xFF // no acceptable methods
	socks5Connect    = 0x01
	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04
	socks5AuthOK     = 0x00
)

// socks5ReplyNames maps SOCKS5 reply codes to human-readable, credential-free
// descriptions.
var socks5ReplyNames = map[byte]string{
	0x01: "general SOCKS server failure",
	0x02: "connection not allowed by ruleset",
	0x03: "network unreachable",
	0x04: "host unreachable",
	0x05: "connection refused",
	0x06: "TTL expired",
	0x07: "command not supported",
	0x08: "address type not supported",
}

// socks5Handshake performs method negotiation, optional user/pass
// authentication and a CONNECT request over an already-established
// connection to the SOCKS5 hop. The destination address is the next hop
// (or the final target when this is the last hop).
func socks5Handshake(conn net.Conn, auth Auth, targetAddr string) error {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return &HopError{Kind: FailureProtocol, Op: "socks",
			Err: fmt.Errorf("bad target address %q", targetAddr)}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return &HopError{Kind: FailureProtocol, Op: "socks",
			Err: fmt.Errorf("bad target port %q", portStr)}
	}

	// Method negotiation.
	if auth.Type == AuthBasic && auth.Username != "" {
		if len(auth.Username) > 255 || len(auth.Password) > 255 {
			return &HopError{Kind: FailureAuth, Op: "socks",
				Err: errors.New("username/password too long")}
		}
		if _, err := conn.Write([]byte{socks5Version, 2, socks5NoAuth, socks5UserPass}); err != nil {
			return &HopError{Kind: FailureProtocol, Op: "socks", Err: err}
		}
	} else {
		if _, err := conn.Write([]byte{socks5Version, 1, socks5NoAuth}); err != nil {
			return &HopError{Kind: FailureProtocol, Op: "socks", Err: err}
		}
	}

	buf := make([]byte, 256)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return &HopError{Kind: FailureProtocol, Op: "socks",
			Err: fmt.Errorf("reading method selection: %w", err)}
	}
	if buf[0] != socks5Version {
		return &HopError{Kind: FailureProtocol, Op: "socks",
			Err: fmt.Errorf("unexpected SOCKS version %d", buf[0])}
	}
	switch buf[1] {
	case socks5NoAuth:
	case socks5UserPass:
		if err := socks5UserPassAuth(conn, auth); err != nil {
			return err
		}
	case socks5NoneAcc:
		return &HopError{Kind: FailureAuth, Op: "socks",
			Err: errors.New("no acceptable authentication methods")}
	default:
		return &HopError{Kind: FailureProtocol, Op: "socks",
			Err: fmt.Errorf("unsupported auth method 0x%02x", buf[1])}
	}

	// CONNECT request.
	req := []byte{socks5Version, socks5Connect, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, socks5AtypIPv4)
			req = append(req, v4...)
		} else {
			req = append(req, socks5AtypIPv6)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return &HopError{Kind: FailureProtocol, Op: "socks", Err: errors.New("hostname too long")}
		}
		req = append(req, socks5AtypDomain, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return &HopError{Kind: FailureProtocol, Op: "socks", Err: err}
	}

	// Reply: VER REP RSV ATYP BND.ADDR BND.PORT
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return &HopError{Kind: FailureProtocol, Op: "socks",
			Err: fmt.Errorf("reading connect reply: %w", err)}
	}
	if buf[0] != socks5Version {
		return &HopError{Kind: FailureProtocol, Op: "socks",
			Err: fmt.Errorf("unexpected SOCKS reply version %d", buf[0])}
	}
	if buf[1] != socks5AuthOK {
		return &HopError{Kind: socks5ReplyKind(buf[1]), Op: "socks",
			Err: errors.New(socks5ReplyNames[buf[1]])}
	}
	var addrLen int
	switch buf[3] {
	case socks5AtypIPv4:
		addrLen = 4
	case socks5AtypIPv6:
		addrLen = 16
	case socks5AtypDomain:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return &HopError{Kind: FailureProtocol, Op: "socks", Err: err}
		}
		addrLen = int(buf[0])
	default:
		return &HopError{Kind: FailureProtocol, Op: "socks",
			Err: fmt.Errorf("unsupported address type 0x%02x in reply", buf[3])}
	}
	// Consume bound address + bound port; the caller doesn't need them.
	if _, err := io.ReadFull(conn, buf[:addrLen+2]); err != nil {
		return &HopError{Kind: FailureProtocol, Op: "socks",
			Err: fmt.Errorf("reading bound address: %w", err)}
	}
	return nil
}

func socks5UserPassAuth(conn net.Conn, auth Auth) error {
	msg := []byte{0x01, byte(len(auth.Username))}
	msg = append(msg, auth.Username...)
	msg = append(msg, byte(len(auth.Password)))
	msg = append(msg, auth.Password...)
	if _, err := conn.Write(msg); err != nil {
		return &HopError{Kind: FailureProtocol, Op: "socks", Err: err}
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return &HopError{Kind: FailureProtocol, Op: "socks",
			Err: fmt.Errorf("reading auth reply: %w", err)}
	}
	if resp[0] != 0x01 || resp[1] != socks5AuthOK {
		return &HopError{Kind: FailureAuth, Op: "socks",
			Err: errors.New("username/password authentication rejected")}
	}
	return nil
}

func socks5ReplyKind(code byte) FailureKind {
	switch code {
	case 0x02, 0x07, 0x08:
		return FailureProtocol
	case 0x03, 0x04, 0x06:
		return FailureUnreachable
	case 0x05:
		return FailureRefused
	default:
		return FailureProtocol
	}
}
