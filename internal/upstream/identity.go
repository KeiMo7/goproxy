package upstream

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Identity is the reuse key of one upstream connection. Two requests may
// share a connection only when every field matches, so connections built
// under different trust or authentication contexts are never mixed.
type Identity struct {
	// Scheme is "http" or "https".
	Scheme string
	// Host is the canonical lower-case host name (or IP literal) without
	// brackets or port.
	Host string
	// Port is the canonical decimal port.
	Port string
	// SNI is the TLS server name actually sent on the wire ("" for plain
	// text).
	SNI string
	// Trust is a digest of every TLS input that affects verification:
	// verification mode, root CAs, client certificates, ALPN, min/max
	// versions, cipher suites and renegotiation policy.
	Trust string
	// Auth is a digest of the request's authentication context. Requests
	// with different credentials never share a connection.
	Auth string
}

// Key renders the identity as a single map key.
func (id Identity) Key() string {
	return id.Scheme + "://" + net.JoinHostPort(id.Host, id.Port) +
		"\x00sni=" + id.SNI + "\x00trust=" + id.Trust + "\x00auth=" + id.Auth
}

// Target returns the dial target "host:port".
func (id Identity) Target() string {
	return net.JoinHostPort(id.Host, id.Port)
}

// CanonicalHostPort normalizes a host:port (with an optional default port)
// into an Identity's Host and Port fields. Hostnames are lower-cased and
// IPv6 literals are stripped of their brackets.
func CanonicalHostPort(hostport, defaultPort string) (host, port string, err error) {
	if hostport == "" {
		return "", "", errors.New("goproxy: empty upstream host")
	}
	h, p, splitErr := net.SplitHostPort(hostport)
	if splitErr != nil {
		// No port: treat the whole value as a host. A bare IPv6 literal
		// contains colons but no valid host:port split.
		if ip := net.ParseIP(strings.Trim(hostport, "[]")); ip != nil {
			h, p = ip.String(), ""
		} else if strings.Contains(hostport, ":") {
			return "", "", fmt.Errorf("goproxy: invalid upstream address %q", hostport)
		} else {
			h, p = hostport, ""
		}
	}
	if h == "" {
		return "", "", fmt.Errorf("goproxy: empty upstream host in %q", hostport)
	}
	if p == "" {
		p = defaultPort
	}
	if p == "" {
		return "", "", fmt.Errorf("goproxy: missing upstream port in %q", hostport)
	}
	if n, convErr := strconv.Atoi(p); convErr != nil || n <= 0 || n > 65535 {
		return "", "", fmt.Errorf("goproxy: invalid upstream port in %q", hostport)
	}
	return canonicalHost(h), p, nil
}

func canonicalHost(h string) string {
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// AuthDigest derives an authentication fingerprint from request headers.
// The digest covers credentials that select an upstream identity (proxy
// authorization, origin authorization, cookies or a caller-supplied token)
// without ever retaining their cleartext. An empty slice means "no
// authentication context".
func AuthDigest(parts ...string) string {
	nonEmpty := false
	for _, p := range parts {
		if p != "" {
			nonEmpty = true
			break
		}
	}
	if !nonEmpty {
		return ""
	}
	h := sha256.New()
	for _, p := range parts {
		// Length-prefix every part so that ("ab","c") and ("a","bc") do
		// not collide.
		fmt.Fprintf(h, "%d:", len(p))
		_, _ = h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TrustDigest derives a stable fingerprint of everything in cfg that can
// change the result of verifying an upstream certificate. Two configs that
// would accept exactly the same certificate for a given name produce the
// same digest; any difference in trust inputs produces a different one.
func TrustDigest(cfg *tls.Config) string {
	if cfg == nil {
		return "nil"
	}
	h := sha256.New()
	w := func(tag string, vals ...string) {
		fmt.Fprintf(h, "%s=%d:", tag, len(vals))
		for _, v := range vals {
			fmt.Fprintf(h, "%d:%s|", len(v), v)
		}
	}
	w("insecure", strconv.FormatBool(cfg.InsecureSkipVerify))
	w("sni", cfg.ServerName)
	w("minver", strconv.Itoa(int(cfg.MinVersion)))
	w("maxver", strconv.Itoa(int(cfg.MaxVersion)))
	w("alpn", strings.Join(cfg.NextProtos, ","))
	w("cipher", intSlice(cfg.CipherSuites))
	w("renego", strconv.Itoa(int(cfg.Renegotiation)))
	w("roots", rootSubjects(cfg.RootCAs))
	w("certs", certificateDigests(cfg.Certificates))
	if cfg.GetClientCertificate != nil {
		w("getclientcert", "custom")
	}
	return hex.EncodeToString(h.Sum(nil))
}

func intSlice(v []uint16) string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = strconv.Itoa(int(x))
	}
	return strings.Join(out, ",")
}

// rootSubjects digests the root CA pool. CertPool exposes no iteration API,
// so the deprecated Subjects list is used when available; a pool without
// enumerable roots is fingerprinted by identity plus size, which keeps a
// custom pool distinct from the system pool.
func rootSubjects(pool *x509.CertPool) string {
	if pool == nil {
		return "nil"
	}
	subjects := pool.Subjects() //nolint:staticcheck // no alternative enumeration API
	encoded := make([]string, len(subjects))
	for i, s := range subjects {
		sum := sha256.Sum256(s)
		encoded[i] = hex.EncodeToString(sum[:8])
	}
	sort.Strings(encoded)
	return fmt.Sprintf("n=%d;%s", len(encoded), strings.Join(encoded, ","))
}

func certificateDigests(certs []tls.Certificate) string {
	if len(certs) == 0 {
		return ""
	}
	encoded := make([]string, len(certs))
	for i := range certs {
		if len(certs[i].Certificate) == 0 {
			encoded[i] = "empty"
			continue
		}
		sum := sha256.Sum256(certs[i].Certificate[0])
		encoded[i] = hex.EncodeToString(sum[:8])
	}
	return strings.Join(encoded, ",")
}
