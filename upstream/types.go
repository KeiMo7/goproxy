// Package upstream adds multi-hop upstream proxy chaining to goproxy.
//
// A Chain is an ordered list of Hop objects. Each hop is reached through
// its own tunnel type (HTTP CONNECT, SOCKS5, or plain HTTP forwarding) and
// authenticates with its own credentials, which are never shared with any
// other hop, logged, or rendered into errors.
//
// A Router selects a chain (plus optional fallback chains) per request
// based on the destination hostname or IP network. Router configs are
// hot-swappable: replacing the config never interrupts in-flight requests.
//
// When no Router is attached to a ProxyHttpServer the proxy behaves exactly
// as before this package existed.
package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"time"
)

// TunnelType describes how a single hop is traversed.
type TunnelType string

const (
	// TunnelConnect speaks HTTP CONNECT to the hop. The resulting tunnel
	// carries any downstream protocol (TLS, nested CONNECT/SOCKS, …).
	TunnelConnect TunnelType = "connect"
	// TunnelSOCKS5 speaks SOCKS5 (RFC 1928), optionally with username/password
	// authentication (RFC 1929).
	TunnelSOCKS5 TunnelType = "socks5"
	// TunnelForward sends ordinary (absolute-form) HTTP requests to the hop.
	// It is only valid as the final hop and only for plain HTTP requests;
	// HTTPS targets require a tunneling final hop.
	TunnelForward TunnelType = "forward"
)

// AuthType selects how a hop authenticates.
type AuthType string

const (
	// AuthNone performs no authentication.
	AuthNone AuthType = "none"
	// AuthBasic sends HTTP Basic credentials (Proxy-Authorization for HTTP
	// proxies, RFC 1929 username/password for SOCKS5 hops).
	AuthBasic AuthType = "basic"
	// AuthToken sends a static token in a configurable header
	// (default: Proxy-Authorization).
	AuthToken AuthType = "token"
)

// Auth carries the credentials of a single hop. A zero Auth means "no auth".
//
// Credentials are held as value types and only ever serialized on the wire
// toward the hop they belong to. They are excluded from logs, events and
// error strings (see HopError and Fingerprint).
type Auth struct {
	// Type is the authentication scheme. The zero value means AuthNone.
	Type AuthType
	// Username/Password are used by AuthBasic and for SOCKS5 user/pass.
	Username string
	Password string
	// Token is used by AuthToken.
	Token string
	// Header names the header carrying Token for AuthToken.
	// Defaults to "Proxy-Authorization".
	Header string
	// Scheme prefixes the token value for AuthToken (e.g. "Bearer").
	// Empty means the raw token is sent.
	Scheme string
}

// Hop is one proxy in a chain.
type Hop struct {
	// Name is a human-readable label used in errors and events. It must not
	// contain credentials.
	Name string
	// Address is the host:port of the hop.
	Address string
	// Tunnel selects the protocol used to traverse the hop.
	// Zero value defaults to TunnelConnect.
	Tunnel TunnelType
	// Auth is the hop-local credential set.
	Auth Auth
	// TLS, when true, wraps the connection to this hop in TLS before speaking
	// its proxy protocol (HTTPS-proxy style).
	TLS bool
	// DialTimeout bounds the TCP dial of this hop. Zero means no per-hop
	// timeout (the request context still applies).
	DialTimeout time.Duration
	// HandshakeTimeout bounds the proxy/SOCKS handshake with this hop.
	HandshakeTimeout time.Duration
	// ChallengeFirst, when true, makes the first CONNECT attempt carry no
	// credentials. On a 407 response the same hop is retried immediately with
	// the configured credentials, without rebuilding the rest of the chain and
	// without replaying any request body. Default (false) sends credentials
	// preemptively.
	ChallengeFirst bool
}

// Chain is an ordered, immutable list of hops with an identity used for
// connection pooling and observability.
type Chain struct {
	// ID uniquely identifies the chain within a Config. It is part of the
	// tunnel pool key, so changing ID forces new tunnels.
	ID string
	// Hops are traversed in order; the last hop connects (or forwards) to
	// the final destination.
	Hops []Hop
}

// FailureKind classifies a hop failure so callers can distinguish "unreachable",
// "timeout", "auth failure" and so on without string matching.
type FailureKind string

const (
	FailureUnreachable FailureKind = "unreachable"
	FailureTimeout     FailureKind = "timeout"
	FailureAuth        FailureKind = "auth"
	FailureRefused     FailureKind = "refused"
	FailureProtocol    FailureKind = "protocol"
	FailureCanceled    FailureKind = "canceled"
)

// FailoverPolicy controls which failure kinds of the primary chain trigger
// fallback to the next chain. The zero value fails over on every kind except
// authentication and context cancellation.
type FailoverPolicy struct {
	// OnKinds explicitly lists the kinds that trigger failover. When empty
	// the default set applies (unreachable, timeout, refused, protocol).
	OnKinds []FailureKind
}

func (p FailoverPolicy) allows(kind FailureKind) bool {
	if len(p.OnKinds) == 0 {
		switch kind {
		case FailureUnreachable, FailureTimeout, FailureRefused, FailureProtocol:
			return true
		default:
			return false
		}
	}
	for _, k := range p.OnKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Route binds a destination match to a primary chain and backup chains.
type Route struct {
	// Primary is the chain ID tried first.
	Primary string
	// Backups are chain IDs tried, in order, when the primary (or an earlier
	// backup) fails with a kind allowed by Policy.
	Backups []string
	// Policy tunes failover behavior.
	Policy FailoverPolicy
	// HostSuffixes matches destination hostnames case-insensitively. A suffix
	// "example.com" matches "example.com" and "a.example.com".
	HostSuffixes []string
	// Hosts matches exact destination hostnames (case-insensitive), port
	// stripped before matching.
	Hosts []string
	// CIDRs matches literal destination IP addresses.
	CIDRs []*net.IPNet
	// Default marks the route used when nothing else matches. At most one
	// default route may exist per Config.
	Default bool
}

// Config is a snapshot of router configuration. Build a new one and call
// Router.Replace to hot-reload; in-flight requests keep using the old snapshot.
type Config struct {
	// Version labels the snapshot. It participates in the tunnel fingerprint,
	// so Replace with a bumped Version forces new tunnels even if the chain
	// contents look identical.
	Version string
	Chains  []Chain
	Routes  []Route
}

// Validate checks internal consistency of the config.
func (c *Config) Validate() error {
	seen := map[string]bool{}
	defaults := 0
	for _, ch := range c.Chains {
		if ch.ID == "" {
			return errors.New("upstream: chain with empty ID")
		}
		if seen[ch.ID] {
			return errors.New("upstream: duplicate chain ID " + ch.ID)
		}
		seen[ch.ID] = true
		if len(ch.Hops) == 0 {
			return errors.New("upstream: chain " + ch.ID + " has no hops")
		}
		for i, h := range ch.Hops {
			if h.Address == "" {
				return errors.New("upstream: chain " + ch.ID + " hop " + itoa(i) + " has no address")
			}
			if h.Tunnel == "" {
				continue
			}
			switch h.Tunnel {
			case TunnelConnect, TunnelSOCKS5, TunnelForward:
			default:
				return errors.New("upstream: chain " + ch.ID + " hop " + itoa(i) + " has unknown tunnel type " + string(h.Tunnel))
			}
			if h.Tunnel == TunnelForward && i != len(ch.Hops)-1 {
				return errors.New("upstream: forward hop is only valid as the last hop (chain " + ch.ID + ")")
			}
		}
	}
	for i, rt := range c.Routes {
		if !seen[rt.Primary] {
			return errors.New("upstream: route " + itoa(i) + " references unknown chain " + rt.Primary)
		}
		for _, b := range rt.Backups {
			if !seen[b] {
				return errors.New("upstream: route " + itoa(i) + " references unknown backup chain " + b)
			}
		}
		if rt.Default {
			defaults++
		}
	}
	if defaults > 1 {
		return errors.New("upstream: multiple default routes")
	}
	return nil
}

// fingerprint hashes everything that can change tunnel behavior. Only a hash
// is ever exposed, so credential values cannot be recovered from it; the hash
// still lets the pool tell "same credentials" from "rotated credentials".
func fingerprint(version string, ch *Chain) string {
	h := sha256.New()
	write := func(s string) { h.Write([]byte(s)); h.Write([]byte{0}) }
	write(version)
	write(ch.ID)
	for _, hop := range ch.Hops {
		write(hop.Name)
		write(hop.Address)
		write(string(hop.Tunnel))
		if hop.TLS {
			write("tls")
		}
		if hop.ChallengeFirst {
			write("challenge-first")
		}
		a := hop.Auth
		write(string(a.Type))
		write(a.Username)
		write(a.Password)
		write(a.Token)
		write(a.Header)
		write(a.Scheme)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// matchesHost reports whether host (with port stripped) matches the route.
func (r *Route) matchesHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	if name, _, err := net.SplitHostPort(h); err == nil {
		h = name
	}
	for _, exact := range r.Hosts {
		if h == strings.ToLower(exact) {
			return true
		}
	}
	for _, suffix := range r.HostSuffixes {
		s := strings.ToLower(strings.TrimPrefix(suffix, "."))
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		for _, n := range r.CIDRs {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
