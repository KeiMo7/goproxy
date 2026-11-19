package upstreamtls

import (
	"net"
	"strings"

	"golang.org/x/net/idna"
)

// NormalizedName is a host name in the canonical form used for policy
// lookups and certificate comparison: ports removed, trailing dots removed,
// lowercased, internationalized names converted to their ASCII (punycode)
// representation. IP literals are returned in their canonical textual form.
type NormalizedName string

// IsIP reports whether the normalized name is an IP address literal.
func (n NormalizedName) IsIP() bool {
	return net.ParseIP(string(n)) != nil
}

// String returns the normalized name as a plain string.
func (n NormalizedName) String() string { return string(n) }

// NormalizeName canonicalizes a host as it appears in a request target or a
// relay URL. The input may include a port ("host.example:8443"), a trailing
// dot ("host.example."), mixed case ("Host.Example"), or an internationalized
// domain ("bücher.example"). The returned name is the single source of truth
// for both policy lookup and certificate comparison.
//
// An error is returned only for malformed internationalized names; callers
// must treat that as a configuration/request failure, never as a reason to
// skip verification.
func NormalizeName(host string) (NormalizedName, error) {
	// Drop any port. net.SplitHostPort understands bracketed IPv6 literals
	// such as "[2001:db8::1]:8443".
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else {
		// A bare IPv6 literal with brackets but no port also splits cleanly;
		// strip the brackets in that case.
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}

	// A trailing dot is an absolute-name marker, not part of the labels.
	host = strings.TrimSuffix(host, ".")

	// IP literals are not DNS names: canonicalize them and do not run them
	// through IDNA (which would reject numeric input).
	if ip := net.ParseIP(host); ip != nil {
		return NormalizedName(ip.String()), nil
	}

	// DNS names are case-insensitive; compare and register them lowercased.
	host = strings.ToLower(host)
	if host == "" {
		return "", &VerificationError{
			Kind:   FailureConfig,
			Reason: "no host name available to verify",
		}
	}

	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", &VerificationError{
			Kind:   FailureConfig,
			Target: host,
			Reason: "malformed internationalized domain name",
			Err:    err,
		}
	}
	return NormalizedName(ascii), nil
}
