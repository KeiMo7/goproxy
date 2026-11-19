# Upstream TLS trust policy

By default goproxy historically skipped verification of every upstream TLS
certificate (`Tr.TLSClientConfig.InsecureSkipVerify = true`). The upstream
trust feature replaces that blanket bypass with per-target, per-hop
verification while keeping every existing default working when no policy is
configured.

## Concepts

- **Registry** (`proxy.TrustRegistry()`): holds the whole trust
  configuration and serves immutable snapshots. An empty registry changes
  nothing about verification strength — every target uses system trust.
- **Target policy**: one normalized target name maps to one of three modes:
  - `TrustModeSystemTrust` — verify against system roots (or the roots
    configured on `Tr.TLSClientConfig.RootCAs`) and the requested name.
  - `TrustModePrivateCA` — verify against an explicitly registered issuer
    group, plus the requested name. Targets without a matching registration
    never inherit this trust.
  - `TrustModeSkipVerify` — an explicit, per-target bypass. Unlike a global
    switch, every bypass is recorded on the request's TLS report.
- **Snapshot / version**: each `ReplaceTrustPolicy` installs a new immutable
  snapshot with an incremented version. Connections established under an
  older snapshot keep using it for their whole lifetime; the new policy only
  affects subsequently established connections. The version appears on every
  hop report, making old-vs-new behavior observable.

## Configuring targets and issuer groups

```go
group, err := goproxy.NewTrustGroup(internalCAPEM)
if err != nil { /* malformed PEM: fail closed */ }

version, err := proxy.ReplaceTrustPolicy(
    map[string]*goproxy.TrustGroupBuilder{"internal": group},
    []goproxy.TrustTargetEntry{
        {Host: "svn.internal", Mode: goproxy.TrustModePrivateCA, Group: "internal"},
        {Host: "legacy.badcert.example", Mode: goproxy.TrustModeSkipVerify},
        // Per-target protocol bounds are supported:
        // {Host: "strict.example", Mode: goproxy.TrustModePrivateCA,
        //  Group: "internal", MinTLSVersion: tls.VersionTLS12},
    },
)
```

The whole replacement is validated before it becomes effective. Unknown
group references, malformed PEM, or inverted version bounds return an error
and leave the previous configuration in place — a bad policy load never
degrades into trusting everything.

If the same target appears more than once in one replacement, entries are
keyed by normalized name and the last explicit entry wins; the outcome never
depends on map iteration order.

## Name normalization

Policy names and certificate comparison use one canonical form, produced by
`goproxy.NormalizeHostName`:

- ports removed (`host:8443` → `host`)
- trailing dot trimmed (`host.` → `host`)
- letters lowercased (`HOST` → `host`)
- internationalized names converted to punycode (`bücher.example` →
  `xn--bcher-kva.example`)
- IP literals canonicalized; an IP target compares against IP SANs only and
  never falls back to DNS matching or to skipping the check

## The narrowed legacy switch

`Tr.TLSClientConfig.InsecureSkipVerify` still works, but its scope can be
narrowed to an explicit target list:

```go
proxy.Tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
_ = proxy.SetLegacySkipVerifyTargets([]string{"only-this.example"})
```

With an empty list (the default) the switch keeps its original blanket scope
for backward compatibility, but every bypass now appears in the request's
`UpstreamTLSReport` rather than happening silently. Unlisted targets always
fall back to system trust.

## Observable per-request reports

Each upstream TLS hop records a structured report:

```go
proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
    for _, r := range goproxy.UpstreamTLSReports(ctx.Req.Context()) {
        // r.Hop ("target" or "relay"), r.Target, r.ServerName,
        // r.PolicyVersion, r.Mode, r.Skipped, r.TLSVersion,
        // r.PeerFingerprint
        _ = r
    }
    return resp
})
```

The peer fingerprint lets callers detect certificate rotation between
requests; the policy version distinguishes connections built before and
after a reload.

## Structured failure categories

Upstream TLS failures are returned as `*goproxy.TLSVerificationError` with a
stable `Kind`, suitable for counting and aggregation without parsing
strings:

| Kind                       | Meaning                                              |
| -------------------------- | ---------------------------------------------------- |
| `TLSFailureNameMismatch`   | cert name/IP does not match the requested hop        |
| `TLSFailureUntrustedIssuer`| chain does not reach a trusted issuer                |
| `TLSFailureExpired`        | cert expired or not yet valid                        |
| `TLSFailureProtocolVersion`| peer only offers a forbidden TLS version             |
| `TLSFailurePeerClosed`     | peer hung up during the handshake                    |
| `TLSFailureConfig`         | bad policy/name input; fails closed, never trusts all|
| `TLSFailureHandshake`      | any other handshake failure                          |

Extract with the standard `errors.As`:

```go
var ve *goproxy.TLSVerificationError
if errors.As(err, &ve) {
    metric(ve.Kind, ve.Target, ve.Hop)
}
```

## Encrypted upstream relays (two independent hops)

When the transport routes through an HTTPS proxy (`Tr.Proxy` returns an
`https://` URL), the proxy performs two independent handshakes:

1. the **relay hop**, verified with the relay's own host name and the policy
   registered for that name;
2. after the CONNECT tunnel, the **target hop**, verified with the target's
   own name and the target's policy.

The two handshakes never share a `ServerName`, root pool, or version bound,
and each produces its own report. A relay presenting an untrusted
certificate fails on the relay hop before any target handshake is attempted.

## Connection pool isolation

One outbound transport (and therefore one connection cache) is maintained
per effective trust policy. The cache key includes the policy version, mode,
TLS bounds, root pool, and bypass flag, so two requests to the same host
under different trust configurations can never reuse each other's pooled
connections, while identical policies still reuse connections normally.
