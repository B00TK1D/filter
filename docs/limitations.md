# Limitations

`proxyd` is a proof of concept for a controlled network. This page states
clearly what it **cannot** intercept or guarantee. None of these are bugs;
they are properties of DNS redirection and TLS interception. See
[`PLAN.md` §5 and §13](../PLAN.md).

## DNS-based redirection only affects clients using this resolver

`proxyd` redirects traffic by answering DNS queries with its own address and by
firewall-redirecting TCP/80 and TCP/443. Traffic that does not use this DNS
server, or that is not on a redirected port, is unaffected:

- **Hard-coded IPs.** Applications that connect to literal IP addresses never
  ask DNS and are not redirected.
- **VPNs and tunnels.** Traffic inside an encrypted tunnel is invisible to the
  DNS/policy rules; whoever terminates the tunnel controls resolution.
- **Custom resolvers in the app.** An app configured with its own resolver, or
  using DoH/DoT directly, bypasses the DNS answer. Firewall redirects of
  TCP/443 still capture plain TCP TLS to that resolver, but the DNS protocol
  itself may be carried inside the tunneled/encrypted channel.

## DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT)

- **DoT (TCP/UDP 853)** can be blocked outright; the deploy script does this
  by default (`BLOCK_DOT=yes`), which pushes well-behaved clients back to this
  resolver.
- **DoH (TCP/443)** is indistinguishable from ordinary HTTPS. A domain
  blocklist can block well-known DoH endpoints by name, but that is
  **best-effort and cannot be guaranteed** from a domain list alone. Clients
  with a hard-coded alternate DoH endpoint, an IP literal, or a nonstandard
  endpoint will bypass DNS policy.

## QUIC / HTTP/3 (UDP/443)

DNS interception and TCP/80+443 interception **do not** intercept QUIC/HTTP3,
which runs over UDP/443. The deploy script can reject or drop client UDP/443
(`udp443.mode`) so compatible clients fall back to TCP-based HTTP/2 or
HTTP/1.1. Some applications will not fall back and will simply fail — this is
explicit and expected. Full QUIC interception is a future, separate project and
is an explicit non-goal.

## ECH (Encrypted Client Hello)

Encrypted Client Hello hides the SNI needed to choose a certificate and enforce
domain policy. When ECH is in use, `proxyd` cannot see the intended hostname and
must fall back to its unknown-SNI policy (reject, or best-effort passthrough).

## Certificate pinning and custom trust stores

Any client that pins a server certificate/public key, or that ships an embedded
trust store, will reject `proxyd`'s leaf certificate. These cannot be
transparently intercepted. Options are to bypass them (firewall/UID/mark) or
accept the connection failure. `proxyd` does not attempt to defeat pinning or
ECH.

## Client certificates, ECH, and other TLS specialties

Mutual TLS (client certificates), TLS 1.3 ECH, and exotic extensions may fail
or degrade. `proxyd` presents its own leaf and establishes a separate upstream
connection; it does not forward client certificates to the origin.

## IP-literal URLs and missing SNI

- `https://192.0.2.10/` has no hostname for policy and no SNI; with the default
  `tls.unknown_sni: reject`, such connections are closed with a
  connection-level log.
- `tls.unknown_sni: passthrough` relays a non-SNI connection to its original
  destination via `SO_ORIGINAL_DST`. It **cannot** read the URL or enforce
  domain policy, and it only works when a real, non-proxy original destination
  can be recovered — which is not the case when DNS has rewritten the
  destination to the proxy. Treat it as a best-effort compatibility escape
  hatch, not an enforcement mechanism.

## QUIC/HTTP3 and non-TCP protocols

Only TCP/80 and TCP/443 are intercepted. Everything else (SSH, SMTP, custom
protocols, arbitrary ports) is untouched. `proxyd` deliberately does not
provide a generic TCP tunnel that bypasses policy.

## IPv6

IPv6 interception is opt-in (`dns.ipv6_enabled`). Only enable it once the
listeners, firewall rules, and upstream routing actually work for IPv6.
Otherwise `proxyd` returns NODATA for `AAAA` queries rather than handing out an
unusable address.

## Enforcement trade-off

Defaults are **fail-closed**: blocked names get `NXDOMAIN`, and unknown TLS
destinations are rejected. This maximizes enforcement but can break
applications that legitimately lack SNI or use pinned certificates. Each
deployment must choose between strict enforcement and application
compatibility, and document that choice.

## Not production multi-platform software

Transparent interception is implemented for Linux only. The PoC makes no claim
about other operating systems, distributed policy management, high availability,
or scale.
