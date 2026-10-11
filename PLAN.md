# PLAN.md --- Transparent DNS + HTTP(S) Filtering Proxy

## 1. Goal and scope

Implement a Linux-first, Go-based transparent DNS and HTTP/HTTPS
interception service for a controlled network. For the proof of concept,
it must log DNS queries and HTTP(S) connection/request metadata, load a
simple domain blocklist, and block matching domains. Clients do not
support explicit proxy settings.

The service consists of: - An authoritative-for-policy DNS forwarder
that answers client queries using configured interception addresses. -
Transparent TCP interception for HTTP (port 80) and HTTPS (port 443),
installed with OS firewall rules. - An HTTP reverse-proxy/request
handler and HTTPS TLS interception (MITM) using a locally generated root
CA trusted by managed clients. - Shared domain policy, structured
logging, configuration, and health endpoints.

**Important:** DNS rewriting by itself is not sufficient for transparent
proxying. Because the rewritten destination is the proxy's IP, the
original hostname usually has to be recovered from the HTTP `Host`
header or TLS SNI. OS-level interception is still required to capture
connections and handle nonstandard cases. This is not a universal way to
intercept arbitrary protocols or traffic on arbitrary ports.

## 2. Recommended architecture

Use small, testable Go packages: - `cmd/proxyd/`: entry point,
startup/shutdown, config validation. - `internal/config/`: config file,
defaults, validation. - `internal/dns/`: UDP/TCP DNS listener, upstream
forwarding, policy, A/AAAA rewriting, query logging. -
`internal/policy/`: normalized domain matching, allowlist/exception
precedence, blocklist reload. - `internal/intercept/`: transparent TCP
listener and original-destination helpers for the supported Linux
firewall mode. - `internal/httpproxy/`: HTTP parsing, request logging,
upstream forwarding, response handling. - `internal/tlsmitm/`: root CA
loading/creation, leaf certificate cache, TLS handshake and ALPN. -
`internal/logging/`: structured logs, redaction, rotation/output
configuration. - `internal/health/`: readiness and liveness endpoints. -
`deploy/`: example config, systemd unit, and firewall setup/teardown
scripts. - `tests/`: unit, integration, and network-namespace tests.

Keep DNS, policy, logging, and request handling independent of firewall
implementation. Start with Linux as the supported platform; hide
OS-specific interception behind interfaces rather than claiming
cross-platform transparency.

## 3. DNS behavior

-   Listen on configurable UDP and TCP DNS ports (default service port
    53 when run with appropriate privileges).
-   Forward upstream queries through a separately configured resolver
    path that bypasses the interception rules to prevent loops.
-   For ordinary A and AAAA queries, return configured interception
    IPv4/IPv6 addresses. Only return an address family for which the
    host is actually listening and reachable. If IPv6 interception is
    disabled, use a documented configurable policy (prefer NODATA over
    returning an unusable IPv6 address).
-   For blocked names, return configurable `NXDOMAIN` or sinkhole
    behavior; default to `NXDOMAIN`. Log the query and policy decision.
-   Define behavior for CNAME chains, multiple questions, reverse
    lookups, DNSSEC/DO flags, TTLs, and unsupported record types.
    Forward record types not rewritten by policy unless configured
    otherwise.
-   Normalize names case-insensitively, remove a trailing dot for
    matching, and apply exact-domain plus subdomain matching
    (`example.com` matches itself and `*.example.com`, not
    `notexample.com`).
-   Include optional allowlist entries and deterministic precedence:
    explicit allowlist, then blocklist, then default policy.
-   Support both UDP and TCP DNS, bounded timeouts, request limits, and
    graceful shutdown.
-   Clearly document that DNS-over-HTTPS (DoH), DNS-over-TLS (DoT),
    VPNs, hard-coded IPs, and other encrypted/custom resolution paths
    may bypass DNS policy. Provide optional firewall rules to block
    common bypass paths (e.g. outbound TCP/UDP 853); DoH endpoint
    blocking is best-effort and cannot be guaranteed from a domain list
    alone.

## 4. Transparent TCP and HTTP/HTTPS handling

-   Provide a documented Linux `nftables` setup that redirects TCP/80
    and TCP/443 to the service. Prefer a design that can recover the
    original destination when available, and explicitly document what
    destination information is lost when DNS has rewritten the
    destination to the proxy address.
-   Prevent proxy-originated upstream connections from re-entering
    interception rules. Use a dedicated process UID, packet mark,
    cgroup, or equivalent carefully tested bypass rule.
-   Listen separately for intercepted HTTP and HTTPS, or reliably
    classify the initial bytes without consuming them.
-   HTTP: parse origin-form and absolute-form requests; derive the
    target host from the request authority/`Host` header; reject
    malformed or ambiguous requests; normalize and check policy before
    forwarding. Preserve methods, paths, query strings, headers,
    streaming bodies, redirects, and response status/headers. Remove
    hop-by-hop headers and handle `Connection` semantics correctly.
-   HTTPS: read the TLS ClientHello, use SNI to choose the hostname,
    check policy, and present a generated leaf certificate signed by the
    local root CA. Establish a separate TLS connection to the actual
    upstream hostname and verify the upstream certificate using the
    system trust store. Never disable upstream certificate verification
    by default.
-   Cache leaf certificates by normalized hostname with bounded
    size/expiry. Support TLS 1.2 and 1.3, and negotiate HTTP/1.1 and
    HTTP/2 via ALPN where supported by Go's TLS stack. Preserve
    streaming and support WebSocket upgrades and common long-lived
    requests where feasible.
-   Log a request only after its host is known. For TLS connections
    where no usable SNI is available, use an explicit configurable
    policy: reject with a clear connection-level log by default, or
    offer a carefully documented pass-through mode that logs only
    connection metadata and cannot inspect URL paths or reliably enforce
    domain policy.
-   Support normal hostname-based traffic first. IP-literal URLs,
    missing SNI, ECH, client certificate authentication, certificate
    pinning, custom trust stores, and applications with embedded trust
    roots may fail or require bypass rules. Do not claim these are
    transparently interceptable.
-   A valid client-facing certificate is required for HTTPS
    interception. A locally trusted root makes the proxy able to
    impersonate hostnames for which it issues certificates; this is a
    powerful capability and must be treated as a security boundary.

## 5. HTTP/3, QUIC, and protocol compatibility

-   DNS interception and TCP/80+443 interception do not intercept
    QUIC/HTTP/3, which uses UDP/443.
-   For the initial release, add an optional firewall rule to reject or
    drop client UDP/443 so compatible clients can fall back to TCP-based
    HTTP/2 or HTTP/1.1. Make this behavior explicit in config/deployment
    docs; some apps will fail rather than fall back.
-   Do not silently pretend HTTP/3 is supported. Treat full QUIC
    interception as a future, separate project with substantial protocol
    and TLS complexity.
-   Cover IPv4 and IPv6 deliberately. Do not advertise interception for
    an address family until firewall rules, listeners, and upstream
    routing are tested.
-   Document that ECH can hide the hostname needed for MITM, and TLS
    pinning/custom trust can reject the generated certificate. Offer a
    deny, bypass, or fail-closed policy per deployment, with secure
    defaults.
-   DNS-based redirection affects only traffic that uses this DNS
    server. It cannot force arbitrary hard-coded-IP or tunneled traffic
    through the proxy.

## 6. Blocklist and policy

-   Initial format: one domain per line, allowing blank lines and
    comments beginning with `#`; optionally accept common hosts-file
    lines (`0.0.0.0 domain` / `127.0.0.1 domain`).
-   Load the blocklist at startup; fail with a clear error for an
    unreadable configured file. Validate and normalize entries, skip
    malformed entries with warnings, and report counts.
-   Support SIGHUP or a configurable polling interval for atomic reload.
    Parse into a new immutable snapshot and swap it atomically so
    requests never observe a partially loaded list.
-   Keep policy evaluation fast and deterministic. Include unit tests
    for case, trailing dots, subdomains, lookalike suffixes,
    IDNs/punycode, allowlist precedence, and reloads.

## 7. Logging, privacy, and observability

Emit structured JSON logs to stdout by default, with optional file
output. Include timestamps, client IP, protocol, hostname, port, HTTP
method, URL path/query (configurable), status/result, bytes in/out when
available, latency, and policy action/reason. DNS logs should include
query name/type, client IP, answer/action, and latency.

-   Never log credentials, cookies, authorization headers,
    request/response bodies, or full sensitive headers by default.
-   Make full URL logging configurable because paths and query strings
    can contain secrets; provide a hostname-only privacy mode.
-   Log TLS handshake failures, unknown-SNI cases, upstream verification
    failures, blocked requests, DNS errors, and reload results.
-   Add `/healthz` and `/readyz` on a configurable management address
    that is not exposed to untrusted client networks by default. Do not
    expose CA keys or configuration secrets via endpoints.

## 8. Root CA and key management

-   On first startup, create a local root CA certificate and private key
    if neither exists. Persist them in a configurable data directory and
    reuse them across restarts.
-   If only one file exists, the pair is invalid, or the certificate/key
    do not match, fail closed with an actionable error; do not silently
    replace the CA and break client trust.
-   Restrict private-key permissions (directory `0700`, key `0600` on
    Unix), use a cryptographically secure random source, set appropriate
    CA basic constraints/key usage, and choose a documented validity
    period.
-   Never expose the root private key over the network or include it in
    logs. Document the secure out-of-band process for installing the
    root certificate (not the private key) on clients.
-   Generate leaf certificates on demand and cache them. Persisting leaf
    certificates is unnecessary for the POC unless justified.
-   Provide an explicit development-only option for regenerating the CA;
    never rotate it automatically.

## 9. Configuration and deployment

Use YAML or TOML, with CLI flags for config path and version/help.
Include settings for: - DNS listen address/port and upstream
resolvers. - HTTP/HTTPS interception listen addresses. - Interception
addresses returned by DNS and enabled address families. - Blocklist and
optional allowlist paths/reload interval. - CA/key/data paths and
leaf-cache limits. - Log output, verbosity, URL/query logging, and
privacy mode. - Unknown-SNI behavior and UDP/443 policy. -
Management/health listen address. - Timeouts, maximum concurrent
connections, idle timeouts, and resource limits.

Ship an example config, Linux `nftables` install/remove scripts, systemd
unit with least privilege practical, and a troubleshooting guide.
Validate configuration before binding sockets or modifying firewall
rules. Firewall setup must be explicit and reversible; the service
should not unexpectedly rewrite host firewall policy at startup.

## 10. Security and failure behavior

-   Assume clients and upstream responses are untrusted. Bound header
    sizes, body streaming, connection counts, DNS message sizes, and
    timeouts.
-   Verify upstream TLS certificates and hostnames; defend against
    malformed requests, request smuggling ambiguities, and DNS rebinding
    surprises.
-   Require explicit opt-in for listening on non-loopback management
    interfaces.
-   Default to fail-closed for blocklist decisions and unknown TLS
    destinations; document the trade-off between strict enforcement and
    application compatibility.
-   Do not intercept unrelated ports or protocols. Do not provide a
    generic TCP tunnel that bypasses policy without an explicit
    configuration choice.
-   State clearly that TLS interception exposes decrypted traffic to the
    proxy operator and should be used only on devices/networks the
    operator is authorized to administer.

## 11. Proof-of-concept acceptance criteria

1.  `go test ./...` passes; `go vet ./...` is clean.
2.  Starting with no CA files creates a valid root CA and key.
    Restarting reuses the exact same CA. Corrupt or mismatched CA files
    cause a clear startup failure.
3.  DNS serves UDP and TCP, logs queries, rewrites enabled A/AAAA
    records to configured interception addresses, and returns the
    configured block response for blocked domains.
4.  Domain matching blocks a listed domain and its subdomains without
    blocking lookalike suffixes; allowlist precedence and reload
    behavior are tested.
5.  Through a Linux test network namespace and documented firewall
    rules, an HTTP client using the service DNS can access an allowed
    HTTP site; logs include hostname, method, path (if enabled),
    outcome, and latency.
6.  A managed HTTPS client trusting the generated root can access an
    allowed HTTPS site; the proxy presents a hostname-valid leaf
    certificate, verifies the upstream certificate, and logs request
    metadata.
7.  A blocked HTTP/HTTPS hostname is denied before the request is
    forwarded upstream, with a clear policy log.
8.  Tests cover HTTP/1.1, HTTP/2 where supported, streaming bodies,
    redirects, WebSocket upgrade where feasible, IPv4, IPv6
    configuration, malformed requests, upstream TLS failures, unknown
    SNI, and timeout/shutdown behavior.
9.  Optional UDP/443 blocking is documented and tested to demonstrate
    fallback behavior and known app failures.
10. Documentation explains installation, firewall rollback, CA trust
    installation, limitations (DoH/DoT, QUIC/HTTP/3, ECH, pinning,
    hard-coded IPs), log privacy, and troubleshooting.

## 12. Suggested implementation order

1.  Config, structured logging, policy matcher, blocklist tests.
2.  CA creation/loading and leaf certificate generation/cache.
3.  DNS UDP/TCP service, upstream bypass, A/AAAA rewrite, and policy
    logging.
4.  HTTP handler and upstream forwarding with request/response logging.
5.  TLS ClientHello/SNI handling, MITM TLS, ALPN, upstream verification.
6.  Linux transparent interception and loop-prevention firewall scripts.
7.  End-to-end network-namespace tests, UDP/443 fallback option,
    packaging, security review, and documentation.

## 13. Explicit non-goals for the POC

Full QUIC/HTTP/3 proxying; universal interception of every
protocol/port; defeating certificate pinning or ECH; transparent
interception of VPN traffic; guaranteed DoH detection; user interface;
distributed policy management; and production-grade multi-platform
transparent interception.

