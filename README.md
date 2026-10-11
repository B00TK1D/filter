# proxyd — transparent DNS + HTTP(S) filtering proxy

`proxyd` is a Linux-first, Go-based transparent DNS and HTTP/HTTPS
interception service for a controlled network. It is the proof-of-concept
described in [`PLAN.md`](PLAN.md).

It provides:

- A **DNS forwarder** that answers `A`/`AAAA` queries with configured
  interception addresses (so client traffic lands on the proxy), enforces a
  domain blocklist, and logs every query.
- A **transparent HTTP proxy** (port 80) that derives the destination from the
  request authority/`Host` header, checks policy, and forwards requests while
  preserving methods, paths, streaming bodies, redirects, and WebSocket
  upgrades.
- A **transparent HTTPS proxy** (port 443) that performs TLS interception
  (MITM) using a locally generated root CA, choosing the hostname from the TLS
  SNI, verifying the upstream certificate against the system trust store, and
  negotiating HTTP/2 or HTTP/1.1 via ALPN.
- A **shared domain policy** with an optional allowlist and atomic reload.
- **Structured JSON logging**, a root **CA lifecycle**, configuration,
  health endpoints, deploy scripts, and tests.

The OS firewall (nftables) redirects TCP/80 and TCP/443 to `proxyd`. DNS
rewriting alone is not sufficient for transparent proxying: because the
rewritten destination is the proxy's IP, the original hostname is recovered
from the HTTP `Host` header or the TLS SNI.

> **Security boundary.** TLS interception lets the proxy impersonate hosts for
> which it issues certificates and exposes decrypted traffic to the operator.
> Only deploy it on devices and networks you are authorized to administer.

## Table of contents

- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Building](#building)
- [Configuration](#configuration)
- [Blocklist and policy](#blocklist-and-policy)
- [Logging and privacy](#logging-and-privacy)
- [Root CA and TLS interception](#root-ca-and-tls-interception)
- [Deployment](#deployment)
- [Health endpoints](#health-endpoints)
- [Testing](#testing)
- [Acceptance criteria](#acceptance-criteria)
- [Documentation](#documentation)

## How it works

```
                 DNS (UDP/TCP :53)                HTTP/HTTPS
   client ─────────────────────────► proxyd ─────────────────────► upstream
     │                                 │
     │  A/AAAA -> intercept address    │  Host / SNI -> policy
     │  blocked -> NXDOMAIN/sinkhole   │  blocked -> 403 / TLS block
     └──────── firewall redirect ──────┘  allowed -> reverse proxy / MITM
              (TCP/80, TCP/443)
```

1. The client asks `proxyd` for `example.com`.
2. `proxyd` gives back `dns.intercept_ipv4` (or `dns.intercept_ipv6`) so the
   client connects to the proxy. Blocked names get `NXDOMAIN` (default) or a
   sinkhole address.
3. The nftables rules `redirect` TCP/80 and TCP/443 to `proxyd`'s HTTP/HTTPS
   listeners.
4. `proxyd` recovers the hostname (HTTP `Host` header or TLS SNI), applies the
   same policy, and either blocks the request or forwards it upstream. Upstream
   connections carry `limits.upstream_mark` (`SO_MARK`) and/or come from a
   bypass UID so the firewall lets them out without re-entering interception.

## Quick start

```sh
# Build.
make build            # or: go build ./cmd/proxyd

# Try it locally with loopback defaults (no root required, no firewall needed).
mkdir -p /tmp/proxyd
cat > /tmp/proxyd/config.yaml <<'EOF'
dns:
  listen_udp: "127.0.0.1:5353"
  listen_tcp: "127.0.0.1:5353"
  upstream: ["1.1.1.1:53"]
  intercept_ipv4: "127.0.0.1"
policy:
  blocklist: "/tmp/proxyd/blocklist.txt"
ca:
  data_dir: "/tmp/proxyd/ca"
logging:
  format: "text"
EOF
printf 'ads.example\n' > /tmp/proxyd/blocklist.txt

./proxyd -config /tmp/proxyd/config.yaml
```

The full production example is [`deploy/config.example.yaml`](deploy/config.example.yaml).

## Building

Requirements: Go 1.27+, Linux (the transparent interception path is
Linux-only).

```sh
go build -o proxyd ./cmd/proxyd
go vet ./...
go test ./...
```

A `Makefile` wraps the common tasks:

| Target | Purpose |
| --- | --- |
| `make build` | Compile `./proxyd` |
| `make test` | `go test ./...` |
| `make vet` | `go vet ./...` |
| `make fmt` / `make fmt-check` | Format / verify formatting |
| `make e2e` | Run the root-gated network-namespace test |
| `make clean` | Remove build artifacts |

The version is overridable at build time:

```sh
go build -ldflags "-X main.Version=1.2.3" -o proxyd ./cmd/proxyd
```

## Configuration

Configuration is a YAML file passed with `-config` (default `config.yaml`).
Unknown fields are rejected, values are defaulted and validated before any
socket is bound. Run `proxyd -version` for the version and see the full
annotated example at [`deploy/config.example.yaml`](deploy/config.example.yaml).

### CLI flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-config` | `config.yaml` | Path to the YAML configuration file |
| `-version` | | Print the version and exit |
| `-dev-regenerate-ca` / `ca.regenerate` | `false` | **Development only.** Delete and recreate the root CA at startup |

### Key sections

| Section | Key | Default | Meaning |
| --- | --- | --- | --- |
| `dns` | `listen_udp` / `listen_tcp` | `127.0.0.1:5353` | DNS listeners (UDP and TCP) |
| | `upstream` | `["1.1.1.1:53","9.9.9.9:53"]` | Forwarding resolvers; **must bypass interception** |
| | `intercept_ipv4` | `127.0.0.1` | Address returned for `A` queries |
| | `intercept_ipv6` | `::1` | Address returned for `AAAA` when enabled |
| | `ipv6_enabled` | `false` | Advertise IPv6 interception |
| | `block_mode` | `nxdomain` | `nxdomain` or `sinkhole` |
| | `sinkhole_ipv4` / `sinkhole_ipv6` | | Addresses for sinkhole mode |
| | `ttl` | `60` | TTL of synthesized answers |
| | `timeout` / `query_timeout` | `3s` / `5s` | Upstream exchange / total query budget |
| | `max_udp_size` | `1232` | Advertised EDNS0 UDP payload size |
| `http` | `listen` | `127.0.0.1:8080` | Transparent HTTP listener |
| `https` | `listen` | `127.0.0.1:8443` | Transparent HTTPS listener |
| | `alpn` | `["h2","http/1.1"]` | Protocols advertised to clients |
| `policy` | `blocklist` | **(required)** | Blocklist file path |
| | `allowlist` | | Optional; takes precedence |
| | `reload_interval` | `0s` | Polling interval; `0` disables polling (SIGHUP still reloads) |
| `ca` | `data_dir` | `/var/lib/proxyd` | Directory holding the CA |
| | `cert_file` / `key_file` | `<data_dir>/rootCA.pem` / `rootCA-key.pem` | CA overrides |
| | `validity` / `leaf_validity` | `8760h` / `720h` | CA / leaf lifetimes |
| | `leaf_cache_size` | `1024` | Bounded leaf certificate cache |
| | `regenerate` | `false` | **Development only** |
| `logging` | `level` | `info` | `debug`, `info`, `warn`, `error` |
| | `format` | `json` | `json` or `text` |
| | `output` | `""` (stdout) | File path or stdout |
| | `log_urls` | `false` | Log full paths/query strings |
| | `privacy_mode` | `false` | Hostname-only logging |
| `tls` | `unknown_sni` | `reject` | `reject` or `passthrough` |
| `limits` | `max_conns` | `1024` | Concurrent connection cap |
| | `max_header_bytes` | `65536` | HTTP header bound |
| | `read_header_timeout` / `idle_timeout` | `10s` / `90s` | HTTP timeouts |
| | `dial_timeout` / `tls_handshake_timeout` / `response_header_timeout` | `10s` / `10s` / `30s` | Upstream timeouts |
| | `shutdown_timeout` | `15s` | Graceful shutdown budget |
| | `upstream_mark` | `0` | `SO_MARK` for proxy-originated sockets (`0` disables) |
| `udp443` | `mode` | `allow` | `allow`, `reject`, or `drop`; documents QUIC policy for the firewall scripts |
| `management` | `listen` | `127.0.0.1:9090` | Health endpoints |
| | `allow_non_loopback` | `false` | Required to bind a non-loopback management address |

Durations use Go syntax (`3s`, `90s`, `8760h`).

## Blocklist and policy

The blocklist is one domain per line. Blank lines and `#` comments are
ignored, and hosts-file lines (`0.0.0.0 domain` / `127.0.0.1 domain`) are
accepted. Names are normalized case-insensitively with the trailing dot
removed and matched exactly or as a subdomain: `example.com` matches itself and
`*.example.com` but **not** `notexample.com`. Internationalized names are
handled via punycode.

Precedence is deterministic: **explicit allowlist → blocklist → default
allow**.

Reload is atomic: a new immutable snapshot is parsed and swapped in, so
in-flight requests never observe a partially loaded list. Trigger a reload with
`SIGHUP` (the systemd unit uses `ExecReload=/bin/kill -HUP $MAINPID`) or by
setting `policy.reload_interval`. Parse failures leave the previous snapshot in
place and are logged.

See [`internal/policy/policy.go`](internal/policy/policy.go) for the matching
rules and its unit tests for edge cases.

## Logging and privacy

Logs are structured JSON on stdout by default (or `text`/file). Events include:

| Event | Notable fields |
| --- | --- |
| `startup`, `ready`, `shutdown` | addresses, version, modes |
| `policy_load`, `policy_reload` | entry counts, skipped entries, errors |
| `ca_ready`, `ca_regenerated` | cert path, subject, expiry |
| `dns_query` | `client`, `question`, `type`, `action` (`allow`/`block`/`forward`/`error`), `reason`, `answer`/`rcode`, `latency_ms` |
| `http_request` | `client`, `scheme`, `host`, `port`, `method`, `path`, `action`, `reason`, `status`, `bytes_in`, `bytes_out`, `latency_ms` |
| `tls_handshake` | `client`/`host`, `action` (`reject`/`block`/`passthrough`), `reason` |

**Secrets are never logged by default.** Credentials, cookies, `Authorization`,
`Set-Cookie`, `Proxy-Authorization`, `X-Api-Key`, `X-Auth-Token`, and
`Proxy-Authenticate` headers are redacted, and request/response bodies are not
logged. Paths and query strings can contain secrets, so they are only logged
when `logging.log_urls: true`; `logging.privacy_mode: true` forces
hostname-only logging regardless. See [`docs/privacy.md`](docs/privacy.md).

## Root CA and TLS interception

On first startup `proxyd` creates an ECDSA P-256 root CA (default 1 year) and
private key under `ca.data_dir`, then reuses them across restarts. The key file
is stored `0600` in a `0700` directory. If only one file is present, or the
pair is mismatched/corrupt, startup fails with an actionable error rather than
silently rotating the CA. Leaf certificates are generated on demand, cached by
normalized hostname with bounded size and lifetime, and signed by the CA.

For HTTPS interception to work, clients must trust the root CA
(`ca.data_dir/rootCA.pem`). See [`docs/ca-trust.md`](docs/ca-trust.md) for
installation on Linux, Windows, macOS, and Firefox.

- Upstream TLS is always verified against the system trust store; verification
  is never disabled by default.
- TLS 1.2/1.3 and HTTP/2 or HTTP/1.1 (ALPN) are supported.
- Connections without a usable SNI are **rejected** by default; the
  `passthrough` mode relays them to the original destination (`SO_ORIGINAL_DST`)
  uninspected and can neither read URLs nor enforce domain policy. It is
  best-effort and only works when a real, non-proxy destination can be
  recovered — which is not the case after DNS rewriting to the proxy.

## Deployment

The [`deploy/`](deploy) directory contains:

- [`config.example.yaml`](deploy/config.example.yaml) — annotated production
  config.
- [`nftables-setup.sh`](deploy/nftables-setup.sh) — installs interception
  rules (and optional DoT / UDP/443 blocking).
- [`nftables-teardown.sh`](deploy/nftables-teardown.sh) — removes them.
- [`proxyd.service`](deploy/proxyd.service) — least-privilege systemd unit.

### Install as a service

```sh
install -m 0755 proxyd /usr/local/bin/proxyd
useradd -r -s /usr/sbin/nologin -d /var/lib/proxyd proxyd
install -d -o proxyd -g proxyd -m 0700 /var/lib/proxyd
install -m 0644 deploy/config.example.yaml /etc/proxyd/config.yaml
install -m 0644 deploy/proxyd.service /etc/systemd/system/proxyd.service
systemctl daemon-reload
systemctl enable --now proxyd
```

### Install the firewall rules

Firewall setup is explicit and reversible. `proxyd` never rewrites host
firewall policy at startup; an administrator installs the rules:

```sh
# Redirect TCP/80->HTTP_PORT, TCP/443->HTTPS_PORT, block DoT, reject client
# UDP/443 (QUIC) so clients fall back to TCP.
HTTP_PORT=8080 HTTPS_PORT=8443 UDP443_MODE=reject deploy/nftables-setup.sh
```

Environment knobs: `HTTP_PORT`, `HTTPS_PORT`, `MARK`, `BYPASS_UID`,
`BLOCK_DOT` (`yes`/`no`), `UDP443_MODE` (`allow`/`drop`/`reject`). Keep `MARK`
in sync with `limits.upstream_mark`.

### Roll back the firewall rules

```sh
deploy/nftables-teardown.sh
```

Teardown is idempotent and removes every `proxyd-nat` and `proxyd-filter`
table (IPv4 and IPv6). See [`docs/installation.md`](docs/installation.md) for
the full walkthrough.

## Health endpoints

`GET /healthz` reports liveness; `GET /readyz` reports readiness (returns
non-2xx until all listeners are up and during shutdown). They listen on
`management.listen` (`127.0.0.1:9090` by default). Binding a non-loopback
management address requires `management.allow_non_loopback: true`. Endpoints
never expose the CA key or configuration secrets.

## Testing

```sh
make test     # unit + integration tests (go test ./...)
make vet
make e2e      # network-namespace end-to-end test (requires root)
```

Unit and package integration tests cover policy matching and reload, config
validation, CA creation/reuse/mismatch, DNS UDP+TCP rewrite and block, HTTP
forwarding (streaming, redirects, WebSocket, malformed requests), HTTPS MITM
(HTTP/1.1, HTTP/2, unknown SNI, upstream TLS failure), logging, and the
resolver.

The end-to-end test [`tests/netns_test.go`](tests/netns_test.go) is gated by
the `integration` build tag and requires root plus `ip`, `nft`, `curl`, and
`go`. It builds `proxyd`, creates a client network namespace, installs nftables
redirect rules, points the namespace resolver at `proxyd`, and verifies DNS
rewrite, transparent HTTP, transparent HTTPS (with the proxy CA), blocked-domain
`NXDOMAIN`, and the resulting log lines:

```sh
go test -tags integration -run TestNetworkNamespace -v -timeout 180s ./tests/
```

See [`tests/README.md`](tests/README.md).

## Acceptance criteria

[`PLAN.md` §11](PLAN.md) maps to this implementation as follows:

| # | Criterion | Where |
| --- | --- | --- |
| 1 | `go test ./...` passes, `go vet` clean | `make test`, `make vet` |
| 2 | CA created, reused on restart, mismatches fail | [`internal/tlsmitm/ca_test.go`](internal/tlsmitm/ca_test.go) |
| 3 | DNS UDP+TCP rewrite/block, logging | [`internal/dns/server_test.go`](internal/dns/server_test.go), `tests/netns_test.go` |
| 4 | Policy precedence and reload | [`internal/policy/policy_test.go`](internal/policy/policy_test.go) |
| 5 | End-to-end HTTP via netns | [`tests/netns_test.go`](tests/netns_test.go) |
| 6 | HTTPS MITM with upstream verification | `tests/netns_test.go`, [`internal/httpproxy/mitm_test.go`](internal/httpproxy/mitm_test.go) |
| 7 | Blocked before forward | [`internal/httpproxy/proxy_test.go`](internal/httpproxy/proxy_test.go) |
| 8 | HTTP/1.1, HTTP/2, streaming, redirects, WebSocket, malformed, upstream TLS failure, unknown SNI, timeouts | [`internal/httpproxy/proxy_test.go`](internal/httpproxy/proxy_test.go), [`mitm_test.go`](internal/httpproxy/mitm_test.go) |
| 9 | UDP/443 blocking documented and tested | [`deploy/nftables-setup.sh`](deploy/nftables-setup.sh), [`docs/limitations.md`](docs/limitations.md) |
| 10 | Installation, rollback, CA trust, limitations, privacy, troubleshooting docs | [`docs/`](docs) |

## Documentation

- [docs/installation.md](docs/installation.md) — prerequisites, install,
  firewall setup and rollback, verification.
- [docs/ca-trust.md](docs/ca-trust.md) — installing and managing the root CA.
- [docs/limitations.md](docs/limitations.md) — DoH/DoT, QUIC/HTTP3, ECH,
  pinning, hard-coded IPs, and other guarantees `proxyd` does **not** make.
- [docs/privacy.md](docs/privacy.md) — log schema, redaction, and privacy
  modes.
- [docs/troubleshooting.md](docs/troubleshooting.md) — common problems and
  fixes.
- [tests/README.md](tests/README.md) — running the test suites.

## Non-goals

Full QUIC/HTTP3 proxying; universal interception of every protocol or port;
defeating certificate pinning or ECH; intercepting VPN traffic; guaranteed DoH
detection; a UI; distributed policy management; and production-grade
multi-platform transparency. See [`PLAN.md` §13](PLAN.md).
