# Tests

`proxyd` has three test layers:

1. **Unit tests** — per package (`internal/*`).
2. **Package integration tests** — in-process, no root required (HTTP MITM,
   HTTP/2, WebSocket, unknown SNI, DNS UDP/TCP, etc.).
3. **Network-namespace end-to-end test** — root-gated, exercises the real
   binary, nftables, and a client namespace.

## Unit and package integration tests

```sh
make test       # go test ./...
make vet        # go vet ./...
make fmt-check  # gofmt -l (must be empty)
```

These run everywhere with no special privileges. Coverage highlights:

| Package | What it verifies |
| --- | --- |
| `internal/config` | Defaults, YAML parsing, validation errors |
| `internal/policy` | Normalization, subdomain vs. lookalike matching, IDN/punycode, allowlist precedence, atomic reload |
| `internal/tlsmitm` | CA create/reuse/mismatch, leaf cache, ClientHello SNI parsing |
| `internal/dns` | UDP + TCP rewrite, block (NXDOMAIN/sinkhole), IPv6 NODATA, upstream errors, logging |
| `internal/httpproxy` | HTTP/1.1 forwarding, streaming, redirects, WebSocket, malformed/ambiguous requests, HTTPS MITM, HTTP/2, unknown SNI, upstream TLS failure, blocked-before-forward |
| `internal/health` | `/healthz` and `/readyz` |
| `internal/logging` | Levels, formats, redaction, privacy modes |
| `internal/resolver` | Upstream resolution with mark/loop avoidance |

## Network-namespace end-to-end test

`tests/netns_test.go` is gated behind the `integration` build tag and requires
root and the `ip`, `nft`, `curl`, and `go` binaries. It:

1. Builds `proxyd` from `cmd/proxyd`.
2. Creates a veth pair and a client network namespace with the proxy as its
   gateway and resolver.
3. Starts an authoritative DNS server and upstream HTTP/HTTPS servers on the
   host side, plus a proxy root CA.
4. Installs nftables `redirect` rules inside the namespace (with a `meta mark`
   bypass) and starts `proxyd` inside the namespace with `SSL_CERT_FILE`
   trusting the upstream test CA.
5. Asserts:
   - **dns-rewrite** — an `A` query returns the interception address.
   - **http-transparent** — `curl http://www.poc.test/hello?q=1` reaches the
     upstream and returns the expected body.
   - **https-transparent** — `curl --cacert rootCA.pem https://www.poc.test/secure`
     succeeds through TLS MITM.
   - **blocked-domain** — `curl http://blocked-poc.test/` fails to resolve
     because DNS returns `NXDOMAIN`.
   - **logs** — the log contains `dns_query`/`block`, `http_request` with the
     expected host, `GET`, `status:200`, `action":"allow"`, and `latency_ms`.

Run it:

```sh
sudo go test -tags integration -run TestNetworkNamespace -v -timeout 180s ./tests/
```

or `make e2e`.

### Requirements and notes

- Must run as root (the test skips otherwise, as do missing commands).
- Uses `172.20.0.0/24` for the veth pair and `www.poc.test` /
  `blocked-poc.test` as test names. Ports 53/80/443/5353/8080/8443/9090 must be
  free on the host.
- Cleans up the namespace, veth link, and `/etc/netns/<ns>` on completion.
- Some environments (containers without `CAP_NET_ADMIN`, restricted nftables)
  cannot run it; the test skips when prerequisites are missing.

## Formatting

All Go sources must be `gofmt`-clean:

```sh
gofmt -l .   # prints unformatted files; empty output is clean
```
