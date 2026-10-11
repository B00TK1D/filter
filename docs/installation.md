# Installation

This guide installs `proxyd` as a systemd service and applies the transparent
interception rules. It targets a Linux host that acts as the gateway/DNS for a
controlled network.

## Prerequisites

- Linux with nftables (`nft`) and an init system running systemd.
- Go 1.27+ to build, or a prebuilt `proxyd` binary.
- Root (or `CAP_NET_BIND_SERVICE` plus `CAP_NET_ADMIN` if using `upstream_mark`)
  to bind ports 53/80/443 and to install firewall rules.
- A **dedicated upstream resolver path** that bypasses the interception rules.
  Forwarding back through the intercepted path will loop. Options are:
  - a resolver reachable on an address/port not redirected, or
  - `limits.upstream_mark` (`SO_MARK`) plus the firewall's mark-bypass rules,
  - or a process UID allowed by `BYPASS_UID`.

## Build and install

```sh
make build
install -m 0755 proxyd /usr/local/bin/proxyd

# Least-privilege service user and data directory.
useradd -r -s /usr/sbin/nologin -d /var/lib/proxyd proxyd
install -d -o proxyd -g proxyd -m 0700 /var/lib/proxyd

# Configuration.
install -d -m 0755 /etc/proxyd
install -m 0644 deploy/config.example.yaml /etc/proxyd/config.yaml
$EDITOR /etc/proxyd/config.yaml

# Blocklist (one domain per line).
install -m 0644 /dev/null /etc/proxyd/blocklist.txt
$EDITOR /etc/proxyd/blocklist.txt
```

Adjust at minimum:

- `dns.upstream` — resolvers that bypass interception.
- `dns.intercept_ipv4` (and `dns.intercept_ipv6` + `dns.ipv6_enabled`) — the
  proxy address clients should connect to.
- `dns.listen_udp` / `dns.listen_tcp` — normally `0.0.0.0:53`.
- `http.listen` / `https.listen` — keep these in sync with `HTTP_PORT` /
  `HTTPS_PORT` in the firewall script.
- `policy.blocklist` — the file path.
- `limits.upstream_mark` — keep in sync with `MARK` in the firewall script.
- `management.listen` — keep loopback unless you intentionally expose it.

## Validate before starting

`proxyd` validates configuration (and loads the blocklist and CA) before binding
sockets. Check it interactively first:

```sh
proxyd -config /etc/proxyd/config.yaml
```

Configuration errors are printed to stderr and the process exits non-zero. The
first run creates the root CA under `ca.data_dir` (`/var/lib/proxyd`).

## Install the systemd unit

```sh
install -m 0644 deploy/proxyd.service /etc/systemd/system/proxyd.service
systemctl daemon-reload
systemctl enable --now proxyd
systemctl status proxyd
journalctl -u proxyd -f
```

The unit runs as the unprivileged `proxyd` user with `CAP_NET_BIND_SERVICE`.
If you set `limits.upstream_mark`, sockets are marked with `SO_MARK`, which
needs `CAP_NET_ADMIN`; uncomment the `AmbientCapabilities` /
`CapabilityBoundingSet` lines in the unit and add `CAP_NET_ADMIN`.

## Install the interception rules

> The service never modifies the host firewall itself. An administrator applies
> these rules, and they are fully reversible.

```sh
# Defaults: HTTP->8080, HTTPS->8443, mark 1, block DoT, reject UDP/443.
HTTP_PORT=8080 HTTPS_PORT=8443 MARK=1 UDP443_MODE=reject \
  deploy/nftables-setup.sh
```

The script is idempotent (it removes prior `proxyd` tables first). It installs,
for IPv4 and IPv6:

- a `prerouting` and an `output` NAT chain redirecting TCP/80 to `HTTP_PORT`
  and TCP/443 to `HTTPS_PORT`, with a `meta mark $MARK accept` bypass;
- optional `skuid $BYPASS_UID accept` bypass rules;
- filter rules blocking outbound DoT (TCP/UDP 853) when `BLOCK_DOT=yes`;
- the configured UDP/443 policy (`reject`, `drop`, or `allow`).

Environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `HTTP_PORT` | `8080` | proxyd HTTP listener port |
| `HTTPS_PORT` | `8443` | proxyd HTTPS listener port |
| `MARK` | `1` | `SO_MARK` owned by proxyd (`limits.upstream_mark`) |
| `BYPASS_UID` | *(empty)* | Service user whose traffic bypasses interception |
| `BLOCK_DOT` | `yes` | Block outbound TCP/UDP 853 (DoT) |
| `UDP443_MODE` | `reject` | `allow`, `drop`, or `reject` client UDP/443 (QUIC) |

## Roll back the interception rules

```sh
deploy/nftables-teardown.sh
```

This deletes the `proxyd-nat` and `proxyd-filter` tables for both IPv4 and IPv6
and is idempotent (safe to run even if the rules were never installed). The
`setup` script also calls it first, so re-running setup replaces the rules
cleanly.

## Verify the installation

```sh
systemctl status proxyd
curl -fsS http://127.0.0.1:9090/healthz && echo
curl -fsS http://127.0.0.1:9090/readyz && echo

# From a client that uses this host as its resolver:
dig +short example.com          # -> dns.intercept_ipv4
dig +short blocked.example      # -> empty (NXDOMAIN) for a blocked name
curl -sS http://example.com/    # transits proxyd
```

For a full end-to-end verification that builds `proxyd`, creates a client
network namespace, installs the rules, and exercises DNS/HTTP/HTTPS, run the
integration test in [`tests/README.md`](../tests/README.md).

## Uninstall

```sh
systemctl disable --now proxyd
deploy/nftables-teardown.sh
rm -f /usr/local/bin/proxyd /etc/systemd/system/proxyd.service
rm -rf /etc/proxyd /var/lib/proxyd
```

Remove the root CA from any clients that trusted it (see
[ca-trust.md](ca-trust.md)).
