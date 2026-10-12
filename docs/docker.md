# Docker deployment

The repository ships a multi-stage `Dockerfile`, a `.dockerignore`, and a
`docker-compose.yml` that make `proxyd` self-contained: **the container installs
its own interception rules** and needs **no host scripts**. You only run
`docker compose up -d`; the container sets up the host firewall redirects,
starts the proxy, and removes the rules again on shutdown.

## How it works

The container runs with `network_mode: host`, so it shares the host network
namespace, and with `CAP_NET_ADMIN`, which lets it edit the host's netfilter
rules. On startup its entrypoint applies the same nftables rules as a native
install (it reuses `deploy/nftables-setup.sh` verbatim, so there is one source
of truth) and then runs `proxyd`. On `SIGTERM` it removes the rules again.

- **Port forwards** are nftables `redirect` rules in the host's `nat` chains:
  TCP/80 → `HTTP_PORT`, TCP/443 → `HTTPS_PORT`.
- **Bypass** for proxy-originated upstream connections uses `SO_MARK`
  (`limits.upstream_mark` ↔ `MARK`).
- **DNS** is served directly on `:53`; clients use the Docker host as resolver.

Because the container edits the host firewall, it needs `NET_ADMIN` and host
networking; there are no host scripts to run.

## Prerequisites

- Docker with the Compose plugin. The image bundles `nftables`, so the host does
  not need the `nft` package installed.
- **Rootful** Docker: rootless Docker cannot share the host network namespace or
  install host firewall rules.
- `deploy/docker/config.yaml` edited for your network (at minimum
  `dns.intercept_ipv4`), and `deploy/docker/blocklist.txt`.

The container needs only `NET_ADMIN` (plus the default `NET_BIND_SERVICE`); it
does **not** need `--privileged`. If your environment restricts capabilities
further, `privileged: true` is a working fallback.

## Build

```sh
docker build -t proxyd:latest --build-arg VERSION=0.1.0 .

# or via Compose:
docker compose build
```

Multi-arch images (e.g. amd64 + arm64) with buildx:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=0.1.0 -t your-registry/proxyd:0.1.0 --push .
```

## Configure

Two files in `deploy/docker/` are mounted at `/etc/proxyd/`:

- `config.yaml` — service configuration. Set `dns.intercept_ipv4` to the
  **host's LAN/gateway IP** clients can reach, and keep `http.listen` /
  `https.listen` / `limits.upstream_mark` / `udp443.mode` in sync with the
  `environment:` values in `docker-compose.yml`.
- `blocklist.txt` — one domain per line.

The entrypoint is driven by environment variables (set in
`docker-compose.yml`):

| Variable | Default | Meaning |
| --- | --- | --- |
| `FIREWALL` | `1` | `1` installs/removes the interception rules; `0` leaves the host firewall untouched |
| `HTTP_PORT` | `8080` | Redirect target and `http.listen` port |
| `HTTPS_PORT` | `8443` | Redirect target and `https.listen` port |
| `MARK` | `1` | `SO_MARK` bypass value (`limits.upstream_mark`) |
| `BLOCK_DOT` | `yes` | Block outbound TCP/UDP 853 (DoT) |
| `UDP443_MODE` | `reject` | `allow`, `drop`, or `reject` client UDP/443 (QUIC fallback) |
| `BYPASS_UID` | *(empty)* | User whose traffic bypasses interception |

If you change a port in `config.yaml`, change the matching environment variable
too.

## Run

```sh
docker compose up -d --build
```

That is the entire deployment: the container installs the redirect/block rules
on the host, starts proxyd, and reports healthy. Nothing else runs on the host.

## Firewall lifecycle

- **Start:** the entrypoint removes any stale `proxyd-nat`/`proxyd-filter`
  tables, installs fresh rules, then starts proxyd. If it cannot manage the
  firewall (missing `NET_ADMIN` or not host-networked) it fails loudly instead
  of running without interception.
- **Stop** (`docker compose down`, `docker stop`): proxyd receives `SIGTERM`,
  shuts down gracefully (up to `stop_grace_period: 30s`), and the entrypoint
  removes the rules.
- **Hard kill**: `docker kill` (SIGKILL) cannot run cleanup. Remove stale tables
  with:

```sh
docker run --rm --network host --cap-add NET_ADMIN \
  --entrypoint bash proxyd:latest /usr/local/lib/proxyd/nftables-teardown.sh
```

To run proxyd **without** any firewall management (for example when another
component owns interception), set `FIREWALL: "0"`.

## Verify

```sh
docker compose ps
docker inspect --format '{{.State.Health.Status}}' proxyd   # healthy
docker compose logs -f

# Health endpoints (loopback inside the container by default).
docker exec proxyd wget -qO- http://127.0.0.1:9090/healthz
docker exec proxyd wget -qO- http://127.0.0.1:9090/readyz

# Confirm the host rules are installed.
sudo nft list tables | grep proxyd

# From a client using the host as its resolver:
dig +short example.com          # -> dns.intercept_ipv4
dig +short blocked.example      # -> empty (NXDOMAIN) for a blocked name
```

The image `HEALTHCHECK` polls `/readyz` on `127.0.0.1:9090`. If you change
`management.listen`, update the healthcheck accordingly.

## Root CA and clients

The root CA is created on first start under `/var/lib/proxyd` (the named volume
`proxyd-data`) and reused across restarts and upgrades. Export it to install on
clients:

```sh
docker compose cp proxyd:/var/lib/proxyd/rootCA.pem ./rootCA.pem
```

Then follow [ca-trust.md](ca-trust.md). Never copy `rootCA-key.pem`.

## Reload, logs, and lifecycle

| Action | Command |
| --- | --- |
| Follow logs (JSON) | `docker compose logs -f` |
| Reload the blocklist (`SIGHUP`) | `docker compose kill -s HUP proxyd` |
| Restart after a config change | `docker compose restart proxyd` |
| Stop (removes firewall rules) | `docker compose down` |

`docker compose kill -s HUP` signals proxyd directly; the entrypoint is not
involved, so the firewall rules stay installed.

## Loop prevention

Upstream connections must not re-enter interception. The default uses
`limits.upstream_mark: 1`; the entrypoint installs `meta mark 1 accept` bypass
rules. Keep the two in sync, and keep `NET_ADMIN` so `SO_MARK` works.
Alternatives: resolve through a non-redirected path, or set `BYPASS_UID` to a
dedicated upstream owner.

## Without host networking

For a smoke test you can run the proxy without interception. Set
`FIREWALL=0`, use bridge networking, and map the ports you want (the management
endpoint stays on container loopback):

```sh
docker run --rm -e FIREWALL=0 -p 5353:53/udp -p 5353:53/tcp \
  -p 8080:8080 -p 8443:8443 \
  -v "$PWD/deploy/docker:/etc/proxyd" proxyd:latest
```

Interception will not work in this mode; it is only for validating the proxy.
The supported deployment is `network_mode: host` with `NET_ADMIN`.

## Updating proxyd

```sh
git pull
docker compose build --pull
docker compose up -d
```

The CA volume persists, so clients keep trusting the same root across upgrades.
The container removes and reinstalls the firewall rules on restart.

## Security notes

- The container modifies the **host** firewall and runs as root inside the
  image (needed for `:53`, `SO_MARK`, and nftables). It is granted only
  `NET_ADMIN` and the default `NET_BIND_SERVICE` — it is **not** `--privileged`.
- The management endpoint stays on container loopback. Set
  `management.allow_non_loopback: true` only with firewall restrictions.
- `rootCA-key.pem` in the `proxyd-data` volume is a high-value secret. Protect
  the Docker host and the volume accordingly.
- Anyone who can control this container effectively controls host firewall
  policy; restrict Docker access to trusted administrators.
