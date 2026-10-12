# Docker deployment

The repository ships a multi-stage `Dockerfile`, a `.dockerignore`, and a
`docker-compose.yml` for simple deployment. The image is a small Alpine runtime
with a static, CGO-free `proxyd` binary and CA roots for upstream TLS
verification.

The container only runs the proxy. **The host firewall (nftables) still owns
interception**: proxyd never modifies host firewall rules. Because the redirect
rules and `SO_MARK` bypass operate in the host network namespace, the container
runs with `network_mode: host`.

## Prerequisites

- Docker with the Compose plugin (or just Docker for `docker run`).
- Root on the host to install the firewall rules.
- `deploy/docker/config.yaml` edited for your network (at minimum
  `dns.intercept_ipv4`), and `deploy/docker/blocklist.txt`.

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

Two files in `deploy/docker/` are mounted read-only at `/etc/proxyd/`:

- `config.yaml` — the service configuration. Set `dns.intercept_ipv4` to the
  **host's LAN/gateway IP** clients can reach (not a container address), and
  keep `http.listen`/`https.listen` in sync with `HTTP_PORT`/`HTTPS_PORT` in
  the firewall script.
- `blocklist.txt` — one domain per line.

Configuration is read at startup; changes need a restart. Blocklist changes are
picked up live.

## Run

```sh
# Start the proxy (host networking, restart on failure).
docker compose up -d

# Install the host interception rules.
sudo deploy/nftables-setup.sh

# ...or override the firewall ports to match a custom config:
sudo HTTP_PORT=8080 HTTPS_PORT=8443 MARK=1 UDP443_MODE=reject deploy/nftables-setup.sh
```

`docker-compose.yml` grants `NET_ADMIN` so `limits.upstream_mark` (`SO_MARK`)
works and `NET_BIND_SERVICE` so the container can bind `:53`. If you use a
resolver- or UID-based loop-prevention instead, remove `NET_ADMIN` and set
`limits.upstream_mark: 0`.

## Verify

```sh
docker compose ps
docker inspect --format '{{.State.Health.Status}}' proxyd   # healthy
docker compose logs -f

# Health endpoints (loopback inside the container by default).
docker exec proxyd wget -qO- http://127.0.0.1:9090/healthz
docker exec proxyd wget -qO- http://127.0.0.1:9090/readyz

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
| Stop | `docker compose down` |
| Rollback firewall rules | `sudo deploy/nftables-teardown.sh` |

## Loop prevention

Upstream connections must not re-enter interception. The default config uses
`limits.upstream_mark: 1`, and the setup script installs
`meta mark 1 accept` bypass rules. Keep the two in sync. Alternatives:

- Resolve through an upstream reachable on a non-redirected path.
- Use `BYPASS_UID=...` in the setup script for a dedicated upstream owner.

If `upstream_mark` is non-zero the container needs `NET_ADMIN` (already in
`docker-compose.yml`).

## Bridge-networking alternative (testing only)

For a quick smoke test without touching the host network you can skip host
networking, but interception will not work unless the host redirects to the
published ports. In that case:

- set `dns.listen_udp`/`listen_tcp` to `:5353` (an unprivileged port),
- publish ports (`-p 53:5353/udp -p 53:5353/tcp -p 8080:8080 -p 8443:8443`),
- and add a host DNS redirect from `:53` to `:5353`.

This is documented only to make the difference explicit; the supported
deployment is `network_mode: host`.

## Updating proxyd

```sh
git pull
docker compose build --pull
docker compose up -d
```

The CA volume persists, so clients keep trusting the same root across upgrades.

## Security notes

- The container runs as root inside the image to bind `:53` and to set
  `SO_MARK`. It has no shell services, no SUID binaries beyond the base image,
  and only the capabilities listed in `docker-compose.yml`. To run as the
  non-root `proxyd` user, `setcap cap_net_bind_service,cap_net_admin+ep
  /usr/local/bin/proxyd`, set `USER proxyd` in the image, and keep the caps in
  `cap_add` (do not set `no-new-privileges`).
- The management endpoint stays on container loopback. Set
  `management.allow_non_loopback: true` only with firewall restrictions.
- `rootCA-key.pem` in the `proxyd-data` volume is a high-value secret. Protect
  the Docker host and the volume accordingly.
