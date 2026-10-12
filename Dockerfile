# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build stage: produce a static, CGO-free proxyd binary.
# ---------------------------------------------------------------------------
FROM golang:1.27-alpine AS build

ARG VERSION=dev
# Set by buildx for multi-arch builds; default to the host when unset.
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Cache dependencies in their own layer.
COPY go.mod go.sum ./
RUN go mod download

# Only the packages the binary needs are copied, keeping the context small.
COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN CGO_ENABLED=0 GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" \
    -o /out/proxyd ./cmd/proxyd

# ---------------------------------------------------------------------------
# Runtime stage: minimal Alpine with CA roots for upstream TLS verification.
# ---------------------------------------------------------------------------
FROM alpine:3.20

# ca-certificates: verify upstream TLS. tzdata: correct log timestamps.
# nftables+bash: install interception rules from the entrypoint. busybox wget
# (already present) backs the HEALTHCHECK below.
RUN apk add --no-cache ca-certificates tzdata nftables bash \
 && addgroup -S proxyd \
 && adduser -S -G proxyd -h /var/lib/proxyd -s /sbin/nologin proxyd \
 && install -d -o proxyd -g proxyd -m 0700 /var/lib/proxyd \
 && install -d -o proxyd -g proxyd -m 0755 /etc/proxyd

COPY --from=build /out/proxyd /usr/local/bin/proxyd

# Reuse the exact firewall scripts from a native install.
COPY deploy/nftables-setup.sh deploy/nftables-teardown.sh /usr/local/lib/proxyd/
COPY deploy/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/lib/proxyd/*.sh

# Default config and an empty blocklist. docker-compose mounts over these.
COPY deploy/config.example.yaml /etc/proxyd/config.yaml
RUN install -o proxyd -g proxyd -m 0644 /dev/null /etc/proxyd/blocklist.txt

# Ports: DNS (UDP/TCP 53), transparent HTTP/HTTPS, management.
EXPOSE 53/udp 53/tcp 8080 8443 9090

# The root CA is persisted here; mount a volume to keep it across upgrades.
VOLUME ["/var/lib/proxyd"]

# The entrypoint installs host interception rules (needs CAP_NET_ADMIN +
# host networking), binds the privileged DNS port :53, and optionally marks
# upstream sockets with SO_MARK, so it runs as root inside the container by
# default. Set FIREWALL=0 to skip firewall management.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:9090/readyz || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/usr/local/bin/proxyd", "-config", "/etc/proxyd/config.yaml"]
