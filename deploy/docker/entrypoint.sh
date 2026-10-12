#!/bin/sh
# Container entrypoint for proxyd.
#
# With network_mode: host the container shares the host network namespace, so
# the nftables redirect rules applied here take effect on the host. The
# firewall rules themselves are the same scripts used by a native install
# (deploy/nftables-setup.sh / nftables-teardown.sh), so there is a single
# source of truth.
#
# Environment (all optional):
#   FIREWALL      1|0  install/remove interception rules (default 1)
#   HTTP_PORT     host port both the redirect targets and proxyd listens on
#   HTTPS_PORT    same for HTTPS
#   MARK          SO_MARK owned by proxyd (must match limits.upstream_mark)
#   BYPASS_UID    service user whose traffic bypasses interception
#   BLOCK_DOT     yes|no  block outbound TCP/UDP 853
#   UDP443_MODE   allow|drop|reject  QUIC fallback policy
#
# Set FIREWALL=0 to run proxyd without touching the host firewall (for example
# when another component manages interception).
set -eu

SCRIPT_DIR=/usr/local/lib/proxyd
FIREWALL="${FIREWALL:-1}"

child=""
stopping=0
torn_down=0

teardown() {
	if [ "$torn_down" = "1" ]; then
		return 0
	fi
	torn_down=1
	if [ "$FIREWALL" = "1" ]; then
		bash "$SCRIPT_DIR/nftables-teardown.sh" || true
	fi
	return 0
}

on_term() {
	stopping=1
	if [ -n "$child" ]; then
		kill -TERM "$child" 2>/dev/null || true
	fi
}

on_hup() {
	if [ -n "$child" ]; then
		kill -HUP "$child" 2>/dev/null || true
	fi
}

trap teardown EXIT
trap on_term INT TERM
trap on_hup HUP

if [ "$FIREWALL" = "1" ]; then
	echo "entrypoint: installing interception rules (http=${HTTP_PORT:-8080}, https=${HTTPS_PORT:-8443}, mark=${MARK:-1}, block_dot=${BLOCK_DOT:-yes}, udp443=${UDP443_MODE:-reject})" >&2
	if ! bash "$SCRIPT_DIR/nftables-setup.sh"; then
		echo "entrypoint: failed to install host firewall rules. The container needs host networking and CAP_NET_ADMIN; alternatively set FIREWALL=0." >&2
		exit 1
	fi
fi

if [ "$stopping" = "1" ]; then
	exit 0
fi

# If the first argument is a flag, treat the whole command line as arguments to
# proxyd, so `docker run IMAGE -version` works as expected.
if [ "${1:-}" != "" ] && [ "${1#-}" != "$1" ]; then
	set -- /usr/local/bin/proxyd "$@"
fi

# Run proxyd as a child so signals can be forwarded and the rules removed on
# exit. "$@" is the image CMD (proxyd plus its arguments).
"$@" &
child=$!

# Wait for proxyd. Signals such as SIGHUP interrupt wait() and make it return a
# nonzero status even though proxyd is still running, so keep waiting while the
# child is alive.
status=0
while :; do
	status=0
	wait "$child" || status=$?
	if [ "$status" -eq 0 ]; then
		break
	fi
	if ! kill -0 "$child" 2>/dev/null; then
		break
	fi
done
child=""
exit "$status"
