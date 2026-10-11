#!/usr/bin/env bash
# proxyd firewall setup (nftables)
#
# Redirects client TCP/80 and TCP/443 to the proxyd interception listeners and
# optionally blocks outbound DoT (TCP/UDP 853) and client UDP/443 (QUIC) so
# clients fall back to TCP.
#
# This modifies the host firewall. Run it deliberately, and remove it with
# deploy/nftables-teardown.sh.
#
# Environment (all optional):
#   HTTP_PORT       proxyd HTTP listener port            (default 8080)
#   HTTPS_PORT      proxyd HTTPS listener port           (default 8443)
#   MARK            socket mark owned by proxyd          (default 1)
#   BYPASS_UID      systemd user of proxyd to bypass     (default empty)
#   BLOCK_DOT       yes|no : block outbound TCP/UDP 853  (default yes)
#   UDP443_MODE     allow|drop|reject                    (default reject)
#
# Requirements: nftables (nft), root.

set -euo pipefail

HTTP_PORT="${HTTP_PORT:-8080}"
HTTPS_PORT="${HTTPS_PORT:-8443}"
MARK="${MARK:-1}"
BYPASS_UID="${BYPASS_UID:-}"
BLOCK_DOT="${BLOCK_DOT:-yes}"
UDP443_MODE="${UDP443_MODE:-reject}"

if [[ "$(id -u)" != "0" ]]; then
  echo "error: this script must run as root" >&2
  exit 1
fi
command -v nft >/dev/null || { echo "error: nft not found" >&2; exit 1; }

# Idempotent: remove any previous proxyd rules first.
"$(dirname "$0")/nftables-teardown.sh" || true

echo "installing proxyd nftables rules (http->${HTTP_PORT}, https->${HTTPS_PORT}, mark=${MARK})"

# Borrow the mark value before redirecting.
nft -f - <<EOF
add table ip proxyd-nat
add chain ip proxyd-nat prerouting { type nat hook prerouting priority dstnat; policy accept; }
add chain ip proxyd-nat output { type nat hook output priority -100; policy accept; }
add rule ip proxyd-nat prerouting meta mark ${MARK} accept
add rule ip proxyd-nat output meta mark ${MARK} accept
add rule ip proxyd-nat prerouting tcp dport { 80, 443 } redirect to :${HTTP_PORT}
add rule ip proxyd-nat output tcp dport 80 redirect to :${HTTP_PORT}
add rule ip proxyd-nat output tcp dport 443 redirect to :${HTTPS_PORT}

add table ip6 proxyd-nat
add chain ip6 proxyd-nat prerouting { type nat hook prerouting priority dstnat; policy accept; }
add chain ip6 proxyd-nat output { type nat hook output priority -100; policy accept; }
add rule ip6 proxyd-nat prerouting meta mark ${MARK} accept
add rule ip6 proxyd-nat output meta mark ${MARK} accept
add rule ip6 proxyd-nat prerouting tcp dport { 80, 443 } redirect to :${HTTP_PORT}
add rule ip6 proxyd-nat output tcp dport 80 redirect to :${HTTP_PORT}
add rule ip6 proxyd-nat output tcp dport 443 redirect to :${HTTPS_PORT}
EOF

if [[ -n "${BYPASS_UID}" ]]; then
  nft add rule ip proxyd-nat prerouting skuid "${BYPASS_UID}" accept
  nft add rule ip proxyd-nat output skuid "${BYPASS_UID}" accept
  nft add rule ip6 proxyd-nat prerouting skuid "${BYPASS_UID}" accept
  nft add rule ip6 proxyd-nat output skuid "${BYPASS_UID}" accept
fi

# Filter chains: outbound DoT blocking and client UDP/443 policy.
nft -f - <<EOF
add table ip proxyd-filter
add chain ip proxyd-filter prerouting { type filter hook prerouting priority filter; policy accept; }
add chain ip proxyd-filter output { type filter hook output priority filter; policy accept; }
add rule ip proxyd-filter output meta mark ${MARK} accept
add table ip6 proxyd-filter
add chain ip6 proxyd-filter prerouting { type filter hook prerouting priority filter; policy accept; }
add chain ip6 proxyd-filter output { type filter hook output priority filter; policy accept; }
add rule ip6 proxyd-filter output meta mark ${MARK} accept
EOF

if [[ "${BLOCK_DOT}" == "yes" ]]; then
  nft add rule ip proxyd-filter output tcp dport 853 reject
  nft add rule ip proxyd-filter output udp dport 853 reject
  nft add rule ip6 proxyd-filter output tcp dport 853 reject
  nft add rule ip6 proxyd-filter output udp dport 853 reject
  echo "  blocking outbound DoT (TCP/UDP 853)"
fi

case "${UDP443_MODE}" in
  allow)
    ;;
  drop)
    nft add rule ip proxyd-filter prerouting udp dport 443 drop
    nft add rule ip proxyd-filter output udp dport 443 drop
    echo "  dropping client UDP/443 (QUIC fallback)"
    ;;
  reject)
    nft add rule ip proxyd-filter prerouting udp dport 443 reject
    nft add rule ip proxyd-filter output udp dport 443 reject
    nft add rule ip6 proxyd-filter prerouting udp dport 443 reject
    nft add rule ip6 proxyd-filter output udp dport 443 reject
    echo "  rejecting client UDP/443 (QUIC fallback)"
    ;;
  *)
    echo "error: UDP443_MODE must be allow|drop|reject, got '${UDP443_MODE}'" >&2
    exit 1
    ;;
esac

echo "installed. Roll back with deploy/nftables-teardown.sh"