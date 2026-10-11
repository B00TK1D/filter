#!/usr/bin/env bash
# proxyd firewall teardown (nftables)
#
# Removes every rule installed by deploy/nftables-setup.sh. Idempotent;
# exits 0 even when the tables were never created.

set -euo pipefail

if [[ "$(id -u)" != "0" ]]; then
  echo "error: this script must run as root" >&2
  exit 1
fi
command -v nft >/dev/null || { echo "error: nft not found" >&2; exit 1; }

for table in proxyd-nat proxyd-filter; do
  for family in ip ip6; do
    if nft list table "${family}" "${table}" >/dev/null 2>&1; then
      nft delete table "${family}" "${table}"
      echo "removed ${family} ${table}"
    fi
  done
done

echo "proxyd firewall rules removed"