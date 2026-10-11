# Troubleshooting

## Service will not start

`proxyd` prints a clear error to stderr and exits non-zero. Common causes:

| Message | Cause / fix |
| --- | --- |
| `read config: ... no such file` | Wrong `-config` path. |
| `parse config: ... field ... not found` | Unknown YAML key (unknown fields are rejected). Check spelling against [`deploy/config.example.yaml`](../deploy/config.example.yaml). |
| various `dns.*`, `policy.blocklist`, `management.listen` errors | Validation failed. The message names the exact field. |
| `load policy: ...` | Blocklist path unreadable/missing. Check permissions and the path. |
| `bind ... address already in use` | Another resolver/agent holds port 53/80/443, or `proxyd` is already running. Check `ss -lntup`. |
| `permission denied` binding `:53`/`:80`/`:443` | Run with `CAP_NET_BIND_SERVICE` (the systemd unit does this) or as root. |

Configuration is validated **before** any socket is bound, so a failed start
never leaves listeners or firewall changes half-applied.

## Clients do not resolve through proxyd

- Confirm the client's resolver points at the `proxyd` host
  (`dns.listen_udp`/`listen_tcp`).
- Verify the service is ready: `curl -fsS http://127.0.0.1:9090/readyz`.
- Query directly: `dig @<proxy-ip> -p 53 example.com`. Expect
  `dns.intercept_ipv4`. If you changed `dns.listen_udp` to a nonstandard port,
  include `-p`.
- Check the logs for `dns_query` events. No event means the query never arrived
  (firewall/resolver path issue).
- Blocked names return `NXDOMAIN` (default) or a sinkhole address; this is
  expected.
- `AAAA` queries for an IPv6-disabled deployment return NODATA. That is
  intentional (see [limitations.md](limitations.md)).

## DNS forwarding loops or upstream errors

`dns_query` events with `action":"error","reason":"upstream"` usually mean the
upstream resolvers are reached through the intercepted path.

- Point `dns.upstream` at resolvers that are not redirected, **or**
- Set `limits.upstream_mark` and ensure the firewall's mark-bypass rules
  (`MARK`) match it, **or**
- Use a bypass `BYPASS_UID`.

If a query is answered by the proxy for a host that should have been forwarded,
check the blocklist/allowlist contents and the `reason` field in the log.

## HTTP requests return 403

- `status:403` with `action":"block"` means the policy blocked the host.
  Confirm the host is intentionally listed and check allowlist precedence.
- `status:400` (`reason":"malformed"`) means the request had an ambiguous or
  invalid authority/`Host`.
- `status:421` (`reason":"sni-mismatch"`) means the TLS SNI and the HTTP `Host`
  disagreed (a possible smuggling/rebinding attempt); the request is refused.

## HTTPS interception fails in the client

- **Certificate not trusted**: the client must trust `rootCA.pem`. See
  [ca-trust.md](ca-trust.md). Confirm the client is using the trust store you
  think it is (many apps have their own).
- **App pins certificates** or embeds roots: it will reject the leaf. This
  cannot be fixed transparently. Use an explicit bypass or accept failure.
- **HTTP/3 / QUIC**: the client may prefer UDP/443. Set `UDP443_MODE=reject`
  (default in the script) so clients fall back to TCP.
- **Unknown SNI**: `tls_handshake` logs with `reason":"no-sni"` mean the
  connection had no usable SNI and was rejected (default) or passed through.
- **ECH enabled**: the hostname is hidden from the proxy; see
  [limitations.md](limitations.md).

## Upstream TLS verification failures

`proxyd` never disables upstream verification. If the origin uses a certificate
that does not validate against the system trust store (private CA, expired,
wrong hostname, missing intermediates), the upstream failure is logged and the
client receives `502`.

- For a private CA, add its roots to the **proxy host's** system trust store
  (`update-ca-certificates` / `update-ca-trust`), not the client's.
- Confirm system time is correct (validity windows).

## Transparent redirect not happening

- Verify the rules are installed: `nft list ruleset | grep -A5 proxyd`.
- Ensure the client's traffic actually traverses this host (routing/gateway).
- Check `HTTP_PORT`/`HTTPS_PORT` match `http.listen`/`https.listen`.
- Ensure proxy-originated sockets are marked (`limits.upstream_mark` == `MARK`)
  or come from `BYPASS_UID`; otherwise upstream connections loop back into the
  redirect.
- Re-run `deploy/nftables-setup.sh` (it tears down old rules first).

## Policy changes are not taking effect

- Send `SIGHUP`: `systemctl reload proxyd` or `kill -HUP <pid>`.
- Or set `policy.reload_interval` for polling.
- Check for `policy_reload` log events. A parse failure logs an error and keeps
  the previous snapshot, so a malformed edit silently preserves old rules until
  fixed.

## Health endpoint unreachable

- It listens on `management.listen` (default `127.0.0.1:9090`), which is
  loopback-only by design. To reach it remotely, set
  `management.allow_non_loopback: true` **and** firewall the port to trusted
  management networks.
- A non-loopback `management.listen` without `allow_non_loopback` fails
  validation at startup.

## High memory or connection warnings

- Lower `limits.max_conns`, `limits.max_header_bytes`, or the timeouts.
- Reduce `ca.leaf_cache_size` if many distinct hostnames are seen.
- Ensure `limits.idle_timeout` is set so idle client connections are reclaimed.

## Collecting diagnostics

```sh
systemctl status proxyd
journalctl -u proxyd --since "10 min ago"
nft list ruleset
ss -lntup | grep proxyd
```

Keep `logging.level: debug` only temporarily; debug can be verbose.
