# Logging and privacy

`proxyd` emits structured logs intended to be safe to collect and retain. This
page describes the schema, the controls, and the privacy trade-offs.

## Format and destination

- `logging.format: json` (default) or `text`.
- `logging.output`: `""` writes to stdout (recommended under systemd/journald);
  a path appends to that file. The file is created if missing.
- `logging.level`: `debug`, `info`, `warn`, or `error`.

With systemd the unit writes to the journal (`journalctl -u proxyd`).

## Event schema

Every record carries a timestamp and level. Operational events use `"event"`:

| Event | Level | Fields |
| --- | --- | --- |
| `startup` | info | `version`, listener addresses, `udp443_mode`, `unknown_sni`, `log_urls`, `privacy_mode` |
| `policy_load` / `policy_reload` | info | `blocklist`, `allowlist`, `block_entries`, `allow_entries`, `skipped`, `loaded_at`, `error` |
| `ca_ready` | info | `cert`, `subject`, `not_after` |
| `ca_regenerated` | warn | `cert` |
| `ready` | info | bound addresses |
| `shutdown` | info | |
| `dns_query` | info/warn | `client`, `question`, `type`, `action` (`allow`/`block`/`forward`/`error`), `reason`, `answer` or `rcode`, `latency_ms` |
| `http_request` | info/warn | `client`, `scheme`, `host`, `port`, `method`, `path`, `action`, `reason`, `status`, `bytes_in`, `bytes_out`, `latency_ms` |
| `tls_handshake` | info/warn | `client` and/or `host`, `action` (`reject`/`block`/`passthrough`), `reason` |

Example:

```json
{"time":"2026-01-01T12:00:00Z","level":"INFO","msg":"request forwarded","event":"http_request","client":"10.0.0.5","scheme":"https","host":"example.com","port":"443","method":"GET","path":"/","action":"allow","reason":"default","status":200,"bytes_in":0,"bytes_out":1256,"latency_ms":42}
```

## What is never logged by default

- Request or response **bodies**.
- Credentials and sensitive headers: `Authorization`, `Proxy-Authorization`,
  `Cookie`, `Set-Cookie`, `Proxy-Authenticate`, `X-Api-Key`, `X-Auth-Token`
  (see `logging.RedactedHeaders`).
- TLS private keys or CA key material.

## URL and path logging

Paths and query strings frequently contain secrets (tokens, session IDs, search
terms). They are controlled by two settings:

- `logging.log_urls: false` (default) — only the host is logged; `path` is
  omitted.
- `logging.log_urls: true` — full request path and query string are logged.
- `logging.privacy_mode: true` — forces hostname-only logging even if
  `log_urls` is true.

Start with hostname-only logging and only enable full URLs after confirming no
sensitive data flows through the paths.

## Sensitive events that are logged

For security and troubleshooting, `proxyd` does log: TLS handshake failures,
unknown-SNI rejections, upstream certificate verification failures, blocked
requests, DNS errors, and policy reload results. These carry hostnames, client
IPs, and reasons, but not payloads or credentials.

## Log storage and retention

- `logging.output` appends; use `logrotate` or your collector to bound growth.
- The systemd unit sends logs to the journal; configure journald retention
  there.
- Treat logs as sensitive: they contain client IPs and visited hostnames.

## Management endpoints

`/healthz` and `/readyz` expose only liveness/readiness. They never expose CA
keys or configuration secrets, and are bound to loopback unless
`management.allow_non_loopback: true` is explicitly set.
