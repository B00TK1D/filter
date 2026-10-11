# Root CA trust

HTTPS interception (MITM) requires `proxyd` to present a leaf certificate the
client trusts. `proxyd` signs leaves with a locally generated root CA; clients
must trust that CA. **Only** the CA certificate (`rootCA.pem`) is distributed —
never the private key.

## Where the CA lives

| File | Default | Notes |
| --- | --- | --- |
| Certificate | `<ca.data_dir>/rootCA.pem` | Public; distribute to clients |
| Private key | `<ca.data_dir>/rootCA-key.pem` | Secret; `0600`, in a `0700` directory |

With the default config this is `/var/lib/proxyd/rootCA.pem` and
`/var/lib/proxyd/rootCA-key.pem`. Override with `ca.cert_file` / `ca.key_file`.

On first startup `proxyd` creates an ECDSA P-256 CA (default `ca.validity:
8760h`). Restarts reuse the exact same CA. If only one of the two files exists,
or the pair is corrupt or mismatched, startup fails clearly instead of silently
rotating the CA (which would break every trusting client).

## Security warnings

- The CA can impersonate any hostname for clients that trust it. Treat
  `rootCA-key.pem` as a high-value secret and the proxy host as a security
  boundary.
- The key is never served by an endpoint and never logged.
- Do not copy the private key to clients. Distribute only `rootCA.pem`.
- Distribute the certificate over an out-of-band, authenticated channel.

## Install the CA on clients

Copy `rootCA.pem` to the client first (via a secure channel), then:

### Debian / Ubuntu

```sh
sudo cp rootCA.pem /usr/local/share/ca-certificates/proxyd-rootCA.crt
sudo update-ca-certificates
```

### RHEL / Fedora / CentOS

```sh
sudo cp rootCA.pem /etc/pki/ca-trust/source/anchors/proxyd-rootCA.pem
sudo update-ca-trust
```

### Arch

```sh
sudo cp rootCA.pem /etc/ca-certificates/trust-source/anchors/proxyd-rootCA.crt
sudo trust extract-compat
```

### Windows

```powershell
Import-Certificate -FilePath rootCA.pem -CertStoreLocation Cert:\LocalMachine\Root
```

Or via the GUI: `certlm.msc` → Trusted Root Certification Authorities →
Import.

### macOS

```sh
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain rootCA.pem
```

### Firefox

Firefox uses its own trust store:

1. Settings → Privacy & Security → Certificates → View Certificates.
2. Authorities → Import → select `rootCA.pem` → trust it to identify websites.

### Android / iOS

- **iOS**: AirDrop or email the `.pem`, then Settings → General → VPN & Device
  Management → install the profile, then Settings → General → About →
  Certificate Trust Settings → enable full trust.
- **Android**: Install as a user certificate (Settings → Security →
  Encryption & credentials). Note that apps that only trust the system store
  will not honor user-installed CAs.

## Applications with their own trust stores

Many applications and runtimes do not use the OS trust store:

- **Java**: import into the JRE/JDK truststore with `keytool`.
- **Node.js**: set `NODE_EXTRA_CA_CERTS=/path/to/rootCA.pem`.
- **Python (requests/urllib)**: set `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`.
- **Go**: honors `SSL_CERT_FILE` and `SSL_CERT_DIR`.
- **curl**: honors the system store, or use `--cacert`.
- Browsers and apps with **certificate pinning** or embedded roots will reject
  the leaf certificate; these cannot be intercepted transparently. See
  [limitations.md](limitations.md).

## Regenerate the CA (development only)

To deliberately replace the CA and issue a fresh one:

```sh
proxyd -dev-regenerate-ca -config /etc/proxyd/config.yaml   # or ca.regenerate: true
```

This deletes and recreates `rootCA.pem` / `rootCA-key.pem`. Every client must
reinstall the new certificate. **Never enable this in production.** The service
logs a warning (`ca_regenerated`) when it happens.

## Remove the CA

Uninstall it with the inverse of the commands above (e.g.
`update-ca-certificates --fresh` after deleting the file, or remove it from the
Windows/macOS/Firefox trust stores). Removing trust is immediate for new
connections.
