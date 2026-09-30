# Node.js trust setup

Node.js 22.15.0 or newer is required by certkit. Node's CA behavior depends on the platform and runtime configuration.

## Prefer the system store where supported

Node 22.15.0 documents `--use-system-ca` for Windows and macOS. It combines system trust with Node's bundled roots. Set it for one process:

```sh
node --use-system-ca app.js
```

Or for child Node processes in the current shell:

```sh
export NODE_OPTIONS=--use-system-ca
node app.js
```

PowerShell:

```powershell
$env:NODE_OPTIONS = '--use-system-ca'
node app.js
```

On Linux, Node 22.15 follows the OpenSSL default CA file and directory (commonly `/etc/ssl/cert.pem` and `/etc/ssl/certs`), which distributions generally maintain as their system CA store. The Node 22.15 docs record non-Windows/non-macOS support for the `--use-system-ca` flag beginning in Node 23.9.0; do not assume that flag works on Linux in the Node 22 line.

## Add certkit's CA explicitly

After running `certkit install` or `certkit create`, export the CA certificate path for a Node process that does not use the OS trust store. The CA directory is printed by `certkit caroot`; the CA certificate filename is `ca-cert.pem`.

macOS/Linux:

```sh
export NODE_EXTRA_CA_CERTS="$(certkit caroot)/ca-cert.pem"
node app.js
```

PowerShell:

```powershell
$caDir = certkit caroot
$env:NODE_EXTRA_CA_CERTS = Join-Path $caDir 'ca-cert.pem'
node app.js
```

For a Node HTTPS client using an explicit `ca` option, include the required CA there: Node ignores both its normal roots and `NODE_EXTRA_CA_CERTS` when that option is set.

## CI and containers

CI often has no writable OS trust store or interactive elevation. Generate the CA and leaf in a job-local directory, then give Node the CA PEM:

```sh
export CERTKIT_HOME="$RUNNER_TEMP/certkit-ca"
certkit create localhost
export NODE_EXTRA_CA_CERTS="$CERTKIT_HOME/ca-cert.pem"
node scripts/https-smoke.mjs
```

The certificate and key are written to the current directory by default; keep them out of artifacts and source control. To use an explicit output directory, create it first and pass `--output`/`-o` to `create`. Delete the job-local CA directory and generated key files at job end.

If another program needs a PEM file rather than a system-store entry, use `certkit create` and configure that client with the returned certificate and key paths. Do not publish or reuse the development CA key outside the local job.

## Details

- `NODE_EXTRA_CA_CERTS` is read only when Node starts. Restart the process after changing it.
- The file must contain PEM certificates. A missing or malformed file emits a warning; errors are otherwise ignored.
- The variable is ignored when Node runs as setuid root or with Linux file capabilities.
- `NODE_OPTIONS` applies to descendant Node processes in the shell environment. Avoid setting it globally on shared runners.

References: [Node.js 22.15 CLI: `--use-system-ca`](https://nodejs.org/download/release/v22.15.0/docs/api/cli.html#--use-system-ca) and [`NODE_EXTRA_CA_CERTS`](https://nodejs.org/download/release/v22.15.0/docs/api/cli.html#node_extra_ca_certsfile).
