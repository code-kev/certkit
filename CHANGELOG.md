# Changelog

## 1.0.0-beta.2

### Patch Changes

- 9daf24d: Reject unknown CLI options before commands run, validate DNS names before URL normalization, keep sudo output off JSON stdout, and detect Linux trust tools from PATH without `which`.

## 1.0.0-beta.1

This is certkit's first public prerelease. It provides a JavaScript library for generating locally trusted development certificates, a CLI for creating certificates and installing, inspecting, or removing CA trust, and a Vite 7/8 plugin for opt-in HTTPS.

### Requirements and limits

- Node.js 22.15.0 or newer is required. Certkit does not download runtime binaries or require OpenSSL.
- Linux browser NSS integration requires the system `certutil` utility. Certkit does not install it.
- macOS trust uses the current user's login keychain, and Windows writes to the current user's Root store. Linux system CA trust is host-wide; browser NSS trust applies to the detected user or browser profiles. Linux `/etc/pki/nssdb` is manual-only, and NSS profiles containing only legacy `cert8.db` files are unsupported.
- WSL Linux trust does not extend to Windows browsers. See the [trust matrix](docs/trust-matrix.md) for platform and browser verification details.
- The Vite plugin does not enable HTTPS by itself; configure `server.https: {}`. The library generates certificates but does not install trust.

See the [README](README.md), [CLI reference](docs/cli.md), and [trust matrix](docs/trust-matrix.md) for setup and supported behavior.

## Unreleased

Changes after `1.0.0-beta.1` will be listed here.
