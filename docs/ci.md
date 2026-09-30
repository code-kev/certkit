# CI and native trust verification

Hosted CI runs coverage on Ubuntu, macOS, and Windows with Node 22.15.0 and
Node 24. It provisions and checks OpenSSL and NSS tools; macOS also checks
`security`. Ubuntu runs a real system trust install, acceptance, removal, and
rejection test. Windows fixture tests run in hosted CI. The interactive W1
gate also passed a non-admin current-user trust cycle on Windows Server 2025
console with Chrome 154.0.8037.58. A separate Server 2025 RDP Firefox/Chrome
acceptance run passed installation and browser checks, but its final uninstall
readback and rejection check remain pending. These machine results do not
establish coverage for other Windows releases or locales; see the
[trust matrix](trust-matrix.md).

## macOS acceptance gate

On the macOS hosted runners exercised on September 30, 2026,
`security add-trusted-cert` stalled until the test's 30-second timeout.
Hosted macOS coverage and oracle checks remain enabled. User-domain native
trust installation is verified in a signed-in Mac session where the native
authorization prompt can be answered.

To run the native adapter test from a checkout in that session:

```sh
pnpm install --frozen-lockfile
pnpm build
CERTKIT_MACOS_INTERACTIVE_E2E=1 pnpm vitest run test/e2e/trust.test.ts
```

This opt-in test changes user-domain trust settings using a throwaway keychain.
Approve the native prompt when requested. It checks exact certificate readback,
default-policy acceptance, removal, and rejection, then removes trust settings
before deleting the keychain. A cleanup failure fails the test and retains its
artifacts for recovery. The test does not itself exercise a browser or the
production login keychain.

The signed-in acceptance gate also exercises the actual CLI against the login
keychain and checks HTTPS browser acceptance, uninstall, and subsequent
rejection. These machine checks passed on macOS 26.6; Firefox NSS integration
was checked separately. Earlier macOS versions remain unverified. Re-run the
signed-in gate when changing macOS trust behavior, and record the OS/browser
versions and cleanup result.
