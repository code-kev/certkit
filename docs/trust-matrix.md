# Trust and platform verification matrix

This matrix reports observed combinations, not a promise that every OS/browser release behaves the same. **Machine-verified** means the listed setup was exercised directly. **Reported** means a passing result was reported but its full source record or exact environment was not retained. **Pending** means no direct result is claimed. Re-check after major OS or browser changes.

| OS / environment | Store or browser | Tier | Verification level and last verified | Observed result / limit |
| --- | --- | --- | --- | --- |
| macOS 26.6 | Current-user login keychain; Chrome and Safari | Supported | Machine-verified · 2026-09-30 | Install, default-policy status, browser HTTPS acceptance, uninstall, and rejection after removal passed in a signed-in session. The System keychain is not written. |
| macOS 26.6 | Firefox NSS profile | Supported | Machine-verified · 2026-09-30 | Firefox 156.0.1 tested. |
| Earlier macOS releases | Login keychain / browsers | Supported | Pending · — | No older OS release is claimed. |
| Ubuntu 24.04.5 | Linux system CA store | Supported | Machine-verified · 2026-09-30 | `update-ca-certificates` install/readback/removal path exercised. |
| Ubuntu 24.04.5 | Chromium and Firefox NSS | Supported | Machine-verified · 2026-09-30 | Chrome 154.0.8037.57 and Firefox 156.0.1 tested with the apt/deb browser setup. Requires `certutil` from `libnss3-tools`. |
| Ubuntu 24.04 | Chromium and Firefox NSS via Snap | Supported | Reported · 2026-09-30 | Passing round-two outcome reported; exact browser versions and raw test record were not retained. |
| Debian 13 / Freedesktop 25.08 | Flatpak Firefox NSS | Supported | Machine-verified · 2026-09-30 | Firefox 157 browser acceptance, removal, and negative checks passed. Requires NSS `certutil`. |
| Fedora 44 | Linux system and NSS stores | Supported | Reported · 2026-09-30 | Passing round-two outcome reported; exact versions and raw test record were not retained. Requires system `certutil` for browser NSS. |
| Windows Server 2025 console | Current-user Root store; Chrome | Supported | Machine-verified · 2026-09-30 | W1 non-admin install/status/uninstall trust cycle passed; Chrome 154.0.8037.58 acceptance tested. Trust applies only to the installing user. |
| Windows Server 2025 RDP session | Current-user Root store; Chrome and Firefox | Supported | Partially machine-verified · 2026-09-30 | Install refusal/approval, exact certificate readback, and Chrome 154.0.8037.93 plus Firefox 157 acceptance passed. Final uninstall readback and rejection remain pending. |
| Windows | Firefox NSS profile with OS-root import disabled | Best effort | Reported · 2026-09-30 | Direct NSS Firefox 157 outcome reported in round two; complete source record was not retained. Windows NSS `certutil` support depends on Mozilla NSS tools, not Microsoft's unrelated `certutil.exe`. |
| WSL2 Ubuntu 24.04 | Linux system trust and Windows isolation | Best effort | Machine-verified · 2026-09-30 | WSL2 2.7.14.0, kernel 6.18.33.2. Linux trust succeeds inside WSL; Windows browsers do not inherit it. Install in Windows for those browsers. |
| WSL1 | Linux system trust and browser behavior | Best effort | Pending · — | No WSL1 result is claimed. |
| Any OS | NSS `cert8.db`-only profile | Unsupported | Not applicable · — | Legacy `cert8.db`-only databases are unsupported. |
| Linux with `/etc/pki/nssdb` target | System NSS database | Best effort / manual-only | Design limit · v1 | `status` can inspect it; certkit does not write it or elevate for it. Use documented manual steps with `sudo` throughout. |
| Windows localized builds | Current-user store / CLI text | Supported | Pending · — | No localized Windows result is claimed. |

## Scope notes

- Windows writes only to the **current user’s** Root store. Running an elevated shell does not change that target; other users, services, and applications under another account do not inherit the installing user’s trust.
- On WSL, the Linux trust store and Windows browser trust are separate. Linux-side success does not establish Windows browser trust.
- Firefox on macOS and Windows normally imports OS roots. Direct NSS handling is relevant when Firefox OS-root import is disabled; the Windows result above is separately labeled with its evidence level.
- On Linux, the browser NSS databases require the system `certutil` utility. Certkit does not download or install it.
- NSS verifier `certutil -V` has had intermittent hosted-runner failures under concurrent load. CI isolates the required verifier invocation; the intermittent failure remains unexplained.
- Hosted macOS native trust mutation timed out at `security add-trusted-cert`. Hosted coverage and native oracles remain enabled; production login-keychain acceptance was checked in a signed-in session. See [CI verification details](ci.md).
