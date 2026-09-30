# Coming from devcert?

certkit and devcert can coexist. They use distinct CA identities and data directories; certkit's installer and uninstaller identify its CA by certificate fingerprint and leave unrelated certificates in place. Prior art: devcert established a JavaScript `certificateFor` API backed by a local CA and OS trust integration. See the [devcert README](https://github.com/davewasmer/devcert).

## Move one application at a time

1. Keep the existing devcert setup while you update and verify the application.
2. Install certkit and its Linux `certutil` prerequisite if needed.
3. Run `certkit install`, then replace the devcert call with certkit's API or configure the [Vite plugin](../README.md#vite).
4. Test the actual browser and runtime. `certkit status` reports detected stores, but an `unknown` or `not-detected` result is not proof of trust.
5. Remove the `devcert` dependency only after no project code calls it.

## Remove old devcert trust separately

`certkit uninstall` removes certkit's CA; it does not remove devcert's CA. devcert's README explains that its OS and browser trust entries may need manual removal. Before removing anything, identify the old CA by its certificate fingerprint and delete only that exact entry from each store/profile where devcert installed it. Do not remove a certificate based on a matching display name alone.

On Linux, browser NSS databases need `certutil` to inspect and remove their own entries. System trust removal uses the distribution's CA directory and rebuild command. On macOS and Windows, use the certificate management UI for the affected user and remove only the verified devcert CA. Close affected browsers and restart them after changing trust.

If both tools remain in use, keep their CA material separate. `certkit caroot` prints certkit's current data directory; it contains `ca-cert.pem`, `ca-key.pem`, and state/cache files. Treat `ca-key.pem` as a private signing key: never commit, copy to another machine, or attach it to an issue.
