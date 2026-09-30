# Vite example

This minimal app uses certkit's named Vite plugin export. From the repository root, install the local CA for the current user with `pnpm exec certkit install`, then run the Vite config from this directory. Trust-store behavior depends on the OS/browser; Linux NSS needs `certutil`. See [the trust matrix](../../docs/trust-matrix.md).

The checked-in preview image is a visual snapshot of this page served over local HTTP. It does not verify HTTPS or browser certificate acceptance.
