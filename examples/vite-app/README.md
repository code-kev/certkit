# Vite example

This minimal app uses certkit's named Vite plugin export. From the repository root, install dependencies, build the checkout, and install the local CA for the current user. Then start this example:

```sh
# repository root
pnpm install
pnpm build
node dist/cli/index.js install

# repository root
cd examples/vite-app
pnpm exec vite
```

The Vite config enables HTTPS. Trust-store behavior depends on the OS/browser; Linux NSS needs `certutil`. See [the trust matrix](../../docs/trust-matrix.md).

Open the URL printed by Vite to try the app over HTTPS. Verify browser acceptance against the trust matrix for your platform.
