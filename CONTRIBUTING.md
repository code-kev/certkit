# Contributing

Bug reports, reproducible platform results, documentation fixes, and focused code changes are welcome. Please read the [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## Questions and ideas

Usage questions, setup help, and proposals belong in [Discussions](https://github.com/code-kev/certkit/discussions). Use the issue forms for reproducible bugs and scoped feature requests, and [report vulnerabilities privately](https://github.com/code-kev/certkit/security/advisories/new) instead of in a public thread.

## Before opening an issue

- Search existing issues and pull requests.
- For bugs, include certkit version or commit, operating system and version, browser and version, the affected trust store, exact command, and sanitized output.
- Never attach a CA private key, leaf private key, credentials, or unredacted personal paths.
- Feature requests should describe the task and constraints before proposing an implementation.

## Development

Requirements: Node.js 22.15.0 or newer and pnpm 10.34.5.

```sh
git clone https://github.com/code-kev/certkit.git
cd certkit
corepack enable
pnpm install --frozen-lockfile
pnpm test
pnpm lint
pnpm typecheck
pnpm build
```

Tests run with fixtures by default. Native trust tests can change OS trust settings; read [CI and native trust verification](docs/ci.md) before opting in. Do not run native trust mutations on a machine whose trust store you cannot safely restore.

## Pull requests

- Community contributors and casual testers should work from forks. Keep pull requests focused and explain the user-visible reason. Only `code-kev` merges changes to `main`.
- Every pull request needs one approval from an independent reviewer. `code-kev` and `spencermbawe` are eligible reviewers, but an author cannot approve their own change. New commits dismiss stale approvals, the latest push needs approval from someone other than its pusher, and review conversations must be resolved.
- Required checks must pass before merge. Merges use squash merge after an independent approval; reviewer access does not grant permission to merge into `main`.
- Add or update tests for behavior changes and documentation for user-visible behavior.
- Add a Changesets entry for package behavior changes. Documentation-only changes do not need one.
- Run the relevant checks above and include the results in the pull request.
- Follow Conventional Commits for the pull request title (for example, `docs: explain Node trust setup`).

Contributions are submitted under Apache-2.0 §5; there is no CLA or DCO requirement. See the [release guide](docs/releasing.md) for the maintainer release process.
