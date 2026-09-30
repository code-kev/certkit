# Repository guide

- Read the relevant source and tests before changing behavior.
- Keep changes focused and follow the existing TypeScript and documentation style.
- Do not add runtime dependencies without a clear need.
- Run `pnpm test`, `pnpm lint`, `pnpm typecheck`, and `pnpm build` for code changes; run the checks relevant to documentation-only changes.
- Native trust tests can modify operating-system trust settings. Read [docs/ci.md](docs/ci.md) before running an opt-in native test.
- Never include certificate private keys, secrets, or personal machine data in issues, logs, examples, or commits.
- Use [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance and [docs/releasing.md](docs/releasing.md) for release instructions.
