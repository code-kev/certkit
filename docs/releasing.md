# Releasing

Releases use `.github/workflows/release.yml`. The workflow validates that the selected commit is on `main`, its tag matches the package version, and the `required`, `test`, `build`, `lint`, and `typecheck` checks succeeded on that exact commit from GitHub Actions. Missing, pending, skipped, failed, or unavailable checks stop the run. `pr-title` and PR-scoped `dependency-review` are explicit exemptions.

Before a tag release can publish, configure the `npm-publish` GitHub environment with at least one required reviewer, enable immutable releases for the repository, and configure npm trusted publishing for this workflow and environment. The package `repository` object must be the canonical `git+https://github.com/code-kev/certkit.git` URL; the source gate verifies it. Store a fine-grained `RELEASE_SETTINGS_TOKEN` as an `npm-publish` environment secret with repository `Administration: read` only; GitHub does not expose the immutable-release setting to the workflow's `GITHUB_TOKEN`. The workflow uses that token only for the immutable-release settings read, uses `GITHUB_TOKEN` for environment and release APIs, and stops if the token, reviewer rule, or immutable setting is unavailable. It also checks `immutable: true` on an already-published GitHub Release. These owner-side settings and the read-only secret are pending setup. Do not create or change them as part of a release run.

## First publication

The initial version starts before a tag exists:

1. Open `Release` with **Run workflow**, select the `main` branch, and enter the exact 40-character commit SHA from the merged version PR.
2. The workflow validates the source and required checks, builds and packs once, installs that tarball in a fresh consumer, checks the public imports, declarations, CLI version, network denial, and installed dependency tree, and saves the tarball with its manifest. The artifact expires after 90 days.
3. Download the named artifact from that successful workflow run. Verify `manifest.json` against the tarball with `sha256sum` and check that `integrity` is the tarball's `sha512-…` SRI value.
4. Publish that exact `.tgz` interactively with npm 2FA. Compare `npm view certkit@VERSION dist.integrity` with the manifest `integrity`. Do not rebuild, repack, retag, or publish another tarball for the version.
5. Tag the same checked commit `vVERSION` and push the tag. The workflow finds the bootstrap artifact by version and selected source SHA, even if `main` advanced after dispatch. It verifies the manifest's full SHA and version, checks the digest and npm registry integrity, skips npm publish, and creates the GitHub release metadata. The first version has no npm OIDC provenance; the release records that fact. Bind the npm trusted publisher before the next release.
6. Revoke any temporary credential used for the manual publish.

The workflow never stores an npm token. The bootstrap dispatch stops before the OIDC publish job. Until the release-day bootstrap rehearsal is completed, this path is prepared but unrehearsed.

## Later releases and retries

Merge the manually prepared Changesets version PR, then create and push the matching `vVERSION` tag. The tag run validates the same source gates before building. It creates one tarball, smoke-tests that tarball, and passes it to the protected `npm-publish` job by artifact ID; every consumer recomputes and checks the tarball SHA-256 from `manifest.json`.

If a version is already present in npm, the workflow never publishes it again and never builds a replacement. It resolves the prior tarball artifact for that exact source commit and version and checks the manifest, SHA-256, SRI, and current registry integrity. Missing, expired, or ambiguous artifacts stop the workflow. Complete missing metadata manually and record it; immutable published releases cannot be edited.

Use **Re-run failed jobs** while the tested artifact is retained; the workflow reuses it. Each run records the selected source SHA in its Actions title. If an earlier matching run or attempt exists without an available artifact, the workflow stops even when npm still reports the version as unpublished. This can also block a retry after a failure before artifact upload, because the workflow cannot prove that no tarball was produced. Recover manually from the original tarball or prepare a separately reviewed release source; the workflow will not rebuild that version automatically. Do not start a second bootstrap for an already published version. Artifact retention is at most 90 days, so complete the first-publication publish-and-tag handoff within that window.

The workflow generates GitHub artifact attestations for the exact tarball and separately for the CycloneDX SBOM. The SBOM records the release source SHA, version, and tarball SHA-256. The workflow uploads the tarball, manifest, and SBOM to a draft GitHub Release and publishes the draft only after those steps succeed. Immutable-release repository settings must remain enabled.

The producer lockfile check and fresh npm consumer install both inspect package identity and reject runtime lifecycle scripts. `@peculiar/utils` is allowed as an already-locked transitive dependency of `@peculiar/asn1-schema` in the `@peculiar/x509` runtime closure.
