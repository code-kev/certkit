# Security policy

## Report a vulnerability

Please do not report security vulnerabilities in public issues. Use [GitHub’s private vulnerability reporting for this repository](https://github.com/code-kev/certkit/security/advisories/new). Include the affected certkit version or commit, platform, impact, and a minimal reproduction. Do not include real private keys, customer data, or credentials.

If private GitHub reporting is unavailable, contact [the maintainer privately](mailto:rodrigs.kevin@gmail.com). Do not post exploit details publicly.

## Response and disclosure

We aim to acknowledge a report within 14 days. Fix timing depends on severity and affected releases; remediation is best effort. We ask reporters to coordinate public disclosure for up to 90 days while a fix is prepared. We will work with the reporter on a shorter schedule when the issue is already public or active exploitation requires it.

## Supported versions

For each supported major version, security fixes target its latest minor release. Before the first npm release, there are no published package versions covered by this policy; report issues against the repository’s current code.

## Scope

This policy covers certkit’s source, release artifacts, and project-controlled distribution configuration. A locally installed certkit development CA is intended only for development on the user’s own machine. If a generated CA may have been exposed or used to intercept real traffic, report it privately and remove that CA with `certkit uninstall` after coordinating any required investigation.

Trusting a local CA means software that can use its signing key can mint certificates trusted by that user’s applications. certkit protects stored keys against other local accounts and accidental exposure; it cannot protect a key from hostile code already running as the same user. Never share or commit the CA key.
