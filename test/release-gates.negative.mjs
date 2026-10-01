import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { checkConsumerTree } from '../scripts/check-deps.mjs';
import {
  assertEgressDenied,
  assertSettingsToken,
  releaseRunMatchesSource,
  releaseStateForTag,
  requiredChecks,
  resolveReusableArtifact,
  selectReusableArtifact,
  verifyCheckRuns,
  verifyManifest,
  verifyPublishedRelease,
  verifyRegistryIntegrity,
  verifyRepository,
  verifyTagVersion,
} from '../scripts/release.mjs';

const releaseWorkflow = readFileSync(
  new URL('../.github/workflows/release.yml', import.meta.url),
  'utf8',
);
const workflowStepScript = (name) => {
  const start = releaseWorkflow.indexOf(`- name: ${name}`);
  assert.notEqual(start, -1, `missing workflow step: ${name}`);
  const end = releaseWorkflow.indexOf('\n      - ', start);
  const step = releaseWorkflow.slice(start, end < 0 ? undefined : end);
  const runStart = step.indexOf('        run: |\n');
  assert.notEqual(runStart, -1, `workflow step has no script: ${name}`);
  return step
    .slice(runStart + '        run: |\n'.length)
    .split('\n')
    .map((line) => {
      if (line && !line.startsWith('          ')) return undefined;
      return line.slice(10);
    })
    .filter((line) => line !== undefined)
    .join('\n')
    .replace(/\n+$/, '');
};
const sourceStep = releaseWorkflow.slice(
  releaseWorkflow.indexOf(
    '- name: Validate selected source and required checks',
  ),
  releaseWorkflow.indexOf(
    '\n      - name:',
    releaseWorkflow.indexOf(
      '- name: Validate selected source and required checks',
    ),
  ),
);
const sourceRunStart = sourceStep.indexOf('        run: |\n');
assert.notEqual(sourceRunStart, -1);
const sourceLines = [];
for (const line of sourceStep
  .slice(sourceRunStart + '        run: |\n'.length)
  .split('\n')) {
  if (line && !line.startsWith('          ')) break;
  sourceLines.push(line.slice(10));
}
const sourceScript = sourceLines.join('\n').replace(/\n+$/, '');
const sourcePrefixEnd = sourceScript.indexOf('\nversion=');
assert.notEqual(sourcePrefixEnd, -1);
const sourceSelectionPrefix = sourceScript.slice(0, sourcePrefixEnd);
const dispatchGuardStart = releaseWorkflow.indexOf(
  '- name: Guard workflow-dispatch mode',
);
assert.notEqual(dispatchGuardStart, -1);
const dispatchGuardEnd = releaseWorkflow.indexOf(
  '\n      - name:',
  dispatchGuardStart,
);
const dispatchGuardStep = releaseWorkflow.slice(
  dispatchGuardStart,
  dispatchGuardEnd,
);
const resumeArtifactGuardScript = workflowStepScript(
  'Require the original artifact for tagged release recovery',
);
const publishedReleaseStepStart = releaseWorkflow.indexOf(
  '- name: Verify published release immutability and assets',
);
assert.notEqual(publishedReleaseStepStart, -1);
const publishedReleaseStepEnd = releaseWorkflow.indexOf(
  '\n      - name:',
  publishedReleaseStepStart,
);
const publishedReleaseStep = releaseWorkflow.slice(
  publishedReleaseStepStart,
  publishedReleaseStepEnd,
);
const publishedReleaseRunStart =
  publishedReleaseStep.indexOf('        run: |\n');
assert.notEqual(publishedReleaseRunStart, -1);
const publishedReleaseLines = [];
for (const line of publishedReleaseStep
  .slice(publishedReleaseRunStart + '        run: |\n'.length)
  .split('\n')) {
  if (line && !line.startsWith('          ')) break;
  publishedReleaseLines.push(line.slice(10));
}
const publishedReleaseScript = publishedReleaseLines
  .join('\n')
  .replace(/\n+$/, '');
const recoveryAttestationScript = workflowStepScript(
  'Verify tagged recovery tarball attestation',
);
const publishedReleaseFixture = mkdtempSync(
  join(tmpdir(), 'certkit published release-'),
);
try {
  const checkout = join(publishedReleaseFixture, 'checkout');
  const releaseDir = join(checkout, 'release');
  const output = join(publishedReleaseFixture, 'github-output');
  const preload = join(publishedReleaseFixture, 'github-fixture.mjs');
  mkdirSync(releaseDir, { recursive: true });
  writeFileSync(join(releaseDir, 'certkit-v1.2.3.tgz'), 'fixture');
  writeFileSync(output, '');
  writeFileSync(
    preload,
    `globalThis.fetch = async () => new Response(JSON.stringify([{
      id: 42, tag_name: 'v1.2.3', draft: false, immutable: true, prerelease: false,
      assets: ['certkit-v1.2.3.tgz', 'manifest.json', 'sbom.cdx.json'].map(name => ({ name }))
    }]), { status: 200 });\n`,
  );
  const verifyPublishedReleaseStep = (script) =>
    spawnSync('bash', ['-e', '-o', 'pipefail', '-c', script], {
      cwd: checkout,
      env: {
        ...process.env,
        GITHUB_OUTPUT: output,
        GITHUB_TOKEN: 'fixture',
        GITHUB_REPOSITORY: 'code-kev/certkit',
        RELEASE_TAG: 'v1.2.3',
        RELEASE_VERSION: '1.2.3',
        NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
        RELEASE_HELPER: fileURLToPath(
          new URL('../scripts/release.mjs', import.meta.url),
        ),
      },
      encoding: 'utf8',
    });
  const outputCheck = verifyPublishedReleaseStep(
    publishedReleaseScript.replace(
      'node scripts/release.mjs release-state',
      'node "$RELEASE_HELPER" release-state',
    ),
  );
  assert.match(
    publishedReleaseScript,
    /node scripts\/release\.mjs release-state/,
  );
  assert.match(
    readFileSync(join(checkout, 'release-state.txt'), 'utf8'),
    /exists=true\ndraft=false\n/,
    `release-state helper output was not captured: ${outputCheck.stderr}`,
  );
  assert.equal(outputCheck.status, 0, outputCheck.stderr);
  assert.equal(readFileSync(output, 'utf8'), '');
} finally {
  rmSync(publishedReleaseFixture, { recursive: true, force: true });
}
const dispatchGuardRunStart = dispatchGuardStep.indexOf('        run: |\n');
assert.notEqual(dispatchGuardRunStart, -1);
const dispatchGuardLines = [];
for (const line of dispatchGuardStep
  .slice(dispatchGuardRunStart + '        run: |\n'.length)
  .split('\n')) {
  if (line && !line.startsWith('          ')) break;
  dispatchGuardLines.push(line.slice(10));
}
const dispatchGuardScript = dispatchGuardLines.join('\n').replace(/\n+$/, '');
const sourceHistory = mkdtempSync(join(tmpdir(), 'certkit-source-selection-'));
const emptyGitConfig = join(sourceHistory, 'empty.gitconfig');
const fixtureGitEnv = {
  ...process.env,
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: emptyGitConfig,
  GIT_CONFIG_COUNT: '1',
  GIT_CONFIG_KEY_0: 'user.useConfigOnly',
  GIT_CONFIG_VALUE_0: 'true',
};
for (const name of [
  'EMAIL',
  'GIT_AUTHOR_NAME',
  'GIT_AUTHOR_EMAIL',
  'GIT_COMMITTER_NAME',
  'GIT_COMMITTER_EMAIL',
  'GIT_CONFIG_PARAMETERS',
])
  delete fixtureGitEnv[name];
const gitRun = (args) => {
  const result = spawnSync('git', args, {
    env: fixtureGitEnv,
    encoding: 'utf8',
  });
  assert.equal(
    result.status,
    0,
    `git ${args.join(' ')} failed with status ${result.status}:\n${result.stderr || result.error?.message || 'no stderr'}`,
  );
  return result.stdout;
};
const gitOutput = (args) => gitRun(args).trim();
let selectedSha;
try {
  writeFileSync(emptyGitConfig, '');
  const origin = join(sourceHistory, 'origin.git');
  const seed = join(sourceHistory, 'seed');
  const checkout = join(sourceHistory, 'checkout');
  gitRun(['init', '--bare', '--initial-branch=main', origin]);
  gitRun(['init', '--initial-branch=main', seed]);
  gitRun(['-C', seed, 'config', 'user.name', 'Release test']);
  gitRun(['-C', seed, 'config', 'user.email', 'release@example.test']);
  writeFileSync(join(seed, 'source.txt'), 'base\n');
  gitRun(['-C', seed, 'add', 'source.txt']);
  gitRun(['-C', seed, 'commit', '-m', 'base']);
  const ancestorSha = gitOutput(['-C', seed, 'rev-parse', 'HEAD']);
  writeFileSync(join(seed, 'source.txt'), 'main tip\n');
  gitRun(['-C', seed, 'commit', '-am', 'main tip']);
  const mainTipSha = gitOutput(['-C', seed, 'rev-parse', 'HEAD']);
  gitRun(['-C', seed, 'remote', 'add', 'origin', origin]);
  gitRun(['-C', seed, 'push', '-u', 'origin', 'main']);
  gitRun(['-C', seed, 'tag', '-a', 'v1.2.3', '-m', 'v1.2.3', ancestorSha]);
  gitRun(['-C', seed, 'push', 'origin', 'refs/tags/v1.2.3']);
  gitRun(['clone', origin, checkout]);
  gitRun(['-C', checkout, 'config', 'user.name', 'Release test']);
  gitRun(['-C', checkout, 'config', 'user.email', 'release@example.test']);
  const runDispatchGuard = (
    finalize,
    published,
    resume = false,
    ref = 'refs/heads/main',
  ) =>
    spawnSync('bash', ['-e', '-o', 'pipefail', '-c', dispatchGuardScript], {
      cwd: checkout,
      env: {
        ...fixtureGitEnv,
        EVENT_NAME: 'workflow_dispatch',
        FINALIZE_PUBLISHED_RELEASE: String(finalize),
        RESUME_TAGGED_RELEASE: String(resume),
        PACKAGE_PUBLISHED: String(published),
        RELEASE_VERSION: '1.2.3',
        RELEASE_SHA: ancestorSha,
        GITHUB_REF: ref,
      },
      encoding: 'utf8',
    });
  assert.equal(runDispatchGuard(false, false).status, 0);
  assert.notEqual(
    runDispatchGuard(false, true).status,
    0,
    'default dispatch must refuse an already-published version',
  );
  assert.equal(runDispatchGuard(true, true).status, 0);
  assert.equal(runDispatchGuard(false, false, true).status, 0);
  assert.notEqual(
    runDispatchGuard(false, true, true).status,
    0,
    'tagged release recovery must reject an already-published version',
  );
  assert.notEqual(
    runDispatchGuard(true, false, true).status,
    0,
    'tagged release recovery cannot be combined with metadata finalization',
  );
  assert.notEqual(
    runDispatchGuard(false, false, true, 'refs/heads/codex/recovery').status,
    0,
    'tagged release recovery must run from main',
  );
  assert.notEqual(
    runDispatchGuard(true, false).status,
    0,
    'metadata recovery must require an already-published version',
  );
  gitRun([
    '-C',
    seed,
    'tag',
    '--force',
    '--annotate',
    '--message',
    'mismatched v1.2.3',
    'v1.2.3',
    mainTipSha,
  ]);
  gitRun(['-C', seed, 'push', '--force', 'origin', 'refs/tags/v1.2.3']);
  assert.notEqual(
    runDispatchGuard(true, true).status,
    0,
    'metadata recovery must require the version tag to target the selected commit',
  );
  assert.notEqual(
    runDispatchGuard(false, false, true).status,
    0,
    'tagged release recovery must require the version tag to target the selected commit',
  );
  gitRun(['-C', seed, 'push', 'origin', ':refs/tags/v1.2.3']);
  assert.notEqual(
    runDispatchGuard(true, true).status,
    0,
    'metadata recovery must require an existing version tag',
  );
  assert.notEqual(
    runDispatchGuard(false, false, true).status,
    0,
    'tagged release recovery must require an existing version tag',
  );
  const runSelection = (requestedSha) =>
    spawnSync('bash', ['-e', '-o', 'pipefail', '-c', sourceSelectionPrefix], {
      cwd: checkout,
      env: { ...fixtureGitEnv, RELEASE_SHA: requestedSha },
      encoding: 'utf8',
    });

  gitRun(['-C', checkout, 'checkout', ancestorSha]);
  const valid = runSelection(ancestorSha);
  assert.equal(valid.status, 0, valid.stderr);
  selectedSha = ancestorSha;
  gitRun(['-C', checkout, 'checkout', mainTipSha]);
  const mismatch = runSelection(ancestorSha);
  assert.notEqual(
    mismatch.status,
    0,
    'a requested ancestor must not validate when a different commit is checked out',
  );
  for (const invalidSha of ['', 'not-a-sha'])
    assert.notEqual(runSelection(invalidSha).status, 0);
  gitRun(['-C', checkout, 'checkout', '--orphan', 'unrelated']);
  gitRun(['-C', checkout, 'commit', '--allow-empty', '-m', 'unrelated']);
  const unrelatedSha = gitOutput(['-C', checkout, 'rev-parse', 'HEAD']);
  assert.notEqual(runSelection(unrelatedSha).status, 0);
} finally {
  rmSync(sourceHistory, { recursive: true, force: true });
}

const sha = selectedSha;
const checkRuns = requiredChecks.map((name) => ({
  name,
  head_sha: sha,
  app: { id: 15368 },
  status: 'completed',
  conclusion: 'success',
  started_at: '2026-09-30T00:00:00Z',
}));
verifyCheckRuns(checkRuns, sha);
for (const invalid of [
  checkRuns.slice(1),
  checkRuns.map((run, index) =>
    index ? run : { ...run, conclusion: 'skipped' },
  ),
  checkRuns.map((run, index) =>
    index ? run : { ...run, status: 'in_progress' },
  ),
  checkRuns.map((run, index) =>
    index ? run : { ...run, conclusion: 'failure' },
  ),
  checkRuns.map((run, index) =>
    index ? run : { ...run, head_sha: 'b'.repeat(40) },
  ),
  checkRuns.map((run, index) => (index ? run : { ...run, app: { id: 1 } })),
])
  assert.throws(() => verifyCheckRuns(invalid, sha));

verifyTagVersion('v1.2.3', '1.2.3');
assert.throws(() => verifyTagVersion('v1.2.4', '1.2.3'));
const releaseTag = 'v1.2.3';
const draftRelease = { id: 91, tag_name: releaseTag, draft: true };
assert.deepEqual(releaseStateForTag([draftRelease], releaseTag), {
  exists: true,
  draft: true,
  id: 91,
  action: 'edit',
});
assert.deepEqual(releaseStateForTag([], releaseTag), {
  exists: false,
  draft: false,
  id: '',
  action: 'create',
});
assert.throws(() =>
  releaseStateForTag([draftRelease, draftRelease], releaseTag),
);
const releaseHelper = readFileSync(
  new URL('../scripts/release.mjs', import.meta.url),
  'utf8',
);
const egressSmoke = readFileSync(
  new URL('../scripts/egress-smoke.mjs', import.meta.url),
  'utf8',
);
assert.match(releaseHelper, /githubList\('releases\?per_page=100'\)/);
assert.doesNotMatch(releaseHelper, /releases\/tags/);
assert.match(
  releaseHelper,
  /actions\/workflows\/release\.yml\/runs\?per_page=100/,
);
assert.match(releaseHelper, /actions\/artifacts\?name=/);
assert.doesNotMatch(releaseHelper, /runs\?head_sha=/);
assert.match(
  releaseWorkflow,
  /^run-name: Release \$\{\{ inputs\.release_sha \|\| github\.sha \}\}$/m,
);
assert.match(
  releaseWorkflow,
  /selected: \$\{\{ steps\.source\.outputs\.selected \}\}/,
);
assert.match(releaseWorkflow, /echo "selected=\$RELEASE_SHA"/);
assert.match(
  releaseWorkflow,
  /ref: \$\{\{ needs\.validate\.outputs\.selected \}\}/,
);
assert.match(
  releaseWorkflow,
  /RELEASE_SHA: \$\{\{ needs\.validate\.outputs\.selected \}\}/,
);
assert.match(releaseWorkflow, /node scripts\/release\.mjs repository/);
assert.match(
  releaseWorkflow,
  /RELEASE_VERSION="\$version" node scripts\/release\.mjs checks/,
);
assert.doesNotMatch(releaseWorkflow, /needs\.validate\.outputs\.sha/);
assert.match(
  releaseWorkflow,
  /sudo unshare --net -- runuser .*scripts\/egress-smoke\.mjs/,
);
assert.match(
  egressSmoke,
  /createRequire\(resolve\('consumer', 'package\.json'\)\)/,
);
assert.match(egressSmoke, /consumerRequire\.resolve\('certkit'\)/);
assert.match(egressSmoke, /consumerRequire\.resolve\('certkit\/vite'\)/);
assert.match(releaseWorkflow, /RELEASE_ACTION.*outputs\.action/);
assert.match(
  releaseWorkflow,
  /resume_tagged_release:[\s\S]*?default: false[\s\S]*?type: boolean/,
);
assert.match(releaseWorkflow, /resume_artifact_id:[\s\S]*?type: string/);
assert.match(
  releaseWorkflow,
  /finalize_published_release:[\s\S]*?default: false[\s\S]*?type: boolean/,
);
assert.match(
  releaseWorkflow,
  /if: github\.event_name == 'push' \|\| \(github\.event_name == 'workflow_dispatch' && \(\(inputs\.finalize_published_release && needs\.validate\.outputs\.published == 'true'\) \|\| inputs\.resume_tagged_release\)\)/,
);
assert.match(
  releaseWorkflow,
  /if: github\.event_name == 'workflow_dispatch' && inputs\.finalize_published_release != true/,
);
assert.match(
  releaseWorkflow,
  /Require published version before metadata recovery[\s\S]*?test "\$PACKAGE_PUBLISHED" = true/,
);
assert.match(
  releaseWorkflow,
  /Guard workflow-dispatch mode[\s\S]*?RESUME_TAGGED_RELEASE[\s\S]*?test "\$PACKAGE_PUBLISHED" = false/,
);
assert.match(
  releaseWorkflow,
  /test "\$FINALIZE_PUBLISHED_RELEASE" != true \|\| test "\$RESUME_TAGGED_RELEASE" != true/,
);
assert.match(
  dispatchGuardStep,
  /test "\$GITHUB_REF" = refs\/heads\/main[\s\S]*expected_tag="v\$RELEASE_VERSION"[\s\S]*tag_sha.*RELEASE_SHA/,
);
assert.match(
  sourceScript,
  /if \[\[ "\$EVENT_NAME" == push \]\]; then\n\s+RELEASE_VERSION="\$version" node scripts\/release\.mjs version/,
);
assert.doesNotMatch(sourceScript, /RESUME_TAGGED_RELEASE/);
const registryGuardIndex = releaseWorkflow.indexOf(
  '- name: Require published version before metadata recovery',
);
const installNpmIndex = releaseWorkflow.indexOf(
  '- name: Install OIDC-capable npm CLI',
);
const publishNpmIndex = releaseWorkflow.indexOf(
  '- name: Publish the tested tarball by OIDC',
);
assert.ok(
  registryGuardIndex < installNpmIndex && installNpmIndex < publishNpmIndex,
);
assert.match(
  releaseWorkflow,
  /Confirm registry integrity after publish\n {8}if: steps\.registry\.outputs\.published != 'true' && \(github\.event_name == 'push' \|\| \(github\.event_name == 'workflow_dispatch' && inputs\.resume_tagged_release\)\)/,
);
assert.match(
  releaseWorkflow.slice(
    publishNpmIndex,
    releaseWorkflow.indexOf('\n      - name:', publishNpmIndex),
  ),
  /if: steps\.registry\.outputs\.published != 'true' && \(github\.event_name == 'push' \|\| \(github\.event_name == 'workflow_dispatch' && inputs\.resume_tagged_release\)\)/,
);
assert.match(
  releaseWorkflow,
  /SOURCE_COMMIT: \$\{\{ needs\.validate\.outputs\.selected \}\}/,
);
assert.match(
  releaseWorkflow,
  /Attest the SBOM[\s\S]*?subject-path: release-metadata\/sbom\.cdx\.json/,
);
assert.doesNotMatch(
  releaseWorkflow.slice(
    releaseWorkflow.indexOf('- name: Attest the SBOM'),
    releaseWorkflow.indexOf(
      '\n      - name:',
      releaseWorkflow.indexOf('- name: Attest the SBOM'),
    ),
  ),
  /sbom-path:/,
);
assert.match(
  releaseWorkflow,
  /Attest tarball and SBOM separately\n {8}if: github\.event_name == 'push' \|\| \(github\.event_name == 'workflow_dispatch' && inputs\.resume_tagged_release\)/,
);
assert.match(
  recoveryAttestationScript,
  /--source-digest "\$GITHUB_SHA" --source-ref "\$GITHUB_REF"/,
);
assert.match(
  recoveryAttestationScript,
  /--signer-workflow "\$GITHUB_REPOSITORY\/\.github\/workflows\/release\.yml" --deny-self-hosted-runners/,
);
assert.doesNotMatch(
  releaseWorkflow.slice(
    releaseWorkflow.indexOf(
      '- name: Verify tagged recovery tarball attestation',
    ),
    releaseWorkflow.indexOf(
      '\n      - name:',
      releaseWorkflow.indexOf(
        '- name: Verify tagged recovery tarball attestation',
      ),
    ),
  ),
  /GITHUB_(?:SHA|REF):/,
);
assert.match(
  releaseWorkflow,
  /Verify the original tarball attestation[\s\S]*?gh attestation verify "\$tarball" --repo "\$GITHUB_REPOSITORY" --source-digest "\$RELEASE_SHA" --source-ref "refs\/tags\/\$RELEASE_TAG" --signer-workflow "\$GITHUB_REPOSITORY\/\.github\/workflows\/release\.yml" --deny-self-hosted-runners/,
);
const releaseNotesStep = releaseWorkflow.slice(
  releaseWorkflow.indexOf('- name: Create or reuse draft'),
  releaseWorkflow.indexOf(
    '\n      - name:',
    releaseWorkflow.indexOf('- name: Create or reuse draft'),
  ),
);
assert.match(
  releaseNotesStep,
  /SOURCE_COMMIT: \$\{\{ needs\.validate\.outputs\.selected \}\}/,
);
assert.match(
  releaseNotesStep,
  /Source commit: %s\\nTarball SHA-256: %s\\n' "\$SOURCE_COMMIT"/,
);
assert.match(releaseWorkflow, /RELEASE_ACTION.*== edit.*gh release edit/s);
assert.match(releaseWorkflow, /DRAFT_ID.*steps\.draft_release\.outputs\.id/);
assert.match(
  releaseWorkflow,
  /PATCH "repos\/\$GITHUB_REPOSITORY\/releases\/\$DRAFT_ID"/,
);
assert.doesNotMatch(releaseWorkflow, /releases\/tags\/\$RELEASE_TAG/);

const npmPublishScript = workflowStepScript(
  'Publish the tested tarball by OIDC',
);
assert.match(npmPublishScript, /npm publish "\.\/\$tarball" --tag "\$npm_tag"/);
const releaseTagFixture = mkdtempSync(join(tmpdir(), 'certkit-release-tags-'));
try {
  const bin = join(releaseTagFixture, 'bin');
  mkdirSync(bin);
  mkdirSync(join(releaseTagFixture, 'release'));
  writeFileSync(join(releaseTagFixture, 'release', 'certkit-fixture.tgz'), 'x');
  const npmCapture = join(releaseTagFixture, 'npm-args.txt');
  writeFileSync(
    join(bin, 'npm'),
    '#!/bin/sh\nprintf "%s\\n" "$*" >> "$NPM_CAPTURE"\n',
    { mode: 0o755 },
  );
  for (const [version, expectedTag] of [
    ['1.0.0-beta.2', 'beta'],
    ['1.0.0', 'latest'],
    ['1.2.3+build-7', 'latest'],
  ]) {
    const publish = spawnSync(
      'bash',
      ['-e', '-o', 'pipefail', '-c', npmPublishScript],
      {
        cwd: releaseTagFixture,
        env: {
          ...process.env,
          PATH: `${bin}:${process.env.PATH}`,
          RELEASE_VERSION: version,
          NPM_CAPTURE: npmCapture,
        },
        encoding: 'utf8',
      },
    );
    assert.equal(publish.status, 0, publish.stderr);
    assert.equal(
      readFileSync(npmCapture, 'utf8').trimEnd(),
      `publish ./release/certkit-fixture.tgz --tag ${expectedTag}`,
    );
    writeFileSync(npmCapture, '');
  }
} finally {
  rmSync(releaseTagFixture, { recursive: true, force: true });
}

const artifactGuardFixture = mkdtempSync(
  join(tmpdir(), 'certkit-release-artifact-guard-'),
);
try {
  const runArtifactGuard = (reuse, resolvedArtifactId, requiredArtifactId) =>
    spawnSync(
      'bash',
      ['-e', '-o', 'pipefail', '-c', resumeArtifactGuardScript],
      {
        cwd: artifactGuardFixture,
        env: {
          ...process.env,
          RESUME_TAGGED_RELEASE: 'true',
          RESOLVED_REUSE: reuse,
          RESOLVED_ARTIFACT_ID: resolvedArtifactId,
          RESUME_ARTIFACT_ID: requiredArtifactId,
        },
        encoding: 'utf8',
      },
    );
  assert.equal(
    runArtifactGuard('true', '11135119901', '11135119901').status,
    0,
  );
  assert.notEqual(
    runArtifactGuard('false', '', '11135119901').status,
    0,
    'recovery must refuse to build when its original artifact is absent',
  );
  assert.notEqual(
    runArtifactGuard('true', '11135119902', '11135119901').status,
    0,
    'recovery must refuse a different artifact ID',
  );
  assert.notEqual(
    runArtifactGuard('true', '11135119901', '').status,
    0,
    'recovery must require an explicit original artifact ID',
  );
} finally {
  rmSync(artifactGuardFixture, { recursive: true, force: true });
}

const prereleaseScript = workflowStepScript('Set draft prerelease metadata');
const prereleaseFixture = mkdtempSync(
  join(tmpdir(), 'certkit-release-prerelease-'),
);
try {
  const bin = join(prereleaseFixture, 'bin');
  mkdirSync(bin);
  const ghCapture = join(prereleaseFixture, 'gh-args.txt');
  writeFileSync(
    join(bin, 'gh'),
    '#!/bin/sh\nprintf "%s\\n" "$*" >> "$GH_CAPTURE"\n',
    { mode: 0o755 },
  );
  for (const [version, expectedValue] of [
    ['1.0.0-beta.2', 'true'],
    ['1.0.0', 'false'],
    ['1.2.3+build-7', 'false'],
  ]) {
    const update = spawnSync(
      'bash',
      ['-e', '-o', 'pipefail', '-c', prereleaseScript],
      {
        cwd: prereleaseFixture,
        env: {
          ...process.env,
          PATH: `${bin}:${process.env.PATH}`,
          GITHUB_REPOSITORY: 'code-kev/certkit',
          DRAFT_ID: '91',
          RELEASE_VERSION: version,
          GH_CAPTURE: ghCapture,
        },
        encoding: 'utf8',
      },
    );
    assert.equal(update.status, 0, update.stderr);
    assert.match(
      readFileSync(ghCapture, 'utf8').trimEnd(),
      new RegExp(`releases/91 --field prerelease=${expectedValue}$`),
    );
    writeFileSync(ghCapture, '');
  }
} finally {
  rmSync(prereleaseFixture, { recursive: true, force: true });
}

const artifactName = `certkit-v1.2.3-${sha.slice(0, 12)}`;
const reusableArtifact = {
  name: artifactName,
  expired: false,
  artifactId: 27,
  runId: 19,
  event: 'workflow_dispatch',
};
const currentRun = {
  id: 33,
  event: 'push',
  head_sha: sha,
  display_title: `Release ${sha}`,
};
const bootstrapRun = {
  id: 19,
  event: 'workflow_dispatch',
  head_sha: 'b'.repeat(40),
  display_title: `Release ${sha}`,
};
assert.equal(releaseRunMatchesSource(bootstrapRun, sha), true);
assert.equal(
  releaseRunMatchesSource(
    { ...bootstrapRun, display_title: `Release ${'b'.repeat(40)}` },
    sha,
  ),
  false,
);
assert.deepEqual(
  resolveReusableArtifact({
    runs: [currentRun, bootstrapRun],
    artifacts: [
      {
        id: 27,
        name: artifactName,
        expired: false,
        workflow_run: { id: 19 },
      },
    ],
    name: artifactName,
    sha,
    packagePublished: true,
    currentRunId: 33,
    currentAttempt: 1,
  }),
  reusableArtifact,
);
assert.equal(
  resolveReusableArtifact({
    runs: [
      {
        ...currentRun,
        id: 34,
        event: 'workflow_dispatch',
        head_sha: 'b'.repeat(40),
      },
    ],
    artifacts: [],
    name: artifactName,
    sha,
    packagePublished: false,
    currentRunId: 34,
    currentAttempt: 1,
  }),
  undefined,
);
for (const retry of [
  {
    runs: [currentRun, bootstrapRun],
    artifacts: [],
    currentAttempt: 1,
  },
  {
    runs: [currentRun],
    artifacts: [],
    currentAttempt: 2,
  },
  {
    runs: [currentRun, bootstrapRun],
    artifacts: [
      {
        id: 28,
        name: artifactName,
        expired: true,
        workflow_run: { id: 19 },
      },
    ],
    currentAttempt: 1,
  },
])
  assert.throws(() =>
    resolveReusableArtifact({
      ...retry,
      name: artifactName,
      sha,
      packagePublished: false,
      currentRunId: 33,
    }),
  );
assert.throws(() =>
  resolveReusableArtifact({
    runs: [currentRun],
    artifacts: [],
    name: artifactName,
    sha,
    packagePublished: true,
    currentRunId: 33,
    currentAttempt: 1,
  }),
);
assert.throws(() =>
  resolveReusableArtifact({
    runs: [currentRun],
    artifacts: [],
    name: artifactName,
    sha,
    packagePublished: false,
    currentRunId: 99,
    currentAttempt: 1,
  }),
);
assert.throws(() =>
  resolveReusableArtifact({
    runs: [currentRun],
    artifacts: [{ id: 89, name: artifactName, expired: false }],
    name: artifactName,
    sha,
    packagePublished: false,
    currentRunId: 33,
    currentAttempt: 1,
  }),
);
assert.equal(
  resolveReusableArtifact({
    runs: [currentRun],
    artifacts: [
      { id: 88, name: artifactName, expired: false, workflow_run: { id: 77 } },
    ],
    name: artifactName,
    sha,
    packagePublished: false,
    currentRunId: 33,
    currentAttempt: 1,
  }),
  undefined,
);
assert.throws(() =>
  resolveReusableArtifact({
    runs: [currentRun, bootstrapRun],
    artifacts: [
      {
        id: 27,
        name: artifactName,
        expired: false,
        workflow_run: { id: 19 },
      },
      {
        id: 28,
        name: artifactName,
        expired: false,
        workflow_run: { id: 19 },
      },
    ],
    name: artifactName,
    sha,
    packagePublished: false,
    currentRunId: 33,
    currentAttempt: 1,
  }),
);
assert.deepEqual(
  selectReusableArtifact(
    [
      { ...reusableArtifact, expired: true, artifactId: 28 },
      { ...reusableArtifact, name: 'another-artifact' },
      reusableArtifact,
    ],
    artifactName,
    true,
  ),
  reusableArtifact,
);
assert.equal(
  selectReusableArtifact(
    [{ ...reusableArtifact, expired: true }],
    artifactName,
    false,
  ),
  undefined,
);
assert.throws(() =>
  selectReusableArtifact(
    [{ ...reusableArtifact, expired: true }],
    artifactName,
    true,
  ),
);
assert.throws(() =>
  selectReusableArtifact(
    [reusableArtifact, { ...reusableArtifact, artifactId: 28 }],
    artifactName,
    false,
  ),
);
assert.doesNotThrow(() => assertEgressDenied({ code: 'ENETUNREACH' }));
assert.doesNotThrow(() => assertEgressDenied({ code: 'EPERM' }));
for (const probe of [
  { connected: true },
  { code: 'ETIMEDOUT' },
  { code: 'ECONNRESET' },
  { code: 'ERR_TLS_CERT_ALTNAME_INVALID' },
])
  assert.throws(() => assertEgressDenied(probe));
verifyRepository(
  {
    repository: {
      type: 'git',
      url: 'git+https://github.com/code-kev/certkit.git',
    },
  },
  'code-kev/certkit',
);
assert.throws(() =>
  verifyRepository(
    { repository: { type: 'git', url: 'https://github.com/code-kev/certkit' } },
    'code-kev/certkit',
  ),
);
assertSettingsToken('read-only-token');
assert.throws(() => assertSettingsToken(''));
verifyPublishedRelease(
  {
    draft: false,
    immutable: true,
    prerelease: true,
    assets: [{ name: 'package.tgz' }],
  },
  ['package.tgz'],
  '1.2.3-beta.2',
);
verifyPublishedRelease(
  {
    draft: false,
    immutable: true,
    prerelease: false,
    assets: [{ name: 'package.tgz' }],
  },
  ['package.tgz'],
  '1.2.3',
);
verifyPublishedRelease(
  {
    draft: false,
    immutable: true,
    prerelease: false,
    assets: [{ name: 'package.tgz' }],
  },
  ['package.tgz'],
  '1.2.3+build-7',
);
assert.throws(() =>
  verifyPublishedRelease(
    {
      draft: false,
      immutable: true,
      prerelease: false,
      assets: [{ name: 'package.tgz' }],
    },
    ['package.tgz'],
    '1.2.3-beta.2',
  ),
);
assert.throws(
  () =>
    verifyPublishedRelease(
      {
        draft: false,
        immutable: true,
        prerelease: false,
        assets: [{ name: 'package.tgz' }],
      },
      ['package.tgz'],
    ),
  /release version is required/,
);
assert.throws(() =>
  verifyPublishedRelease(
    {
      draft: false,
      immutable: true,
      prerelease: true,
      assets: [{ name: 'package.tgz' }],
    },
    ['package.tgz'],
    '1.2.3',
  ),
);
assert.throws(() =>
  verifyPublishedRelease(
    {
      draft: false,
      immutable: true,
      prerelease: false,
      assets: [],
    },
    ['package.tgz'],
    '1.2.3',
  ),
);

const directory = mkdtempSync(join(tmpdir(), 'certkit-release-'));
try {
  const tarball = join(directory, 'certkit-1.2.3.tgz');
  const manifestPath = join(directory, 'manifest.json');
  writeFileSync(tarball, 'one tested tarball');
  const bytes = readFileSync(tarball);
  const manifest = {
    name: 'certkit',
    version: '1.2.3',
    sourceSha: sha,
    runId: '42',
    sha256: createHash('sha256').update(bytes).digest('hex'),
    integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
  };
  writeFileSync(manifestPath, JSON.stringify(manifest));
  verifyManifest(manifest, tarball, { sha, version: '1.2.3', runId: '42' });
  verifyRegistryIntegrity(manifest, manifest.integrity);
  assert.throws(() => verifyRegistryIntegrity(manifest, 'sha512-altered'));
  for (const options of [
    { ...manifest, version: '9.9.9' },
    { ...manifest, sourceSha: 'b'.repeat(40) },
    { ...manifest, sha256: '0'.repeat(64) },
  ])
    assert.throws(() =>
      verifyManifest(options, tarball, { sha, version: '1.2.3', runId: '42' }),
    );
  assert.throws(() =>
    verifyManifest(manifest, tarball, { sha, version: '1.2.3', runId: '43' }),
  );
  writeFileSync(tarball, 'altered tarball');
  assert.throws(() =>
    verifyManifest(manifest, tarball, { sha, version: '1.2.3', runId: '42' }),
  );

  const consumer = join(directory, 'consumer');
  const certkit = join(consumer, 'node_modules/certkit');
  mkdirSync(join(consumer, 'node_modules/citty/node_modules/evil'), {
    recursive: true,
  });
  mkdirSync(certkit, { recursive: true });
  writeFileSync(
    join(certkit, 'package.json'),
    JSON.stringify({ name: 'certkit' }),
  );
  writeFileSync(
    join(consumer, 'node_modules/citty/package.json'),
    JSON.stringify({ name: 'citty' }),
  );
  writeFileSync(
    join(consumer, 'node_modules/citty/node_modules/evil/package.json'),
    JSON.stringify({ name: 'evil' }),
  );
  assert.throws(
    () => checkConsumerTree(consumer),
    /disallowed runtime dependency: evil/,
  );
  rmSync(join(consumer, 'node_modules/citty/node_modules/evil'), {
    recursive: true,
  });
  mkdirSync(join(consumer, 'node_modules/citty/node_modules/picocolors'));
  writeFileSync(
    join(consumer, 'node_modules/citty/node_modules/picocolors/package.json'),
    JSON.stringify({ name: 'picocolors' }),
  );
  checkConsumerTree(consumer);
  writeFileSync(
    join(consumer, 'node_modules/citty/node_modules/picocolors/package.json'),
    JSON.stringify({
      name: 'picocolors',
      scripts: { postinstall: 'node install.js' },
    }),
  );
  assert.throws(
    () => checkConsumerTree(consumer),
    /postinstall lifecycle script/,
  );
} finally {
  rmSync(directory, { recursive: true, force: true });
}

console.log('release gate negative controls passed');
