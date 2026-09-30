import assert from 'node:assert/strict';
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

const sha = 'a'.repeat(40);
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
const releaseWorkflow = readFileSync(
  new URL('../.github/workflows/release.yml', import.meta.url),
  'utf8',
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
  /sudo unshare --net -- runuser .*scripts\/egress-smoke\.mjs/,
);
assert.match(
  egressSmoke,
  /createRequire\(resolve\('consumer', 'package\.json'\)\)/,
);
assert.match(egressSmoke, /consumerRequire\.resolve\('certkit'\)/);
assert.match(egressSmoke, /consumerRequire\.resolve\('certkit\/vite'\)/);
assert.match(releaseWorkflow, /RELEASE_ACTION.*outputs\.action/);
assert.match(releaseWorkflow, /RELEASE_ACTION.*== edit.*gh release edit/s);
assert.match(releaseWorkflow, /DRAFT_ID.*steps\.draft_release\.outputs\.id/);
assert.match(
  releaseWorkflow,
  /PATCH "repos\/\$GITHUB_REPOSITORY\/releases\/\$DRAFT_ID"/,
);
assert.doesNotMatch(releaseWorkflow, /releases\/tags\/\$RELEASE_TAG/);

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
  { draft: false, immutable: true, assets: [{ name: 'package.tgz' }] },
  ['package.tgz'],
);
assert.throws(() =>
  verifyPublishedRelease(
    { draft: false, immutable: false, assets: [{ name: 'package.tgz' }] },
    ['package.tgz'],
  ),
);
assert.throws(() =>
  verifyPublishedRelease({ draft: false, immutable: true, assets: [] }, [
    'package.tgz',
  ]),
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
