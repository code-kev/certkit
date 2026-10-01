import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { checkConsumerTree } from './check-deps.mjs';

export const requiredChecks = [
  'required',
  'test',
  'build',
  'lint',
  'typecheck',
];
export const exemptChecks = ['pr-title', 'dependency-review'];

export function verifyCheckRuns(checkRuns, sha) {
  const runs = checkRuns.filter(
    (run) => run.app?.id === 15368 && run.head_sha === sha,
  );
  for (const name of requiredChecks) {
    const latest = runs
      .filter((run) => run.name === name)
      .sort((a, b) => Date.parse(b.started_at) - Date.parse(a.started_at))[0];
    assert(latest, `mandatory check missing on ${sha}: ${name}`);
    assert.equal(
      latest.status,
      'completed',
      `mandatory check is pending: ${name}`,
    );
    assert.equal(
      latest.conclusion,
      'success',
      `mandatory check did not succeed: ${name}`,
    );
  }
  console.log(
    `mandatory checks passed on ${sha}: ${requiredChecks.join(', ')}`,
  );
  console.log(`explicit PR-only exemptions: ${exemptChecks.join(', ')}`);
}

export function verifyTagVersion(tag, version) {
  assert.equal(
    tag,
    `v${version}`,
    `tag ${tag} does not match package version ${version}`,
  );
}

export function verifyRepository(packageJson, repository) {
  assert.deepEqual(
    packageJson.repository,
    {
      type: 'git',
      url: `git+https://github.com/${repository}.git`,
    },
    'package repository URL must match the GitHub trusted publisher repository',
  );
}

export function assertSettingsToken(token) {
  assert(
    typeof token === 'string' && token.length > 0,
    'RELEASE_SETTINGS_TOKEN is required to verify immutable releases',
  );
}

export function releaseStateForTag(releases, tag) {
  const matches = releases.filter((release) => release.tag_name === tag);
  assert(matches.length <= 1, `ambiguous releases for ${tag}`);
  const release = matches[0];
  if (!release)
    return { exists: false, draft: false, id: '', action: 'create' };
  assert.equal(
    typeof release.draft,
    'boolean',
    'release draft state is missing',
  );
  assert(Number.isSafeInteger(release.id), `release ${tag} has no valid ID`);
  return {
    exists: true,
    draft: release.draft,
    id: release.id,
    action: release.draft ? 'edit' : 'skip',
  };
}

export function releaseRunMatchesSource(run, sha) {
  return run.event === 'workflow_dispatch'
    ? run.display_title === `Release ${sha}`
    : run.event === 'push' && run.head_sha === sha;
}

export function selectReusableArtifact(
  artifacts,
  name,
  packagePublished,
  priorProducer = false,
  currentAttempt = 1,
) {
  const candidates = artifacts.filter(
    (artifact) => artifact.name === name && !artifact.expired,
  );
  assert(candidates.length <= 1, `ambiguous reusable artifacts for ${name}`);
  const candidate = candidates[0];
  if (packagePublished)
    assert(
      candidate,
      `published ${name} has no saved tested tarball; refusing to rebuild`,
    );
  if (!candidate)
    assert(
      !priorProducer && currentAttempt === 1,
      `prior release run or attempt has no saved tested tarball for ${name}; refusing to rebuild`,
    );
  return candidate;
}

export function resolveReusableArtifact({
  runs,
  artifacts,
  name,
  sha,
  packagePublished,
  currentRunId,
  currentAttempt,
}) {
  assert(Array.isArray(runs), 'release workflow run list is unavailable');
  assert(Array.isArray(artifacts), 'release artifact list is unavailable');
  assert(
    Number.isSafeInteger(currentRunId) && Number.isSafeInteger(currentAttempt),
    'current release run identity is unavailable',
  );
  assert(currentAttempt >= 1, 'current release run attempt is invalid');
  const currentId = String(currentRunId);
  const runById = new Map(
    runs.map((run) => {
      assert(Number.isSafeInteger(run.id), 'release run has no valid ID');
      return [String(run.id), run];
    }),
  );
  const currentRun = runById.get(currentId);
  assert(
    currentRun && releaseRunMatchesSource(currentRun, sha),
    `current release run identity is unavailable for ${sha}`,
  );
  const priorRun = runs.some(
    (run) => String(run.id) !== currentId && releaseRunMatchesSource(run, sha),
  );
  const matchingArtifacts = [];
  for (const artifact of artifacts) {
    if (artifact.name !== name) continue;
    assert(
      Number.isSafeInteger(artifact.id) &&
        typeof artifact.expired === 'boolean' &&
        Number.isSafeInteger(artifact.workflow_run?.id),
      `artifact identity is unavailable for ${name}`,
    );
    const run = runById.get(String(artifact.workflow_run.id));
    if (!run) continue;
    if (
      run.event !== 'workflow_dispatch' &&
      !(run.event === 'push' && run.head_sha === sha)
    )
      continue;
    matchingArtifacts.push({
      name: artifact.name,
      expired: artifact.expired,
      artifactId: artifact.id,
      runId: artifact.workflow_run.id,
      event: run.event,
    });
  }
  return selectReusableArtifact(
    matchingArtifacts,
    name,
    packagePublished,
    priorRun || matchingArtifacts.length > 0,
    currentAttempt,
  );
}

export function assertEgressDenied(probe) {
  assert(
    ['EACCES', 'EPERM', 'EHOSTUNREACH', 'ENETUNREACH'].includes(probe.code),
    `outbound TCP connection was not proven blocked (${probe.code ?? 'connected'})`,
  );
}

export function bindSbom(path, manifestPath) {
  const sbom = JSON.parse(readFileSync(path, 'utf8'));
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  assert.equal(
    manifest.sourceSha,
    process.env.RELEASE_SHA,
    'SBOM source SHA mismatch',
  );
  assert.equal(
    manifest.version,
    process.env.RELEASE_VERSION,
    'SBOM version mismatch',
  );
  sbom.metadata ??= {};
  sbom.metadata.properties ??= [];
  sbom.metadata.properties.push(
    { name: 'certkit:release-source-sha', value: process.env.RELEASE_SHA },
    { name: 'certkit:release-version', value: process.env.RELEASE_VERSION },
    { name: 'certkit:tarball-sha256', value: manifest.sha256 },
  );
  writeFileSync(path, `${JSON.stringify(sbom, null, 2)}\n`);
}

export function verifyManifest(manifest, tarball, { sha, version, runId }) {
  assert.equal(manifest.name, 'certkit', 'artifact package name mismatch');
  assert.equal(manifest.version, version, 'artifact version mismatch');
  assert.equal(manifest.sourceSha, sha, 'artifact source SHA mismatch');
  if (runId)
    assert.equal(manifest.runId, runId, 'artifact producer run mismatch');
  const bytes = readFileSync(tarball);
  const digest = createHash('sha256').update(bytes).digest('hex');
  assert.equal(manifest.sha256, digest, 'tarball SHA-256 mismatch');
  const integrity = `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
  assert.equal(manifest.integrity, integrity, 'tarball SRI mismatch');
  console.log(`verified ${tarball}: sha256 ${digest}`);
}

export function verifyRegistryIntegrity(manifest, integrity) {
  assert.equal(
    manifest.integrity,
    integrity,
    'npm registry integrity differs from tarball',
  );
}

export function verifyPublishedRelease(release, expectedAssets, version) {
  assert(
    typeof version === 'string' && version.length > 0,
    'release version is required to verify GitHub prerelease status',
  );
  assert.equal(release.draft, false, 'GitHub release is still a draft');
  assert.equal(release.immutable, true, 'published release is not immutable');
  assert.equal(
    release.prerelease,
    version.split('+', 1)[0].includes('-'),
    'GitHub prerelease status does not match package version',
  );
  const assets = new Set(release.assets.map((asset) => asset.name));
  for (const name of expectedAssets)
    assert(
      assets.has(name),
      `published immutable release is missing ${name}; complete manually`,
    );
}

export function writeManifest(tarball, manifestPath, { sha, version, runId }) {
  const bytes = readFileSync(tarball);
  writeFileSync(
    manifestPath,
    `${JSON.stringify(
      {
        name: 'certkit',
        version,
        sourceSha: sha,
        runId,
        tarball: tarball.split('/').at(-1),
        sha256: createHash('sha256').update(bytes).digest('hex'),
        integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
      },
      null,
      2,
    )}\n`,
  );
}

async function githubGet(path, token = process.env.GITHUB_TOKEN) {
  const response = await fetch(
    `https://api.github.com/repos/${process.env.GITHUB_REPOSITORY}/${path}`,
    {
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'x-github-api-version': '2022-11-28',
      },
    },
  );
  if (!response.ok)
    throw new Error(
      `GitHub API ${path}: ${response.status} ${await response.text()}`,
    );
  return response.json();
}

async function githubList(path, key) {
  const values = [];
  let url = `https://api.github.com/repos/${process.env.GITHUB_REPOSITORY}/${path}`;
  while (url) {
    const response = await fetch(url, {
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        'x-github-api-version': '2022-11-28',
      },
    });
    if (!response.ok)
      throw new Error(
        `GitHub API ${path}: ${response.status} ${await response.text()}`,
      );
    const page = await response.json();
    const items = key ? page[key] : page;
    assert(Array.isArray(items), `GitHub API ${path}: invalid list response`);
    values.push(...items);
    url = response.headers.get('link')?.match(/<([^>]+)>; rel="next"/)?.[1];
  }
  return values;
}

async function resolveArtifact() {
  const sha = process.env.RELEASE_SHA;
  const version = process.env.RELEASE_VERSION;
  const name = `certkit-v${version}-${sha.slice(0, 12)}`;
  const runs = await githubList(
    'actions/workflows/release.yml/runs?per_page=100',
    'workflow_runs',
  );
  const artifacts = await githubList(
    `actions/artifacts?name=${encodeURIComponent(name)}&per_page=100`,
    'artifacts',
  );
  const candidate = resolveReusableArtifact({
    runs,
    artifacts,
    name,
    sha,
    packagePublished: process.env.PACKAGE_PUBLISHED === 'true',
    currentRunId: Number(process.env.GITHUB_RUN_ID),
    currentAttempt: Number(process.env.GITHUB_RUN_ATTEMPT),
  });
  const output = process.env.GITHUB_OUTPUT;
  writeFileSync(
    output,
    `reuse=${candidate ? 'true' : 'false'}\nrun_id=${candidate?.runId ?? ''}\nartifact_id=${candidate?.artifactId ?? ''}\nevent=${candidate?.event ?? ''}\nname=${name}\n`,
    { flag: 'a' },
  );
  console.log(
    candidate
      ? `reusing artifact ${candidate.artifactId} from run ${candidate.runId}`
      : `no saved artifact for ${name}; build once`,
  );
}

async function listCheckRuns(sha) {
  const runs = [];
  let url = `https://api.github.com/repos/${process.env.GITHUB_REPOSITORY}/commits/${sha}/check-runs?per_page=100`;
  while (url) {
    const response = await fetch(url, {
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        'x-github-api-version': '2022-11-28',
      },
    });
    if (!response.ok)
      throw new Error(
        `check-runs API: ${response.status} ${await response.text()}`,
      );
    const page = await response.json();
    runs.push(...page.check_runs);
    url = response.headers.get('link')?.match(/<([^>]+)>; rel="next"/)?.[1];
  }
  return runs;
}

async function assertReleaseSettings() {
  assertSettingsToken(process.env.RELEASE_SETTINGS_TOKEN);
  const [immutable, environment] = await Promise.all([
    githubGet('immutable-releases', process.env.RELEASE_SETTINGS_TOKEN),
    githubGet('environments/npm-publish'),
  ]);
  assert.equal(
    immutable.enabled,
    true,
    'repository immutable releases must be enabled',
  );
  assert(
    environment.protection_rules?.some(
      (rule) => rule.type === 'required_reviewers' && rule.reviewers?.length,
    ),
    'npm-publish environment must have at least one required reviewer',
  );
  console.log(
    'immutable releases and npm-publish required reviewer are configured',
  );
}

async function releaseState() {
  const tag = process.env.RELEASE_TAG;
  const version = process.env.RELEASE_VERSION;
  const releases = await githubList('releases?per_page=100');
  const release = releases.find((item) => item.tag_name === tag);
  const state = releaseStateForTag(releases, tag);
  if (state.exists && !state.draft)
    verifyPublishedRelease(
      release,
      [process.env.TARBALL_NAME, 'manifest.json', 'sbom.cdx.json'],
      version,
    );
  writeFileSync(
    process.env.GITHUB_OUTPUT,
    `exists=${state.exists}\ndraft=${state.draft}\nid=${state.id}\naction=${state.action}\n`,
    { flag: 'a' },
  );
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'checks') {
    const sha = process.env.RELEASE_SHA;
    if (!/^[0-9a-f]{40}$/.test(sha ?? ''))
      throw new Error('invalid release SHA');
    verifyCheckRuns(await listCheckRuns(sha), sha);
  } else if (command === 'repository') {
    const packageJson = JSON.parse(
      execFileSync('git', ['show', `${process.env.RELEASE_SHA}:package.json`], {
        encoding: 'utf8',
      }),
    );
    verifyRepository(packageJson, process.env.RELEASE_REPOSITORY);
  } else if (command === 'settings') {
    await assertReleaseSettings();
  } else if (command === 'release-state') {
    await releaseState();
  } else if (command === 'resolve-artifact') {
    await resolveArtifact();
  } else if (command === 'state') {
    const url = `https://registry.npmjs.org/certkit/${encodeURIComponent(process.env.RELEASE_VERSION)}`;
    const response = await fetch(url);
    if (response.status === 404) {
      console.log('published=false');
      return;
    }
    if (!response.ok)
      throw new Error(`npm registry query failed: ${response.status}`);
    const published = await response.json();
    console.log('published=true');
    console.log(`integrity=${published.dist?.integrity ?? ''}`);
  } else if (command === 'manifest') {
    writeManifest(args[0], args[1], {
      sha: process.env.RELEASE_SHA,
      version: process.env.RELEASE_VERSION,
      runId: process.env.GITHUB_RUN_ID,
    });
  } else if (command === 'verify') {
    const manifest = JSON.parse(readFileSync(args[1], 'utf8'));
    verifyManifest(manifest, args[0], {
      sha: process.env.RELEASE_SHA,
      version: process.env.RELEASE_VERSION,
      runId: process.env.ARTIFACT_RUN_ID,
    });
    if (process.env.REGISTRY_INTEGRITY)
      verifyRegistryIntegrity(manifest, process.env.REGISTRY_INTEGRITY);
  } else if (command === 'consumer-tree') {
    checkConsumerTree(args[0]);
  } else if (command === 'bind-sbom') {
    bindSbom(args[0], args[1]);
  } else if (command === 'version') {
    verifyTagVersion(process.env.RELEASE_TAG, process.env.RELEASE_VERSION);
  } else if (command === 'settings-token') {
    assertSettingsToken(process.env.RELEASE_SETTINGS_TOKEN);
  } else {
    throw new Error(`unknown command: ${command}`);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href)
  main().catch((error) => {
    console.error(`release gate failed: ${error.message}`);
    process.exitCode = 1;
  });
