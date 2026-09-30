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
  assertSettingsToken,
  requiredChecks,
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
