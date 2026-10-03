import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  bindConsumerLock,
  prepareConsumer,
} from '../scripts/prepare-consumer.mjs';
import { writeManifest } from '../scripts/release.mjs';

const anchor = JSON.parse(
  readFileSync(
    new URL('../scripts/consumer/package-lock.json', import.meta.url),
  ),
);
const pkg = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url)),
);
const manifest = {
  name: 'certkit',
  version: '1.0.0-beta.4',
  integrity: `sha512-${Buffer.alloc(64, 7).toString('base64')}`,
};
pkg.version = manifest.version;
const bound = bindConsumerLock(anchor, manifest, pkg);
assert.equal(bound.packages['node_modules/certkit'].version, manifest.version);
assert.equal(
  bound.packages['node_modules/certkit'].integrity,
  manifest.integrity,
);
assert.equal(anchor.packages['node_modules/certkit'].version, '0.0.0');
for (const [path, entry] of Object.entries(anchor.packages)) {
  if (path !== 'node_modules/certkit')
    assert.deepEqual(bound.packages[path], entry);
}

for (const field of [
  'dependencies',
  'peerDependencies',
  'peerDependenciesMeta',
]) {
  const changed = structuredClone(pkg);
  changed[field] = { ...changed[field], unexpected: '1.0.0' };
  assert.throws(() => bindConsumerLock(anchor, manifest, changed), /contract/);
}
assert.throws(() => bindConsumerLock({}, manifest, pkg), /lockfile/);
assert.throws(
  () => bindConsumerLock(anchor, { ...manifest, integrity: '' }, pkg),
  /integrity/,
);
assert.throws(
  () => bindConsumerLock(anchor, { ...manifest, name: 'other' }, pkg),
  /identity/,
);
assert.throws(
  () => bindConsumerLock(anchor, { ...manifest, version: '2.0.0' }, pkg),
  /identity/,
);
for (const replacement of [
  { resolved: 'https://untrusted.invalid/package.tgz' },
  { integrity: '' },
  { link: true },
  { version: '^2.1.0' },
]) {
  const changed = structuredClone(anchor);
  Object.assign(changed.packages['node_modules/@peculiar/x509'], replacement);
  assert.throws(() => bindConsumerLock(changed, manifest, pkg), /registry/);
}

// Keep the reviewed npm packages anchored to the producer's production closure.
const production = JSON.parse(
  execFileSync('pnpm', ['ls', '--prod', '--depth', 'Infinity', '--json'], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  }),
);
const productionPackages = new Set();
const visitProduction = (node) => {
  const name = node.name ?? node.from;
  if (name !== 'certkit') productionPackages.add(`${name}@${node.version}`);
  for (const child of Object.values(node.dependencies ?? {}))
    visitProduction(child);
};
for (const node of production) visitProduction(node);
const consumerPackages = new Set();
const pnpm = readFileSync(
  new URL('../pnpm-lock.yaml', import.meta.url),
  'utf8',
);
for (const [path, entry] of Object.entries(anchor.packages)) {
  if (!path || path === 'node_modules/certkit') continue;
  const name = path.split('node_modules/').at(-1);
  consumerPackages.add(`${name}@${entry.version}`);
  const key = `${name}@${entry.version}`.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const block = pnpm.match(
    new RegExp(
      `^  '?${key}'?:\\n    resolution: \\{integrity: ([^}\\n]+)\\}`,
      'm',
    ),
  );
  assert(block, `consumer package missing from producer lock: ${name}`);
  assert.equal(block[1], entry.integrity, `consumer SRI mismatch: ${name}`);
}
assert.deepEqual(
  consumerPackages,
  productionPackages,
  'consumer package identities must match the producer production closure',
);
console.log(
  'Consumer lock identity, contract and registry integrity gates passed.',
);

const temp = mkdtempSync(join(tmpdir(), 'certkit-consumer-gates-'));
const env = {
  RELEASE_SHA: 'a'.repeat(40),
  RELEASE_VERSION: manifest.version,
  ARTIFACT_RUN_ID: '42',
};
const previous = Object.fromEntries(
  Object.keys(env).map((key) => [key, process.env[key]]),
);
try {
  Object.assign(process.env, env);
  mkdirSync(join(temp, 'package'));
  writeFileSync(join(temp, 'package/package.json'), JSON.stringify(pkg));
  const tarball = join(temp, 'certkit.tgz');
  execFileSync('tar', ['-czf', tarball, '-C', temp, 'package']);
  const manifestPath = join(temp, 'manifest.json');
  writeManifest(tarball, manifestPath, {
    sha: env.RELEASE_SHA,
    version: manifest.version,
    runId: '42',
  });
  const consumer = join(temp, 'consumer');
  prepareConsumer(tarball, manifestPath, consumer);
  const prepared = JSON.parse(
    readFileSync(join(consumer, 'package-lock.json')),
  );
  assert.equal(
    prepared.packages['node_modules/certkit'].integrity,
    JSON.parse(readFileSync(manifestPath)).integrity,
  );
  assert.deepEqual(
    readFileSync(join(consumer, 'certkit.tgz')),
    readFileSync(tarball),
  );
  assert.throws(
    () => prepareConsumer(tarball, manifestPath, consumer),
    /EEXIST/,
  );
  writeFileSync(tarball, 'tampered');
  const rejected = join(temp, 'rejected');
  assert.throws(
    () => prepareConsumer(tarball, manifestPath, rejected),
    /SHA-256 mismatch/,
  );
  assert.equal(
    existsSync(rejected),
    false,
    'reject tampering before consumer creation',
  );
} finally {
  for (const [key, value] of Object.entries(previous)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  rmSync(temp, { recursive: true, force: true });
}
console.log('Consumer preparation rejects tampering before install.');
