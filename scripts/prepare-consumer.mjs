import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { verifyManifest } from './release.mjs';

export function bindConsumerLock(anchor, manifest, pkg) {
  assert.equal(
    anchor.lockfileVersion,
    3,
    'consumer lockfile must use version 3',
  );
  const locked = anchor.packages?.['node_modules/certkit'];
  assert(locked, 'consumer lockfile must contain the certkit root');
  assert.equal(
    manifest.name,
    'certkit',
    'release manifest package name must be certkit',
  );
  assert.equal(
    pkg.name,
    manifest.name,
    'tarball package name differs from release manifest',
  );
  assert.equal(
    pkg.version,
    manifest.version,
    'tarball package version differs from release manifest',
  );
  assert.match(
    manifest.integrity,
    /^sha512-[A-Za-z0-9+/]{86}==$/,
    'missing tarball integrity',
  );
  assert.deepEqual(
    anchor.packages['']?.dependencies,
    { certkit: 'file:certkit.tgz' },
    'consumer lockfile must install only the local certkit tarball',
  );
  assert.equal(
    locked.resolved,
    'file:certkit.tgz',
    'consumer lockfile root must be local',
  );
  for (const field of [
    'dependencies',
    'optionalDependencies',
    'peerDependencies',
    'peerDependenciesMeta',
  ]) {
    assert.deepEqual(
      pkg[field] ?? {},
      locked[field] ?? {},
      `consumer ${field} contract changed; review and update its lockfile`,
    );
  }
  assert(
    !pkg.bundleDependencies && !pkg.bundledDependencies,
    'consumer dependency contract must not bundle packages',
  );
  for (const [path, entry] of Object.entries(anchor.packages)) {
    if (!path || path === 'node_modules/certkit') continue;
    assert(
      !entry.link,
      `consumer registry package must not be a link: ${path}`,
    );
    assert.match(
      entry.version,
      /^\d+\.\d+\.\d+(?:-[\w.-]+)?$/,
      `consumer registry version must be exact: ${path}`,
    );
    assert.match(
      entry.integrity,
      /^sha512-[A-Za-z0-9+/]{86}==$/,
      `consumer registry integrity missing: ${path}`,
    );
    assert.equal(
      new URL(entry.resolved).origin,
      'https://registry.npmjs.org',
      `consumer registry URL is not approved: ${path}`,
    );
  }
  const bound = structuredClone(anchor);
  bound.packages['node_modules/certkit'].version = manifest.version;
  bound.packages['node_modules/certkit'].integrity = manifest.integrity;
  bound.packages['node_modules/certkit'].bin = pkg.bin;
  bound.packages['node_modules/certkit'].engines = pkg.engines;
  return bound;
}

export function prepareConsumer(tarball, manifestPath, directory) {
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  verifyManifest(manifest, tarball, {
    sha: process.env.RELEASE_SHA,
    version: process.env.RELEASE_VERSION,
    runId: process.env.ARTIFACT_RUN_ID,
  });
  const pkg = JSON.parse(
    execFileSync('tar', ['-xOf', tarball, 'package/package.json'], {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
      timeout: 10000,
    }),
  );
  const anchor = JSON.parse(
    readFileSync(
      new URL('./consumer/package-lock.json', import.meta.url),
      'utf8',
    ),
  );
  const lock = bindConsumerLock(anchor, manifest, pkg);
  mkdirSync(directory);
  copyFileSync(tarball, join(directory, 'certkit.tgz'));
  copyFileSync(
    new URL('./consumer/package.json', import.meta.url),
    join(directory, 'package.json'),
  );
  writeFileSync(
    join(directory, 'package-lock.json'),
    `${JSON.stringify(lock, null, 2)}\n`,
  );
  console.log(
    'Prepared consumer from the verified tarball and reviewed registry lock.',
  );
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const args = process.argv.slice(2);
    assert(
      args.length === 3 && args.every(Boolean),
      'expected tarball, manifest and new consumer directory',
    );
    prepareConsumer(...args);
  } catch (error) {
    console.error(`consumer preparation failed: ${error.message}`);
    process.exitCode = 1;
  }
}
