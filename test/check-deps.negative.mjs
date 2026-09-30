import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const temp = mkdtempSync(join(tmpdir(), 'certkit-deps-negative-'));
try {
  const packageDir = join(temp, 'debug');
  mkdirSync(packageDir);
  writeFileSync(
    join(packageDir, 'package.json'),
    JSON.stringify({
      name: 'debug',
      version: '1.0.0',
      scripts: { postinstall: 'node install.js' },
    }),
  );
  const treeFile = join(temp, 'tree.json');
  writeFileSync(
    treeFile,
    JSON.stringify([
      {
        name: 'certkit',
        version: '0.0.0',
        path: root,
        dependencies: {
          debug: { name: 'debug', version: '1.0.0', path: packageDir },
        },
      },
    ]),
  );
  const result = spawnSync(
    process.execPath,
    [join(root, 'scripts/check-deps.mjs'), '--input', treeFile],
    { encoding: 'utf8' },
  );
  assert.notEqual(
    result.status,
    0,
    'disallowed transitive dependency must fail the checker',
  );
  assert.match(result.stderr, /disallowed runtime dependency: debug/);
  assert.match(result.stderr, /debug declares postinstall lifecycle script/);

  const cittyDir = join(temp, 'citty');
  const picocolorsDir = join(temp, 'picocolors');
  const utilsDir = join(temp, 'peculiar-utils');
  for (const [directory, name, version] of [
    [cittyDir, 'citty', '0.2.2'],
    [picocolorsDir, 'picocolors', '1.1.1'],
    [utilsDir, '@peculiar/utils', '2.0.3'],
  ]) {
    mkdirSync(directory, { recursive: true });
    writeFileSync(
      join(directory, 'package.json'),
      JSON.stringify({ name, version }),
    );
  }
  const utilityLeaf = {
    name: '@peculiar/utils',
    version: '2.0.3',
    path: utilsDir,
    deduped: true,
  };
  const dedupedTree = join(temp, 'deduped-tree.json');
  writeFileSync(
    dedupedTree,
    JSON.stringify([
      {
        name: 'certkit',
        version: '0.0.0',
        path: root,
        dependencies: {
          citty: {
            name: 'citty',
            version: '0.2.2',
            path: cittyDir,
            dependencies: { '@peculiar/utils': utilityLeaf },
          },
          picocolors: {
            name: 'picocolors',
            version: '1.1.1',
            path: picocolorsDir,
            dependencies: {
              '@peculiar/utils': {
                ...utilityLeaf,
                dependencies: {
                  debug: {
                    name: 'debug',
                    version: '1.0.0',
                    path: packageDir,
                  },
                },
              },
            },
          },
        },
      },
    ]),
  );
  const dedupedResult = spawnSync(
    process.execPath,
    [join(root, 'scripts/check-deps.mjs'), '--input', dedupedTree],
    { encoding: 'utf8' },
  );
  assert.notEqual(
    dedupedResult.status,
    0,
    'a later expanded duplicate node must have its children checked',
  );
  assert.match(dedupedResult.stderr, /disallowed runtime dependency: debug/);

  const mismatchTree = join(temp, 'mismatch-tree.json');
  writeFileSync(
    mismatchTree,
    JSON.stringify([
      {
        name: 'certkit',
        version: '0.0.0',
        path: root,
        dependencies: {
          citty: { name: 'citty', version: '0.2.2', path: packageDir },
        },
      },
    ]),
  );
  const mismatchProducer = spawnSync(
    process.execPath,
    [join(root, 'scripts/check-deps.mjs'), '--input', mismatchTree],
    { encoding: 'utf8' },
  );
  assert.match(
    mismatchProducer.stderr,
    /package identity mismatch: expected citty, got debug/,
  );

  const consumerDir = join(temp, 'consumer');
  const consumerPackage = join(consumerDir, 'node_modules/citty');
  mkdirSync(consumerPackage, { recursive: true });
  writeFileSync(
    join(consumerPackage, 'package.json'),
    JSON.stringify({ name: 'debug', version: '1.0.0' }),
  );
  const mismatchConsumer = spawnSync(
    process.execPath,
    [join(root, 'scripts/check-deps.mjs'), '--consumer-tree', consumerDir],
    { encoding: 'utf8' },
  );
  assert.match(
    mismatchConsumer.stderr,
    /package identity mismatch: expected citty, got debug/,
  );
} finally {
  rmSync(temp, { recursive: true, force: true });
}
