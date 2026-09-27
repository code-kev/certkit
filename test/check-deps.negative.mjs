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
} finally {
  rmSync(temp, { recursive: true, force: true });
}
