import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const script = resolve('scripts/check-source-policy.mjs');
const root = mkdtempSync(join(tmpdir(), 'certkit-policy-'));
const git = (...args) => execFileSync('git', args, { cwd: root });
const check = (...args) =>
  spawnSync(process.execPath, [script, ...args], { cwd: root });
try {
  git('init', '--quiet');
  const file = join(root, 'source.ts');
  writeFileSync(file, '// documentation: https://biomejs.dev/schemas/\n');
  git('add', '.');
  assert.equal(check().status, 0);
  writeFileSync(
    file,
    '// workspace: ' + ['de', 'v/private.md'].join('') + '\n',
  );
  assert.equal(check().status, 1);
  assert.equal(check('--staged').status, 0);
  git('add', '.');
  writeFileSync(file, '// clean working copy\n');
  assert.equal(check('--staged').status, 1);
  writeFileSync(file, '// TO' + 'DO: fix this\n');
  assert.equal(check().status, 1);
  writeFileSync(file, 'const value = 1; // TO' + 'DO: fix this\n');
  assert.equal(check().status, 1);
  writeFileSync(file, '/* TO' + 'DO: fix this */\n');
  assert.equal(check().status, 1);
  writeFileSync(file, 'echo ok # TO' + 'DO: fix this\n');
  assert.equal(check().status, 1);
  writeFileSync(file, '<!-- TO' + 'DO: fix this -->\n');
  assert.equal(check().status, 1);
  writeFileSync(
    file,
    '// TO' + 'DO: https://github.com/code-kev/certkit/issues/123\n',
  );
  assert.equal(check().status, 0);
  console.log(
    'Source policy rejects private pointers and unlinked TODOs, including staged content.',
  );
} finally {
  rmSync(root, { recursive: true, force: true });
}
