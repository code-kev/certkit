import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const script = resolve('scripts/check-changeset.mjs');
const root = mkdtempSync(join(tmpdir(), 'certkit-changeset-'));
const git = (...args) =>
  execFileSync('git', args, { cwd: root, encoding: 'utf8' });
const commit = () =>
  git(
    '-c',
    'user.name=Test',
    '-c',
    'user.email=test@example.invalid',
    '-c',
    'commit.gpgsign=false',
    'commit',
    '--quiet',
    '-am',
    'fixture',
  );
try {
  git('init', '--quiet');
  writeFileSync(
    join(root, 'package.json'),
    '{"name":"fixture","version":"0.0.0"}',
  );
  git('add', '.');
  commit();
  const base = git('rev-parse', 'HEAD').trim();
  const bin = join(root, 'bin');
  mkdirSync(bin);
  const pnpm = join(bin, 'pnpm');
  writeFileSync(pnpm, '#!/bin/sh\nexit 42\n');
  chmodSync(pnpm, 0o755);
  const check = () =>
    spawnSync(process.execPath, [script, base], {
      cwd: root,
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
    });
  writeFileSync(join(root, 'README.md'), 'Documentation only');
  git('add', 'README.md');
  commit();
  assert.equal(check().status, 0);
  writeFileSync(
    join(root, 'package.json'),
    '{"name":"fixture","version":"0.1.0"}',
  );
  commit();
  assert.equal(check().status, 0);
  writeFileSync(
    join(root, 'package.json'),
    '{"name":"fixture","version":"0.1.0","engines":{"node":">=24"}}',
  );
  commit();
  assert.notEqual(check().status, 0);
  writeFileSync(
    pnpm,
    `#!/bin/sh\nprintf '{"releases":[{"name":"fixture","type":"patch"}]}' > "$6"\n`,
  );
  assert.equal(check().status, 0);
  git('reset', '--hard', base);
  mkdirSync(join(root, 'src'));
  writeFileSync(join(root, 'src', 'index.ts'), 'export const changed = true;');
  git('add', 'src');
  commit();
  writeFileSync(pnpm, '#!/bin/sh\nexit 42\n');
  assert.notEqual(check().status, 0);
  git('reset', '--hard', base);
  writeFileSync(
    join(root, 'tsdown.config.ts'),
    'export default { dts: false };',
  );
  git('add', 'tsdown.config.ts');
  commit();
  assert.notEqual(check().status, 0);
  writeFileSync(pnpm, `#!/bin/sh\nprintf '{"releases":[]}' > "$6"\n`);
  assert.notEqual(check().status, 0);
  console.log(
    'Changeset check gates runtime/contract changes and permits docs/version-only changes.',
  );
} finally {
  rmSync(root, { recursive: true, force: true });
}
