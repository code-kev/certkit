import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';

const base = process.argv[2];
if (!base) throw new Error('A comparison ref is required.');
const git = (...args) => execFileSync('git', args, { encoding: 'utf8' });
const ancestor = git('merge-base', base, 'HEAD').trim();
const files = git('diff', '--name-only', '-z', `${ancestor}..HEAD`)
  .split('\0')
  .filter(Boolean);
const manifest = (ref) => {
  const { version: _version, ...rest } = JSON.parse(
    git('show', `${ref}:package.json`),
  );
  return JSON.stringify(rest);
};
const userFacing =
  files.some(
    (file) =>
      file.startsWith('src/') ||
      ['tsdown.config.ts', 'tsdown.config.json', 'tsconfig.json'].includes(
        file,
      ),
  ) ||
  (files.includes('package.json') && manifest(ancestor) !== manifest('HEAD'));
if (!userFacing) {
  console.log('No runtime or package-contract changes requiring a changeset.');
} else {
  const dir = mkdtempSync(join(tmpdir(), 'certkit-release-plan-'));
  const output = join(dir, 'status.json');
  try {
    execFileSync(
      'pnpm',
      [
        'changeset',
        'status',
        '--since',
        base,
        '--output',
        relative(process.cwd(), output),
      ],
      { stdio: 'inherit' },
    );
    const plan = JSON.parse(readFileSync(output, 'utf8'));
    const { name } = JSON.parse(git('show', 'HEAD:package.json'));
    if (
      !plan.releases.some(
        (release) =>
          release.name === name &&
          ['patch', 'minor', 'major'].includes(release.type),
      )
    )
      throw new Error(
        'Published behavior changes require a release changeset.',
      );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
