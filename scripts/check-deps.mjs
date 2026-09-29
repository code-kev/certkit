import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import process from 'node:process';

const allowed = new Set([
  'certkit',
  '@peculiar/x509',
  'tsyringe',
  'reflect-metadata',
  'pvtsutils',
  'pvutils',
  'asn1js',
  'tslib',
  'citty',
  'picocolors',
]);
const allowedPrefixes = ['@peculiar/asn1-'];
const lifecycleScripts = ['preinstall', 'install', 'postinstall'];

function check(tree) {
  const errors = [];
  const visited = new Set();
  const visit = (pkg) => {
    const name = pkg?.name ?? pkg?.from;
    if (typeof name !== 'string')
      throw new Error('invalid package node in dependency tree');
    const key = `${name}@${pkg.version ?? ''}:${pkg.path ?? ''}`;
    if (visited.has(key)) return;
    visited.add(key);
    if (
      !allowed.has(name) &&
      !allowedPrefixes.some((prefix) => name.startsWith(prefix))
    ) {
      errors.push(`disallowed runtime dependency: ${name}`);
    }
    if (!pkg.path) throw new Error(`missing installed path for ${name}`);
    const manifest = JSON.parse(
      readFileSync(`${pkg.path}/package.json`, 'utf8'),
    );
    for (const script of lifecycleScripts) {
      if (Object.hasOwn(manifest.scripts ?? {}, script))
        errors.push(`${name} declares ${script} lifecycle script`);
    }
    for (const child of [
      ...Object.values(pkg.dependencies ?? {}),
      ...Object.values(pkg.unsavedDependencies ?? {}),
    ])
      visit(child);
  };
  for (const root of Array.isArray(tree) ? tree : [tree]) visit(root);
  if (errors.length) throw new Error(errors.join('\n'));
}

try {
  const fixtureIndex = process.argv.indexOf('--input');
  const json =
    fixtureIndex === -1
      ? execFileSync(
          'pnpm',
          ['ls', '--prod', '--depth', 'Infinity', '--json'],
          { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
        )
      : readFileSync(process.argv[fixtureIndex + 1], 'utf8');
  check(JSON.parse(json));
  console.log('runtime dependency closure is allowed and install-script-free');
} catch (error) {
  console.error(`dependency check failed: ${error.message}`);
  process.exitCode = 1;
}
