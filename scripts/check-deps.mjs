import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, realpathSync } from 'node:fs';
import process from 'node:process';
import { pathToFileURL } from 'node:url';

const allowed = new Set([
  'certkit',
  '@peculiar/x509',
  // @peculiar/asn1-schema dependency already present in the pinned x509 closure.
  '@peculiar/utils',
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
  const expanded = new Set();
  const visit = (pkg) => {
    const name = pkg?.name ?? pkg?.from;
    if (typeof name !== 'string')
      throw new Error('invalid package node in dependency tree');
    const key = `${name}@${pkg.version ?? ''}:${pkg.path ?? ''}`;
    if (!visited.has(key)) {
      visited.add(key);
      if (!pkg.path) throw new Error(`missing installed path for ${name}`);
      const manifest = JSON.parse(
        readFileSync(`${pkg.path}/package.json`, 'utf8'),
      );
      validateManifest(name, manifest, errors);
    }
    const children = [
      ...Object.values(pkg.dependencies ?? {}),
      ...Object.values(pkg.unsavedDependencies ?? {}),
    ];
    if (children.length === 0 || expanded.has(key)) return;
    expanded.add(key);
    for (const child of children) visit(child);
  };
  for (const root of Array.isArray(tree) ? tree : [tree]) visit(root);
  if (errors.length) throw new Error(errors.join('\n'));
}

function validateManifest(name, manifest, errors) {
  if (manifest.name !== name)
    errors.push(
      `package identity mismatch: expected ${name}, got ${manifest.name}`,
    );
  if (
    !allowed.has(name) &&
    !allowedPrefixes.some((prefix) => name.startsWith(prefix))
  )
    errors.push(`disallowed runtime dependency: ${name}`);
  for (const script of lifecycleScripts)
    if (Object.hasOwn(manifest.scripts ?? {}, script))
      errors.push(`${name} declares ${script} lifecycle script`);
}

export function checkConsumerTree(root) {
  const errors = [];
  const visited = new Set();
  function visitPackage(directory, installedName) {
    const manifest = JSON.parse(
      readFileSync(`${directory}/package.json`, 'utf8'),
    );
    if (typeof installedName !== 'string')
      throw new Error(`missing installed package name at ${directory}`);
    validateManifest(installedName, manifest, errors);
    const realPath = realpathSync(directory);
    if (visited.has(realPath)) return;
    visited.add(realPath);
    visitNodeModules(`${directory}/node_modules`);
  }
  function visitNodeModules(directory) {
    let entries;
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch (error) {
      if (error.code === 'ENOENT') return;
      throw error;
    }
    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;
      const path = `${directory}/${entry.name}`;
      if (entry.name.startsWith('@'))
        for (const scoped of readdirSync(path))
          visitPackage(`${path}/${scoped}`, `${entry.name}/${scoped}`);
      else visitPackage(path, entry.name);
    }
  }
  visitNodeModules(`${root}/node_modules`);
  if (errors.length) throw new Error(errors.join('\n'));
  console.log(`consumer dependency tree passed (${visited.size} packages)`);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const consumerIndex = process.argv.indexOf('--consumer-tree');
    if (consumerIndex !== -1) {
      checkConsumerTree(process.argv[consumerIndex + 1]);
      process.exit(0);
    }
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
    console.log(
      'runtime dependency closure is allowed and install-script-free',
    );
  } catch (error) {
    console.error(`dependency check failed: ${error.message}`);
    process.exitCode = 1;
  }
}
