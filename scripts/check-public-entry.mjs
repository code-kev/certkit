import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

const entryPath = new URL('../dist/index.js', import.meta.url);
const reflectPath = new URL('../dist/reflect-metadata.js', import.meta.url);
const cliPath = new URL('../dist/cli/index.js', import.meta.url);
assert.ok(existsSync(reflectPath), 'dist/reflect-metadata.js must be emitted');
const entry = readFileSync(entryPath, 'utf8');
const imports =
  entry.match(/^import\s+["']\.\/reflect-metadata\.js["'];?$/gm) ?? [];
assert.equal(
  imports.length,
  1,
  'dist/index.js must import reflect-metadata.js once',
);

const cli = readFileSync(cliPath, 'utf8');
const cliShim =
  cli.match(/^import\s+["'](\.\.\/reflect-metadata-[^"']+\.js)["'];?$/gm) ?? [];
assert.equal(
  cliShim.length,
  1,
  'dist/cli/index.js must import the relative reflect-metadata shim before core',
);
const shimPath = cliShim[0]?.match(/["']([^"']+)["']/)?.[1];
const internalImports =
  cli.match(/^import .*?["'](?:\.\.\/|\.\/)[^"']+\.js["'];?$/gm) ?? [];
const coreImports = internalImports.filter(
  (line) => !line.includes('reflect-metadata-'),
);
assert.ok(
  shimPath && existsSync(new URL(shimPath, cliPath)) && coreImports.length > 0,
  'dist/cli/index.js reflect-metadata import must resolve to an emitted file',
);
for (const coreImport of coreImports)
  assert.ok(
    cli.indexOf(cliShim[0] ?? '') < cli.indexOf(coreImport),
    'dist/cli/index.js must load reflect-metadata before certificate core',
  );
