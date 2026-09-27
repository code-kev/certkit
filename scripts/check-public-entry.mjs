import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

const entryPath = new URL('../dist/index.js', import.meta.url);
const reflectPath = new URL('../dist/reflect-metadata.js', import.meta.url);
assert.ok(existsSync(reflectPath), 'dist/reflect-metadata.js must be emitted');
const entry = readFileSync(entryPath, 'utf8');
const imports =
  entry.match(/^import\s+["']\.\/reflect-metadata\.js["'];?$/gm) ?? [];
assert.equal(
  imports.length,
  1,
  'dist/index.js must import reflect-metadata.js once',
);
