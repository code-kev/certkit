import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';

// Temporary backport of upstream's depth-limit fix: https://github.com/micromatch/braces/pull/72
// Keep the fixed 100-level cap until a maintained braces release provides equivalent parser and AST guards.
const require = createRequire(import.meta.url);
const changesetsRequire = createRequire(require.resolve('@changesets/cli'));
const configRequire = createRequire(
  changesetsRequire.resolve('@changesets/config'),
);
const micromatchRequire = createRequire(configRequire.resolve('micromatch'));
const bracesPath = micromatchRequire.resolve('braces');
assert.match(
  bracesPath.replaceAll('\\', '/'),
  /\/braces@3\.0\.3_patch_hash=[^/]+\/node_modules\/braces\/index\.js$/,
);
const braces = require(bracesPath);

for (const [pattern, output] of [
  ['a\\{b,c\\}z', ['a{b,c}z']],
  ['a{"b,c"}z', ['a{b,c}z']],
  ['[a-{b,c}]', ['[a-{b,c}]']],
]) {
  assert.deepEqual(braces(pattern), output);
  assert.deepEqual(braces(pattern, { expand: true }), output);
}
for (const pattern of ['{{a}}', '{a,{b}}', '{{x}y}', '{a,{b,{c}}', '{}{a}']) {
  assert.equal(
    braces.stringify(braces.parse(pattern), { escapeInvalid: true }),
    pattern,
  );
}

for (const [open, close] of [
  ['{', '}'],
  ['(', ')'],
  ['{(', ')}'],
]) {
  const nesting = open === '{(' ? 50 : 100;
  const acceptedPattern = `${open.repeat(nesting)}leaf${close.repeat(nesting)}`;
  const rejectedPattern = `${open.repeat(nesting + 1)}leaf${close.repeat(nesting + 1)}`;

  for (const call of [
    () => braces.parse(acceptedPattern),
    () => braces.compile(acceptedPattern),
    () => braces.expand(acceptedPattern),
  ]) {
    assert.doesNotThrow(call);
  }

  for (const call of [
    () => braces.parse(rejectedPattern),
    () => braces(rejectedPattern),
    () => braces(rejectedPattern, { expand: true }),
    () => braces.compile(rejectedPattern),
    () => braces.expand(rejectedPattern),
    () => braces.stringify(rejectedPattern),
    () => braces.parse(rejectedPattern, { maxDepth: Number.MAX_SAFE_INTEGER }),
  ]) {
    assert.throws(call, /max depth/i);
  }
}

assert.throws(() => braces.parse('{{a,b},c}', { maxDepth: 1 }), /max depth/i);
assert.doesNotThrow(() => braces.parse('{{a,b},c}', { maxDepth: 2 }));
assert.throws(() => braces.parse('{{a,b},c}', { maxDepth: 1.5 }), /max depth/i);
const overLimitPattern = `${'{'.repeat(101)}leaf${'}'.repeat(101)}`;
for (const invalidMaxDepth of [Number.NaN, Number.POSITIVE_INFINITY, '1']) {
  assert.throws(
    () => braces.parse(overLimitPattern, { maxDepth: invalidMaxDepth }),
    /max depth/i,
  );
}

const makeNestedAst = (depth) => {
  let node = { type: 'text', value: 'leaf' };
  for (let index = 0; index < depth; index++) {
    const brace = { type: 'brace', commas: 1, ranges: 0, nodes: [node] };
    node.parent = brace;
    node = brace;
  }
  const root = { type: 'root', nodes: [node] };
  node.parent = root;
  return root;
};

for (const call of [
  () => braces.compile(makeNestedAst(100)),
  () => braces.expand(makeNestedAst(100)),
  () => braces.stringify(makeNestedAst(100)),
]) {
  assert.doesNotThrow(call);
}

for (const call of [
  () =>
    braces.compile(makeNestedAst(101), { maxDepth: Number.MAX_SAFE_INTEGER }),
  () =>
    braces.expand(makeNestedAst(101), { maxDepth: Number.MAX_SAFE_INTEGER }),
  () =>
    braces.stringify(makeNestedAst(101), { maxDepth: Number.MAX_SAFE_INTEGER }),
]) {
  assert.throws(call, /max depth/i);
}

for (const call of [
  () => braces.compile(makeNestedAst(2), { maxDepth: 1 }),
  () => braces.expand(makeNestedAst(2), { maxDepth: 1 }),
  () => braces.stringify(makeNestedAst(2), { maxDepth: 1 }),
]) {
  assert.throws(call, /max depth/i);
}

for (const call of [
  () => braces.compile(makeNestedAst(100).nodes[0]),
  () => braces.expand(makeNestedAst(100).nodes[0]),
  () => braces.stringify(makeNestedAst(100).nodes[0]),
]) {
  assert.doesNotThrow(call);
}
for (const call of [
  () => braces.compile(makeNestedAst(101).nodes[0]),
  () => braces.expand(makeNestedAst(101).nodes[0]),
  () => braces.stringify(makeNestedAst(101).nodes[0]),
]) {
  assert.throws(call, /max depth/i);
}

const cycleScript = `
  const braces = require(process.env.CERTKIT_BRACES_ENTRY);
  const ast = { type: 'paren', nodes: [{ type: 'paren', nodes: [{ type: 'text', value: 'a' }] }] };
  if (process.env.CERTKIT_CYCLE === 'self') ast.parent = ast;
  else ast.parent = { type: 'paren', parent: ast };
  braces.expand(ast);
`;
for (const cycle of ['self', 'multiple']) {
  const result = spawnSync(process.execPath, ['-e', cycleScript], {
    encoding: 'utf8',
    env: {
      ...process.env,
      CERTKIT_BRACES_ENTRY: bracesPath,
      CERTKIT_CYCLE: cycle,
    },
    timeout: 2_000,
  });
  assert.notEqual(
    result.error?.code,
    'ETIMEDOUT',
    'cyclic AST expansion must not hang',
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /AST parent chain contains a cycle/);
}

const deepBraceLiteral = '{'.repeat(101);
const escapedPattern = '\\{'.repeat(101);
const quotedPattern = `"${deepBraceLiteral}"`;
const bracketPattern = `[${deepBraceLiteral}]`;
for (const pattern of [escapedPattern, quotedPattern, bracketPattern]) {
  assert.doesNotThrow(() => braces.parse(pattern));
  assert.doesNotThrow(() => braces(pattern));
}
