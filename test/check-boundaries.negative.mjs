import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const file = join('src', 'core', `boundary-probe-${process.pid}.ts`);
try {
  writeFileSync(
    file,
    "import { detect } from '../platforms/detect.js';\nexport { detect };\n",
    { flag: 'wx' },
  );
  const result = spawnSync(process.execPath, ['scripts/check-boundaries.mjs'], {
    encoding: 'utf8',
  });
  assert.notEqual(
    result.status,
    0,
    'Forbidden core-to-platform dependency passed.',
  );
  assert.match(result.stderr, /core-to-outer-layers/, result.stderr);
  console.log('Boundary gate rejects a real forbidden dependency.');
} finally {
  rmSync(file, { force: true });
}
