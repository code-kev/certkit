import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const staged = process.argv.includes('--staged');
const args = staged
  ? ['diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z']
  : ['ls-files', '-z'];
const files = execFileSync('git', args, { encoding: 'utf8' })
  .split('\0')
  .filter(Boolean);
const errors = [];
for (const file of files) {
  if (/^(dev|\.opencode)\//.test(file)) {
    errors.push(`${file}: private workspace file`);
    continue;
  }
  if (!/\.(?:[cm]?[jt]sx?|md|ya?ml|jsonc?|sh)$/.test(file)) continue;
  const text = staged
    ? execFileSync('git', ['show', `:${file}`], { encoding: 'utf8' })
    : readFileSync(file, 'utf8');
  if (file === 'README.md' && /\d+\.\d+\.\d+-beta\.\d+/.test(text))
    errors.push(
      `${file}: pins a prerelease version; describe the dist-tag instead`,
    );
  for (const [index, line] of text.split('\n').entries()) {
    if (/(?<![\w.])dev\/|\b(?:SPEC|ADR)-\d+/.test(line))
      errors.push(`${file}:${index + 1}: private artifact reference`);
    if (
      /\/\/\s*TODO\b|\/\*\s*TODO\b|#\s*TODO\b|<!--\s*TODO\b|^\s*\*\s*TODO\b/.test(
        line,
      ) &&
      !/https:\/\/github\.com\/[^\s]+\/issues\/\d+/.test(line)
    )
      errors.push(`${file}:${index + 1}: TODO requires a public issue URL`);
  }
}
if (errors.length) {
  console.error(errors.join('\n'));
  process.exitCode = 1;
} else console.log('Public source policy passed.');
