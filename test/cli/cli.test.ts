import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { run } from '../../src/platforms/run.js';

const cli = resolve('dist/cli/index.js');
const originalCaDir = process.env.CERTKIT_HOME;

afterEach(() => {
  if (originalCaDir === undefined) delete process.env.CERTKIT_HOME;
  else process.env.CERTKIT_HOME = originalCaDir;
});

describe('CLI skeleton', () => {
  it('prints the CA directory without creating it', async () => {
    const caDir = join(mkdtempSync(join(tmpdir(), 'certkit-cli-')), 'ca');
    process.env.CERTKIT_HOME = caDir;

    const result = await run([process.execPath, cli, 'caroot']);

    expect(result).toEqual({ code: 0, stdout: `${caDir}\n`, stderr: '' });
    expect(existsSync(caDir)).toBe(false);
    rmSync(join(caDir, '..'), { recursive: true, force: true });
  });

  it('prints CA directory JSON with the schema version', async () => {
    const root = mkdtempSync(join(tmpdir(), 'certkit-cli-json-'));
    const caDir = join(root, 'ca');
    process.env.CERTKIT_HOME = caDir;
    const result = await run([process.execPath, cli, 'caroot', '--json']);
    const output = JSON.parse(result.stdout) as {
      schemaVersion: number;
      caDir: string;
    };

    expect(result.code).toBe(0);
    expect(output).toEqual({ schemaVersion: 1, caDir });
    expect(existsSync(caDir)).toBe(false);
    rmSync(root, { recursive: true, force: true });
  });

  it('prints a human report and exits 1 iff a store is untrusted', async () => {
    const root = mkdtempSync(join(tmpdir(), 'certkit-cli-status-'));
    const caDir = join(root, 'ca');
    process.env.CERTKIT_HOME = caDir;
    const jsonResult = await run([process.execPath, cli, 'status', '--json']);
    const output = JSON.parse(jsonResult.stdout) as {
      stores: Array<{ state: string }>;
    };
    const result = await run([process.execPath, cli, 'status', '--no-color']);

    expect(result.code).toBe(
      output.stores.some((store) => store.state === 'untrusted') ? 1 : 0,
    );
    expect(result.stdout).toContain(caDir);
    expect(result.stdout).toContain('Stores:');
    if (output.stores.some((store) => store.state === 'untrusted'))
      expect(result.stdout).toContain('untrusted');
    expect(result.stderr).toBe('');
    expect(result.stdout).not.toContain('\u001b[');
    expect(existsSync(caDir)).toBe(false);
    rmSync(root, { recursive: true, force: true });
  });

  it('prints status JSON with exactly the report fields and schema version', async () => {
    const root = mkdtempSync(join(tmpdir(), 'certkit-cli-status-json-'));
    process.env.CERTKIT_HOME = join(root, 'ca');
    const result = await run([process.execPath, cli, '--json', 'status']);
    const output = JSON.parse(result.stdout) as {
      schemaVersion: number;
      caDir: string;
      ca: null | { subject: string; serial: string; expiresAt: string };
      stores: Array<{ state: string }>;
    };

    expect(result.code).toBe(
      output.stores.some((store) => store.state === 'untrusted') ? 1 : 0,
    );
    expect(Object.keys(output).sort()).toEqual([
      'ca',
      'caDir',
      'schemaVersion',
      'stores',
    ]);
    expect(output.schemaVersion).toBe(1);
    rmSync(root, { recursive: true, force: true });
  });

  it('prints status errors with only the error schema fields', async () => {
    const root = mkdtempSync(join(tmpdir(), 'certkit-cli-status-error-'));
    const caPath = join(root, 'not-a-directory');
    writeFileSync(caPath, '');
    process.env.CERTKIT_HOME = caPath;
    const result = await run([process.execPath, cli, 'status', '--json']);
    const output = JSON.parse(result.stdout) as {
      schemaVersion: number;
      error: { code: string; message: string };
    };

    expect(result.code).toBe(1);
    expect(Object.keys(output).sort()).toEqual(['error', 'schemaVersion']);
    expect(Object.keys(output.error).sort()).toEqual(['code', 'message']);
    expect(output.schemaVersion).toBe(1);
    expect(output.error.code).toBe('CA_UNREADABLE');
    rmSync(root, { recursive: true, force: true });
  });

  it('prints the package version', async () => {
    const result = await run([process.execPath, cli, '--version']);
    expect(result.code).toBe(0);
    expect(result.stdout.trim()).toBe(
      (await import('../../package.json', { with: { type: 'json' } })).default
        .version,
    );
  });

  it('prints help to stderr and exits 2 for an unknown command', async () => {
    const result = await run([process.execPath, cli, 'missing']);
    expect(result.code).toBe(2);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('USAGE');
    expect(result.stderr).toContain('caroot');
  });

  it('treats inherited object keys as unknown commands', async () => {
    const result = await run([process.execPath, cli, 'constructor']);
    expect(result.code).toBe(2);
    expect(result.stdout).toBe('');
    expect(result.stderr).toContain('USAGE');
    expect(result.stderr).toContain('Unknown command: constructor');
  });
});
