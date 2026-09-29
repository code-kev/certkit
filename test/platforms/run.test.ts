import { inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import { resolveNssCertutil, run } from '../../src/platforms/run.js';

describe('platform command runner', () => {
  it('passes argv entries as data without shell interpretation', async () => {
    const args = ['$(rm -rf ~)', 'space here', '; echo unsafe'];
    const result = await run([
      process.execPath,
      '-e',
      'process.stdout.write(JSON.stringify(process.argv.slice(1)))',
      ...args,
    ]);
    expect(result).toEqual({
      code: 0,
      stdout: JSON.stringify(args),
      stderr: '',
    });
  });

  it('returns nonzero exit codes without throwing', async () => {
    await expect(
      run([process.execPath, '-e', 'process.exit(7)']),
    ).resolves.toMatchObject({ code: 7 });
  });

  it('kills a command after its timeout', async () => {
    const key =
      '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----';
    const error = await run(
      [
        process.execPath,
        '-e',
        'process.stdout.write(process.argv.at(-1)); setTimeout(() => {}, 10_000)',
        '--',
        key,
      ],
      { timeoutMs: 20 },
    ).catch((failure: unknown) => failure);
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).toMatch(/timed out/i);
    expect(inspect(error, { depth: null })).not.toContain('secret');
    expect(inspect(error, { depth: null })).not.toContain(key);
    expect((error as Error & { cause?: unknown }).cause).toBeUndefined();
  });

  it('does not expose captured output or raw child errors on unexpected failure', async () => {
    const key =
      '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----';
    const outcome: unknown = await run([
      process.execPath,
      '-e',
      'process.stdout.write(process.argv.at(-1)); process.kill(process.pid, "SIGKILL")',
      '--',
      key,
    ]).catch((failure: unknown) => failure);
    // Windows has no signal kills: the child surfaces as a numeric exit code.
    if (process.platform === 'win32') {
      expect(outcome).toMatchObject({ code: expect.any(Number) });
      expect(inspect(outcome, { depth: null })).not.toContain('secret');
      expect(inspect(outcome, { depth: null })).not.toContain(key);
      return;
    }
    expect(outcome).toBeInstanceOf(Error);
    expect(inspect(outcome, { depth: null })).not.toContain('secret');
    expect(inspect(outcome, { depth: null })).not.toContain(key);
    expect((outcome as Error & { cause?: unknown }).cause).toBeUndefined();
  });

  it('maps a missing executable to UNSUPPORTED_PLATFORM', async () => {
    const error = await run([
      '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----',
    ]).catch((failure: unknown) => failure);
    expect(error).toMatchObject({
      name: 'CertkitError',
      code: 'UNSUPPORTED_PLATFORM',
    });
    expect(inspect(error, { depth: null })).not.toContain('secret');
    expect(inspect(error, { depth: null })).not.toContain(
      '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----',
    );
    expect((error as Error & { cause?: unknown }).cause).toBeUndefined();
  });

  it('redacts private keys in returned output', async () => {
    const key =
      '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----';
    const result = await run([
      process.execPath,
      '-e',
      'process.stdout.write(process.argv.at(-1)); process.stderr.write(process.argv.at(-1))',
      '--',
      key,
    ]);
    expect(result.stdout).toBe('[REDACTED]');
    expect(result.stderr).toBe('[REDACTED]');
    expect(result.stdout).not.toContain('secret');
  });

  it('uses only an explicit NSS certutil override when provided', async () => {
    await expect(
      resolveNssCertutil({ CERTKIT_CERTUTIL: process.execPath }),
    ).resolves.toBe(process.execPath);
  });

  it('does not treat the Windows system certutil as NSS certutil', async () => {
    await expect(
      resolveNssCertutil({
        CERTKIT_CERTUTIL: 'C:\\Windows\\System32\\certutil.exe',
      }),
    ).resolves.toBeNull();
  });
});
