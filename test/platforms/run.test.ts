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
    await expect(
      run([process.execPath, '-e', 'setTimeout(() => {}, 10_000)'], {
        timeoutMs: 20,
      }),
    ).rejects.toThrow(/timed out/i);
  });

  it('maps a missing executable to UNSUPPORTED_PLATFORM', async () => {
    await expect(
      run(['/definitely/missing/certkit-command']),
    ).rejects.toMatchObject({
      name: 'CertkitError',
      code: 'UNSUPPORTED_PLATFORM',
    });
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
