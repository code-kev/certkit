import { X509Certificate } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { mintCa } from '../../src/core/certgen.js';
import type { Environment } from '../../src/platforms/detect.js';
import type { RunResult } from '../../src/platforms/run.js';
import { createWindowsAdapter } from '../../src/platforms/windows.js';

const environment: Environment = {
  os: 'windows',
  wsl: false,
  stores: [{ store: 'windows-root', detected: true }],
};
const tempDirs: string[] = [];

afterEach(async () => {
  for (const dir of tempDirs.splice(0))
    await rm(dir, { recursive: true, force: true });
});

function result(stdout = '', code = 0, stderr = ''): RunResult {
  return { code, stdout, stderr };
}

async function fixture(ca: string): Promise<{ caCertPath: string }> {
  const dir = await mkdtemp(join(tmpdir(), 'certkit windows -'));
  tempDirs.push(dir);
  const caCertPath = join(dir, "Certkit CA's $HOME.pem");
  await writeFile(caCertPath, ca);
  return { caCertPath };
}

async function certificates(): Promise<{ ca: string; other: string }> {
  return {
    ca: (await mintCa('fixture')).certPem,
    other: (await mintCa('fixture')).certPem,
  };
}

function storeOutput(...certificates: string[]): string {
  return certificates
    .map((pem) => Buffer.from(new X509Certificate(pem).raw).toString('base64'))
    .join('\r\n');
}

function sha1(pem: string): string {
  return new X509Certificate(pem).fingerprint.replaceAll(':', '').toUpperCase();
}

function adapter(
  _caCertPath: string,
  run: (argv: string[]) => Promise<RunResult>,
) {
  return createWindowsAdapter({ run });
}

const enumerateArgv = [
  'powershell.exe',
  '-NoLogo',
  '-NoProfile',
  '-NonInteractive',
  '-Command',
  "$ErrorActionPreference = 'Stop'; Get-ChildItem -LiteralPath Cert:\\CurrentUser\\Root -ErrorAction Stop | ForEach-Object { [Convert]::ToBase64String($_.RawData) }",
];

describe('Windows Root store adapter', () => {
  it('checks the current-user Root store by exact SHA-256 certificate identity', async () => {
    const { ca, other } = await certificates();
    const { caCertPath } = await fixture(ca);
    const calls: string[][] = [];
    const instance = adapter(caCertPath, async (argv) => {
      calls.push(argv);
      return result(storeOutput(other, ca));
    });

    await expect(instance.checkTrust(ca, environment)).resolves.toEqual([
      { state: 'trusted', target: 'default' },
    ]);
    expect(calls).toEqual([enumerateArgv]);
    await expect(instance.inspectInstalled(ca, 'default')).resolves.toBe(
      'present',
    );
  });

  it('reports a different certificate as untrusted and never deletes by subject', async () => {
    const { ca, other } = await certificates();
    const { caCertPath } = await fixture(ca);
    const calls: string[][] = [];
    const instance = adapter(caCertPath, async (argv) => {
      calls.push(argv);
      return result(storeOutput(other));
    });

    await expect(instance.checkTrust(ca, environment)).resolves.toEqual([
      { state: 'untrusted', target: 'default' },
    ]);
    await instance.uninstall(ca, 'default');
    expect(calls).toEqual([enumerateArgv, enumerateArgv]);
    await expect(instance.inspectInstalled(ca, 'default')).resolves.toBe(
      'absent',
    );
  });

  it('returns unknown when store enumeration is malformed or fails', async () => {
    const { ca } = await certificates();
    const { caCertPath } = await fixture(ca);
    const malformed = adapter(caCertPath, async () => result('not base64'));
    await expect(malformed.checkTrust(ca, environment)).resolves.toMatchObject([
      { state: 'unknown', target: 'default' },
    ]);

    const failed = adapter(caCertPath, async () =>
      result('', 1, 'Access denied'),
    );
    await expect(failed.checkTrust(ca, environment)).resolves.toMatchObject([
      { state: 'unknown', target: 'default' },
    ]);
  });

  it('installs without elevation and verifies the SHA-1 thumbprint by read-back', async () => {
    const { ca } = await certificates();
    const { caCertPath } = await fixture(ca);
    const calls: string[][] = [];
    const instance = adapter(caCertPath, async (argv) => {
      calls.push(argv);
      return argv[1] === '-addstore'
        ? result('Certificate added to store.')
        : result(
            `================ Certificate ================\r\nCert Hash(sha1): ${sha1(ca)}\r\nCertUtil: -store command completed successfully.`,
          );
    });

    await expect(instance.install(caCertPath, 'default')).resolves.toEqual({
      state: 'verified',
    });
    expect(calls).toEqual([
      ['certutil', '-user', '-addstore', 'Root', caCertPath],
      ['certutil', '-user', '-store', 'Root', sha1(ca)],
    ]);
  });

  it('stops after a failed add without issuing a read-back', async () => {
    const { ca } = await certificates();
    const { caCertPath } = await fixture(ca);
    const calls: string[][] = [];
    const instance = adapter(caCertPath, async (argv) => {
      calls.push(argv);
      return result('Access denied', 1);
    });

    await expect(instance.install(caCertPath, 'default')).rejects.toMatchObject(
      {
        code: 'STORE_WRITE_FAILED',
      },
    );
    expect(calls).toEqual([
      ['certutil', '-user', '-addstore', 'Root', caCertPath],
    ]);
  });

  it('keeps install inconclusive when read-back does not find the exact thumbprint', async () => {
    const { ca, other } = await certificates();
    const { caCertPath } = await fixture(ca);
    const calls: string[][] = [];
    const instance = adapter(caCertPath, async (argv) => {
      calls.push(argv);
      return argv[1] === '-addstore'
        ? result()
        : result(`Cert Hash(sha1): ${sha1(other)}`);
    });

    await expect(
      instance.install(caCertPath, 'default'),
    ).resolves.toMatchObject({
      state: 'inconclusive',
    });
    expect(calls[1]).toEqual(['certutil', '-user', '-store', 'Root', sha1(ca)]);
  });

  it('uninstalls only the SHA-256 matched certificate using its SHA-1 thumbprint', async () => {
    const { ca, other } = await certificates();
    const { caCertPath } = await fixture(ca);
    const calls: string[][] = [];
    let enumerations = 0;
    const instance = adapter(caCertPath, async (argv) => {
      calls.push(argv);
      if (argv[0] === 'powershell.exe') {
        enumerations += 1;
        return result(
          storeOutput(...(enumerations === 1 ? [other, ca] : [other])),
        );
      }
      return result('CertUtil: -delstore command completed successfully.');
    });

    await instance.uninstall(ca, 'default');
    expect(calls).toEqual([
      enumerateArgv,
      ['certutil', '-user', '-delstore', 'Root', sha1(ca)],
      enumerateArgv,
    ]);
  });

  it('retains failure when Windows removal cannot be verified', async () => {
    const { ca } = await certificates();
    const calls: string[][] = [];
    const instance = adapter('/unused/ca.pem', async (argv) => {
      calls.push(argv);
      return argv[0] === 'powershell.exe'
        ? result(storeOutput(ca))
        : result('CertUtil: -delstore command completed successfully.');
    });

    await expect(instance.uninstall(ca, 'default')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('remains'),
    });
    expect(calls).toEqual([
      enumerateArgv,
      ['certutil', '-user', '-delstore', 'Root', sha1(ca)],
      enumerateArgv,
    ]);
  });

  it('does not run commands for an undetected Windows store', async () => {
    let calls = 0;
    const instance = adapter('/unused/ca.pem', async () => {
      calls += 1;
      return result();
    });

    await expect(
      instance.checkTrust('unused', {
        ...environment,
        stores: [{ store: 'windows-root', detected: false }],
      }),
    ).resolves.toEqual([{ state: 'not-detected', target: 'default' }]);
    expect(calls).toBe(0);
  });
});
