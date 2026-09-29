import { X509Certificate } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
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
  isInteractive: () => boolean = () => true,
) {
  return createWindowsAdapter({ run, isInteractive });
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
      return argv.includes('-addstore')
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
      return argv.includes('-addstore')
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
    await expect(
      instance.checkTrust('unused', { os: 'linux', wsl: false, stores: [] }),
    ).resolves.toEqual([{ state: 'not-detected', target: 'default' }]);
    expect(calls).toBe(0);
  });

  it('rejects non-default targets before running commands', async () => {
    const { ca } = await certificates();
    const { caCertPath } = await fixture(ca);
    let calls = 0;
    const instance = adapter(caCertPath, async () => {
      calls += 1;
      return result();
    });

    await expect(instance.inspectInstalled(ca, 'other')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('only supports target "default"'),
    });
    await expect(instance.install(caCertPath, 'other')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
    });
    await expect(instance.uninstall(ca, 'other')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
    });
    expect(calls).toBe(0);
  });

  it('ignores blank lines in store enumeration output', async () => {
    const { ca, other } = await certificates();
    const { caCertPath } = await fixture(ca);
    const instance = adapter(caCertPath, async () =>
      result(`\r\n${storeOutput(other)}\r\n\r\n${storeOutput(ca)}\r\n`),
    );

    await expect(instance.checkTrust(ca, environment)).resolves.toEqual([
      { state: 'trusted', target: 'default' },
    ]);
  });

  it('treats base64-looking non-certificate output as uninspectable', async () => {
    const { ca } = await certificates();
    const { caCertPath } = await fixture(ca);
    const instance = adapter(caCertPath, async () => result('AAAA'));

    await expect(instance.checkTrust(ca, environment)).resolves.toMatchObject([
      { state: 'unknown', target: 'default' },
    ]);
    await expect(instance.inspectInstalled(ca, 'default')).resolves.toBe(
      'inconclusive',
    );
  });

  it('reports inspect and check failures when enumeration throws', async () => {
    const { ca } = await certificates();
    const { caCertPath } = await fixture(ca);
    const failed = adapter(caCertPath, async () => result('', 1));
    await expect(failed.inspectInstalled(ca, 'default')).resolves.toBe(
      'inconclusive',
    );

    const throwing = adapter(caCertPath, async () => {
      throw new Error('powershell missing');
    });
    await expect(throwing.inspectInstalled(ca, 'default')).resolves.toBe(
      'inconclusive',
    );
    await expect(throwing.checkTrust(ca, environment)).resolves.toMatchObject([
      { state: 'unknown', target: 'default' },
    ]);
  });

  it('keeps install inconclusive when the read-back command fails', async () => {
    const { ca } = await certificates();
    const { caCertPath } = await fixture(ca);
    const rejecting = adapter(caCertPath, async (argv) => {
      if (argv.includes('-addstore'))
        return result('Certificate added to store.');
      throw new Error('read-back failed');
    });
    await expect(
      rejecting.install(caCertPath, 'default'),
    ).resolves.toMatchObject({ state: 'inconclusive' });

    const failing = adapter(caCertPath, async (argv) =>
      argv.includes('-addstore')
        ? result('Certificate added to store.')
        : result('', 1),
    );
    await expect(failing.install(caCertPath, 'default')).resolves.toMatchObject(
      { state: 'inconclusive' },
    );
  });

  it('wraps unexpected install errors', async () => {
    const { ca } = await certificates();
    const { caCertPath } = await fixture(ca);
    const instance = adapter(caCertPath, async () => result());

    await expect(
      instance.install(`${caCertPath}.missing`, 'default'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining(
        'Could not verify the current-user Windows Root store install',
      ),
    });
  });

  it('refuses uninstall when the store cannot be inspected', async () => {
    const { ca } = await certificates();
    const { caCertPath } = await fixture(ca);
    const instance = adapter(caCertPath, async () => result('', 1));

    await expect(instance.uninstall(ca, 'default')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('Could not inspect'),
    });
  });

  it('retains the CA when deletion fails', async () => {
    const { ca } = await certificates();
    const { caCertPath } = await fixture(ca);
    const calls: string[][] = [];
    const instance = adapter(caCertPath, async (argv) => {
      calls.push(argv);
      return argv[0] === 'powershell.exe'
        ? result(storeOutput(ca))
        : result('Access denied', 1);
    });

    await expect(instance.uninstall(ca, 'default')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('Could not remove'),
    });
    expect(calls).toEqual([
      enumerateArgv,
      ['certutil', '-user', '-delstore', 'Root', sha1(ca)],
    ]);
  });

  it('fails closed when post-removal enumeration fails', async () => {
    const { ca } = await certificates();
    const { caCertPath } = await fixture(ca);
    let enumerations = 0;
    const instance = adapter(caCertPath, async (argv) => {
      if (argv[0] === 'powershell.exe') {
        enumerations += 1;
        return enumerations === 1 ? result(storeOutput(ca)) : result('', 1);
      }
      return result('CertUtil: -delstore command completed successfully.');
    });

    await expect(instance.uninstall(ca, 'default')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('remains'),
    });
  });

  it('wraps unexpected uninstall errors', async () => {
    const { ca } = await certificates();
    const { caCertPath } = await fixture(ca);
    const instance = adapter(caCertPath, async () => {
      throw new Error('powershell missing');
    });

    await expect(instance.uninstall(ca, 'default')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('Could not complete Windows CA removal'),
    });
  });

  it('refuses install in a non-interactive session without running certutil', async () => {
    const { ca } = await certificates();
    const { caCertPath } = await fixture(ca);
    const calls: string[][] = [];
    const instance = adapter(
      caCertPath,
      async (argv) => {
        calls.push(argv);
        return result();
      },
      () => false,
    );

    await expect(instance.install(caCertPath, 'default')).rejects.toMatchObject(
      {
        code: 'STORE_WRITE_FAILED',
        message: expect.stringContaining('interactive'),
      },
    );
    expect(calls).toEqual([]);
  });

  it('refuses uninstall in a non-interactive session before any deletion', async () => {
    const { ca } = await certificates();
    const { caCertPath } = await fixture(ca);
    const calls: string[][] = [];
    const instance = adapter(
      caCertPath,
      async (argv) => {
        calls.push(argv);
        return result(storeOutput(ca));
      },
      () => false,
    );

    await expect(instance.uninstall(ca, 'default')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('interactive'),
    });
    expect(calls.some((argv) => argv.includes('-delstore'))).toBe(false);
  });

  it('default interactivity check treats SSH sessions as non-interactive even with TTYs', async () => {
    const { ca } = await certificates();
    const { caCertPath } = await fixture(ca);
    const stdinTTY = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
    const stdoutTTY = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
    Object.defineProperty(process.stdin, 'isTTY', { value: true });
    Object.defineProperty(process.stdout, 'isTTY', { value: true });
    vi.stubEnv('SSH_CONNECTION', '10.0.0.1 22 10.0.0.2 22');
    try {
      const instance = createWindowsAdapter({ run: async () => result() });
      await expect(
        instance.install(caCertPath, 'default'),
      ).rejects.toMatchObject({ code: 'STORE_WRITE_FAILED' });
    } finally {
      vi.unstubAllEnvs();
      if (stdinTTY) Object.defineProperty(process.stdin, 'isTTY', stdinTTY);
      if (stdoutTTY) Object.defineProperty(process.stdout, 'isTTY', stdoutTTY);
    }
  });

  it('treats uninstall of an absent CA as a no-op even when non-interactive', async () => {
    const { ca, other } = await certificates();
    const { caCertPath } = await fixture(ca);
    const instance = adapter(
      caCertPath,
      async () => result(storeOutput(other)),
      () => false,
    );

    await expect(instance.uninstall(ca, 'default')).resolves.toBeUndefined();
  });
});
