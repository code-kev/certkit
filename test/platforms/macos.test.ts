import { X509Certificate } from 'node:crypto';
import { existsSync, statSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { mintCa } from '../../src/core/certgen.js';
import type { Environment } from '../../src/platforms/detect.js';
import { createMacosAdapter } from '../../src/platforms/macos.js';
import type { RunResult } from '../../src/platforms/run.js';

const environment: Environment = {
  os: 'macos',
  wsl: false,
  stores: [{ store: 'macos-keychain', detected: true }],
};
const tempDirs: string[] = [];

afterEach(async () => {
  for (const dir of tempDirs.splice(0))
    await rm(dir, { recursive: true, force: true });
});

function result(stdout = '', code = 0, stderr = ''): RunResult {
  return { code, stdout, stderr };
}

async function fixture(ca: string): Promise<{
  caCertPath: string;
  keychainPath: string;
}> {
  const dir = await mkdtemp(join(tmpdir(), 'certkit macos -'));
  tempDirs.push(dir);
  const caCertPath = join(dir, "Certkit CA's $HOME.pem");
  const keychainPath = join(dir, 'login.keychain-db');
  await Promise.all([
    writeFile(caCertPath, ca),
    writeFile(keychainPath, 'fixture keychain'),
  ]);
  return { caCertPath, keychainPath };
}

async function certificates(): Promise<{ ca: string; other: string }> {
  return {
    ca: (await mintCa('fixture')).certPem,
    other: (await mintCa('fixture')).certPem,
  };
}

function adapter(
  caCertPath: string,
  keychainPath: string,
  run: (argv: string[]) => Promise<RunResult>,
) {
  return createMacosAdapter({ caCertPath, keychainPath, run });
}

function pemBlocks(...certificates: string[]): string {
  return certificates.join('\n');
}

describe('macOS keychain adapter', () => {
  it('reports a missing macOS keychain as not-detected without running commands', async () => {
    let calls = 0;
    const instance = createMacosAdapter({
      caCertPath: '/not-read-on-an-absent-store/ca.pem',
      keychainPath: '/unused/login.keychain-db',
      run: async () => {
        calls++;
        return result();
      },
    });

    await expect(
      instance.checkTrust('unused', {
        ...environment,
        stores: [{ store: 'macos-keychain', detected: false }],
      }),
    ).resolves.toEqual([{ state: 'not-detected', target: 'default' }]);
    expect(calls).toBe(0);
  });

  it('checks the login keychain even when another keychain is first in the user search list', async () => {
    const { ca, other } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const otherKeychain = join(dirname(keychainPath), 'other.keychain-db');
    const calls: string[][] = [];
    const instance = adapter(caCertPath, keychainPath, async (argv) => {
      calls.push(argv);
      if (argv[1] === 'list-keychains')
        return result(`  "${otherKeychain}"\n  "${keychainPath}"\n`);
      if (argv[1] === 'find-certificate') return result(pemBlocks(other, ca));
      return result('certificate verification successful');
    });

    await expect(instance.checkTrust(ca, environment)).resolves.toEqual([
      { state: 'trusted', target: 'default' },
    ]);
    expect(calls).toEqual([
      ['security', 'list-keychains', '-d', 'user'],
      [
        'security',
        'find-certificate',
        '-a',
        '-c',
        'certkit development CA',
        '-p',
        keychainPath,
      ],
      ['security', 'verify-cert', '-c', caCertPath, '-p', 'ssl', '-l', '-L'],
    ]);
  });

  it('reports absent and malformed user search lists without writing', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const absentCalls: string[][] = [];
    const absent = adapter(caCertPath, keychainPath, async (argv) => {
      absentCalls.push(argv);
      return result('  "/other/login.keychain-db"\n');
    });

    await expect(absent.checkTrust(ca, environment)).resolves.toEqual([
      {
        state: 'not-detected',
        target: 'default',
        detail: expect.any(String),
      },
    ]);
    expect(absentCalls).toEqual([['security', 'list-keychains', '-d', 'user']]);

    const malformed = adapter(caCertPath, keychainPath, async () =>
      result('"unterminated keychain list'),
    );
    await expect(malformed.checkTrust(ca, environment)).resolves.toEqual([
      { state: 'unknown', target: 'default', detail: expect.any(String) },
    ]);
  });

  it('keeps same-subject different-fingerprint certificates from proving trust', async () => {
    const { ca, other } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const instance = adapter(caCertPath, keychainPath, async (argv) =>
      argv[1] === 'list-keychains'
        ? result(`"${keychainPath}"\n`)
        : argv[1] === 'find-certificate'
          ? result(other)
          : result('certificate verification successful'),
    );

    await expect(instance.checkTrust(ca, environment)).resolves.toMatchObject([
      { state: 'unknown', target: 'default', detail: expect.any(String) },
    ]);
  });

  it('reports a default-policy Never Trust result as untrusted', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const instance = adapter(caCertPath, keychainPath, async (argv) =>
      argv[1] === 'list-keychains'
        ? result(`"${keychainPath}"\n`)
        : argv[1] === 'find-certificate'
          ? result(ca)
          : result('', 1, 'SecTrustEvaluate result: kSecTrustResultDeny'),
    );

    await expect(instance.checkTrust(ca, environment)).resolves.toMatchObject([
      { state: 'untrusted', target: 'default' },
    ]);
  });

  it('runs a user-domain install and verifies the login-keychain fingerprint', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const calls: string[][] = [];
    const instance = adapter(caCertPath, keychainPath, async (argv) => {
      calls.push(argv);
      if (argv[1] === 'list-keychains') return result(`"${keychainPath}"\n`);
      if (argv[1] === 'find-certificate') return result(ca);
      return result();
    });

    await expect(instance.install(caCertPath, 'default')).resolves.toEqual({
      state: 'verified',
    });
    expect(calls).toEqual([
      ['security', 'list-keychains', '-d', 'user'],
      [
        'security',
        'add-trusted-cert',
        '-r',
        'trustRoot',
        '-p',
        'ssl',
        '-k',
        keychainPath,
        caCertPath,
      ],
      [
        'security',
        'find-certificate',
        '-a',
        '-c',
        'certkit development CA',
        '-p',
        keychainPath,
      ],
    ]);
  });

  it('refuses install when the login keychain is absent from the user list', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const calls: string[][] = [];
    const instance = adapter(caCertPath, keychainPath, async (argv) => {
      calls.push(argv);
      return result('"/other/login.keychain-db"\n');
    });

    await expect(instance.install(caCertPath, 'default')).rejects.toMatchObject(
      {
        code: 'STORE_WRITE_FAILED',
        message: expect.stringContaining(keychainPath),
      },
    );
    expect(calls).toEqual([['security', 'list-keychains', '-d', 'user']]);
  });

  it('refuses install before commands when the login keychain file is absent', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    await rm(keychainPath);
    let calls = 0;
    const instance = adapter(caCertPath, keychainPath, async () => {
      calls++;
      return result();
    });

    await expect(instance.install(caCertPath, 'default')).rejects.toMatchObject(
      {
        code: 'STORE_WRITE_FAILED',
        message: expect.stringContaining('unavailable'),
      },
    );
    expect(calls).toBe(0);
  });

  it('keeps install pending when add fails even if the certificate is present', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const calls: string[][] = [];
    const instance = adapter(caCertPath, keychainPath, async (argv) => {
      calls.push(argv);
      if (argv[1] === 'list-keychains') return result(`"${keychainPath}"\n`);
      if (argv[1] === 'add-trusted-cert')
        return result('', 1, 'native authentication denied');
      return result(ca);
    });

    await expect(instance.install(caCertPath, 'default')).rejects.toMatchObject(
      {
        code: 'STORE_WRITE_FAILED',
      },
    );
    expect(calls.map((argv) => argv[1])).toEqual([
      'list-keychains',
      'add-trusted-cert',
    ]);
  });

  it('keeps a successful add inconclusive when fingerprint read-back is unavailable', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const instance = adapter(caCertPath, keychainPath, async (argv) =>
      argv[1] === 'list-keychains'
        ? result(`"${keychainPath}"\n`)
        : argv[1] === 'find-certificate'
          ? result('', 1, 'read failed')
          : result(),
    );

    await expect(
      instance.install(caCertPath, 'default'),
    ).resolves.toMatchObject({ state: 'inconclusive' });
  });

  it('keeps interrupted user trust export data private and outside the CA directory', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const caDir = dirname(caCertPath);
    let exportDir: string | undefined;
    let exportDirMode: number | undefined;
    const instance = adapter(caCertPath, keychainPath, async (argv) => {
      if (argv[1] === 'find-certificate') return result(ca);
      if (argv[1] === 'trust-settings-export') {
        const outputPath = argv.at(-1);
        if (!outputPath) throw new Error('missing export path');
        exportDir = dirname(outputPath);
        exportDirMode = statSync(exportDir).mode & 0o777;
        await writeFile(outputPath, '<plist><dict/></plist>');
        throw new Error('simulated interruption after export');
      }
      throw new Error(`unexpected command ${argv[1]}`);
    });

    await expect(instance.uninstall(ca, 'default')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
    });
    expect(exportDir).toBeDefined();
    expect(exportDir).not.toBe(caDir);
    if (process.platform !== 'win32')
      expect((exportDirMode ?? 0) & 0o077).toBe(0);
    expect(existsSync(exportDir ?? '')).toBe(false);
    expect(existsSync(caCertPath)).toBe(true);
  });

  it.each([
    'trust export',
    'trust removal',
    'certificate deletion',
    'deletion read-back',
  ])('gives manual recovery guidance after %s fails', async (failure) => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const sha1 = new X509Certificate(ca).fingerprint
      .replaceAll(':', '')
      .toLowerCase();
    let finds = 0;
    const instance = adapter(caCertPath, keychainPath, async (argv) => {
      if (argv[1] === 'find-certificate') {
        finds++;
        if (failure === 'deletion read-back' && finds === 2)
          return result('', 1, 'keychain read failed');
        return result(ca);
      }
      if (argv[1] === 'trust-settings-export') {
        if (failure === 'trust export')
          return result('', 1, 'trust settings unavailable');
        if (failure === 'trust removal') {
          const outputPath = argv.at(-1);
          if (!outputPath) throw new Error('missing export path');
          await writeFile(
            outputPath,
            `<plist><dict><key>${sha1}</key><dict/></dict></plist>`,
          );
          return result();
        }
        return result('', 1, 'No Trust Settings were found');
      }
      if (argv[1] === 'remove-trusted-cert')
        return result('', 1, 'native authentication denied');
      if (argv[1] === 'delete-certificate')
        return failure === 'certificate deletion'
          ? result('', 1, 'native authentication denied')
          : result();
      throw new Error(`unexpected command ${argv[1]}`);
    });

    await expect(instance.uninstall(ca, 'default')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('certkit uninstall --dry-run'),
    });
  });

  it('removes only user trust and the exact login-keychain fingerprint without search-list membership', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const identity = new X509Certificate(ca);
    const sha1 = identity.fingerprint.replaceAll(':', '').toLowerCase();
    const sha256 = identity.fingerprint256.replaceAll(':', '').toLowerCase();
    const calls: string[][] = [];
    const otherKeychain = join(dirname(keychainPath), 'other.keychain-db');
    let userTrust = true;
    let loginCert = true;
    let otherCert = true;
    const instance = adapter(caCertPath, keychainPath, async (argv) => {
      calls.push(argv);
      if (argv[1] === 'trust-settings-export') {
        const outputPath = argv.at(-1);
        if (!outputPath) throw new Error('missing export path');
        await writeFile(
          outputPath,
          userTrust
            ? `<plist><dict><key>${sha1}</key><dict/></dict></plist>`
            : '<plist><dict/></plist>',
        );
        return result();
      }
      if (argv[1] === 'find-certificate')
        return result(
          argv.at(-1) === keychainPath && loginCert
            ? ca
            : argv.at(-1) === otherKeychain && otherCert
              ? ca
              : '',
        );
      if (argv[1] === 'remove-trusted-cert') {
        userTrust = false;
        return result();
      }
      if (argv[1] === 'delete-certificate') {
        if (argv.at(-1) === keychainPath) loginCert = false;
        if (argv.at(-1) === otherKeychain) otherCert = false;
        return result();
      }
      throw new Error(`unexpected command ${argv[1]}`);
    });

    await instance.uninstall(ca, 'default');
    expect(calls.map((argv) => argv[1])).toEqual([
      'find-certificate',
      'trust-settings-export',
      'remove-trusted-cert',
      'trust-settings-export',
      'delete-certificate',
      'find-certificate',
    ]);
    expect(calls).toContainEqual([
      'security',
      'trust-settings-export',
      expect.stringContaining('certkit-trust-'),
    ]);
    expect(calls).toContainEqual([
      'security',
      'remove-trusted-cert',
      caCertPath,
    ]);
    expect(calls).toContainEqual([
      'security',
      'delete-certificate',
      '-Z',
      sha256,
      keychainPath,
    ]);
    expect(calls.some((argv) => argv.includes('-d'))).toBe(false);
    expect(calls.some((argv) => argv.includes(otherKeychain))).toBe(false);
    expect(otherCert).toBe(true);
  });

  it('rejects non-default targets before touching the keychain', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    let calls = 0;
    const instance = adapter(caCertPath, keychainPath, async () => {
      calls++;
      return result();
    });

    for (const act of [
      () => instance.inspectInstalled(ca, 'system'),
      () => instance.install(caCertPath, 'system'),
      () => instance.uninstall(ca, 'system'),
    ])
      await expect(act()).rejects.toMatchObject({
        code: 'STORE_WRITE_FAILED',
        message: expect.stringContaining('only supports target "default"'),
      });
    expect(calls).toBe(0);
  });

  it('inspects installed state by fingerprint without exporting trust settings', async () => {
    const { ca, other } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const present = adapter(caCertPath, keychainPath, async () => result(ca));
    await expect(present.inspectInstalled(ca, 'default')).resolves.toBe(
      'present',
    );

    const absent = adapter(caCertPath, keychainPath, async () => result(other));
    await expect(absent.inspectInstalled(ca, 'default')).resolves.toBe(
      'absent',
    );

    const unreadable = adapter(caCertPath, keychainPath, async () =>
      result('', 1, 'read failed'),
    );
    await expect(unreadable.inspectInstalled(ca, 'default')).resolves.toBe(
      'inconclusive',
    );

    await expect(
      present.inspectInstalled('not a pem', 'default'),
    ).resolves.toBe('inconclusive');
  });

  it('treats a malformed keychain certificate block as inconclusive', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const instance = adapter(caCertPath, keychainPath, async () =>
      result(
        '-----BEGIN CERTIFICATE-----\n###not-a-certificate###\n-----END CERTIFICATE-----',
      ),
    );

    await expect(instance.inspectInstalled(ca, 'default')).resolves.toBe(
      'inconclusive',
    );
  });

  it('reports unknown when the user keychain list fails or is malformed', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const expected = [
      {
        state: 'unknown',
        target: 'default',
        detail: expect.stringContaining('keychain list'),
      },
    ];

    const failed = adapter(caCertPath, keychainPath, async () =>
      result('', 1, 'list failed'),
    );
    await expect(failed.checkTrust(ca, environment)).resolves.toEqual(expected);

    const interiorQuote = adapter(caCertPath, keychainPath, async () =>
      result('"bad "quoted" path"'),
    );
    await expect(interiorQuote.checkTrust(ca, environment)).resolves.toEqual(
      expected,
    );

    const emptyPath = adapter(caCertPath, keychainPath, async () =>
      result('""'),
    );
    await expect(emptyPath.checkTrust(ca, environment)).resolves.toEqual(
      expected,
    );
  });

  it.skipIf(process.platform === 'win32')(
    'reports unknown when the login keychain exists but cannot be inspected',
    async () => {
      const { ca } = await certificates();
      const { caCertPath } = await fixture(ca);
      const lockedDir = join(dirname(caCertPath), 'locked');
      await mkdir(lockedDir);
      const keychainPath = join(lockedDir, 'login.keychain-db');
      await writeFile(keychainPath, 'fixture keychain');
      await chmod(lockedDir, 0o000);
      let calls = 0;
      const instance = adapter(caCertPath, keychainPath, async () => {
        calls++;
        return result();
      });

      try {
        await expect(instance.checkTrust(ca, environment)).resolves.toEqual([
          {
            state: 'unknown',
            target: 'default',
            detail: expect.stringContaining('could not be inspected'),
          },
        ]);
        expect(calls).toBe(0);
      } finally {
        await chmod(lockedDir, 0o700);
      }
    },
  );

  it('reports unknown when the CA file no longer matches the requested identity', async () => {
    const { ca, other } = await certificates();
    const { caCertPath, keychainPath } = await fixture(other);
    let calls = 0;
    const instance = adapter(caCertPath, keychainPath, async () => {
      calls++;
      return result();
    });

    await expect(instance.checkTrust(ca, environment)).resolves.toEqual([
      {
        state: 'unknown',
        target: 'default',
        detail: expect.stringContaining('does not match'),
      },
    ]);
    expect(calls).toBe(0);
  });

  it('reports not-detected when the login keychain file is absent', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    await rm(keychainPath);
    let calls = 0;
    const instance = adapter(caCertPath, keychainPath, async () => {
      calls++;
      return result();
    });

    await expect(instance.checkTrust(ca, environment)).resolves.toEqual([
      {
        state: 'not-detected',
        target: 'default',
        detail: expect.stringContaining('unavailable'),
      },
    ]);
    expect(calls).toBe(0);
  });

  it('reports unknown when the keychain certificate read fails', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const instance = adapter(caCertPath, keychainPath, async (argv) =>
      argv[1] === 'list-keychains'
        ? result(`"${keychainPath}"\n`)
        : result('', 1, 'read failed'),
    );

    await expect(instance.checkTrust(ca, environment)).resolves.toEqual([
      {
        state: 'unknown',
        target: 'default',
        detail: expect.stringContaining('inconclusive'),
      },
    ]);
  });

  it('reports unknown when the SSL policy result is neither success nor refusal', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const instance = adapter(caCertPath, keychainPath, async (argv) =>
      argv[1] === 'list-keychains'
        ? result(`"${keychainPath}"\n`)
        : argv[1] === 'find-certificate'
          ? result(ca)
          : result('', 1, 'errSecInternalComponent'),
    );

    await expect(instance.checkTrust(ca, environment)).resolves.toEqual([
      {
        state: 'unknown',
        target: 'default',
        detail: 'The default SSL trust result could not be established.',
      },
    ]);
  });

  it('reports unknown when the CA file cannot be read at all', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    await rm(caCertPath);
    let calls = 0;
    const instance = adapter(caCertPath, keychainPath, async () => {
      calls++;
      return result();
    });

    await expect(instance.checkTrust(ca, environment)).resolves.toEqual([
      {
        state: 'unknown',
        target: 'default',
        detail: expect.stringContaining('could not be established'),
      },
    ]);
    expect(calls).toBe(0);
  });

  it('refuses install when the user keychain list cannot be confirmed', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const instance = adapter(caCertPath, keychainPath, async () =>
      result('', 1, 'list failed'),
    );

    await expect(instance.install(caCertPath, 'default')).rejects.toMatchObject(
      {
        code: 'STORE_WRITE_FAILED',
        message: expect.stringContaining('not confirmed in'),
      },
    );
  });

  it('keeps a successful add inconclusive when the read-back command crashes', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const instance = adapter(caCertPath, keychainPath, async (argv) => {
      if (argv[1] === 'list-keychains') return result(`"${keychainPath}"\n`);
      if (argv[1] === 'find-certificate') throw new Error('security crashed');
      return result();
    });

    await expect(instance.install(caCertPath, 'default')).resolves.toEqual({
      state: 'inconclusive',
      detail: expect.stringContaining('read-back was unavailable'),
    });
  });

  it('fails install when the CA is absent after a successful add command', async () => {
    const { ca, other } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const instance = adapter(caCertPath, keychainPath, async (argv) => {
      if (argv[1] === 'list-keychains') return result(`"${keychainPath}"\n`);
      if (argv[1] === 'find-certificate') return result(other);
      return result();
    });

    await expect(instance.install(caCertPath, 'default')).rejects.toMatchObject(
      {
        code: 'STORE_WRITE_FAILED',
        message: expect.stringContaining('did not contain'),
      },
    );
  });

  it('wraps unexpected install failures without recovery guidance', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'certkit macos -'));
    tempDirs.push(dir);
    const missing = join(dir, 'missing-ca.pem');
    const instance = adapter(
      missing,
      join(dir, 'login.keychain-db'),
      async () => result(),
    );

    await expect(instance.install(missing, 'default')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('Could not verify'),
    });
  });

  it('retains recovery data when the CA file does not match the uninstall identity', async () => {
    const { ca, other } = await certificates();
    const { caCertPath, keychainPath } = await fixture(other);
    let calls = 0;
    const instance = adapter(caCertPath, keychainPath, async () => {
      calls++;
      return result();
    });

    await expect(instance.uninstall(ca, 'default')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('does not match'),
    });
    expect(calls).toBe(0);
  });

  it('retains recovery data when the login keychain cannot be read for uninstall', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const instance = adapter(caCertPath, keychainPath, async () =>
      result('', 1, 'read failed'),
    );

    await expect(instance.uninstall(ca, 'default')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining(
        'Could not read the macOS login keychain',
      ),
    });
  });

  it('retains recovery data when exported trust settings are unreadable', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const instance = adapter(caCertPath, keychainPath, async (argv) => {
      if (argv[1] === 'find-certificate') return result(ca);
      if (argv[1] === 'trust-settings-export') {
        const outputPath = argv.at(-1);
        if (!outputPath) throw new Error('missing export path');
        await writeFile(outputPath, 'not a plist at all');
        return result();
      }
      throw new Error(`unexpected command ${argv[1]}`);
    });

    await expect(instance.uninstall(ca, 'default')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('unreadable user trust settings'),
    });
  });

  it('retains recovery data when the user trust setting survives removal', async () => {
    const { ca } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const sha1 = new X509Certificate(ca).fingerprint
      .replaceAll(':', '')
      .toLowerCase();
    const instance = adapter(caCertPath, keychainPath, async (argv) => {
      if (argv[1] === 'find-certificate') return result(ca);
      if (argv[1] === 'trust-settings-export') {
        const outputPath = argv.at(-1);
        if (!outputPath) throw new Error('missing export path');
        await writeFile(
          outputPath,
          `<plist><dict><key>${sha1}</key><dict/></dict></plist>`,
        );
        return result();
      }
      if (argv[1] === 'remove-trusted-cert') return result();
      throw new Error(`unexpected command ${argv[1]}`);
    });

    await expect(instance.uninstall(ca, 'default')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('remains after removal'),
    });
  });

  it('skips certificate deletion when the login keychain never held the CA', async () => {
    const { ca, other } = await certificates();
    const { caCertPath, keychainPath } = await fixture(ca);
    const calls: string[][] = [];
    const instance = adapter(caCertPath, keychainPath, async (argv) => {
      calls.push(argv);
      if (argv[1] === 'find-certificate') return result(other);
      if (argv[1] === 'trust-settings-export')
        return result('', 1, 'No Trust Settings were found');
      throw new Error(`unexpected command ${argv[1]}`);
    });

    await expect(instance.uninstall(ca, 'default')).resolves.toBeUndefined();
    expect(calls.map((argv) => argv[1])).toEqual([
      'find-certificate',
      'trust-settings-export',
    ]);
  });
});
