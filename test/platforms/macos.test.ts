import { X509Certificate } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { mintCa } from '../../src/core/certgen.js';
import type { Environment } from '../../src/platforms/detect.js';
import { createMacosAdapter } from '../../src/platforms/macos.js';
import type { RunResult } from '../../src/platforms/run.js';

const systemKeychain = '/Library/Keychains/System.keychain';
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

async function certificates(): Promise<{ ca: string; other: string }> {
  return {
    ca: (await mintCa('fixture')).certPem,
    other: (await mintCa('fixture')).certPem,
  };
}

async function caPath(pem: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'certkit-macos-'));
  tempDirs.push(dir);
  const file = join(dir, "Certkit CA's $HOME.pem");
  await writeFile(file, pem);
  return file;
}

function pemBlocks(...certificates: string[]): string {
  return certificates.join('\n');
}

describe('macOS keychain adapter', () => {
  it('reports a missing macOS keychain as not-detected without running commands', async () => {
    let calls = 0;
    const adapter = createMacosAdapter({
      caCertPath: '/not-read-on-an-absent-store/ca.pem',
      run: async () => {
        calls++;
        return result();
      },
      elevate: async () => result(),
    });

    await expect(
      adapter.checkTrust('unused', {
        ...environment,
        stores: [{ store: 'macos-keychain', detected: false }],
      }),
    ).resolves.toEqual([{ state: 'not-detected', target: 'default' }]);
    expect(calls).toBe(0);
  });

  it('compares every default-keychain match by SHA-256 and verifies SSL trust', async () => {
    const { ca, other } = await certificates();
    const caCertPath = await caPath(ca);
    const calls: string[][] = [];
    const adapter = createMacosAdapter({
      caCertPath,
      run: async (argv) => {
        calls.push(argv);
        return argv[1] === 'find-certificate'
          ? result(pemBlocks(other, ca))
          : result('certificate verification successful');
      },
      elevate: async () => result(),
    });

    await expect(adapter.checkTrust(ca, environment)).resolves.toEqual([
      { state: 'trusted', target: 'default' },
    ]);
    expect(calls).toEqual([
      [
        'security',
        'find-certificate',
        '-a',
        '-c',
        'certkit development CA',
        '-p',
      ],
      ['security', 'verify-cert', '-c', caCertPath, '-p', 'ssl', '-l', '-L'],
    ]);
  });

  it('keeps same-subject different-fingerprint certificates from proving trust', async () => {
    const { ca, other } = await certificates();
    const caCertPath = await caPath(ca);
    const adapter = createMacosAdapter({
      caCertPath,
      run: async (argv) =>
        argv[1] === 'find-certificate'
          ? result(other)
          : result('certificate verification successful'),
      elevate: async () => result(),
    });

    await expect(adapter.checkTrust(ca, environment)).resolves.toEqual([
      {
        state: 'unknown',
        target: 'default',
        detail: expect.any(String),
      },
    ]);
  });

  it('reports a default-policy Never Trust result as untrusted', async () => {
    const { ca } = await certificates();
    const caCertPath = await caPath(ca);
    const adapter = createMacosAdapter({
      caCertPath,
      run: async (argv) =>
        argv[1] === 'find-certificate'
          ? result(ca)
          : result('', 1, 'SecTrustEvaluate result: kSecTrustResultDeny'),
      elevate: async () => result(),
    });

    await expect(adapter.checkTrust(ca, environment)).resolves.toMatchObject([
      { state: 'untrusted', target: 'default' },
    ]);
  });

  it('returns a verified install receipt only after a System-keychain fingerprint read-back', async () => {
    const { ca } = await certificates();
    const caCertPath = await caPath(ca);
    const calls: string[][] = [];
    const elevated: string[][] = [];
    const adapter = createMacosAdapter({
      caCertPath,
      run: async (argv) => {
        calls.push(argv);
        return result(ca);
      },
      elevate: async (argv) => {
        elevated.push(argv);
        return result();
      },
    });

    await expect(adapter.install(caCertPath, 'default')).resolves.toEqual({
      state: 'verified',
    });
    expect(elevated).toEqual([
      [
        'security',
        'add-trusted-cert',
        '-d',
        '-r',
        'trustRoot',
        '-k',
        systemKeychain,
        caCertPath,
      ],
    ]);
    expect(calls).toEqual([
      [
        'security',
        'find-certificate',
        '-a',
        '-c',
        'certkit development CA',
        '-p',
        systemKeychain,
      ],
    ]);
  });

  it('keeps an install pending when the System-keychain read-back is unavailable', async () => {
    const { ca } = await certificates();
    const caCertPath = await caPath(ca);
    const elevated: string[][] = [];
    const adapter = createMacosAdapter({
      caCertPath,
      run: async () => {
        throw new Error('read failed');
      },
      elevate: async (argv) => {
        elevated.push(argv);
        return result();
      },
    });

    await expect(adapter.install(caCertPath, 'default')).resolves.toMatchObject(
      {
        state: 'inconclusive',
      },
    );
    expect(elevated).toHaveLength(1);
  });

  it('removes admin trust before only the explicit System-keychain copy, then retries only what remains', async () => {
    const { ca } = await certificates();
    const caCertPath = await caPath(ca);
    const sha1 = new X509Certificate(ca).fingerprint.replaceAll(':', '');
    const sha256 = new X509Certificate(ca).fingerprint256
      .replaceAll(':', '')
      .toLowerCase();
    const elevated: string[][] = [];
    const finds: string[][] = [];
    let adminTrust = true;
    let systemCert = true;
    const loginKeychainCopy = true;
    let failDeleteOnce = true;
    const adapter = createMacosAdapter({
      caCertPath,
      run: async (argv) => {
        if (argv[1] === 'trust-settings-export') {
          const outputPath = argv[argv.length - 1];
          if (!outputPath) throw new Error('missing export path');
          await writeFile(
            outputPath,
            adminTrust
              ? `<plist><dict><key>${sha1}</key><dict/></dict></plist>`
              : '<plist><dict/></plist>',
          );
          return result();
        }
        if (argv[1] === 'find-certificate') {
          finds.push(argv);
          return result(
            argv.includes(systemKeychain)
              ? systemCert
                ? pemBlocks(ca)
                : ''
              : loginKeychainCopy
                ? pemBlocks(ca)
                : '',
          );
        }
        throw new Error(`unexpected command ${argv[1]}`);
      },
      elevate: async (argv) => {
        elevated.push(argv);
        if (argv[1] === 'remove-trusted-cert') adminTrust = false;
        if (argv[1] === 'delete-certificate' && failDeleteOnce) {
          failDeleteOnce = false;
          return result('', 1, 'fixture failure');
        }
        if (argv[1] === 'delete-certificate') systemCert = false;
        return result();
      },
    });

    await expect(adapter.uninstall(ca, 'default')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
    });
    expect(elevated).toEqual([
      ['security', 'remove-trusted-cert', '-d', caCertPath],
      ['security', 'delete-certificate', '-Z', sha256, systemKeychain],
    ]);

    await adapter.uninstall(ca, 'default');
    expect(elevated).toHaveLength(3);
    expect(elevated[2]).toEqual(elevated[1]);
    expect(finds.every((argv) => argv.at(-1) === systemKeychain)).toBe(true);

    await adapter.uninstall(ca, 'default');
    expect(elevated).toHaveLength(3);
  });
});
