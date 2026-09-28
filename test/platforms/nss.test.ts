import { X509Certificate } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { mintCa } from '../../src/core/certgen.js';
import type { Environment } from '../../src/platforms/detect.js';
import {
  createNssAdapter,
  nssCertificateNickname,
} from '../../src/platforms/nss.js';
import type { RunResult } from '../../src/platforms/run.js';

const roots: string[] = [];
const certutil = '/fixture/nss/bin/certutil';
const result = (stdout = '', code = 0): RunResult => ({
  code,
  stdout,
  stderr: '',
});

function environment(...targets: string[]): Environment {
  return {
    os: 'linux',
    wsl: false,
    stores: [
      {
        store: 'nss',
        detected: targets.length > 0,
        targets,
        installTargets: targets,
      },
    ],
  };
}

async function fixture(): Promise<{ dir: string; ca: string; other: string }> {
  const dir = await mkdtemp(join(tmpdir(), 'certkit-nss-'));
  roots.push(dir);
  return {
    dir,
    ca: (await mintCa('fixture')).certPem,
    other: (await mintCa('fixture')).certPem,
  };
}

function listing(nickname: string, flags = 'C,,'): string {
  return `Certificate Nickname Trust Attributes\n                   SSL,S/MIME,JAR/XPI\n\n${nickname} ${flags}\n`;
}

function fingerprint(pem: string): string {
  return new X509Certificate(pem).fingerprint256
    .replaceAll(':', '')
    .toLowerCase();
}

const adapter = (run: (argv: string[]) => Promise<RunResult>) =>
  createNssAdapter({
    run,
    resolveCertutil: async () => certutil,
    fs: { mkdir: async () => {}, hasDatabaseFile: () => true },
  });

afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

describe('NSS store adapter', () => {
  it('checks each database by fingerprint and requires the SSL C bit', async () => {
    const { ca } = await fixture();
    const nickname = nssCertificateNickname(ca);
    const targets = ['/profile/firefox', '/home/chromium/nssdb'];
    const calls: string[][] = [];
    const instance = adapter(async (argv) => {
      calls.push(argv);
      if (argv.includes('-n')) return result(ca);
      return result(
        listing(nickname, argv.includes(`sql:${targets[1]}`) ? ',C,' : 'C,,'),
      );
    });

    await expect(
      instance.checkTrust(ca, environment(...targets)),
    ).resolves.toEqual([
      { state: 'trusted', target: targets[0] },
      {
        state: 'untrusted',
        target: targets[1],
        detail: 'present without SSL trust',
      },
    ]);
    expect(calls).toEqual(
      targets.flatMap((target) => [
        [certutil, '-L', '-d', `sql:${target}`],
        [certutil, '-L', '-n', nickname, '-d', `sql:${target}`, '-a'],
      ]),
    );
  });

  it('uses distinct fingerprint nicknames and removes only the matching certificate block', async () => {
    const { dir, ca, other } = await fixture();
    const caPath = join(dir, 'ca.pem');
    const otherPath = join(dir, 'other.pem');
    await writeFile(caPath, ca);
    await writeFile(otherPath, other);
    const target = join(dir, 'profile');
    const entries = new Map<string, string>();
    const calls: string[][] = [];
    const instance = adapter(async (argv) => {
      calls.push(argv);
      if (argv[1] === '-A') {
        entries.set(argv[3] ?? '', argv.at(-1) === caPath ? ca : other);
        return result();
      }
      if (argv[1] === '-D') {
        entries.delete(argv[3] ?? '');
        return result();
      }
      if (argv.includes('-n')) {
        const nickname = argv[argv.indexOf('-n') + 1] ?? '';
        const pem = entries.get(nickname);
        const dump =
          nickname === nssCertificateNickname(ca) ? `${other}\n${ca}` : pem;
        return result(dump ?? '', dump ? 0 : 1);
      }
      return result(
        `Certificate Nickname Trust Attributes\n                   SSL,S/MIME,JAR/XPI\n\n${[
          ...entries.keys(),
        ]
          .map((nickname) => `${nickname} C,,`)
          .join('\n')}`,
      );
    });

    await expect(instance.install(caPath, target)).resolves.toEqual({
      state: 'verified',
    });
    await expect(instance.install(otherPath, target)).resolves.toEqual({
      state: 'verified',
    });
    expect(nssCertificateNickname(ca)).not.toBe(nssCertificateNickname(other));
    expect(calls.filter((argv) => argv[1] === '-A')).toEqual([
      [
        certutil,
        '-A',
        '-n',
        nssCertificateNickname(ca),
        '-t',
        'C,,',
        '-d',
        `sql:${target}`,
        '-i',
        caPath,
      ],
      [
        certutil,
        '-A',
        '-n',
        nssCertificateNickname(other),
        '-t',
        'C,,',
        '-d',
        `sql:${target}`,
        '-i',
        otherPath,
      ],
    ]);

    await instance.uninstall(ca, target);
    expect(calls.at(-2)).toEqual([
      certutil,
      '-D',
      '-n',
      nssCertificateNickname(ca),
      '-d',
      `sql:${target}`,
    ]);
    expect(entries.has(nssCertificateNickname(ca))).toBe(false);
    expect(entries.has(nssCertificateNickname(other))).toBe(true);
    const remainingPem = entries.get(nssCertificateNickname(other));
    expect(remainingPem).toBeDefined();
    expect(fingerprint(remainingPem ?? '')).toBe(fingerprint(other));
  });

  it('refuses uninstall when a derived nickname is ambiguous', async () => {
    const { ca } = await fixture();
    const nickname = nssCertificateNickname(ca);
    const calls: string[][] = [];
    const instance = adapter(async (argv) => {
      calls.push(argv);
      return result(`${listing(nickname)}\n${nickname} C,,`);
    });

    await expect(instance.uninstall(ca, '/profile')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('ambiguous'),
    });
    expect(calls).toHaveLength(1);
  });

  it('refuses uninstall unless exactly one dumped PEM block matches the CA', async () => {
    const { ca, other } = await fixture();
    const nickname = nssCertificateNickname(ca);
    const calls: string[][] = [];
    const instance = adapter(async (argv) => {
      calls.push(argv);
      return argv.includes('-n')
        ? result(`${ca}\n${ca}`)
        : result(listing(nickname));
    });

    await expect(instance.uninstall(ca, '/profile')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('fingerprint'),
    });
    expect(calls.some((argv) => argv[1] === '-D')).toBe(false);

    const missingMatch = adapter(async (argv) =>
      argv.includes('-n') ? result(other) : result(listing(nickname)),
    );
    await expect(missingMatch.uninstall(ca, '/profile')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
    });
  });

  it('keeps a failed NSS import recoverable and gets a fresh receipt on retry', async () => {
    const { dir, ca } = await fixture();
    const caPath = join(dir, 'ca.pem');
    await writeFile(caPath, ca);
    const nickname = nssCertificateNickname(ca);
    const entries = new Map<string, string>();
    let failImport = true;
    const calls: string[][] = [];
    const instance = adapter(async (argv) => {
      calls.push(argv);
      if (argv[1] === '-A') {
        entries.set(nickname, ca);
        if (failImport) {
          failImport = false;
          return result('import reported a failure after writing the cert', 1);
        }
        return result();
      }
      if (argv[1] === '-D') {
        entries.delete(argv[argv.indexOf('-n') + 1] ?? '');
        return result();
      }
      if (argv.includes('-n')) return result(entries.get(nickname) ?? '');
      return result(
        entries.size ? listing(nickname) : listing(nickname).split(nickname)[0],
      );
    });

    await expect(instance.install(caPath, '/profile')).resolves.toMatchObject({
      state: 'inconclusive',
    });
    await expect(instance.install(caPath, '/profile')).resolves.toEqual({
      state: 'verified',
    });
    expect(calls.filter((argv) => argv[1] === '-A')).toHaveLength(2);
    expect(calls.slice(-3).map((argv) => argv[1])).toEqual(['-A', '-L', '-L']);
    expect(calls.some((argv) => argv[1] === '-D')).toBe(true);
  });

  it('initializes a prospective database directory before importing', async () => {
    const { dir, ca } = await fixture();
    const caPath = join(dir, 'ca.pem');
    await writeFile(caPath, ca);
    const target = join(dir, 'pki', 'nssdb');
    const created: Array<{ path: string; mode: number }> = [];
    const calls: string[][] = [];
    const nickname = nssCertificateNickname(ca);
    let initialized = false;
    let added = false;
    const instance = createNssAdapter({
      resolveCertutil: async () => certutil,
      fs: {
        async mkdir(path, options) {
          created.push({ path, mode: options.mode });
          initialized = true;
        },
        hasDatabaseFile: () => initialized && added,
      },
      async run(argv) {
        calls.push(argv);
        if (argv[1] === '-A') {
          if (!initialized) return result('', 255);
          added = true;
          return result();
        }
        if (argv.includes('-n')) return result(added ? ca : '', added ? 0 : 1);
        return result(
          added
            ? listing(nickname)
            : (listing(nickname).split(nickname)[0] ?? ''),
        );
      },
    });

    await expect(instance.install(caPath, target)).resolves.toEqual({
      state: 'verified',
    });
    expect(created).toEqual([{ path: target, mode: 0o700 }]);
  });

  it('treats an uninitialized database directory as absent so a retry can recover', async () => {
    const { dir, ca } = await fixture();
    const caPath = join(dir, 'ca.pem');
    await writeFile(caPath, ca);
    const target = join(dir, 'pki', 'nssdb');
    const calls: string[][] = [];
    const nickname = nssCertificateNickname(ca);
    let database = false;
    let added = false;
    const instance = createNssAdapter({
      resolveCertutil: async () => certutil,
      fs: {
        mkdir: async () => {
          database = true;
        },
        hasDatabaseFile: () => database,
      },
      async run(argv) {
        calls.push(argv);
        if (argv[1] === '-A') {
          database = true;
          added = true;
          return result();
        }
        if (argv[1] === '-D') {
          added = false;
          return result();
        }
        if (argv.includes('-n')) return result(added ? ca : '', added ? 0 : 1);
        return result(
          added
            ? listing(nickname)
            : (listing(nickname).split(nickname)[0] ?? ''),
        );
      },
    });

    await expect(instance.inspectInstalled(ca, target)).resolves.toBe('absent');
    expect(calls).toEqual([]);
    await expect(instance.install(caPath, target)).resolves.toEqual({
      state: 'verified',
    });
    expect(calls.some((argv) => argv[1] === '-A')).toBe(true);
  });

  it('never writes /etc/pki/nssdb and gives manual instructions when certutil is missing', async () => {
    const { dir, ca } = await fixture();
    const caPath = join(dir, 'ca.pem');
    await writeFile(caPath, ca);
    const calls: string[][] = [];
    const protectedTarget = adapter(async (argv) => {
      calls.push(argv);
      return result();
    });

    await expect(
      protectedTarget.install(caPath, '/etc/pki/nssdb'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
    });
    await expect(
      protectedTarget.uninstall(ca, '/etc/pki/nssdb'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
    });
    expect(calls).toEqual([]);

    const missing = createNssAdapter({
      run: async (argv) => {
        calls.push(argv);
        return result();
      },
      resolveCertutil: async () => null,
      fs: { mkdir: async () => {}, hasDatabaseFile: () => true },
    });
    await expect(missing.install(caPath, '/profile')).rejects.toMatchObject({
      code: 'UNSUPPORTED_PLATFORM',
      message: expect.stringContaining('manual'),
    });
    expect(calls).toEqual([]);
  });
});
