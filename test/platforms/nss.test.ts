import { X509Certificate } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mintCa } from '../../src/core/certgen.js';
import type { Environment } from '../../src/platforms/detect.js';
import {
  createNssAdapter,
  nssCertificateNickname,
} from '../../src/platforms/nss.js';
import type { RunResult } from '../../src/platforms/run.js';

// The adapter's default certutil resolution must not depend on the host;
// every adapter that omits resolveCertutil behaves as if certutil is absent.
vi.mock('../../src/platforms/run.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/platforms/run.js')>()),
  resolveNssCertutil: async () => null,
}));

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

function headerOnly(nickname: string): string {
  return listing(nickname).split(nickname)[0] ?? '';
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

describe('NSS store adapter edge cases', () => {
  it('reports not-detected when no nss store or no install targets exist', async () => {
    const { ca } = await fixture();
    const calls: string[][] = [];
    const instance = adapter(async (argv) => {
      calls.push(argv);
      return result();
    });
    const noStore: Environment = { os: 'linux', wsl: false, stores: [] };

    await expect(instance.checkTrust(ca, noStore)).resolves.toEqual([
      { state: 'not-detected', target: 'default' },
    ]);
    await expect(instance.checkTrust(ca, environment())).resolves.toEqual([
      { state: 'not-detected', target: 'default' },
    ]);
    expect(calls).toEqual([]);
  });

  it('reports unknown trust with manual guidance when certutil cannot be resolved', async () => {
    const { ca } = await fixture();
    const calls: string[][] = [];
    const instance = createNssAdapter({
      run: async (argv) => {
        calls.push(argv);
        return result();
      },
      fs: { mkdir: async () => {}, hasDatabaseFile: () => true },
    });

    await expect(
      instance.checkTrust(ca, environment('/profile')),
    ).resolves.toEqual([
      {
        state: 'unknown',
        target: '/profile',
        detail: expect.stringContaining('manually'),
      },
    ]);
    expect(calls).toEqual([]);
  });

  it('maps unreadable or ambiguous database responses to unknown per target', async () => {
    const { ca, other } = await fixture();
    const nickname = nssCertificateNickname(ca);
    const generic = 'The NSS database could not be inspected.';
    const dumps: Record<string, RunResult> = {
      '/t/dump-fails': result('', 1),
      '/t/dump-unreadable': result('garbage'),
      '/t/dump-invalid-pem': result(
        '-----BEGIN CERTIFICATE-----\nnotbase64!!\n-----END CERTIFICATE-----',
      ),
      '/t/no-match': result(other),
      '/t/two-matches': result(`${ca}\n${ca}`),
    };
    const listings: Record<string, RunResult> = {
      '/t/list-fails': result('', 1),
      '/t/list-unreadable': result('no recognizable header'),
      '/t/list-ambiguous': result(`${listing(nickname)}\n${nickname} C,,`),
    };
    const targets = [
      '/t/list-fails',
      '/t/list-unreadable',
      '/t/list-ambiguous',
      '/t/dump-fails',
      '/t/dump-unreadable',
      '/t/dump-invalid-pem',
      '/t/no-match',
      '/t/two-matches',
    ];
    const instance = adapter(async (argv) => {
      const target = (argv[argv.indexOf('-d') + 1] ?? '').replace('sql:', '');
      if (argv.includes('-n')) return dumps[target] ?? result(ca);
      return listings[target] ?? result(listing(nickname));
    });

    await expect(
      instance.checkTrust(ca, environment(...targets)),
    ).resolves.toEqual([
      { state: 'unknown', target: '/t/list-fails', detail: generic },
      { state: 'unknown', target: '/t/list-unreadable', detail: generic },
      { state: 'unknown', target: '/t/list-ambiguous', detail: generic },
      { state: 'unknown', target: '/t/dump-fails', detail: generic },
      { state: 'unknown', target: '/t/dump-unreadable', detail: generic },
      { state: 'unknown', target: '/t/dump-invalid-pem', detail: generic },
      { state: 'untrusted', target: '/t/no-match' },
      { state: 'unknown', target: '/t/two-matches', detail: generic },
    ]);
  });

  it('inspects installed state from listing rows and dumped fingerprints', async () => {
    const { ca, other } = await fixture();
    const nickname = nssCertificateNickname(ca);
    const dumpFor = (dump: RunResult) =>
      adapter(async (argv) =>
        argv.includes('-n') ? dump : result(listing(nickname)),
      );

    const listFails = adapter(async () => result('', 1));
    await expect(listFails.inspectInstalled(ca, '/p')).resolves.toBe(
      'inconclusive',
    );

    const unreadable = adapter(async () => result('no recognizable header'));
    await expect(unreadable.inspectInstalled(ca, '/p')).resolves.toBe(
      'inconclusive',
    );

    const ambiguous = adapter(async () =>
      result(`${listing(nickname)}\n${nickname} C,,`),
    );
    await expect(ambiguous.inspectInstalled(ca, '/p')).resolves.toBe(
      'inconclusive',
    );

    await expect(
      dumpFor(result('', 1)).inspectInstalled(ca, '/p'),
    ).resolves.toBe('inconclusive');
    await expect(
      dumpFor(result('garbage')).inspectInstalled(ca, '/p'),
    ).resolves.toBe('inconclusive');
    await expect(dumpFor(result(ca)).inspectInstalled(ca, '/p')).resolves.toBe(
      'present',
    );
    await expect(
      dumpFor(result(other)).inspectInstalled(ca, '/p'),
    ).resolves.toBe('inconclusive');
    await expect(
      dumpFor(result(`${ca}\n${ca}`)).inspectInstalled(ca, '/p'),
    ).resolves.toBe('inconclusive');

    const exploding = adapter(async () => {
      throw new Error('spawn exploded');
    });
    await expect(exploding.inspectInstalled(ca, '/p')).resolves.toBe(
      'inconclusive',
    );
  });

  it('uses the real filesystem to detect database files and create directories', async () => {
    const { dir, ca } = await fixture();
    const caPath = join(dir, 'ca.pem');
    await writeFile(caPath, ca);
    const nickname = nssCertificateNickname(ca);
    const cert9Dir = join(dir, 'nine');
    const cert8Dir = join(dir, 'eight');
    await mkdir(cert9Dir, { recursive: true });
    await mkdir(cert8Dir, { recursive: true });
    await writeFile(join(cert9Dir, 'cert9.db'), '');
    await writeFile(join(cert8Dir, 'cert8.db'), '');

    const calls: string[][] = [];
    let added = false;
    const target = join(dir, 'fresh', 'nssdb');
    const instance = createNssAdapter({
      resolveCertutil: async () => certutil,
      run: async (argv) => {
        calls.push(argv);
        if (argv[1] === '-A') {
          added = true;
          return result();
        }
        if (argv.includes('-n')) return result(added ? ca : '', added ? 0 : 1);
        return result(added ? listing(nickname) : headerOnly(nickname));
      },
    });

    await expect(instance.inspectInstalled(ca, cert9Dir)).resolves.toBe(
      'absent',
    );
    await expect(instance.inspectInstalled(ca, cert8Dir)).resolves.toBe(
      'absent',
    );
    await expect(
      instance.inspectInstalled(ca, join(dir, 'empty')),
    ).resolves.toBe('absent');
    expect(calls).toEqual([[certutil, '-L', '-d', `sql:${cert9Dir}`]]);

    await expect(instance.install(caPath, target)).resolves.toEqual({
      state: 'verified',
    });
    expect(existsSync(target)).toBe(true);
  });

  it('fails the install when the database directory cannot be created', async () => {
    const { dir, ca } = await fixture();
    const caPath = join(dir, 'ca.pem');
    await writeFile(caPath, ca);
    const calls: string[][] = [];
    const instance = createNssAdapter({
      run: async (argv) => {
        calls.push(argv);
        return result();
      },
      resolveCertutil: async () => certutil,
      fs: {
        mkdir: async () => {
          throw new Error('EACCES: permission denied');
        },
        hasDatabaseFile: () => true,
      },
    });

    await expect(instance.install(caPath, '/profile')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('Could not initialize'),
    });
    expect(calls).toEqual([]);
  });

  it('preserves existing certificates when the prior database state cannot be cleared', async () => {
    const { dir, ca, other } = await fixture();
    const caPath = join(dir, 'ca.pem');
    await writeFile(caPath, ca);
    const nickname = nssCertificateNickname(ca);

    // A failed prior listing is not evidence of a conflict; the import proceeds.
    let recoveredListings = 0;
    const recovered = adapter(async (argv) => {
      if (argv[1] === '-A') return result();
      if (argv.includes('-n')) return result(ca);
      recoveredListings += 1;
      return recoveredListings === 1
        ? result('', 1)
        : result(listing(nickname));
    });
    await expect(recovered.install(caPath, '/profile')).resolves.toEqual({
      state: 'verified',
    });

    const rejects = async (
      run: (argv: string[]) => Promise<RunResult>,
      message: string,
    ) => {
      const calls: string[][] = [];
      const instance = adapter(async (argv) => {
        calls.push(argv);
        return run(argv);
      });
      await expect(instance.install(caPath, '/profile')).rejects.toMatchObject({
        code: 'STORE_WRITE_FAILED',
        message: expect.stringContaining(message),
      });
      expect(calls.some((argv) => argv[1] === '-A')).toBe(false);
    };

    await rejects(async () => result('no recognizable header'), 'unreadable');
    await rejects(
      async () => result(`${listing(nickname)}\n${nickname} C,,`),
      'ambiguous',
    );
    await rejects(
      async (argv) =>
        argv.includes('-n') ? result(other) : result(listing(nickname)),
      'fingerprint',
    );
    await rejects(
      async (argv) =>
        argv.includes('-n') ? result('', 1) : result(listing(nickname)),
      'fingerprint',
    );
    await rejects(async (argv) => {
      if (argv[1] === '-D') return result('', 1);
      return argv.includes('-n') ? result(ca) : result(listing(nickname));
    }, 'idempotent retry');

    await rejects(async (argv) => {
      if (argv[1] === '-D') return result();
      if (argv.includes('-n')) return result(ca);
      return result(listing(nickname));
    }, 'could not be cleared');

    let failedListings = 0;
    await rejects(async (argv) => {
      if (argv[1] === '-D') return result();
      if (argv.includes('-n')) return result(ca);
      failedListings += 1;
      return failedListings === 1 ? result(listing(nickname)) : result('', 1);
    }, 'could not be cleared');

    let garbledListings = 0;
    await rejects(async (argv) => {
      if (argv[1] === '-D') return result();
      if (argv.includes('-n')) return result(ca);
      garbledListings += 1;
      return garbledListings === 1
        ? result(listing(nickname))
        : result('garbage');
    }, 'could not be cleared');
  });

  it('returns an inconclusive receipt when the import read-back cannot confirm trust', async () => {
    const { dir, ca, other } = await fixture();
    const caPath = join(dir, 'ca.pem');
    await writeFile(caPath, ca);
    const nickname = nssCertificateNickname(ca);

    // The first (pre-import) listing is always a clean database; the second
    // listing and the dump follow the scenario under test.
    const scenario = (postListing: RunResult, dump: RunResult) => {
      let listings = 0;
      return adapter(async (argv) => {
        if (argv[1] === '-A') return result();
        if (argv.includes('-n')) return dump;
        listings += 1;
        return listings === 1 ? result(headerOnly(nickname)) : postListing;
      });
    };
    const inconclusive = async (
      postListing: RunResult,
      dump: RunResult,
      detail: string,
    ) => {
      await expect(
        scenario(postListing, dump).install(caPath, '/profile'),
      ).resolves.toMatchObject({
        state: 'inconclusive',
        detail: expect.stringContaining(detail),
      });
    };

    await inconclusive(
      result('', 1),
      result(ca),
      'its read-back was unavailable',
    );
    await inconclusive(
      result(headerOnly(nickname)),
      result(ca),
      'one matching nickname',
    );
    await inconclusive(result('garbage'), result(ca), 'one matching nickname');
    await inconclusive(
      result(listing(nickname, ',C,')),
      result(ca),
      'one matching nickname',
    );
    await inconclusive(
      result(listing(nickname)),
      result('', 1),
      'certificate read-back was unavailable',
    );
    await inconclusive(
      result(listing(nickname)),
      result('garbage'),
      'did not confirm the CA fingerprint',
    );
    await inconclusive(
      result(listing(nickname)),
      result(other),
      'did not confirm the CA fingerprint',
    );
  });

  it('fails the install when the CA certificate file cannot be read', async () => {
    const { dir } = await fixture();
    const calls: string[][] = [];
    const instance = adapter(async (argv) => {
      calls.push(argv);
      return result();
    });

    await expect(
      instance.install(join(dir, 'missing.pem'), '/profile'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('Could not verify'),
    });
    expect(calls).toEqual([]);
  });

  it('keeps CA recovery data on every uninstall failure mode', async () => {
    const { ca } = await fixture();
    const nickname = nssCertificateNickname(ca);

    // None of these reach certutil -D.
    const rejectsBeforeDelete = async (
      run: (argv: string[]) => Promise<RunResult>,
      message: string,
    ) => {
      const calls: string[][] = [];
      const instance = adapter(async (argv) => {
        calls.push(argv);
        return run(argv);
      });
      await expect(instance.uninstall(ca, '/profile')).rejects.toMatchObject({
        code: 'STORE_WRITE_FAILED',
        message: expect.stringContaining(message),
      });
      expect(calls.some((argv) => argv[1] === '-D')).toBe(false);
    };

    await rejectsBeforeDelete(async () => result('', 1), 'Could not inspect');
    await rejectsBeforeDelete(
      async () => result('no recognizable header'),
      'unreadable',
    );
    await rejectsBeforeDelete(
      async (argv) =>
        argv.includes('-n') ? result('', 1) : result(listing(nickname)),
      'fingerprint',
    );
    await rejectsBeforeDelete(
      async (argv) =>
        argv.includes('-n') ? result('garbage') : result(listing(nickname)),
      'fingerprint',
    );
    await rejectsBeforeDelete(async () => {
      throw new Error('spawn exploded');
    }, 'Could not complete NSS CA removal');

    const deleteFails = adapter(async (argv) => {
      if (argv[1] === '-D') return result('', 1);
      return argv.includes('-n') ? result(ca) : result(listing(nickname));
    });
    await expect(deleteFails.uninstall(ca, '/profile')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('Could not remove'),
    });

    const stillListed = adapter(async (argv) => {
      if (argv[1] === '-D') return result();
      return argv.includes('-n') ? result(ca) : result(listing(nickname));
    });
    await expect(stillListed.uninstall(ca, '/profile')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('remains'),
    });

    let failedListings = 0;
    const verifyFails = adapter(async (argv) => {
      if (argv[1] === '-D') return result();
      if (argv.includes('-n')) return result(ca);
      failedListings += 1;
      return failedListings === 1 ? result(listing(nickname)) : result('', 1);
    });
    await expect(verifyFails.uninstall(ca, '/profile')).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('remains'),
    });

    let garbledListings = 0;
    const garbledVerify = adapter(async (argv) => {
      if (argv[1] === '-D') return result();
      if (argv.includes('-n')) return result(ca);
      garbledListings += 1;
      return garbledListings === 1
        ? result(listing(nickname))
        : result('garbage');
    });
    await expect(garbledVerify.uninstall(ca, '/profile')).rejects.toMatchObject(
      {
        code: 'STORE_WRITE_FAILED',
        message: expect.stringContaining('remains'),
      },
    );
  });

  it('treats uninstall as a no-op when the nickname is absent', async () => {
    const { ca } = await fixture();
    const nickname = nssCertificateNickname(ca);
    const calls: string[][] = [];
    const instance = adapter(async (argv) => {
      calls.push(argv);
      return result(headerOnly(nickname));
    });

    await expect(instance.uninstall(ca, '/profile')).resolves.toBeUndefined();
    expect(calls).toHaveLength(1);
    expect(calls[0]?.[1]).toBe('-L');
  });

  it('refuses writes to paths that resolve to /etc/pki/nssdb', async () => {
    const { dir, ca } = await fixture();
    const caPath = join(dir, 'ca.pem');
    await writeFile(caPath, ca);
    const calls: string[][] = [];
    const instance = adapter(async (argv) => {
      calls.push(argv);
      return result();
    });

    await expect(
      instance.install(caPath, '/etc/pki/../pki/nssdb'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('/etc/pki/nssdb'),
    });
    await expect(
      instance.uninstall(ca, '/pki/../etc/pki/nssdb'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('/etc/pki/nssdb'),
    });
    expect(calls).toEqual([]);
  });
});
