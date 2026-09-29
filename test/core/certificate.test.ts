import { X509Certificate as NodeX509Certificate, webcrypto } from 'node:crypto';
import fs, {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  type Stats,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import os, { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  type FsGuard,
  readState as readStateCore,
  withLock as withLockCore,
  writeStateAtomic as writeStateAtomicCore,
} from '../../src/core/cadir.js';
import {
  certificateFor as certificateForCore,
  certificateForLocked,
  ensureCaForInstallLocked,
  readCaForStatus,
  readCaForUninstallLocked,
} from '../../src/core/certificate.js';
import { CertkitError } from '../../src/core/errors.js';
import {
  type CertificateOptions,
  caDir,
  certificateFor,
} from '../../src/index.js';
import { createWindowsFsGuard } from '../../src/platforms/fsguard.js';

const DAY_MS = 86_400_000;
let tempRoot = '';
let dir = '';

function fileOptions(fsGuard?: FsGuard): { fsGuard?: FsGuard } {
  return process.platform === 'win32'
    ? { fsGuard: fsGuard ?? createWindowsFsGuard() }
    : fsGuard
      ? { fsGuard }
      : {};
}

function readState(path: string) {
  return readStateCore(path, fileOptions());
}

function writeStateAtomic(
  path: string,
  state: Parameters<typeof writeStateAtomicCore>[1],
): void {
  writeStateAtomicCore(path, state, fileOptions());
}

function withLock<T>(path: string, operation: () => Promise<T>): Promise<T> {
  return withLockCore(path, operation, fileOptions());
}

function cacheFiles() {
  const files = readdirSync(dir);
  const cert = files.find((name) => /^leaf-[a-f0-9]+\.pem$/.test(name));
  if (!cert) throw new Error('leaf certificate was not written');
  const stem = cert.slice(0, -4);
  return {
    cert: join(dir, cert),
    key: join(dir, `${stem}-key.pem`),
    meta: join(dir, `${stem}.meta.json`),
  };
}

function patchBuiltin<T extends object, K extends keyof T>(
  object: T,
  method: K,
  wrap: (original: T[K]) => T[K],
): () => void {
  const original = object[method];
  object[method] = wrap(original);
  syncBuiltinESMExports();
  return () => {
    object[method] = original;
    syncBuiltinESMExports();
  };
}

function foreignOwnerStat(): Stats {
  const uid = process.getuid?.() ?? 0;
  return {
    isSymbolicLink: () => false,
    isFile: () => true,
    uid: uid + 1,
    mode: 0o600,
  } as Stats;
}

function accessDenied(): Error & { code: string } {
  return Object.assign(new Error('access denied'), { code: 'EACCES' });
}

beforeEach(() => {
  tempRoot = mkdtempSync(join(tmpdir(), 'certkit-certificate-'));
  dir = join(tempRoot, 'ca');
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
  rmSync(tempRoot, { recursive: true, force: true });
});

describe('certificateFor', () => {
  it('creates a protected CA and leaf on first use', async () => {
    const result = await certificateFor(['localhost'], { caDir: dir });

    expect(result.cert).toContain('-----BEGIN CERTIFICATE-----');
    expect(result.key).toContain('-----BEGIN PRIVATE KEY-----');
    expect(result.caCert).toContain('-----BEGIN CERTIFICATE-----');
    expect(readState(dir)?.phase).toBe('active');
    expect(existsSync(join(dir, 'ca-key.pem'))).toBe(true);
    expect(existsSync(join(dir, 'ca-cert.pem'))).toBe(true);
    if (process.platform !== 'win32') {
      expect(lstatSync(join(dir, 'ca-key.pem')).mode & 0o777).toBe(0o600);
      expect(lstatSync(cacheFiles().key).mode & 0o777).toBe(0o600);
    }
  });

  it('returns the same certificate and key from a fresh cache entry', async () => {
    const first = await certificateFor(['localhost'], { caDir: dir });

    await expect(
      certificateFor(['localhost'], { caDir: dir }),
    ).resolves.toEqual(first);
  });

  it('uses a sorted, deduplicated, normalized name-set as the cache key', async () => {
    const first = await certificateFor(
      ['MÜNICH.test', 'localhost', 'localhost'],
      { caDir: dir },
    );

    await expect(
      certificateFor(['localhost', 'xn--mnich-kva.test'], { caDir: dir }),
    ).resolves.toEqual(first);
  });

  it('mints a different certificate for a different name-set', async () => {
    const first = await certificateFor(['one.test'], { caDir: dir });
    const second = await certificateFor(['two.test'], { caDir: dir });

    expect(second.cert).not.toBe(first.cert);
    expect(second.key).not.toBe(first.key);
    expect(second.caCert).toBe(first.caCert);
  });

  it('regenerates a cache entry when validityDays changes', async () => {
    const first = await certificateFor(['localhost'], {
      caDir: dir,
      validityDays: 30,
    });
    const second = await certificateFor(['localhost'], {
      caDir: dir,
      validityDays: 31,
    });

    expect(second.cert).not.toBe(first.cert);
    expect(second.key).not.toBe(first.key);
  });

  it('renews a 60-day leaf with less than 30 days remaining', async () => {
    vi.useFakeTimers();
    const first = await certificateFor(['localhost'], {
      caDir: dir,
      validityDays: 60,
    });
    const meta = JSON.parse(readFileSync(cacheFiles().meta, 'utf8')) as {
      expiresAt: string;
    };
    vi.setSystemTime(Date.parse(meta.expiresAt) - 29 * DAY_MS);

    const second = await certificateFor(['localhost'], {
      caDir: dir,
      validityDays: 60,
    });

    expect(second.cert).not.toBe(first.cert);
  });

  it('keeps a 7-day leaf cached with 6 days remaining', async () => {
    vi.useFakeTimers();
    const first = await certificateFor(['localhost'], {
      caDir: dir,
      validityDays: 7,
    });
    const meta = JSON.parse(readFileSync(cacheFiles().meta, 'utf8')) as {
      expiresAt: string;
    };
    vi.setSystemTime(Date.parse(meta.expiresAt) - 6 * DAY_MS);

    await expect(
      certificateFor(['localhost'], { caDir: dir, validityDays: 7 }),
    ).resolves.toEqual(first);
  });

  it.each([0, 1.5, Number.NaN, 826])(
    'rejects invalid validityDays %s before creating the CA directory',
    async (validityDays) => {
      await expect(
        certificateFor(['localhost'], { caDir: dir, validityDays }),
      ).rejects.toMatchObject({ code: 'INVALID_OPTIONS' });
      expect(existsSync(dir)).toBe(false);
    },
  );

  it('rejects an empty name list before creating the CA directory', async () => {
    await expect(certificateFor([], { caDir: dir })).rejects.toMatchObject({
      code: 'INVALID_NAME',
    });
    expect(existsSync(dir)).toBe(false);
  });

  it('rejects invalid names before creating the CA directory', async () => {
    await expect(
      certificateFor(['invalid name'], { caDir: dir }),
    ).rejects.toMatchObject({ code: 'INVALID_NAME' });
    expect(existsSync(dir)).toBe(false);
  });

  it.each([
    [
      'missing leaf certificate',
      (files: ReturnType<typeof cacheFiles>) => unlinkSync(files.cert),
    ],
    [
      'missing leaf key',
      (files: ReturnType<typeof cacheFiles>) => unlinkSync(files.key),
    ],
    [
      'missing metadata',
      (files: ReturnType<typeof cacheFiles>) => unlinkSync(files.meta),
    ],
    [
      'corrupt leaf certificate',
      (files: ReturnType<typeof cacheFiles>) =>
        writeFileSync(files.cert, 'bad certificate', { mode: 0o600 }),
    ],
    [
      'corrupt leaf key',
      (files: ReturnType<typeof cacheFiles>) =>
        writeFileSync(files.key, 'bad key', { mode: 0o600 }),
    ],
    [
      'mismatched metadata names',
      (files: ReturnType<typeof cacheFiles>) => {
        const meta = JSON.parse(readFileSync(files.meta, 'utf8')) as Record<
          string,
          unknown
        >;
        writeFileSync(
          files.meta,
          JSON.stringify({ ...meta, names: ['other.test'] }),
          { mode: 0o600 },
        );
      },
    ],
    [
      'mismatched metadata validity',
      (files: ReturnType<typeof cacheFiles>) => {
        const meta = JSON.parse(readFileSync(files.meta, 'utf8')) as Record<
          string,
          unknown
        >;
        writeFileSync(
          files.meta,
          JSON.stringify({ ...meta, validityDays: 30 }),
          { mode: 0o600 },
        );
      },
    ],
    [
      'mismatched metadata expiry',
      (files: ReturnType<typeof cacheFiles>) => {
        const meta = JSON.parse(readFileSync(files.meta, 'utf8')) as Record<
          string,
          unknown
        >;
        writeFileSync(
          files.meta,
          JSON.stringify({ ...meta, expiresAt: '2030-01-01T00:00:00.000Z' }),
          { mode: 0o600 },
        );
      },
    ],
  ])('regenerates only the leaf for %s', async (_description, damage) => {
    const first = await certificateFor(['localhost'], { caDir: dir });
    const caKey = readFileSync(join(dir, 'ca-key.pem'));
    const caCert = readFileSync(join(dir, 'ca-cert.pem'));
    const state = readFileSync(join(dir, 'state.json'));
    damage(cacheFiles());

    const second = await certificateFor(['localhost'], { caDir: dir });

    expect(second.cert).not.toBe(first.cert);
    expect(readFileSync(join(dir, 'ca-key.pem'))).toEqual(caKey);
    expect(readFileSync(join(dir, 'ca-cert.pem'))).toEqual(caCert);
    expect(readFileSync(join(dir, 'state.json'))).toEqual(state);
  });

  it('regenerates a leaf whose private key does not match its certificate', async () => {
    const first = await certificateFor(['localhost'], { caDir: dir });
    const other = await certificateFor(['localhost'], {
      caDir: join(tempRoot, 'other-ca'),
    });
    writeFileSync(cacheFiles().key, other.key, { mode: 0o600 });

    const second = await certificateFor(['localhost'], { caDir: dir });

    expect(second.cert).not.toBe(first.cert);
    expect(second.key).not.toBe(other.key);
  });

  it.skipIf(process.platform === 'win32')(
    'preserves a symlinked leaf cache target and fails closed',
    async () => {
      await certificateFor(['localhost'], { caDir: dir });
      const files = cacheFiles();
      const sentinel = join(tempRoot, 'sentinel.pem');
      writeFileSync(sentinel, 'outside bytes', { mode: 0o600 });
      unlinkSync(files.cert);
      symlinkSync(sentinel, files.cert);

      await expect(
        certificateFor(['localhost'], { caDir: dir }),
      ).rejects.toMatchObject({ code: 'CA_UNREADABLE' });
      expect(lstatSync(files.cert).isSymbolicLink()).toBe(true);
      expect(readFileSync(sentinel, 'utf8')).toBe('outside bytes');
    },
  );

  it.each(['ca-key.pem', 'ca-cert.pem'])(
    'fails closed and preserves CA files when %s is corrupt',
    async (filename) => {
      await certificateFor(['localhost'], { caDir: dir });
      writeFileSync(join(dir, filename), 'corrupt CA material', {
        mode: 0o600,
      });
      const before = ['ca-key.pem', 'ca-cert.pem', 'state.json'].map((name) =>
        readFileSync(join(dir, name)),
      );

      await expect(
        certificateFor(['another.test'], { caDir: dir }),
      ).rejects.toMatchObject({ code: 'CA_UNREADABLE' });
      expect(
        ['ca-key.pem', 'ca-cert.pem', 'state.json'].map((name) =>
          readFileSync(join(dir, name)),
        ),
      ).toEqual(before);
    },
  );

  it('instructs the caller to use certkit uninstall for a retiring CA', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    const state = readState(dir);
    if (!state) throw new Error('CA state was not written');
    writeStateAtomic(dir, { ...state, phase: 'retiring' });
    const caKey = readFileSync(join(dir, 'ca-key.pem'));
    const caCert = readFileSync(join(dir, 'ca-cert.pem'));

    await expect(
      certificateFor(['localhost'], { caDir: dir }),
    ).rejects.toMatchObject({
      code: 'CA_UNREADABLE',
      message: expect.stringContaining('certkit uninstall'),
    });
    expect(readFileSync(join(dir, 'ca-key.pem'))).toEqual(caKey);
    expect(readFileSync(join(dir, 'ca-cert.pem'))).toEqual(caCert);
  });

  it('restarts safely from an interrupted initializing state', async () => {
    const first = await certificateFor(['localhost'], { caDir: dir });
    const state = readState(dir);
    if (!state) throw new Error('CA state was not written');
    writeStateAtomic(dir, { ...state, phase: 'initializing' });
    unlinkSync(join(dir, 'ca-cert.pem'));

    const recovered = await certificateFor(['localhost'], { caDir: dir });

    expect(recovered.caCert).not.toBe(first.caCert);
    expect(readState(dir)?.phase).toBe('active');
  });

  it('serializes concurrent identical requests into one cached leaf', async () => {
    const [first, second] = await Promise.all([
      certificateFor(['localhost'], { caDir: dir }),
      certificateFor(['localhost'], { caDir: dir }),
    ]);

    expect(second).toEqual(first);
  });

  it('lets the locked core run under one already-held lock', async () => {
    const result = await withLock(dir, () =>
      certificateForLocked(
        [{ kind: 'dns', ascii: 'localhost' }],
        { validityDays: 825 },
        { dir, ...fileOptions() },
      ),
    );

    expect(result.cert).toContain('-----BEGIN CERTIFICATE-----');
    expect(existsSync(join(dir, '.lock'))).toBe(false);
  });

  it('removes stale protected temp files before reusing the cache', async () => {
    const first = await certificateFor(['localhost'], { caDir: dir });
    const stale = [
      '.certkit-00000000-0000-4000-8000-000000000000.tmp',
      '.leaf-key-00000000-0000-4000-8000-000000000000.tmp',
      '.state-00000000-0000-4000-8000-000000000000.tmp',
    ].map((name) => join(dir, name));
    for (const path of stale)
      writeFileSync(path, 'stale temp', { mode: 0o600 });

    await expect(
      certificateFor(['localhost'], { caDir: dir }),
    ).resolves.toEqual(first);

    expect(stale.some((path) => existsSync(path))).toBe(false);
  });

  it('protects the directory before creating CA and leaf keys', async () => {
    const events: string[] = [];
    let protectedBeforeKey = false;
    const guard: FsGuard = {
      protectDirectory(path) {
        events.push(`protect:${path}`);
        if (!existsSync(join(path, 'ca-key.pem'))) protectedBeforeKey = true;
      },
      assertProtectedDirectory(path) {
        events.push(`assert-directory:${path}`);
      },
      assertProtectedFile(path) {
        events.push(`assert-file:${path}`);
      },
    };

    await certificateForCore(['localhost'], { caDir: dir }, { fsGuard: guard });

    expect(events[0]).toBe(`protect:${dir}`);
    expect(protectedBeforeKey).toBe(true);
    expect(events).toContain(`assert-file:${join(dir, 'ca-key.pem')}`);
    expect(events.some((event) => event.includes('.leaf-key-'))).toBe(true);
  });
});

describe('caDir', () => {
  it('resolves a CA path without creating it', () => {
    const path = join(tempRoot, 'absent');

    expect(caDir({ caDir: path })).toBe(path);
    expect(existsSync(path)).toBe(false);
  });

  it.each([null, 'ca-dir', []])(
    'rejects non-object caDir options (%s)',
    (options) => {
      expect(() =>
        caDir(options as unknown as { caDir?: string }),
      ).toThrowError(
        expect.objectContaining({
          code: 'INVALID_OPTIONS',
          message: 'caDir options must be an object.',
        }),
      );
    },
  );

  it('rejects a non-string caDir override', () => {
    expect(() =>
      caDir({ caDir: 42 } as unknown as { caDir?: string }),
    ).toThrowError(
      expect.objectContaining({
        code: 'INVALID_OPTIONS',
        message: 'caDir must be a string when provided.',
      }),
    );
  });
});

describe('certificateFor input validation', () => {
  it.each([null, 'ca-dir', []])(
    'rejects non-object certificate options (%s)',
    async (options) => {
      await expect(
        certificateFor(['localhost'], options as unknown as CertificateOptions),
      ).rejects.toMatchObject({
        code: 'INVALID_OPTIONS',
        message: 'Certificate options must be an object.',
      });
      expect(existsSync(dir)).toBe(false);
    },
  );

  it('rejects a non-string caDir option', async () => {
    await expect(
      certificateFor(['localhost'], {
        caDir: 42,
      } as unknown as CertificateOptions),
    ).rejects.toMatchObject({
      code: 'INVALID_OPTIONS',
      message: 'caDir must be a string when provided.',
    });
    expect(existsSync(dir)).toBe(false);
  });

  it.each(['localhost', [1], [['localhost']]])(
    'rejects names that are not an array of strings (%s)',
    async (names) => {
      await expect(
        certificateFor(names as unknown as string[], { caDir: dir }),
      ).rejects.toMatchObject({
        code: 'INVALID_NAME',
        message: 'Names must be an array of strings.',
      });
      expect(existsSync(dir)).toBe(false);
    },
  );

  it('resolves the default CA directory from CERTKIT_HOME', async () => {
    vi.stubEnv('CERTKIT_HOME', dir);

    const result = await certificateFor(['localhost']);

    expect(result.cert).toContain('-----BEGIN CERTIFICATE-----');
    expect(readState(dir)?.phase).toBe('active');
  });

  it('normalizes IP names into a canonical cache key', async () => {
    const first = await certificateFor(['127.0.0.1', '::1'], { caDir: dir });

    await expect(
      certificateFor(['::1', '127.0.0.1'], { caDir: dir }),
    ).resolves.toEqual(first);
  });

  it('defaults the locked leaf validity to the maximum', async () => {
    const result = await withLock(dir, () =>
      certificateForLocked(
        [{ kind: 'dns', ascii: 'localhost' }],
        {},
        { dir, ...fileOptions() },
      ),
    );

    expect(result.cert).toContain('-----BEGIN CERTIFICATE-----');
    const meta = JSON.parse(readFileSync(cacheFiles().meta, 'utf8')) as {
      validityDays: number;
    };
    expect(meta.validityDays).toBe(825);
  });
});

describe('CA identity marker', () => {
  it('falls back to environment markers when user info is unavailable', async () => {
    const restore = patchBuiltin(
      os,
      'userInfo',
      () =>
        (() => {
          throw new Error('no user database');
        }) as typeof os.userInfo,
    );
    vi.stubEnv('USER', '');
    vi.stubEnv('USERNAME', '');
    try {
      const result = await certificateFor(['localhost'], { caDir: dir });
      expect(result.cert).toContain('-----BEGIN CERTIFICATE-----');
      expect(readState(dir)?.ca.subject).toContain('OU=user');
    } finally {
      restore();
    }
  });

  it('uses the USER environment marker when the username is empty', async () => {
    const restore = patchBuiltin(
      os,
      'userInfo',
      () => (() => ({ username: '' })) as typeof os.userInfo,
    );
    vi.stubEnv('USER', 'envuser');
    try {
      await certificateFor(['localhost'], { caDir: dir });
      expect(readState(dir)?.ca.subject).toContain('OU=envuser');
    } finally {
      restore();
    }
  });

  it('falls back to a generic marker when no username is available', async () => {
    const restore = patchBuiltin(
      os,
      'userInfo',
      () => (() => ({ username: '' })) as typeof os.userInfo,
    );
    vi.stubEnv('USER', '');
    vi.stubEnv('USERNAME', '');
    try {
      await certificateFor(['localhost'], { caDir: dir });
      expect(readState(dir)?.ca.subject).toContain('OU=user');
    } finally {
      restore();
    }
  });
});

describe('guard verification failures', () => {
  it('rethrows a guard CertkitError from protected temp file verification', async () => {
    const guard: FsGuard = {
      protectDirectory: () => undefined,
      assertProtectedDirectory: () => undefined,
      assertProtectedFile: (path) => {
        if (path.includes('.certkit-'))
          throw new CertkitError(
            'CA_UNREADABLE',
            'guard rejected the temp file',
          );
      },
    };

    await expect(
      certificateForCore(['localhost'], { caDir: dir }, { fsGuard: guard }),
    ).rejects.toMatchObject({
      code: 'CA_UNREADABLE',
      message: 'guard rejected the temp file',
    });
    expect(readdirSync(dir).some((name) => name.includes('.certkit-'))).toBe(
      false,
    );
  });

  it('wraps a plain guard failure during CA material verification', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    const guard: FsGuard = {
      protectDirectory: () => undefined,
      assertProtectedDirectory: () => undefined,
      assertProtectedFile: (path) => {
        if (path.endsWith('ca-key.pem')) throw new Error('acl read failed');
      },
    };

    await expect(
      certificateForCore(['localhost'], { caDir: dir }, { fsGuard: guard }),
    ).rejects.toMatchObject({
      code: 'CA_UNREADABLE',
      message: expect.stringContaining(
        'Filesystem protection could not be verified',
      ),
    });
  });
});

describe('CA material protection', () => {
  it.skipIf(process.platform === 'win32')(
    'fails closed when the CA key is a symlink',
    async () => {
      await certificateFor(['localhost'], { caDir: dir });
      unlinkSync(join(dir, 'ca-key.pem'));
      symlinkSync(join(dir, 'ca-cert.pem'), join(dir, 'ca-key.pem'));

      await expect(
        certificateFor(['localhost'], { caDir: dir }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('CA material is not a regular file'),
      });
    },
  );

  it.skipIf(process.platform === 'win32')(
    'fails closed when CA material loses its restrictive permissions',
    async () => {
      await certificateFor(['localhost'], { caDir: dir });
      chmodSync(join(dir, 'ca-key.pem'), 0o644);

      await expect(
        certificateFor(['localhost'], { caDir: dir }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(
          'CA material permissions are not 0600',
        ),
      });
    },
  );

  it.skipIf(process.platform === 'win32')(
    'fails closed when CA material is owned by another user',
    async () => {
      await certificateFor(['localhost'], { caDir: dir });
      const target = join(dir, 'ca-key.pem');
      const restore = patchBuiltin(
        fs,
        'lstatSync',
        (original) =>
          ((path, options) => {
            if (path === target) return foreignOwnerStat();
            return original(path, options);
          }) as typeof fs.lstatSync,
      );
      try {
        await expect(
          certificateFor(['localhost'], { caDir: dir }),
        ).rejects.toMatchObject({
          code: 'CA_UNREADABLE',
          message: expect.stringContaining(
            'CA material is not owned by the current user',
          ),
        });
      } finally {
        restore();
      }
    },
  );

  it('wraps an inspection failure for CA material', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    const target = join(dir, 'ca-key.pem');
    const restore = patchBuiltin(
      fs,
      'lstatSync',
      (original) =>
        ((path, options) => {
          if (path === target) throw accessDenied();
          return original(path, options);
        }) as typeof fs.lstatSync,
    );
    try {
      await expect(
        certificateFor(['localhost'], { caDir: dir }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Cannot inspect CA material'),
      });
    } finally {
      restore();
    }
  });

  it('wraps a read failure for CA material that disappears mid-read', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    const target = join(dir, 'ca-key.pem');
    let removed = false;
    const guard: FsGuard = {
      protectDirectory: () => undefined,
      assertProtectedDirectory: () => undefined,
      assertProtectedFile: (path) => {
        if (!removed && path === target) {
          removed = true;
          unlinkSync(path);
        }
      },
    };

    await expect(
      certificateForCore(['localhost'], { caDir: dir }, { fsGuard: guard }),
    ).rejects.toMatchObject({
      code: 'CA_UNREADABLE',
      message: expect.stringContaining('Could not read CA material'),
    });
    expect(removed).toBe(true);
  });

  it('fails closed when the CA key does not match the CA certificate', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    await certificateFor(['localhost'], { caDir: join(tempRoot, 'other-ca') });
    writeFileSync(
      join(dir, 'ca-key.pem'),
      readFileSync(join(tempRoot, 'other-ca', 'ca-key.pem')),
      { mode: 0o600 },
    );

    await expect(
      certificateFor(['localhost'], { caDir: dir }),
    ).rejects.toMatchObject({
      code: 'CA_UNREADABLE',
      message: expect.stringContaining(
        'CA key, certificate, or state is invalid',
      ),
    });
  });

  it('fails closed when CA state metadata does not match the CA certificate', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    const state = readState(dir);
    if (!state) throw new Error('CA state was not written');
    writeStateAtomic(dir, { ...state, ca: { ...state.ca, serial: 'ff' } });

    await expect(
      certificateFor(['localhost'], { caDir: dir }),
    ).rejects.toMatchObject({
      code: 'CA_UNREADABLE',
      message: expect.stringContaining(
        'CA key, certificate, or state is invalid',
      ),
    });
  });
});

describe('atomic write failures', () => {
  it('wraps an atomic-write replace failure for CA material', async () => {
    const restore = patchBuiltin(
      fs,
      'renameSync',
      (original) =>
        ((path, destination) => {
          if (String(destination).endsWith('ca-cert.pem'))
            throw new Error('cross-device link');
          return original(path, destination);
        }) as typeof fs.renameSync,
    );
    try {
      await expect(
        certificateFor(['localhost'], { caDir: dir }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Could not atomically write CA file'),
      });
    } finally {
      restore();
    }
    expect(readdirSync(dir).some((name) => name.includes('.certkit-'))).toBe(
      false,
    );
  });

  it('wraps an atomic replace failure for a leaf private key', async () => {
    const restore = patchBuiltin(
      fs,
      'renameSync',
      (original) =>
        ((path, destination) => {
          if (/leaf-[a-f0-9]+-key\.pem$/.test(String(destination)))
            throw new Error('cross-device link');
          return original(path, destination);
        }) as typeof fs.renameSync,
    );
    try {
      await expect(
        certificateFor(['localhost'], { caDir: dir }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Could not replace private key'),
      });
    } finally {
      restore();
    }
    expect(readdirSync(dir).some((name) => name.includes('.leaf-key-'))).toBe(
      false,
    );
  });

  it.skipIf(process.platform === 'win32')(
    'fails closed and preserves a symlinked leaf key target',
    async () => {
      await certificateFor(['localhost'], { caDir: dir });
      const files = cacheFiles();
      const sentinel = join(tempRoot, 'sentinel-key.pem');
      writeFileSync(sentinel, 'outside bytes', { mode: 0o600 });
      unlinkSync(files.key);
      symlinkSync(sentinel, files.key);

      await expect(
        certificateFor(['localhost'], { caDir: dir }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Write target is a symbolic link'),
      });
      expect(lstatSync(files.key).isSymbolicLink()).toBe(true);
      expect(readFileSync(sentinel, 'utf8')).toBe('outside bytes');
    },
  );

  it('fails closed when a leaf certificate target is a directory', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    const files = cacheFiles();
    rmSync(files.cert);
    mkdirSync(files.cert);

    await expect(
      certificateFor(['localhost'], { caDir: dir }),
    ).rejects.toMatchObject({
      code: 'CA_UNREADABLE',
      message: expect.stringContaining('Write target is not a regular file'),
    });
  });

  it('fails closed when freshly written CA material cannot be read back', async () => {
    const restore = patchBuiltin(
      fs,
      'renameSync',
      (original) =>
        ((path, destination) => {
          if (String(destination).endsWith('ca-cert.pem')) {
            unlinkSync(String(path));
            return;
          }
          original(path, destination);
        }) as typeof fs.renameSync,
    );
    try {
      await expect(
        certificateFor(['localhost'], { caDir: dir }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('New CA material is incomplete'),
      });
    } finally {
      restore();
    }
  });
});

describe('leaf cache validation', () => {
  it.skipIf(process.platform === 'win32')(
    'regenerates a leaf whose cache file lost its restrictive permissions',
    async () => {
      const first = await certificateFor(['localhost'], { caDir: dir });
      chmodSync(cacheFiles().cert, 0o644);

      const second = await certificateFor(['localhost'], { caDir: dir });

      expect(second.cert).not.toBe(first.cert);
      expect(lstatSync(cacheFiles().cert).mode & 0o777).toBe(0o600);
    },
  );

  it.skipIf(process.platform === 'win32')(
    'regenerates a leaf whose cache file is owned by another user',
    async () => {
      const first = await certificateFor(['localhost'], { caDir: dir });
      const target = cacheFiles().cert;
      const restore = patchBuiltin(
        fs,
        'lstatSync',
        (original) =>
          ((path, options) => {
            if (path === target) return foreignOwnerStat();
            return original(path, options);
          }) as typeof fs.lstatSync,
      );
      try {
        const second = await certificateFor(['localhost'], { caDir: dir });
        expect(second.cert).not.toBe(first.cert);
      } finally {
        restore();
      }
    },
  );

  it('regenerates a leaf whose cache file cannot be inspected', async () => {
    const first = await certificateFor(['localhost'], { caDir: dir });
    const target = cacheFiles().cert;
    let tripped = false;
    const restore = patchBuiltin(
      fs,
      'lstatSync',
      (original) =>
        ((path, options) => {
          if (!tripped && path === target) {
            tripped = true;
            throw accessDenied();
          }
          return original(path, options);
        }) as typeof fs.lstatSync,
    );
    try {
      const second = await certificateFor(['localhost'], { caDir: dir });
      expect(tripped).toBe(true);
      expect(second.cert).not.toBe(first.cert);
    } finally {
      restore();
    }
  });

  it('regenerates a leaf whose cache file disappears mid-read', async () => {
    const first = await certificateFor(['localhost'], { caDir: dir });
    const target = cacheFiles().cert;
    let removed = false;
    const guard: FsGuard = {
      protectDirectory: () => undefined,
      assertProtectedDirectory: () => undefined,
      assertProtectedFile: (path) => {
        if (!removed && path === target) {
          removed = true;
          unlinkSync(path);
        }
      },
    };

    const second = await certificateForCore(
      ['localhost'],
      { caDir: dir },
      { fsGuard: guard },
    );

    expect(removed).toBe(true);
    expect(second.cert).not.toBe(first.cert);
  });

  it.each([
    ['a JSON array', '["localhost"]'],
    ['a JSON scalar', '42'],
    [
      'a non-date expiry',
      JSON.stringify({
        names: ['localhost'],
        validityDays: 825,
        expiresAt: 'never',
      }),
    ],
  ])(
    'regenerates a leaf whose metadata is %s',
    async (_description, contents) => {
      const first = await certificateFor(['localhost'], { caDir: dir });
      writeFileSync(cacheFiles().meta, contents, { mode: 0o600 });

      const second = await certificateFor(['localhost'], { caDir: dir });

      expect(second.cert).not.toBe(first.cert);
    },
  );

  it('regenerates a cached leaf that has no SAN extension', async () => {
    const first = await certificateFor(['localhost'], { caDir: dir });
    writeFileSync(cacheFiles().cert, readFileSync(join(dir, 'ca-cert.pem')), {
      mode: 0o600,
    });

    const second = await certificateFor(['localhost'], { caDir: dir });

    expect(second.cert).not.toBe(first.cert);
  });

  it('regenerates a cached leaf whose SANs contain non-host entries', async () => {
    const first = await certificateFor(['localhost'], { caDir: dir });
    const files = cacheFiles();
    const {
      SubjectAlternativeNameExtension,
      X509Certificate,
      X509CertificateGenerator,
    } = await import('@peculiar/x509');
    const original = new NodeX509Certificate(first.cert);
    const caSubject = new X509Certificate(first.caCert).subject;
    const caKeyDer = Buffer.from(
      readFileSync(join(dir, 'ca-key.pem'), 'utf8').replace(
        /-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s+/g,
        '',
      ),
      'base64',
    );
    const caKey = await webcrypto.subtle.importKey(
      'pkcs8',
      caKeyDer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    );
    const publicKey = await webcrypto.subtle.importKey(
      'spki',
      original.publicKey.export({ format: 'der', type: 'spki' }),
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      [],
    );
    const crafted = await X509CertificateGenerator.create(
      {
        serialNumber: original.serialNumber,
        subject: 'CN=localhost',
        issuer: caSubject,
        notBefore: original.notBefore,
        notAfter: original.notAfter,
        signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        signingKey: caKey,
        extensions: [
          new SubjectAlternativeNameExtension(
            [
              { type: 'dns', value: 'localhost' },
              { type: 'email', value: 'admin@localhost' },
            ],
            true,
          ),
        ],
      },
      webcrypto,
    );
    writeFileSync(files.cert, crafted.toString('pem'), { mode: 0o600 });

    const second = await certificateFor(['localhost'], { caDir: dir });

    expect(second.cert).not.toBe(first.cert);
    expect(second.cert).not.toBe(crafted.toString('pem'));
  });
});

describe('stale temporary file cleanup', () => {
  const staleName = '.certkit-00000000-0000-4000-8000-000000000000.tmp';

  it('refuses to remove a stale temp path that is a directory', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    mkdirSync(join(dir, staleName));

    await expect(
      certificateFor(['localhost'], { caDir: dir }),
    ).rejects.toMatchObject({
      code: 'CA_UNREADABLE',
      message: expect.stringContaining(
        'Stale temporary file is not a regular file',
      ),
    });
  });

  it.skipIf(process.platform === 'win32')(
    'refuses to remove a stale temp file with loose permissions',
    async () => {
      await certificateFor(['localhost'], { caDir: dir });
      const stale = join(dir, staleName);
      writeFileSync(stale, 'stale', { mode: 0o600 });
      chmodSync(stale, 0o644);

      await expect(
        certificateFor(['localhost'], { caDir: dir }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(
          'Stale temporary file permissions are not 0600',
        ),
      });
    },
  );

  it.skipIf(process.platform === 'win32')(
    'refuses to remove a stale temp file owned by another user',
    async () => {
      await certificateFor(['localhost'], { caDir: dir });
      const stale = join(dir, staleName);
      writeFileSync(stale, 'stale', { mode: 0o600 });
      const restore = patchBuiltin(
        fs,
        'lstatSync',
        (original) =>
          ((path, options) => {
            if (path === stale) return foreignOwnerStat();
            return original(path, options);
          }) as typeof fs.lstatSync,
      );
      try {
        await expect(
          certificateFor(['localhost'], { caDir: dir }),
        ).rejects.toMatchObject({
          code: 'CA_UNREADABLE',
          message: expect.stringContaining(
            'Stale temporary file is not user-owned',
          ),
        });
      } finally {
        restore();
      }
    },
  );

  it('wraps an inspection failure for stale temp files', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    const stale = join(dir, staleName);
    writeFileSync(stale, 'stale', { mode: 0o600 });
    const restore = patchBuiltin(
      fs,
      'lstatSync',
      (original) =>
        ((path, options) => {
          if (path === stale) throw accessDenied();
          return original(path, options);
        }) as typeof fs.lstatSync,
    );
    try {
      await expect(
        certificateFor(['localhost'], { caDir: dir }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(
          'Cannot inspect interrupted CA material',
        ),
      });
    } finally {
      restore();
    }
  });

  it('wraps a removal failure for stale temp files', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    const stale = join(dir, staleName);
    writeFileSync(stale, 'stale', { mode: 0o600 });
    const restore = patchBuiltin(
      fs,
      'unlinkSync',
      (original) =>
        ((path) => {
          if (path === stale) throw accessDenied();
          return original(path);
        }) as typeof fs.unlinkSync,
    );
    try {
      await expect(
        certificateFor(['localhost'], { caDir: dir }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(
          'Could not remove Stale temporary file',
        ),
      });
    } finally {
      restore();
    }
  });

  it('wraps a directory listing failure during temp cleanup', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    const restore = patchBuiltin(
      fs,
      'readdirSync',
      (original) =>
        ((path: fs.PathLike) => {
          if (String(path) === dir) throw accessDenied();
          return (original as (target: fs.PathLike) => string[])(path);
        }) as typeof fs.readdirSync,
    );
    try {
      await expect(
        certificateFor(['localhost'], { caDir: dir }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Could not inspect temporary files'),
      });
    } finally {
      restore();
    }
  });
});

describe('CA lifecycle recovery', () => {
  it('fails closed when CA material exists without a state file', async () => {
    mkdirSync(dir, { mode: 0o700 });
    writeFileSync(join(dir, 'ca-key.pem'), 'orphan key', { mode: 0o600 });

    await expect(
      certificateFor(['localhost'], { caDir: dir }),
    ).rejects.toMatchObject({
      code: 'CA_UNREADABLE',
      message: expect.stringContaining(
        'CA material exists without a state file',
      ),
    });
  });

  it('wraps an inspection failure for orphaned CA material', async () => {
    mkdirSync(dir, { mode: 0o700 });
    const target = join(dir, 'ca-key.pem');
    const restore = patchBuiltin(
      fs,
      'lstatSync',
      (original) =>
        ((path, options) => {
          if (path === target) throw accessDenied();
          return original(path, options);
        }) as typeof fs.lstatSync,
    );
    try {
      await expect(
        certificateFor(['localhost'], { caDir: dir }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Cannot inspect CA directory entry'),
      });
    } finally {
      restore();
    }
  });

  it('fails closed when an active CA key is missing', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    unlinkSync(join(dir, 'ca-key.pem'));

    await expect(
      certificateFor(['localhost'], { caDir: dir }),
    ).rejects.toMatchObject({
      code: 'CA_UNREADABLE',
      message: expect.stringContaining(
        'Active CA key or certificate is missing',
      ),
    });
  });

  it('promotes a fully written initializing CA to active', async () => {
    const first = await certificateFor(['localhost'], { caDir: dir });
    const state = readState(dir);
    if (!state) throw new Error('CA state was not written');
    writeStateAtomic(dir, { ...state, phase: 'initializing' });

    const second = await certificateFor(['localhost'], { caDir: dir });

    expect(second.caCert).toBe(first.caCert);
    expect(readState(dir)?.phase).toBe('active');
  });

  it('restarts an initializing CA whose material is corrupt', async () => {
    const first = await certificateFor(['localhost'], { caDir: dir });
    const state = readState(dir);
    if (!state) throw new Error('CA state was not written');
    writeStateAtomic(dir, { ...state, phase: 'initializing' });
    writeFileSync(join(dir, 'ca-cert.pem'), 'corrupt', { mode: 0o600 });

    const second = await certificateFor(['localhost'], { caDir: dir });

    expect(second.caCert).not.toBe(first.caCert);
    expect(readState(dir)?.phase).toBe('active');
  });
});

describe('locked CA readers', () => {
  it('ensureCaForInstallLocked creates and returns CA material', async () => {
    const material = await ensureCaForInstallLocked(dir, fileOptions());

    expect(material.state.phase).toBe('active');
    expect(material.certPem).toContain('-----BEGIN CERTIFICATE-----');
  });

  it('readCaForStatus rejects CA material without a state file', () => {
    mkdirSync(dir, { mode: 0o700 });
    writeFileSync(join(dir, 'ca-cert.pem'), 'orphan cert', { mode: 0o600 });

    expect(() => readCaForStatus(dir, fileOptions())).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('without a state file'),
      }),
    );
  });

  it('readCaForStatus rejects an active CA with missing material', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    unlinkSync(join(dir, 'ca-cert.pem'));

    expect(() => readCaForStatus(dir, fileOptions())).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('CA key or certificate is missing'),
      }),
    );
  });

  it('readCaForUninstallLocked returns null for an empty directory', () => {
    mkdirSync(dir, { mode: 0o700 });

    expect(readCaForUninstallLocked(dir, fileOptions())).toBeNull();
  });

  it('readCaForUninstallLocked rejects CA material without a state file', () => {
    mkdirSync(dir, { mode: 0o700 });
    writeFileSync(join(dir, 'ca-key.pem'), 'orphan key', { mode: 0o600 });

    expect(() => readCaForUninstallLocked(dir, fileOptions())).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('without a state file'),
      }),
    );
  });

  it('readCaForUninstallLocked returns material for an intact active CA', async () => {
    const first = await certificateFor(['localhost'], { caDir: dir });

    const material = readCaForUninstallLocked(dir, fileOptions());

    expect(material?.state.phase).toBe('active');
    expect(material?.certPem).toBe(first.caCert);
  });

  it('readCaForUninstallLocked guards a missing certificate with remaining trust records', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    const state = readState(dir);
    if (!state) throw new Error('CA state was not written');
    const timestamp = new Date().toISOString();
    const sha256 = 'a'.repeat(64);
    unlinkSync(join(dir, 'ca-cert.pem'));

    writeStateAtomic(dir, {
      ...state,
      trustWrites: [
        {
          store: 'nss',
          target: '/home/test/.pki/nssdb',
          serial: '01',
          sha256,
          timestamp,
        },
      ],
    });
    expect(() => readCaForUninstallLocked(dir, fileOptions())).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('manual fingerprint-based recovery'),
      }),
    );

    writeStateAtomic(dir, {
      ...state,
      pendingWrites: [
        { store: 'nss', target: '/home/test/.pki/nssdb', sha256, timestamp },
      ],
    });
    expect(() => readCaForUninstallLocked(dir, fileOptions())).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('manual fingerprint-based recovery'),
      }),
    );
  });

  it('readCaForUninstallLocked rejects an active CA without a certificate', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    unlinkSync(join(dir, 'ca-cert.pem'));

    expect(() => readCaForUninstallLocked(dir, fileOptions())).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Active CA certificate is missing'),
      }),
    );
  });

  it('readCaForUninstallLocked validates a retiring CA certificate', async () => {
    const first = await certificateFor(['localhost'], { caDir: dir });
    const state = readState(dir);
    if (!state) throw new Error('CA state was not written');
    writeStateAtomic(dir, { ...state, phase: 'retiring' });

    const material = readCaForUninstallLocked(dir, fileOptions());

    expect(material?.state.phase).toBe('retiring');
    expect(material?.certPem).toBe(first.caCert);
  });

  it('readCaForUninstallLocked tolerates a retiring CA without a certificate', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    const state = readState(dir);
    if (!state) throw new Error('CA state was not written');
    writeStateAtomic(dir, { ...state, phase: 'retiring' });
    unlinkSync(join(dir, 'ca-cert.pem'));

    const material = readCaForUninstallLocked(dir, fileOptions());

    expect(material?.state.phase).toBe('retiring');
    expect(material?.certPem).toBeNull();
  });

  it('readCaForUninstallLocked validates an initializing CA certificate', async () => {
    const first = await certificateFor(['localhost'], { caDir: dir });
    const state = readState(dir);
    if (!state) throw new Error('CA state was not written');
    writeStateAtomic(dir, { ...state, phase: 'initializing' });

    const material = readCaForUninstallLocked(dir, fileOptions());

    expect(material?.state.phase).toBe('initializing');
    expect(material?.certPem).toBe(first.caCert);
  });

  it('readCaForUninstallLocked tolerates an initializing CA without a certificate', async () => {
    await certificateFor(['localhost'], { caDir: dir });
    const state = readState(dir);
    if (!state) throw new Error('CA state was not written');
    writeStateAtomic(dir, { ...state, phase: 'initializing' });
    unlinkSync(join(dir, 'ca-cert.pem'));

    const material = readCaForUninstallLocked(dir, fileOptions());

    expect(material?.state.phase).toBe('initializing');
    expect(material?.certPem).toBeNull();
  });
});
