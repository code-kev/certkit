import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
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
} from '../../src/core/certificate.js';
import { caDir, certificateFor } from '../../src/index.js';
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

beforeEach(() => {
  tempRoot = mkdtempSync(join(tmpdir(), 'certkit-certificate-'));
  dir = join(tempRoot, 'ca');
});

afterEach(() => {
  vi.useRealTimers();
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
});
