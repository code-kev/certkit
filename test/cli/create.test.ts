import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { writeCertificateFiles } from '../../src/cli/commands/create.js';
import type { FsGuard } from '../../src/core/cadir.js';
import { CertkitError } from '../../src/core/errors.js';
import { createWindowsFsGuard } from '../../src/platforms/fsguard.js';
import { run } from '../../src/platforms/run.js';

const cli = resolve('dist/cli/index.js');
const originalCaDir = process.env.CERTKIT_HOME;
const roots: string[] = [];

// Placement-preflight tests only need the guard surface, not real ACLs.
const noopGuard: FsGuard = {
  protectDirectory() {},
  assertProtectedDirectory() {},
  assertProtectedFile() {},
};

function fixture(): string {
  const root = mkdtempSync(join(tmpdir(), 'certkit-create-'));
  roots.push(root);
  return root;
}

async function create(
  root: string,
  args: string[],
): Promise<Awaited<ReturnType<typeof run>>> {
  process.env.CERTKIT_HOME = join(root, 'ca');
  return run([process.execPath, cli, 'create', ...args]);
}

afterEach(() => {
  if (originalCaDir === undefined) delete process.env.CERTKIT_HOME;
  else process.env.CERTKIT_HOME = originalCaDir;
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe('create command', () => {
  it('writes a certificate and a private key with JSON paths', async () => {
    const root = fixture();
    const outputDir = join(root, 'out');
    mkdirSync(outputDir);
    const result = await create(root, [
      'localhost',
      'app.test',
      '127.0.0.1',
      '-o',
      outputDir,
      '--json',
    ]);
    expect(result.code).toBe(0);
    const output = JSON.parse(result.stdout) as {
      schemaVersion: number;
      names: string[];
      files: { cert: string; key: string };
    };

    expect(output).toEqual({
      schemaVersion: 1,
      names: ['localhost', 'app.test', '127.0.0.1'],
      files: {
        cert: join(outputDir, 'localhost+2.pem'),
        key: join(outputDir, 'localhost+2-key.pem'),
      },
    });
    expect(readFileSync(output.files.cert, 'utf8')).toContain(
      '-----BEGIN CERTIFICATE-----',
    );
    expect(readFileSync(output.files.key, 'utf8')).toContain(
      '-----BEGIN PRIVATE KEY-----',
    );
    // Windows keys are protected by ACL, not mode bits.
    if (process.platform !== 'win32')
      expect(statSync(output.files.key).mode & 0o777).toBe(0o600);
  });

  it.each([
    ['*.example.com', '_wildcard.example.com.pem'],
    ['::1', '--1.pem'],
    ['con', '_con.pem'],
    ['nul.example.test', '_nul.example.test.pem'],
  ])('sanitizes %s to %s', async (name, filename) => {
    const root = fixture();
    const outputDir = join(root, 'out');
    mkdirSync(outputDir);
    const result = await create(root, [name, '-o', outputDir]);

    expect(result.code).toBe(0);
    expect(existsSync(join(outputDir, filename))).toBe(true);
    expect(readdirSync(outputDir).some((file) => file.includes(':'))).toBe(
      false,
    );
  });

  it('leaves both existing files byte-identical when --force is absent', async () => {
    const root = fixture();
    const outputDir = join(root, 'out');
    mkdirSync(outputDir);
    const cert = join(outputDir, 'localhost.pem');
    const key = join(outputDir, 'localhost-key.pem');
    writeFileSync(cert, 'old certificate');
    writeFileSync(key, 'old key');

    const result = await create(root, ['localhost', '-o', outputDir]);

    expect(result.code).toBe(1);
    expect(readFileSync(cert, 'utf8')).toBe('old certificate');
    expect(readFileSync(key, 'utf8')).toBe('old key');
  });

  it('reports a collision as pure JSON with the operational exit code', async () => {
    const root = fixture();
    const outputDir = join(root, 'out');
    mkdirSync(outputDir);
    writeFileSync(join(outputDir, 'localhost.pem'), 'old certificate');

    const result = await create(root, ['localhost', '-o', outputDir, '--json']);

    expect(result.code).toBe(1);
    expect(JSON.parse(result.stdout)).toEqual({
      schemaVersion: 1,
      error: {
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Output already exists'),
      },
    });
    expect(result.stderr).toBe('');
  });

  it('overwrites existing regular files with --force', async () => {
    const root = fixture();
    const outputDir = join(root, 'out');
    mkdirSync(outputDir);
    const cert = join(outputDir, 'localhost.pem');
    const key = join(outputDir, 'localhost-key.pem');
    writeFileSync(cert, 'old certificate');
    writeFileSync(key, 'old key');

    const result = await create(root, [
      'localhost',
      '-o',
      outputDir,
      '--force',
    ]);

    expect(result.code).toBe(0);
    expect(readFileSync(cert, 'utf8')).toContain('-----BEGIN CERTIFICATE-----');
    expect(readFileSync(key, 'utf8')).toContain('-----BEGIN PRIVATE KEY-----');
    if (process.platform !== 'win32')
      expect(statSync(key).mode & 0o777).toBe(0o600);
  });

  it('rejects a symlinked output with --force without following or changing it', async () => {
    const root = fixture();
    const outputDir = join(root, 'out');
    mkdirSync(outputDir);
    const sentinel = join(root, 'sentinel');
    const key = join(outputDir, 'localhost-key.pem');
    const cert = join(outputDir, 'localhost.pem');
    writeFileSync(sentinel, 'outside bytes');
    writeFileSync(key, 'old key');
    symlinkSync(sentinel, cert);

    const result = await create(root, [
      'localhost',
      '-o',
      outputDir,
      '--force',
    ]);

    expect(result.code).toBe(1);
    expect(lstatSync(cert).isSymbolicLink()).toBe(true);
    expect(readFileSync(sentinel, 'utf8')).toBe('outside bytes');
    expect(readFileSync(key, 'utf8')).toBe('old key');
  });

  it('reports the key replacement after a simulated certificate rename failure', () => {
    const root = fixture();
    const outputDir = join(root, 'out');
    const caDir = join(root, 'ca');
    mkdirSync(outputDir);
    mkdirSync(caDir, { mode: 0o700 });
    const paths = {
      cert: join(outputDir, 'localhost.pem'),
      key: join(outputDir, 'localhost-key.pem'),
    };
    writeFileSync(paths.cert, 'old certificate');
    writeFileSync(paths.key, 'old key');
    let certificateRenameFailed = false;

    expect(() =>
      writeCertificateFiles(
        paths,
        { cert: 'new certificate', key: 'new private key' },
        {
          force: true,
          caDir,
          // Windows placement preflight requires a guard.
          ...(process.platform === 'win32'
            ? {
                fsGuard: {
                  protectDirectory() {},
                  assertProtectedDirectory() {},
                  assertProtectedFile() {},
                },
              }
            : {}),
          rename(from, to) {
            if (to === paths.cert) {
              certificateRenameFailed = true;
              throw new Error('simulated rename failure');
            }
            renameSync(from, to);
          },
        },
      ),
    ).toThrow(`key output was replaced at ${paths.key}`);

    expect(certificateRenameFailed).toBe(true);
    expect(readFileSync(paths.cert, 'utf8')).toBe('old certificate');
    expect(readFileSync(paths.key, 'utf8')).toBe('new private key');
    expect(readdirSync(outputDir).some((name) => name.startsWith('.'))).toBe(
      false,
    );
    expect(readdirSync(caDir)).toEqual([]);
  });

  it('preserves a pre-existing certificate temp-file collision', () => {
    const root = fixture();
    const outputDir = join(root, 'out');
    const caDir = join(root, 'ca');
    mkdirSync(outputDir);
    mkdirSync(caDir, { mode: 0o700 });
    const collision = join(outputDir, '.certkit-cert-collision.tmp');
    writeFileSync(collision, 'pre-existing certificate temp');

    expect(() =>
      writeCertificateFiles(
        {
          cert: join(outputDir, 'localhost.pem'),
          key: join(outputDir, 'localhost-key.pem'),
        },
        { cert: 'certificate', key: 'private key' },
        {
          force: false,
          caDir,
          randomUUID: () => 'cert-collision',
        },
      ),
    ).toThrow();

    expect(readFileSync(collision, 'utf8')).toBe(
      'pre-existing certificate temp',
    );
  });

  it('preserves a pre-existing private-key temp-file collision', () => {
    const root = fixture();
    const outputDir = join(root, 'out');
    const caDir = join(root, 'ca');
    mkdirSync(outputDir);
    mkdirSync(caDir, { mode: 0o700 });
    const collision = join(outputDir, '.leaf-key-key-collision.tmp');
    writeFileSync(collision, 'pre-existing key temp');
    const ids = ['cert-temp', 'key-collision'];

    expect(() =>
      writeCertificateFiles(
        {
          cert: join(outputDir, 'localhost.pem'),
          key: join(outputDir, 'localhost-key.pem'),
        },
        { cert: 'certificate', key: 'private key' },
        {
          force: false,
          caDir,
          randomUUID: () => ids.shift() ?? 'unexpected',
        },
      ),
    ).toThrow();

    expect(readFileSync(collision, 'utf8')).toBe('pre-existing key temp');
    expect(readdirSync(outputDir)).toEqual(['.leaf-key-key-collision.tmp']);
  });

  it.each([false, true])(
    'preflights Windows key placement with an empty key before bytes are staged (force=%s)',
    (force) => {
      const root = fixture();
      const outputDir = join(root, 'out');
      const caDir = join(root, 'ca');
      mkdirSync(outputDir);
      mkdirSync(caDir, { mode: 0o700 });
      const paths = {
        cert: join(outputDir, 'localhost.pem'),
        key: join(outputDir, 'localhost-key.pem'),
      };
      const calls: Array<{ path: string; bytes: number }> = [];
      const guard = createWindowsFsGuard((command, argv) => {
        if (command === 'whoami') return '"USER","S-1-5-21-1-2-3"';
        if (argv.includes('/inheritance:r')) return '';
        const match = /-LiteralPath '((?:[^']|'')*)'/.exec(argv[4] ?? '');
        const path = match?.[1]?.replaceAll("''", "'");
        if (path) {
          let bytes = -1;
          try {
            bytes = readFileSync(path).byteLength;
          } catch {
            // Directory ACL queries have no file contents.
          }
          calls.push({ path, bytes });
          return 'S-1-5-21-1-2-3';
        }
        throw new Error('unexpected ACL invocation');
      });
      guard.protectDirectory(caDir);

      writeCertificateFiles(
        paths,
        { cert: 'certificate', key: 'private key' },
        { force, caDir, fsGuard: guard, platform: 'win32' },
      );

      expect(
        calls.some(
          ({ path, bytes }) => path.includes('.leaf-key-') && bytes === 0,
        ),
      ).toBe(true);
      expect(
        calls.some(
          ({ path, bytes }) =>
            path.startsWith(outputDir) && path !== paths.key && bytes === 0,
        ),
      ).toBe(true);
      const placementProbeIndex = calls.findLastIndex(
        ({ path, bytes }) =>
          path.startsWith(outputDir) && path !== paths.key && bytes === 0,
      );
      const emptyKeyStageIndices = calls.flatMap(({ path, bytes }, index) =>
        path.startsWith(caDir) && path.includes('.leaf-key-') && bytes === 0
          ? [index]
          : [],
      );
      expect(placementProbeIndex).toBeGreaterThanOrEqual(0);
      expect(emptyKeyStageIndices).toHaveLength(2);
      expect(placementProbeIndex).toBeLessThan(emptyKeyStageIndices[1] ?? -1);
      expect(calls.some(({ path }) => path === paths.key)).toBe(true);
      expect(readFileSync(paths.key, 'utf8')).toBe('private key');
      expect(readdirSync(caDir)).toEqual([]);
    },
  );

  it.each([false, true])(
    'fails Windows key placement closed before staging key bytes when the empty placement probe is unprotected (force=%s)',
    (force) => {
      const root = fixture();
      const outputDir = join(root, 'out');
      const caDir = join(root, 'ca');
      mkdirSync(outputDir);
      mkdirSync(caDir, { mode: 0o700 });
      const paths = {
        cert: join(outputDir, 'localhost.pem'),
        key: join(outputDir, 'localhost-key.pem'),
      };
      const calls: Array<{ path: string; bytes: number }> = [];
      const guard = createWindowsFsGuard((command, argv) => {
        if (command === 'whoami') return '"USER","S-1-5-21-1-2-3"';
        if (argv.includes('/inheritance:r')) return '';
        const match = /-LiteralPath '((?:[^']|'')*)'/.exec(argv[4] ?? '');
        const path = match?.[1]?.replaceAll("''", "'");
        if (!path) throw new Error('unexpected ACL invocation');
        let bytes = -1;
        try {
          bytes = readFileSync(path).byteLength;
        } catch {
          // Directory ACL queries have no file contents.
        }
        calls.push({ path, bytes });
        if (path.startsWith(outputDir)) throw new Error('unprotected probe');
        return 'S-1-5-21-1-2-3';
      });
      guard.protectDirectory(caDir);

      expect(() =>
        writeCertificateFiles(
          paths,
          { cert: 'certificate', key: 'private key' },
          { force, caDir, fsGuard: guard, platform: 'win32' },
        ),
      ).toThrow('Key bytes were not placed');

      expect(
        calls.some(
          ({ path, bytes }) => path.startsWith(outputDir) && bytes === 0,
        ),
      ).toBe(true);
      expect(readdirSync(outputDir)).toEqual([]);
      expect(readdirSync(caDir)).toEqual([]);
    },
  );

  it.each([
    ['invalid name', ['bad name', '-o', 'out']],
    ['empty name list', ['-o', 'out']],
    [
      'invalid validity days',
      ['localhost', '--validity-days', '0', '-o', 'out'],
    ],
    [
      'more than 100 names',
      [...Array.from({ length: 101 }, (_, i) => `host${i}.test`), '-o', 'out'],
    ],
    ['missing output directory', ['localhost', '-o', 'missing/']],
  ])('exits 2 for %s', async (_label, args) => {
    const root = fixture();
    const outputDir = join(root, 'out');
    mkdirSync(outputDir);
    const result = await create(root, args);

    expect(result.code).toBe(2);
    expect(result.stderr).not.toContain('Unknown command: create');
    expect(existsSync(join(root, 'ca'))).toBe(false);
  });

  it('prints the untrusted CA hint to stderr without changing success status', async () => {
    const root = fixture();
    const outputDir = join(root, 'out');
    mkdirSync(outputDir);
    const result = await create(root, ['localhost', '-o', outputDir, '--json']);
    const status = await run([process.execPath, cli, 'status', '--json']);
    const report = JSON.parse(status.stdout) as {
      stores: Array<{ state: string }>;
    };

    expect(result.code).toBe(0);
    if (report.stores.some((store) => store.state === 'untrusted'))
      expect(result.stderr).toContain('CA not trusted — run `certkit install`');
    expect(result.stdout).not.toContain('CA not trusted');
  });

  it('requires an fsGuard before Windows key placement', () => {
    const root = fixture();
    const outputDir = join(root, 'out');
    const caDir = join(root, 'ca');
    mkdirSync(outputDir);
    mkdirSync(caDir, { mode: 0o700 });

    expect(() =>
      writeCertificateFiles(
        {
          cert: join(outputDir, 'localhost.pem'),
          key: join(outputDir, 'localhost-key.pem'),
        },
        { cert: 'certificate', key: 'private key' },
        { force: false, caDir, platform: 'win32' },
      ),
    ).toThrow('requires filesystem protection checks');

    expect(readdirSync(outputDir)).toEqual([]);
    expect(readdirSync(caDir)).toEqual([]);
  });

  it('fails Windows placement preflight when the CA directory cannot be inspected', () => {
    const root = fixture();
    const outputDir = join(root, 'out');
    mkdirSync(outputDir);

    expect(() =>
      writeCertificateFiles(
        {
          cert: join(outputDir, 'localhost.pem'),
          key: join(outputDir, 'localhost-key.pem'),
        },
        { cert: 'certificate', key: 'private key' },
        {
          force: false,
          caDir: join(root, 'missing-ca'),
          fsGuard: noopGuard,
          platform: 'win32',
        },
      ),
    ).toThrow('Cannot preserve the protected Windows key ACL');

    expect(readdirSync(outputDir)).toEqual([]);
  });

  it('fails Windows preflight closed when the placed probe vanishes after rename', () => {
    const root = fixture();
    const outputDir = join(root, 'out');
    const caDir = join(root, 'ca');
    mkdirSync(outputDir);
    mkdirSync(caDir, { mode: 0o700 });

    expect(() =>
      writeCertificateFiles(
        {
          cert: join(outputDir, 'localhost.pem'),
          key: join(outputDir, 'localhost-key.pem'),
        },
        { cert: 'certificate', key: 'private key' },
        {
          force: true,
          caDir,
          fsGuard: noopGuard,
          platform: 'win32',
          rename(from, to) {
            renameSync(from, to);
            unlinkSync(to);
          },
        },
      ),
    ).toThrow('Could not verify protected Windows key placement');

    expect(readdirSync(outputDir)).toEqual([]);
    expect(readdirSync(caDir)).toEqual([]);
  });

  it('fails Windows preflight closed when the placed probe is replaced by a directory', () => {
    const root = fixture();
    const outputDir = join(root, 'out');
    const caDir = join(root, 'ca');
    mkdirSync(outputDir);
    mkdirSync(caDir, { mode: 0o700 });

    expect(() =>
      writeCertificateFiles(
        {
          cert: join(outputDir, 'localhost.pem'),
          key: join(outputDir, 'localhost-key.pem'),
        },
        { cert: 'certificate', key: 'private key' },
        {
          force: true,
          caDir,
          fsGuard: noopGuard,
          platform: 'win32',
          rename(from, to) {
            renameSync(from, to);
            unlinkSync(to);
            mkdirSync(to);
          },
        },
      ),
    ).toThrow('Could not verify protected Windows key placement');

    const leftovers = readdirSync(outputDir);
    expect(leftovers).toHaveLength(1);
    expect(lstatSync(join(outputDir, leftovers[0] ?? '')).isDirectory()).toBe(
      true,
    );
    expect(readdirSync(caDir)).toEqual([]);
  });

  it.skipIf(process.platform === 'win32')(
    'fails Windows preflight closed when the placed probe is replaced by a symlink',
    () => {
      const root = fixture();
      const outputDir = join(root, 'out');
      const caDir = join(root, 'ca');
      mkdirSync(outputDir);
      mkdirSync(caDir, { mode: 0o700 });

      expect(() =>
        writeCertificateFiles(
          {
            cert: join(outputDir, 'localhost.pem'),
            key: join(outputDir, 'localhost-key.pem'),
          },
          { cert: 'certificate', key: 'private key' },
          {
            force: true,
            caDir,
            fsGuard: noopGuard,
            platform: 'win32',
            rename(from, to) {
              renameSync(from, to);
              unlinkSync(to);
              symlinkSync(from, to);
            },
          },
        ),
      ).toThrow('Could not verify protected Windows key placement');

      expect(readdirSync(outputDir)).toEqual([]);
      expect(readdirSync(caDir)).toEqual([]);
    },
  );

  it.skipIf(process.platform === 'win32')(
    'rejects a private-key temp file whose mode was narrowed by the umask',
    () => {
      const root = fixture();
      const outputDir = join(root, 'out');
      const caDir = join(root, 'ca');
      mkdirSync(outputDir);
      mkdirSync(caDir, { mode: 0o700 });
      const previousUmask = process.umask(0o777);

      try {
        expect(() =>
          writeCertificateFiles(
            {
              cert: join(outputDir, 'localhost.pem'),
              key: join(outputDir, 'localhost-key.pem'),
            },
            { cert: 'certificate', key: 'private key' },
            { force: false, caDir },
          ),
        ).toThrow('not protected with mode 0600');
      } finally {
        process.umask(previousUmask);
      }

      expect(readdirSync(outputDir)).toEqual([]);
    },
  );

  it.skipIf(process.platform === 'win32')(
    'skips the private-key ownership check when getuid is unavailable',
    () => {
      const root = fixture();
      const outputDir = join(root, 'out');
      const caDir = join(root, 'ca');
      mkdirSync(outputDir);
      mkdirSync(caDir, { mode: 0o700 });
      const paths = {
        cert: join(outputDir, 'localhost.pem'),
        key: join(outputDir, 'localhost-key.pem'),
      };
      const getuid = process.getuid;
      if (!getuid) return;
      delete (process as { getuid?: typeof getuid }).getuid;

      try {
        writeCertificateFiles(
          paths,
          { cert: 'certificate', key: 'private key' },
          { force: false, caDir },
        );
      } finally {
        process.getuid = getuid;
      }

      expect(readFileSync(paths.key, 'utf8')).toBe('private key');
      expect(statSync(paths.key).mode & 0o777).toBe(0o600);
    },
  );

  it.skipIf(process.platform === 'win32')(
    'wraps a guard rejection during private-key staging',
    () => {
      const root = fixture();
      const outputDir = join(root, 'out');
      const caDir = join(root, 'ca');
      mkdirSync(outputDir);
      mkdirSync(caDir, { mode: 0o700 });
      const guard: FsGuard = {
        protectDirectory() {},
        assertProtectedDirectory() {},
        assertProtectedFile() {
          throw new Error('guard boom');
        },
      };

      expect(() =>
        writeCertificateFiles(
          {
            cert: join(outputDir, 'localhost.pem'),
            key: join(outputDir, 'localhost-key.pem'),
          },
          { cert: 'certificate', key: 'private key' },
          { force: false, caDir, fsGuard: guard },
        ),
      ).toThrow('Could not stage private-key output');

      expect(readdirSync(outputDir)).toEqual([]);
    },
  );

  it.skipIf(process.platform === 'win32')(
    'reports a leftover key temp file when cleanup fails after a publish error',
    () => {
      const root = fixture();
      const outputDir = join(root, 'out');
      const caDir = join(root, 'ca');
      mkdirSync(outputDir);
      mkdirSync(caDir, { mode: 0o700 });
      const paths = {
        cert: join(outputDir, 'localhost.pem'),
        key: join(outputDir, 'localhost-key.pem'),
      };
      const keyTemp = join(outputDir, '.leaf-key-key-temp.tmp');
      const ids = ['cert-temp', 'key-temp'];

      expect(() =>
        writeCertificateFiles(
          paths,
          { cert: 'certificate', key: 'private key' },
          {
            force: true,
            caDir,
            randomUUID: () => ids.shift() ?? 'unexpected',
            rename(from, to) {
              renameSync(from, to);
              if (to === paths.key) {
                mkdirSync(from);
                throw new Error('post-rename failure');
              }
            },
          },
        ),
      ).toThrow(`Temporary file may remain at ${keyTemp}`);

      expect(readFileSync(paths.key, 'utf8')).toBe('private key');
      expect(lstatSync(keyTemp).isDirectory()).toBe(true);
      expect(existsSync(paths.cert)).toBe(false);
    },
  );

  it.skipIf(process.platform === 'win32')(
    'treats an already-moved key temp file as cleaned after a publish error',
    () => {
      const root = fixture();
      const outputDir = join(root, 'out');
      const caDir = join(root, 'ca');
      mkdirSync(outputDir);
      mkdirSync(caDir, { mode: 0o700 });
      const paths = {
        cert: join(outputDir, 'localhost.pem'),
        key: join(outputDir, 'localhost-key.pem'),
      };

      expect(() =>
        writeCertificateFiles(
          paths,
          { cert: 'certificate', key: 'private key' },
          {
            force: true,
            caDir,
            rename(from, to) {
              renameSync(from, to);
              if (to === paths.key) throw new Error('post-rename failure');
            },
          },
        ),
      ).toThrow(
        'Could not write certificate outputs; neither output was replaced. post-rename failure',
      );

      expect(readFileSync(paths.key, 'utf8')).toBe('private key');
      expect(readdirSync(outputDir)).toEqual(['localhost-key.pem']);
    },
  );

  it('reports a publish collision past the pre-check with neither output replaced', () => {
    const root = fixture();
    const outputDir = join(root, 'out');
    const caDir = join(root, 'ca');
    mkdirSync(outputDir);
    mkdirSync(caDir, { mode: 0o700 });
    const paths = {
      cert: join(outputDir, 'localhost.pem'),
      key: join(outputDir, 'localhost-key.pem'),
    };
    const guard: FsGuard = {
      protectDirectory() {},
      assertProtectedDirectory() {},
      assertProtectedFile(path) {
        // Simulate a racer creating the key output after the pre-check.
        if (path.endsWith('.tmp')) writeFileSync(paths.key, 'racing bytes');
      },
    };

    expect(() =>
      writeCertificateFiles(
        paths,
        { cert: 'certificate', key: 'private key' },
        { force: false, caDir, fsGuard: guard },
      ),
    ).toThrow(
      'Could not write certificate outputs; neither output was replaced.',
    );

    expect(readFileSync(paths.key, 'utf8')).toBe('racing bytes');
    expect(existsSync(paths.cert)).toBe(false);
  });

  it('reports a non-Error publish failure without appending a detail', () => {
    const root = fixture();
    const outputDir = join(root, 'out');
    const caDir = join(root, 'ca');
    mkdirSync(outputDir);
    mkdirSync(caDir, { mode: 0o700 });
    const paths = {
      cert: join(outputDir, 'localhost.pem'),
      key: join(outputDir, 'localhost-key.pem'),
    };
    let caught: unknown;

    try {
      writeCertificateFiles(
        paths,
        { cert: 'certificate', key: 'private key' },
        {
          force: true,
          caDir,
          // Windows placement preflight requires a guard.
          ...(process.platform === 'win32' ? { fsGuard: noopGuard } : {}),
          rename(from, to) {
            if (to === paths.key) throw 'string failure';
            renameSync(from, to);
          },
        },
      );
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(CertkitError);
    expect((caught as CertkitError).message).toBe(
      'Could not write certificate outputs; neither output was replaced.',
    );
    expect(existsSync(paths.cert)).toBe(false);
    expect(existsSync(paths.key)).toBe(false);
  });
});
