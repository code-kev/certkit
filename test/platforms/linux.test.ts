import { lstat, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { mintCa } from '../../src/core/certgen.js';
import type { Environment } from '../../src/platforms/detect.js';
import {
  createLinuxAdapter,
  type LinuxTrustMechanism,
  linuxActiveStorePath,
  linuxAnchorTarget,
  linuxAnchorTempTarget,
} from '../../src/platforms/linux.js';
import type { RunResult } from '../../src/platforms/run.js';

const tempDirs: string[] = [];
const environment = (mechanism: LinuxTrustMechanism): Environment => ({
  os: 'linux',
  wsl: false,
  stores: [
    {
      store: 'linux-system',
      detected: true,
      detail: mechanism,
    },
  ],
});

afterEach(async () => {
  for (const dir of tempDirs.splice(0))
    await rm(dir, { recursive: true, force: true });
});

async function fixture(): Promise<{
  caCertPath: string;
  ca: string;
  other: string;
  files: Map<string, string>;
  commands: string[][];
  adapter: ReturnType<typeof createLinuxAdapter>;
}> {
  const dir = await mkdtemp(join(tmpdir(), 'certkit linux -'));
  tempDirs.push(dir);
  const caCertPath = join(dir, 'ca-cert.pem');
  const ca = (await mintCa('fixture')).certPem;
  const other = (await mintCa('fixture')).certPem;
  await writeFile(caCertPath, ca);
  const files = new Map<string, string>();
  const commands: string[][] = [];
  const adapter = createLinuxAdapter({
    caCertPath,
    async run(argv) {
      commands.push(argv);
      return {
        code: 0,
        stdout: files.get(linuxActiveStorePath('trust-anchor')) ?? '',
        stderr: '',
      };
    },
    async elevate(argv) {
      commands.push(argv);
      if (argv[0] === 'install') {
        files.set(argv[4] ?? '', ca);
      } else if (argv[0] === 'mv') {
        const temporary = argv[3] ?? '';
        const target = argv[4] ?? '';
        const contents = files.get(temporary);
        if (contents !== undefined) files.set(target, contents);
        files.delete(temporary);
      } else if (argv[0] === 'rm') {
        files.delete(argv[2] ?? '');
      } else if (argv[0] === 'trust' && argv[1] === 'anchor') {
        if (argv[2] === '--remove')
          files.delete(linuxActiveStorePath('trust-anchor'));
        else files.set(linuxActiveStorePath('trust-anchor'), ca);
      } else if (argv[0] === 'update-ca-certificates') {
        files.set(
          linuxActiveStorePath('update-ca-certificates'),
          [...files.entries()]
            .filter(([path]) =>
              path.startsWith('/usr/local/share/ca-certificates/'),
            )
            .map(([, contents]) => contents)
            .join('\n'),
        );
      } else if (argv[0] === 'update-ca-trust') {
        // p11-kit emits `# <name>` comment lines between certificates.
        files.set(
          linuxActiveStorePath('update-ca-trust'),
          [...files.entries()]
            .filter(([path]) =>
              path.startsWith('/etc/pki/ca-trust/source/anchors/'),
            )
            .map(([, contents]) => `# fixture CA\n${contents}`)
            .join('\n'),
        );
      }
    },
    fs: fixtureFs(files, caCertPath),
  });
  return { caCertPath, ca, other, files, commands, adapter };
}

function result(stdout = '', code = 0): RunResult {
  return { code, stdout, stderr: '' };
}

function missingError(path: string): NodeJS.ErrnoException {
  const error = new Error(
    `ENOENT: no such file or directory, open '${path}'`,
  ) as NodeJS.ErrnoException;
  error.code = 'ENOENT';
  return error;
}

function fixtureFs(
  files: Map<string, string>,
  caCertPath: string,
): NonNullable<Parameters<typeof createLinuxAdapter>[0]['fs']> {
  return {
    async readFile(path) {
      const value = files.get(path);
      if (value !== undefined) return value;
      if (path === caCertPath) return readFile(path, 'utf8');
      throw missingError(path);
    },
    async lstat(path) {
      if (files.has(path))
        return { isFile: () => true, isSymbolicLink: () => false };
      if (path === caCertPath) return lstat(path);
      throw missingError(path);
    },
  };
}

describe('Linux system trust adapter', () => {
  it.each([
    ['update-ca-certificates', '/usr/local/share/ca-certificates/'],
    ['update-ca-trust', '/etc/pki/ca-trust/source/anchors/'],
    ['trust-anchor', undefined],
  ] as const)('installs and verifies with %s', async (mechanism, prefix) => {
    const { caCertPath, commands, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, mechanism);

    await expect(
      adapter.install(caCertPath, target, mechanism),
    ).resolves.toEqual({
      state: 'verified',
    });
    if (prefix) expect(target.startsWith(prefix)).toBe(true);
    else expect(target).toBe(caCertPath);
    expect(commands).toEqual(
      mechanism === 'update-ca-certificates'
        ? [
            [
              'install',
              '-m',
              '0644',
              caCertPath,
              linuxAnchorTempTarget(target),
            ],
            ['mv', '-f', '--', linuxAnchorTempTarget(target), target],
            ['update-ca-certificates'],
          ]
        : mechanism === 'update-ca-trust'
          ? [
              [
                'install',
                '-m',
                '0644',
                caCertPath,
                linuxAnchorTempTarget(target),
              ],
              ['mv', '-f', '--', linuxAnchorTempTarget(target), target],
              ['update-ca-trust', 'extract'],
            ]
          : [
              ['trust', 'anchor', caCertPath],
              ['trust', 'list', '--filter=ca-anchors', '--format=pem'],
            ],
    );
  });

  it('retains a written anchor when rebuilding fails', async () => {
    const { caCertPath, commands, files } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-certificates');
    const broken = createLinuxAdapter({
      caCertPath,
      run: async () => result(),
      elevate: async (argv) => {
        commands.push(argv);
        if (argv[0] === 'install')
          files.set(argv[4] ?? '', await readFile(caCertPath, 'utf8'));
        else if (argv[0] === 'mv') {
          files.set(target, files.get(argv[3] ?? '') ?? '');
          files.delete(argv[3] ?? '');
        } else throw new Error('rebuild failed');
      },
      fs: fixtureFs(files, caCertPath),
    });

    await expect(
      broken.install(caCertPath, target, 'update-ca-certificates'),
    ).rejects.toMatchObject({ code: 'STORE_WRITE_FAILED' });
    await expect(
      broken.inspectInstalled(
        await readFile(caCertPath, 'utf8'),
        target,
        'update-ca-certificates',
      ),
    ).resolves.toBe('present');
    expect(commands).toEqual([
      ['install', '-m', '0644', caCertPath, linuxAnchorTempTarget(target)],
      ['mv', '-f', '--', linuxAnchorTempTarget(target), target],
      ['update-ca-certificates'],
    ]);
  });

  it('recognizes a copied temporary anchor and completes its atomic rename on retry', async () => {
    const { caCertPath, ca, files, commands, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-certificates');
    const temporary = linuxAnchorTempTarget(target);
    files.set(temporary, ca);

    await expect(
      adapter.inspectInstalled(ca, target, 'update-ca-certificates'),
    ).resolves.toBe('present');
    await expect(
      adapter.install(caCertPath, target, 'update-ca-certificates'),
    ).resolves.toEqual({ state: 'verified' });
    expect(commands).toEqual([
      ['mv', '-f', '--', temporary, target],
      ['update-ca-certificates'],
    ]);
  });

  it('returns inconclusive only when active-store read-back is unavailable', async () => {
    const { caCertPath, commands } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'trust-anchor');
    const unavailable = createLinuxAdapter({
      caCertPath,
      async run(argv) {
        commands.push(argv);
        throw new Error('read-back unavailable');
      },
      async elevate(argv) {
        commands.push(argv);
      },
    });

    await expect(
      unavailable.install(caCertPath, target, 'trust-anchor'),
    ).resolves.toMatchObject({ state: 'inconclusive' });
    expect(commands).toEqual([
      ['trust', 'anchor', caCertPath],
      ['trust', 'list', '--filter=ca-anchors', '--format=pem'],
    ]);

    commands.length = 0;
    const missingFingerprint = createLinuxAdapter({
      caCertPath,
      run: async () => result(''),
      elevate: async (argv) => {
        commands.push(argv);
      },
    });
    await expect(
      missingFingerprint.install(caCertPath, target, 'trust-anchor'),
    ).rejects.toMatchObject({ code: 'STORE_WRITE_FAILED' });
  });

  it('reports trust only from active-store fingerprint read-back', async () => {
    const { ca, other, files, adapter, caCertPath } = await fixture();
    files.set(linuxActiveStorePath('update-ca-certificates'), other);
    await expect(
      adapter.checkTrust(ca, environment('update-ca-certificates')),
    ).resolves.toMatchObject([{ state: 'untrusted' }]);
    files.set(
      linuxActiveStorePath('update-ca-certificates'),
      `${other}\n${ca}`,
    );
    await expect(
      adapter.checkTrust(ca, environment('update-ca-certificates')),
    ).resolves.toMatchObject([{ state: 'trusted' }]);
    files.delete(linuxActiveStorePath('update-ca-certificates'));
    await expect(
      adapter.checkTrust(ca, environment('update-ca-certificates')),
    ).resolves.toMatchObject([{ state: 'unknown' }]);
    expect(linuxAnchorTarget(caCertPath, 'update-ca-certificates')).not.toBe(
      'default',
    );
  });

  it('uninstalls the persisted mechanism and target, then verifies absence', async () => {
    const { caCertPath, commands, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');
    await adapter.install(caCertPath, target, 'update-ca-trust');
    commands.length = 0;

    await adapter.uninstall(
      await readFile(caCertPath, 'utf8'),
      target,
      'update-ca-trust',
    );

    expect(commands).toEqual([
      ['rm', '--', target],
      ['update-ca-trust', 'extract'],
    ]);
    await expect(
      adapter.inspectInstalled(
        await readFile(caCertPath, 'utf8'),
        target,
        'update-ca-trust',
      ),
    ).resolves.toBe('absent');
  });

  it('refuses to remove an anchor that contains another certificate', async () => {
    const { caCertPath, ca, other, files, commands, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');
    await adapter.install(caCertPath, target, 'update-ca-trust');
    const mixedAnchor = `${ca}\n${other}`;
    files.set(target, mixedAnchor);
    commands.length = 0;

    await expect(
      adapter.uninstall(ca, target, 'update-ca-trust'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringMatching(/manual|inspect/i),
    });

    expect(files.get(target)).toBe(mixedAnchor);
    expect(commands).toEqual([]);
  });

  it('preflights the temporary anchor before removing a matching anchor', async () => {
    const { caCertPath, ca, other, files, commands, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');
    const temporary = linuxAnchorTempTarget(target);
    await adapter.install(caCertPath, target, 'update-ca-trust');
    const mixedTemporary = `${ca}\n${other}`;
    files.set(temporary, mixedTemporary);
    commands.length = 0;

    await expect(
      adapter.uninstall(ca, target, 'update-ca-trust'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringMatching(/manual|inspect/i),
    });

    expect(files.get(target)).toBe(ca);
    expect(files.get(temporary)).toBe(mixedTemporary);
    expect(commands).toEqual([]);
  });

  it('removes a trust anchor by its exact path and skips removal when already absent', async () => {
    const { caCertPath, commands, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'trust-anchor');
    const ca = await readFile(caCertPath, 'utf8');
    await adapter.install(caCertPath, target, 'trust-anchor');
    commands.length = 0;

    await adapter.uninstall(ca, target, 'trust-anchor');

    expect(commands).toEqual([
      ['trust', 'list', '--filter=ca-anchors', '--format=pem'],
      ['trust', 'anchor', '--remove', caCertPath],
      ['trust', 'list', '--filter=ca-anchors', '--format=pem'],
    ]);
    commands.length = 0;
    await adapter.uninstall(ca, target, 'trust-anchor');
    expect(commands).toEqual([
      ['trust', 'list', '--filter=ca-anchors', '--format=pem'],
      ['trust', 'list', '--filter=ca-anchors', '--format=pem'],
    ]);
  });

  it('resolves the mechanism from the target when none is recorded', async () => {
    const { caCertPath, ca, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');

    await expect(adapter.inspectInstalled(ca, target)).resolves.toBe('absent');
    await expect(adapter.install(caCertPath, target)).resolves.toEqual({
      state: 'verified',
    });
    await expect(adapter.inspectInstalled(ca, target)).resolves.toBe('present');
    await expect(adapter.uninstall(ca, target)).resolves.toBeUndefined();

    const otherTarget = linuxAnchorTarget(caCertPath, 'update-ca-certificates');
    await expect(
      adapter.inspectInstalled(ca, otherTarget, 'update-ca-trust'),
    ).resolves.toBe('inconclusive');
    await expect(
      adapter.inspectInstalled(ca, target, 'not-a-mechanism'),
    ).resolves.toBe('inconclusive');
    await expect(
      adapter.inspectInstalled(
        ca,
        '/etc/pki/ca-trust/source/anchors/other.pem',
      ),
    ).resolves.toBe('inconclusive');
  });

  it('inspects trust-anchor installs through the active store', async () => {
    const { caCertPath, ca, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'trust-anchor');

    await expect(
      adapter.inspectInstalled(ca, target, 'trust-anchor'),
    ).resolves.toBe('absent');
    await adapter.install(caCertPath, target, 'trust-anchor');
    await expect(
      adapter.inspectInstalled(ca, target, 'trust-anchor'),
    ).resolves.toBe('present');

    const failing = createLinuxAdapter({
      caCertPath,
      run: async () => result('', 1),
    });
    await expect(
      failing.inspectInstalled(ca, target, 'trust-anchor'),
    ).resolves.toBe('inconclusive');
  });

  it('treats non-file or unreadable anchors as inconclusive', async () => {
    const { caCertPath, ca, files } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');
    const denied = Object.assign(new Error('EACCES: permission denied'), {
      code: 'EACCES',
    });
    const cases: Array<
      NonNullable<Parameters<typeof createLinuxAdapter>[0]['fs']>['lstat']
    > = [
      async () => ({ isFile: () => false, isSymbolicLink: () => true }),
      async () => ({ isFile: () => false, isSymbolicLink: () => false }),
      async () => {
        throw denied;
      },
    ];
    for (const riggedLstat of cases) {
      const rigged = createLinuxAdapter({
        caCertPath,
        run: async () => result(),
        fs: { ...fixtureFs(files, caCertPath), lstat: riggedLstat },
      });
      await expect(
        rigged.inspectInstalled(ca, target, 'update-ca-trust'),
      ).resolves.toBe('inconclusive');
    }
    const unreadable = createLinuxAdapter({
      caCertPath,
      run: async () => result(),
      fs: {
        lstat: async () => ({
          isFile: () => true,
          isSymbolicLink: () => false,
        }),
        readFile: async () => {
          throw denied;
        },
      },
    });
    await expect(
      unreadable.inspectInstalled(ca, target, 'update-ca-trust'),
    ).resolves.toBe('inconclusive');
  });

  it('reports anchors with unparseable contents as different', async () => {
    const { caCertPath, ca, files, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');

    files.set(target, 'not a certificate');
    await expect(
      adapter.inspectInstalled(ca, target, 'update-ca-trust'),
    ).resolves.toBe('absent');
    files.set(
      target,
      '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----',
    );
    await expect(
      adapter.inspectInstalled(ca, target, 'update-ca-trust'),
    ).resolves.toBe('absent');
  });

  it('returns inconclusive when the anchor or CA PEM cannot be parsed', async () => {
    const { caCertPath, ca, files, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');
    files.set(target, ca);

    await expect(
      adapter.inspectInstalled('not a pem', target, 'update-ca-trust'),
    ).resolves.toBe('inconclusive');

    const temporary = linuxAnchorTempTarget(target);
    files.delete(target);
    const symlinkedTemporary = createLinuxAdapter({
      caCertPath,
      run: async () => result(),
      fs: {
        ...fixtureFs(files, caCertPath),
        async lstat(path) {
          if (path === temporary)
            return { isFile: () => false, isSymbolicLink: () => true };
          if (files.has(path))
            return { isFile: () => true, isSymbolicLink: () => false };
          if (path === caCertPath) return lstat(path);
          throw missingError(path);
        },
      },
    });
    await expect(
      symlinkedTemporary.inspectInstalled(ca, target, 'update-ca-trust'),
    ).resolves.toBe('inconclusive');
  });

  it('reports not-detected without a detected linux-system store', async () => {
    const { ca, adapter } = await fixture();
    const expected = [{ state: 'not-detected', target: 'default' }];
    await expect(
      adapter.checkTrust(ca, { os: 'macos', wsl: false, stores: [] }),
    ).resolves.toEqual(expected);
    await expect(
      adapter.checkTrust(ca, { os: 'linux', wsl: false, stores: [] }),
    ).resolves.toEqual(expected);
    await expect(
      adapter.checkTrust(ca, {
        os: 'linux',
        wsl: false,
        stores: [{ store: 'linux-system', detected: false }],
      }),
    ).resolves.toEqual(expected);
  });

  it('reports unknown for unsupported mechanisms and uninspectable stores', async () => {
    const { ca, files, adapter } = await fixture();

    await expect(
      adapter.checkTrust(ca, {
        os: 'linux',
        wsl: false,
        stores: [{ store: 'linux-system', detected: true, detail: 'bogus' }],
      }),
    ).resolves.toEqual([
      {
        state: 'unknown',
        target: 'default',
        detail: 'The detected Linux trust mechanism is unsupported.',
      },
    ]);

    files.set(linuxActiveStorePath('update-ca-certificates'), ca);
    await expect(
      adapter.checkTrust(ca, {
        os: 'linux',
        wsl: false,
        stores: [
          {
            store: 'linux-system',
            detected: true,
            detail: 'update-ca-certificates',
            targets: ['/custom/target'],
          },
        ],
      }),
    ).resolves.toEqual([{ state: 'trusted', target: '/custom/target' }]);

    files.set(linuxActiveStorePath('update-ca-certificates'), 'garbage');
    await expect(
      adapter.checkTrust(ca, environment('update-ca-certificates')),
    ).resolves.toMatchObject([{ state: 'unknown' }]);

    files.set(linuxActiveStorePath('update-ca-certificates'), ca);
    await expect(
      adapter.checkTrust('not a pem', environment('update-ca-certificates')),
    ).resolves.toMatchObject([{ state: 'unknown' }]);
  });

  it('rejects installs to unrecognized targets', async () => {
    const { caCertPath, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');

    await expect(
      adapter.install(caCertPath, '/etc/ssl/certs/other.pem'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('not recognized'),
    });
    await expect(
      adapter.install(caCertPath, target, 'not-a-mechanism'),
    ).rejects.toMatchObject({ code: 'STORE_WRITE_FAILED' });
    await expect(
      adapter.uninstall('unused', '/etc/ssl/certs/other.pem'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('not recognized'),
    });
  });

  it('preserves a different or uninspectable anchor on install', async () => {
    const { caCertPath, other, files, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');

    files.set(target, other);
    await expect(
      adapter.install(caCertPath, target, 'update-ca-trust'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining(target),
    });
    expect(files.get(target)).toBe(other);

    const inconclusive = createLinuxAdapter({
      caCertPath,
      run: async () => result(),
      elevate: async () => {},
      fs: {
        ...fixtureFs(files, caCertPath),
        lstat: async () => ({
          isFile: () => false,
          isSymbolicLink: () => true,
        }),
      },
    });
    await expect(
      inconclusive.install(caCertPath, target, 'update-ca-trust'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('could not be inspected'),
    });
  });

  it('preflights the temporary anchor on install', async () => {
    const { caCertPath, other, files, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');
    const temporary = linuxAnchorTempTarget(target);

    files.set(temporary, other);
    await expect(
      adapter.install(caCertPath, target, 'update-ca-trust'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('temporary Linux anchor'),
    });
    expect(files.get(temporary)).toBe(other);

    files.delete(temporary);
    const inconclusive = createLinuxAdapter({
      caCertPath,
      run: async () => result(),
      elevate: async () => {},
      fs: {
        ...fixtureFs(files, caCertPath),
        async lstat(path) {
          if (path === temporary)
            return { isFile: () => false, isSymbolicLink: () => true };
          if (files.has(path))
            return { isFile: () => true, isSymbolicLink: () => false };
          if (path === caCertPath) return lstat(path);
          throw missingError(path);
        },
      },
    });
    await expect(
      inconclusive.install(caCertPath, target, 'update-ca-trust'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining(
        'temporary Linux anchor target could not be inspected',
      ),
    });
  });

  it('fails without an elevate hook when the anchor must be written', async () => {
    const { caCertPath, files } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');
    const noElevate = createLinuxAdapter({
      caCertPath,
      run: async () => result(),
      fs: fixtureFs(files, caCertPath),
    });

    await expect(
      noElevate.install(caCertPath, target, 'update-ca-trust'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('rerun `certkit install`'),
    });
  });

  it('only rebuilds when the anchor is already present', async () => {
    const { caCertPath, ca, files, commands, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');
    files.set(target, ca);

    await expect(
      adapter.install(caCertPath, target, 'update-ca-trust'),
    ).resolves.toEqual({ state: 'verified' });
    expect(commands).toEqual([['update-ca-trust', 'extract']]);
  });

  it('wraps unexpected install failures', async () => {
    const { caCertPath, files } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');
    const broken = createLinuxAdapter({
      caCertPath,
      run: async () => result(),
      elevate: async () => {},
      fs: {
        ...fixtureFs(files, caCertPath),
        async readFile(path) {
          if (path === caCertPath) throw new Error('disk gone');
          const value = files.get(path);
          if (value !== undefined) return value;
          throw missingError(path);
        },
      },
    });

    await expect(
      broken.install(caCertPath, target, 'update-ca-trust'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining(
        'Could not verify the Linux system trust install',
      ),
    });
  });

  it('guards trust-anchor removal by fingerprint and store readability', async () => {
    const { caCertPath, ca, other, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'trust-anchor');

    await expect(
      adapter.uninstall(other, target, 'trust-anchor'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('does not match the CA fingerprint'),
    });

    const blind = createLinuxAdapter({
      caCertPath,
      run: async () => result('', 1),
      elevate: async () => {},
    });
    await expect(
      blind.uninstall(ca, target, 'trust-anchor'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('could not be inspected'),
    });
  });

  it('preserves uninspectable anchors on uninstall', async () => {
    const { caCertPath, ca, files } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');
    const temporary = linuxAnchorTempTarget(target);
    const rigged = (symlinkPath: string) =>
      createLinuxAdapter({
        caCertPath,
        run: async () => result(),
        elevate: async () => {},
        fs: {
          ...fixtureFs(files, caCertPath),
          async lstat(path) {
            if (path === symlinkPath)
              return { isFile: () => false, isSymbolicLink: () => true };
            if (files.has(path))
              return { isFile: () => true, isSymbolicLink: () => false };
            if (path === caCertPath) return lstat(path);
            throw missingError(path);
          },
        },
      });

    await expect(
      rigged(target).uninstall(ca, target, 'update-ca-trust'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining(
        'Linux anchor target could not be inspected',
      ),
    });
    await expect(
      rigged(temporary).uninstall(ca, target, 'update-ca-trust'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining(
        'temporary Linux anchor target could not be inspected',
      ),
    });
  });

  it('removes a matching temporary anchor on uninstall', async () => {
    const { caCertPath, ca, files, commands, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');
    const temporary = linuxAnchorTempTarget(target);
    files.set(temporary, ca);

    await adapter.uninstall(ca, target, 'update-ca-trust');

    expect(commands).toEqual([
      ['rm', '--', temporary],
      ['update-ca-trust', 'extract'],
    ]);
    expect(files.has(temporary)).toBe(false);
  });

  it('fails closed when removal cannot be verified', async () => {
    const { caCertPath, ca, files, commands } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');
    const lingering = createLinuxAdapter({
      caCertPath,
      run: async () => result(),
      async elevate(argv) {
        commands.push(argv);
      },
      fs: fixtureFs(files, caCertPath),
    });

    files.set(linuxActiveStorePath('update-ca-trust'), ca);
    await expect(
      lingering.uninstall(ca, target, 'update-ca-trust'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining(
        'remains in the active Linux trust store',
      ),
    });

    files.delete(linuxActiveStorePath('update-ca-trust'));
    await expect(
      lingering.uninstall(ca, target, 'update-ca-trust'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('could not be read after removal'),
    });
  });

  it('wraps unexpected uninstall failures', async () => {
    const { caCertPath, ca, files, adapter } = await fixture();
    const target = linuxAnchorTarget(caCertPath, 'update-ca-trust');
    files.set(target, ca);

    await expect(
      adapter.uninstall('not a pem', target, 'update-ca-trust'),
    ).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: expect.stringContaining('Could not complete Linux CA removal'),
    });
  });
});
