import { constants } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { detect } from '../../src/platforms/detect.js';

const home = homedir();
const xdg = process.env.XDG_DATA_HOME ?? path.join(home, '.local', 'share');

type Options = {
  platform?: NodeJS.Platform;
  files?: Record<string, string>;
  directories?: string[];
  readOnly?: string[];
  commands?: string[];
  osRelease?: string;
};

function detector(options: Options = {}) {
  const files = new Map(Object.entries(options.files ?? {}));
  const directories = new Set(options.directories ?? []);
  const readOnly = new Set(options.readOnly ?? []);
  const touched = new Set<string>();
  const fs = {
    async access(target: string, mode?: number) {
      touched.add(target);
      if (
        mode !== undefined &&
        (mode & constants.W_OK) !== 0 &&
        readOnly.has(target)
      )
        throw new Error('EACCES');
      if (
        !files.has(target) &&
        !directories.has(target) &&
        ![...files.keys()].some((file) => path.dirname(file) === target)
      )
        throw new Error('ENOENT');
    },
    async stat(target: string) {
      if (
        !files.has(target) &&
        !directories.has(target) &&
        ![...files.keys()].some((file) => path.dirname(file) === target)
      )
        throw new Error('ENOENT');
      return {
        isDirectory: () =>
          directories.has(target) ||
          [...files.keys()].some((file) => path.dirname(file) === target),
      };
    },
    async readFile(target: string) {
      touched.add(target);
      const value = files.get(target);
      if (value === undefined) throw new Error('ENOENT');
      return value;
    },
  };
  return {
    touched,
    detect: () =>
      detect({
        platform: options.platform ?? 'linux',
        osRelease: async () => options.osRelease ?? '',
        which: async (command: string) =>
          options.commands?.includes(command) ?? false,
        fs,
      }),
  };
}

function nss(env: Awaited<ReturnType<typeof detect>>) {
  return env.stores.find(({ store }) => store === 'nss');
}

describe('environment detection', () => {
  it.each([
    ['darwin', 'macos', 'macos-keychain'],
    ['win32', 'windows', 'windows-root'],
    ['linux', 'linux', 'linux-system'],
  ] as const)(
    'maps %s to %s and the matching system store',
    async (platform, os, store) => {
      const result = await detector({ platform }).detect();
      expect(result.os).toBe(os);
      expect(result.stores.find((item) => item.store === store)).toMatchObject({
        detected: platform !== 'linux',
      });
    },
  );

  it('detects WSL from the Linux kernel release', async () => {
    expect(
      await detector({
        osRelease: 'Linux version 5.15.90.1-microsoft-standard-WSL2',
      }).detect(),
    ).toMatchObject({ wsl: true });
  });

  it('reports the installed Linux trust mechanism', async () => {
    const result = await detector({ commands: ['update-ca-trust'] }).detect();
    expect(
      result.stores.find(({ store }) => store === 'linux-system'),
    ).toMatchObject({ detected: true, detail: 'update-ca-trust' });
  });

  it('keeps the clean-home Chromium DB prospective and creates nothing', async () => {
    const run = detector();
    const result = await run.detect();
    const target = path.join(xdg, 'pki', 'nssdb');
    expect(nss(result)).toMatchObject({
      targets: [],
      installTargets: [target],
    });
    expect(run.touched).not.toContain(target);
  });

  it('prefers an existing legacy Chromium directory, even when it has no DB files', async () => {
    const target = path.join(home, '.pki', 'nssdb');
    const result = await detector({ directories: [target] }).detect();
    expect(nss(result)).toMatchObject({
      targets: [],
      installTargets: [target],
    });
  });

  it('keeps read-only Firefox DBs as status targets only', async () => {
    const base = path.join(home, '.mozilla', 'firefox');
    const profile = path.join(base, 'readonly.default');
    const result = await detector({
      files: {
        [path.join(base, 'profiles.ini')]:
          '[Profile0]\nIsRelative=1\nPath=readonly.default\n',
        [path.join(profile, 'cert9.db')]: '',
      },
      readOnly: [profile],
    }).detect();
    expect(nss(result)?.targets).toContain(profile);
    expect(nss(result)?.installTargets).not.toContain(profile);
  });

  it('ignores a regular file at the legacy Chromium DB path', async () => {
    const legacy = path.join(home, '.pki', 'nssdb');
    const result = await detector({ files: { [legacy]: '' } }).detect();
    expect(nss(result)?.installTargets).not.toContain(legacy);
    expect(nss(result)?.installTargets).toContain(
      path.join(xdg, 'pki', 'nssdb'),
    );
  });

  it('honors XDG_DATA_HOME for the prospective Chromium DB', async () => {
    const custom = '/tmp/certkit-xdg';
    const prior = process.env.XDG_DATA_HOME;
    process.env.XDG_DATA_HOME = custom;
    try {
      expect(nss(await detector().detect())?.installTargets).toContain(
        path.join(custom, 'pki', 'nssdb'),
      );
    } finally {
      if (prior === undefined) delete process.env.XDG_DATA_HOME;
      else process.env.XDG_DATA_HOME = prior;
    }
  });

  it('includes relative and absolute Firefox profile DBs', async () => {
    const base = path.join(home, '.mozilla', 'firefox');
    const first = path.join(base, 'abc.default');
    // resolve() anchors a drive-rooted path to the current drive on Windows.
    const second = path.resolve(
      process.platform === 'win32'
        ? '\\custom-firefox-profile'
        : '/tmp/custom-firefox-profile',
    );
    const result = await detector({
      files: {
        [path.join(base, 'profiles.ini')]:
          `[Profile0]\nIsRelative=1\nPath=abc.default\n[Profile1]\nIsRelative=0\nPath=${second}\n`,
        [path.join(first, 'cert9.db')]: '',
        [path.join(second, 'cert9.db')]: '',
      },
    }).detect();
    expect(nss(result)?.targets).toEqual(
      expect.arrayContaining([first, second]),
    );
    expect(nss(result)?.installTargets).toEqual(
      expect.arrayContaining([first, second]),
    );
  });

  it.each([
    [
      'snap',
      (base: string) =>
        path.join(base, 'snap', 'firefox', 'common', '.mozilla', 'firefox'),
    ],
    [
      'flatpak',
      (base: string) =>
        path.join(
          base,
          '.var',
          'app',
          'org.mozilla.firefox',
          '.mozilla',
          'firefox',
        ),
    ],
  ] as const)('finds %s Firefox profiles', async (_kind, profileBase) => {
    const base = profileBase(home);
    const profile = path.join(base, 'release');
    const result = await detector({
      files: {
        [path.join(base, 'profiles.ini')]:
          '[Profile0]\nIsRelative=1\nPath=release\n',
        [path.join(profile, 'cert9.db')]: '',
      },
    }).detect();
    expect(nss(result)?.targets).toContain(profile);
  });

  it('detects an existing snap Chromium DB', async () => {
    const snap = path.join(
      home,
      'snap',
      'chromium',
      'current',
      '.pki',
      'nssdb',
    );
    expect(
      nss(
        await detector({
          files: { [path.join(snap, 'cert9.db')]: '' },
        }).detect(),
      )?.targets,
    ).toContain(snap);
  });

  it('keeps /etc/pki/nssdb read-only', async () => {
    const target = '/etc/pki/nssdb';
    const result = await detector({
      files: { [path.join(target, 'cert9.db')]: '' },
    }).detect();
    expect(nss(result)?.targets).toContain(target);
    expect(nss(result)?.installTargets).not.toContain(target);
  });
});
