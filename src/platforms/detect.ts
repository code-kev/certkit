import { constants } from 'node:fs';
import {
  access as nodeAccess,
  readFile as nodeReadFile,
  stat as nodeStat,
} from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';
import { run } from './run.js';

export interface Environment {
  os: 'macos' | 'windows' | 'linux';
  wsl: boolean;
  stores: Array<{
    store: 'macos-keychain' | 'windows-root' | 'linux-system' | 'nss';
    detected: boolean;
    detail?: string;
    targets?: string[];
    installTargets?: string[];
  }>;
}

type ProbeFs = Pick<
  typeof import('node:fs/promises'),
  'access' | 'readFile' | 'stat'
>;

export interface DetectProbes {
  platform?: NodeJS.Platform;
  osRelease?: () => Promise<string>;
  which?: (command: string) => Promise<boolean>;
  fs?: ProbeFs;
}

const exists = async (
  fs: ProbeFs,
  target: string,
  mode?: number,
): Promise<boolean> => {
  try {
    await fs.access(target, mode);
    return true;
  } catch {
    return false;
  }
};

async function isDirectory(fs: ProbeFs, target: string): Promise<boolean> {
  try {
    return (await fs.stat(target)).isDirectory();
  } catch {
    return false;
  }
}

async function hasNssDb(fs: ProbeFs, target: string): Promise<boolean> {
  return (
    (await exists(fs, path.join(target, 'cert9.db'))) ||
    exists(fs, path.join(target, 'cert8.db'))
  );
}

function parseProfiles(
  contents: string,
  base: string,
  pathApi: typeof path,
): string[] {
  const profiles: string[] = [];
  let section = '';
  let fields: Record<string, string> = {};
  const add = () => {
    const profilePath = fields['path'];
    if (!/^Profile\d+$/i.test(section) || !profilePath) return;
    profiles.push(
      fields['isrelative'] === '0'
        ? pathApi.resolve(profilePath)
        : pathApi.resolve(base, profilePath),
    );
  };
  for (const line of contents.split(/\r?\n/)) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (header) {
      add();
      section = header[1] ?? '';
      fields = {};
    } else {
      const entry = /^\s*([^=]+?)\s*=\s*(.*?)\s*$/.exec(line);
      const [, key, value] = entry ?? [];
      if (key !== undefined && value !== undefined)
        fields[key.toLowerCase()] = value;
    }
  }
  add();
  return profiles;
}

export async function detect(probes: DetectProbes = {}): Promise<Environment> {
  const platform = probes.platform ?? process.platform;
  const os =
    platform === 'darwin'
      ? 'macos'
      : platform === 'win32'
        ? 'windows'
        : 'linux';
  const fs = probes.fs ?? {
    access: nodeAccess,
    readFile: nodeReadFile,
    stat: nodeStat,
  };
  const which =
    probes.which ??
    (async (command: string) => {
      try {
        return (await run(['which', command])).code === 0;
      } catch {
        return false;
      }
    });
  const home = homedir();
  const stores: Environment['stores'] = [
    { store: 'macos-keychain', detected: os === 'macos' },
    { store: 'windows-root', detected: os === 'windows' },
  ];

  if (os === 'linux') {
    let detail:
      | 'update-ca-certificates'
      | 'update-ca-trust'
      | 'trust-anchor'
      | undefined;
    for (const [command, name] of [
      ['update-ca-certificates', 'update-ca-certificates'],
      ['update-ca-trust', 'update-ca-trust'],
      ['trust', 'trust-anchor'],
    ] as const) {
      if (await which(command)) {
        detail = name;
        break;
      }
    }
    stores.push({
      store: 'linux-system',
      detected: detail !== undefined,
      ...(detail ? { detail } : {}),
    });
  } else {
    stores.push({ store: 'linux-system', detected: false });
  }

  const wsl =
    os === 'linux' &&
    /microsoft/i.test(
      await (
        probes.osRelease ?? (() => nodeReadFile('/proc/version', 'utf8'))
      )().catch(() => ''),
    );
  const pathApi = os === 'windows' ? path.win32 : path;
  const firefoxBases =
    os === 'windows'
      ? [
          pathApi.join(
            process.env['APPDATA'] ?? pathApi.join(home, 'AppData', 'Roaming'),
            'Mozilla',
            'Firefox',
          ),
        ]
      : os === 'macos'
        ? [pathApi.join(home, 'Library', 'Application Support', 'Firefox')]
        : [
            pathApi.join(home, '.mozilla', 'firefox'),
            pathApi.join(home, '.mozilla', 'firefox-esr'),
            pathApi.join(
              home,
              'snap',
              'firefox',
              'common',
              '.mozilla',
              'firefox',
            ),
            pathApi.join(
              home,
              '.var',
              'app',
              'org.mozilla.firefox',
              '.mozilla',
              'firefox',
            ),
          ];
  const targets: string[] = [];
  for (const base of firefoxBases) {
    try {
      const profiles = parseProfiles(
        await fs.readFile(pathApi.join(base, 'profiles.ini'), 'utf8'),
        base,
        pathApi,
      );
      for (const profile of profiles)
        if (await hasNssDb(fs, profile)) targets.push(profile);
    } catch {
      // Missing profile configuration is normal for a browser that is not installed.
    }
  }

  let chromiumProspect: string | undefined;
  if (os === 'linux') {
    const legacy = pathApi.join(home, '.pki', 'nssdb');
    chromiumProspect = (await isDirectory(fs, legacy))
      ? legacy
      : pathApi.join(
          process.env['XDG_DATA_HOME'] || pathApi.join(home, '.local', 'share'),
          'pki',
          'nssdb',
        );
    for (const target of [
      chromiumProspect,
      pathApi.join(home, 'snap', 'chromium', 'current', '.pki', 'nssdb'),
      '/etc/pki/nssdb',
    ]) {
      if (await hasNssDb(fs, target)) targets.push(target);
    }
  }

  const uniqueTargets = [...new Set(targets)];
  const installTargets: string[] = [];
  for (const target of uniqueTargets) {
    if (
      target !== '/etc/pki/nssdb' &&
      (await exists(fs, target, constants.W_OK | constants.X_OK))
    )
      installTargets.push(target);
  }
  if (chromiumProspect && !uniqueTargets.includes(chromiumProspect))
    installTargets.push(chromiumProspect);
  stores.push({
    store: 'nss',
    detected: uniqueTargets.length > 0,
    targets: uniqueTargets,
    installTargets,
  });
  return { os, wsl, stores };
}
