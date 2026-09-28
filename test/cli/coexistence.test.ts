import { createHash, X509Certificate } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createInstallCommand } from '../../src/cli/commands/install.js';
import type { TrustCommandDependencies } from '../../src/cli/commands/trust.js';
import { createUninstallCommand } from '../../src/cli/commands/uninstall.js';
import type { Environment } from '../../src/platforms/detect.js';
import {
  createNssAdapter,
  nssCertificateNickname,
} from '../../src/platforms/nss.js';
import type { RunResult } from '../../src/platforms/run.js';
import type { StoreAdapter } from '../../src/platforms/store.js';

const roots: string[] = [];
const certutil = '/fixture/nss/bin/certutil';
const mkcertPem = readFileSync(
  new URL('../fixtures/foreign-cas/mkcert-ca.pem', import.meta.url),
  'utf8',
);
const corporatePem = readFileSync(
  new URL('../fixtures/foreign-cas/corporate-root.pem', import.meta.url),
  'utf8',
);

function fixture(): string {
  const path = mkdtempSync(join(tmpdir(), 'certkit-coexistence-test-'));
  roots.push(path);
  return path;
}

type TestState = {
  phase: string;
  ca: { subject: string; serial: string; sha256: string };
  trustWrites: Array<{
    store: string;
    target: string;
    serial: string;
    sha256: string;
  }>;
  pendingWrites: Array<{ store: string; target: string; sha256: string }>;
};

function state(path: string): TestState {
  return JSON.parse(
    readFileSync(join(path, 'state.json'), 'utf8'),
  ) as TestState;
}

function sha256Of(pem: string): string {
  return createHash('sha256')
    .update(new X509Certificate(pem).raw)
    .digest('hex');
}

function dependencies(
  path: string,
  env: Environment,
  adapters: StoreAdapter[],
): TrustCommandDependencies {
  return {
    resolveCaDir: () => path,
    detect: async () => env,
    adapterFactory: () => adapters,
  };
}

async function invoke(
  command:
    | ReturnType<typeof createInstallCommand>
    | ReturnType<typeof createUninstallCommand>,
): Promise<void> {
  await command.run?.({
    args: { json: true },
    cmd: command,
    rawArgs: [],
    data: {},
  } as never);
}

function output(): { stdout: string[]; stderr: string[] } {
  const stdout: string[] = [];
  const stderr: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...values) => {
    stdout.push(values.join(' '));
  });
  vi.spyOn(console, 'error').mockImplementation((...values) => {
    stderr.push(values.join(' '));
  });
  return { stdout, stderr };
}

function macEnvironmentWithNss(target: string): Environment {
  return {
    os: 'macos',
    wsl: false,
    stores: [
      { store: 'macos-keychain', detected: true },
      { store: 'windows-root', detected: false },
      { store: 'linux-system', detected: false },
      {
        store: 'nss',
        detected: true,
        targets: [target],
        installTargets: [target],
      },
    ],
  };
}

function nssEnvironment(target: string): Environment {
  return {
    os: 'linux',
    wsl: false,
    stores: [
      {
        store: 'nss',
        detected: true,
        targets: [target],
        installTargets: [target],
      },
    ],
  };
}

type PemStore = Map<string, string[]>;

function storeSnapshot(store: PemStore): Record<string, string[]> {
  return Object.fromEntries(
    [...store].map(([target, pems]) => [target, [...pems]]),
  );
}

function preservingAdapter(
  id: StoreAdapter['id'],
  store: PemStore,
): StoreAdapter {
  const entries = (target: string) => store.get(target) ?? [];
  return {
    id,
    async inspectInstalled(pem, target) {
      return entries(target).includes(pem) ? 'present' : 'absent';
    },
    async checkTrust(pem, env) {
      const targets = env.stores.find((item) => item.store === id)?.targets ?? [
        'default',
      ];
      return targets.map((target) => ({
        target,
        state: entries(target).includes(pem)
          ? ('trusted' as const)
          : ('untrusted' as const),
      }));
    },
    async install(path, target) {
      store.set(target, [...entries(target), readFileSync(path, 'utf8')]);
      return { state: 'verified' as const };
    },
    async uninstall(pem, target) {
      store.set(
        target,
        entries(target).filter((entry) => entry !== pem),
      );
    },
  };
}

function fakeNssDatabase(): {
  adapter: StoreAdapter;
  entries: Map<string, string>;
  extraRows: string[];
} {
  const entries = new Map<string, string>();
  const extraRows: string[] = [];
  const ok = (stdout = '', code = 0): RunResult => ({
    code,
    stdout,
    stderr: '',
  });
  const run = async (argv: string[]): Promise<RunResult> => {
    const nickname = argv[argv.indexOf('-n') + 1] ?? '';
    if (argv[1] === '-A') {
      entries.set(
        nickname,
        readFileSync(argv[argv.indexOf('-i') + 1] ?? '', 'utf8'),
      );
      return ok();
    }
    if (argv[1] === '-D') {
      entries.delete(nickname);
      return ok();
    }
    if (argv.includes('-n')) {
      const pem = entries.get(nickname);
      return ok(pem ?? '', pem ? 0 : 1);
    }
    const rows = [...entries.keys()]
      .map((name) => `${name} C,,`)
      .concat(extraRows);
    return ok(
      `Certificate Nickname Trust Attributes\n                   SSL,S/MIME,JAR/XPI\n\n${rows.join('\n')}\n`,
    );
  };
  return {
    adapter: createNssAdapter({
      run,
      resolveCertutil: async () => certutil,
      fs: { mkdir: async () => {}, hasDatabaseFile: () => true },
    }),
    entries,
    extraRows,
  };
}

beforeEach(() => {
  process.exitCode = 0;
});

afterEach(() => {
  vi.restoreAllMocks();
  process.exitCode = 0;
  for (const path of roots.splice(0))
    rmSync(path, { recursive: true, force: true });
});

describe('coexistence', () => {
  it('preserves foreign CA bytes through install and uninstall', async () => {
    const root = fixture();
    const path = join(root, 'ca');
    const nssTarget = join(root, 'nssdb');
    const env = macEnvironmentWithNss(nssTarget);
    const keychain: PemStore = new Map([['default', [mkcertPem]]]);
    const nss: PemStore = new Map([[nssTarget, [corporatePem]]]);
    const before = {
      keychain: storeSnapshot(keychain),
      nss: storeSnapshot(nss),
    };
    const adapters = [
      preservingAdapter('macos-keychain', keychain),
      preservingAdapter('nss', nss),
    ];
    const deps = dependencies(path, env, adapters);

    output();
    await invoke(createInstallCommand(deps));

    expect(process.exitCode).toBe(0);
    const installed = state(path);
    const foreignSha256 = [mkcertPem, corporatePem].map(sha256Of);
    expect(installed.trustWrites).toHaveLength(2);
    for (const write of installed.trustWrites) {
      expect(write.serial).toBe(installed.ca.serial);
      expect(write.sha256).toBe(installed.ca.sha256);
      expect(foreignSha256).not.toContain(write.sha256);
    }
    expect(installed.pendingWrites).toEqual([]);
    const ourPem = readFileSync(join(path, 'ca-cert.pem'), 'utf8');
    expect(keychain.get('default')).toEqual([mkcertPem, ourPem]);
    expect(nss.get(nssTarget)).toEqual([corporatePem, ourPem]);

    process.exitCode = 0;
    await invoke(createUninstallCommand(deps));

    expect(process.exitCode).toBe(0);
    expect(existsSync(path)).toBe(false);
    expect(storeSnapshot(keychain)).toEqual(before.keychain);
    expect(storeSnapshot(nss)).toEqual(before.nss);
  });

  it('keeps two same-subject certkit CAs apart by fingerprint nickname', async () => {
    const root = fixture();
    const dirA = join(root, 'ca-a');
    const dirB = join(root, 'ca-b');
    const target = join(root, 'nssdb');
    const env = nssEnvironment(target);
    const db = fakeNssDatabase();
    const deps = (dir: string) => dependencies(dir, env, [db.adapter]);

    output();
    await invoke(createInstallCommand(deps(dirA)));
    expect(process.exitCode).toBe(0);
    process.exitCode = 0;
    await invoke(createInstallCommand(deps(dirB)));
    expect(process.exitCode).toBe(0);

    const stateA = state(dirA);
    const stateB = state(dirB);
    expect(stateA.ca.subject).toBe(stateB.ca.subject);
    expect(stateA.ca.sha256).not.toBe(stateB.ca.sha256);
    const pemA = readFileSync(join(dirA, 'ca-cert.pem'), 'utf8');
    const pemB = readFileSync(join(dirB, 'ca-cert.pem'), 'utf8');
    const nicknameA = nssCertificateNickname(pemA);
    const nicknameB = nssCertificateNickname(pemB);
    expect(nicknameA).not.toBe(nicknameB);
    expect(stateA.trustWrites).toMatchObject([
      {
        store: 'nss',
        target,
        serial: stateA.ca.serial,
        sha256: stateA.ca.sha256,
      },
    ]);
    expect(stateB.trustWrites).toMatchObject([
      {
        store: 'nss',
        target,
        serial: stateB.ca.serial,
        sha256: stateB.ca.sha256,
      },
    ]);
    expect(db.entries.get(nicknameA)).toBe(pemA);
    expect(db.entries.get(nicknameB)).toBe(pemB);
    await expect(db.adapter.checkTrust(pemA, env)).resolves.toEqual([
      { state: 'trusted', target },
    ]);
    await expect(db.adapter.checkTrust(pemB, env)).resolves.toEqual([
      { state: 'trusted', target },
    ]);

    process.exitCode = 0;
    await invoke(createUninstallCommand(deps(dirA)));

    expect(process.exitCode).toBe(0);
    expect(existsSync(dirA)).toBe(false);
    expect(db.entries.has(nicknameA)).toBe(false);
    expect(db.entries.get(nicknameB)).toBe(pemB);
    await expect(db.adapter.checkTrust(pemB, env)).resolves.toEqual([
      { state: 'trusted', target },
    ]);
    await expect(db.adapter.checkTrust(pemA, env)).resolves.toEqual([
      { state: 'untrusted', target },
    ]);
  });

  it('refuses ambiguous-nickname removal and retains recovery data', async () => {
    const root = fixture();
    const dir = join(root, 'ca');
    const target = join(root, 'nssdb');
    const env = nssEnvironment(target);
    const db = fakeNssDatabase();
    const deps = dependencies(dir, env, [db.adapter]);

    output();
    await invoke(createInstallCommand(deps));
    expect(process.exitCode).toBe(0);
    const pem = readFileSync(join(dir, 'ca-cert.pem'), 'utf8');
    const nickname = nssCertificateNickname(pem);
    db.extraRows.push(`${nickname} C,,`);

    process.exitCode = 0;
    const result = output();
    await invoke(createUninstallCommand(deps));

    expect(process.exitCode).toBe(1);
    expect(JSON.parse(result.stdout[0] ?? '')).toMatchObject({
      results: [
        {
          store: 'nss',
          target,
          state: 'unknown',
          error: {
            code: 'STORE_WRITE_FAILED',
            message:
              'The derived NSS certificate nickname is ambiguous; no certificate was removed and CA recovery data was retained.',
          },
        },
      ],
    });
    expect(db.entries.get(nickname)).toBe(pem);
    const retained = state(dir);
    expect(retained.phase).toBe('retiring');
    expect(retained.trustWrites).toMatchObject([
      { store: 'nss', target, sha256: retained.ca.sha256 },
    ]);
    expect(existsSync(join(dir, 'ca-cert.pem'))).toBe(true);
    expect(existsSync(join(dir, 'ca-key.pem'))).toBe(true);

    db.extraRows.length = 0;
    process.exitCode = 0;
    await invoke(createUninstallCommand(deps));

    expect(process.exitCode).toBe(0);
    expect(db.entries.has(nickname)).toBe(false);
    expect(existsSync(dir)).toBe(false);
  });
});
