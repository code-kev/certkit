import { spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createInstallCommand } from '../../src/cli/commands/install.js';
import {
  adaptersById,
  adapterTargets,
  emitDryRun,
  emitResults,
  inspectInstalled,
  planInstall,
  planUninstall,
  resolveDependencies,
  type TrustCommandDependencies,
  targetTrustState,
  toErrorResult,
} from '../../src/cli/commands/trust.js';
import { createUninstallCommand } from '../../src/cli/commands/uninstall.js';
import { shQuote } from '../../src/cli/elevate.js';
import type { FsGuard } from '../../src/core/cadir.js';
import { certificateFor as certificateForCore } from '../../src/core/certificate.js';
import { CertkitError } from '../../src/core/errors.js';
import { detect, type Environment } from '../../src/platforms/detect.js';
import {
  linuxAnchorTarget,
  linuxAnchorTempTarget,
} from '../../src/platforms/linux.js';
import { nssCertificateNickname } from '../../src/platforms/nss.js';
import type { StoreAdapter } from '../../src/platforms/store.js';

const roots: string[] = [];

// Trust orchestration, not ACLs: Windows gets a no-op guard (real icacls is
// covered by the fsGuard/cadir tests).
const stubGuard: FsGuard = {
  protectDirectory() {},
  assertProtectedDirectory() {},
  assertProtectedFile() {},
};

function guardOptions(): { fsGuard?: FsGuard } {
  return process.platform === 'win32' ? { fsGuard: stubGuard } : {};
}

function certificateFor(
  names: string[],
  options: { caDir: string },
): ReturnType<typeof certificateForCore> {
  return certificateForCore(names, options, guardOptions());
}
let previousHome: string | undefined;
const loginKeychainPath = join(
  homedir(),
  'Library',
  'Keychains',
  'login.keychain-db',
);

function fixture(): string {
  const path = mkdtempSync(join(tmpdir(), 'certkit-install-test-'));
  roots.push(path);
  return path;
}

function macEnvironment(wsl = false): Environment {
  return {
    os: 'macos',
    wsl,
    stores: [
      { store: 'macos-keychain', detected: true },
      { store: 'windows-root', detected: false },
      { store: 'linux-system', detected: false },
      { store: 'nss', detected: false, targets: [], installTargets: [] },
    ],
  };
}

function macEnvironmentWithNss(target = '/tmp/firefox-profile'): Environment {
  const env = macEnvironment();
  const nss = env.stores.find((store) => store.store === 'nss');
  if (!nss) throw new Error('macOS fixture is missing NSS detection');
  nss.detected = true;
  nss.targets = [target];
  nss.installTargets = [target];
  return env;
}

function windowsEnvironment(): Environment {
  return {
    os: 'windows',
    wsl: false,
    stores: [
      { store: 'macos-keychain', detected: false },
      { store: 'windows-root', detected: true },
      { store: 'linux-system', detected: false },
      { store: 'nss', detected: false, targets: [], installTargets: [] },
    ],
  };
}

function linuxEnvironment(mechanism: string): Environment {
  return {
    os: 'linux',
    wsl: false,
    stores: [
      { store: 'macos-keychain', detected: false },
      { store: 'windows-root', detected: false },
      { store: 'linux-system', detected: true, detail: mechanism },
      { store: 'nss', detected: false, targets: [], installTargets: [] },
    ],
  };
}

function twoDatabaseEnvironment(): Environment {
  return {
    os: 'linux',
    wsl: false,
    stores: [
      { store: 'macos-keychain', detected: false },
      { store: 'windows-root', detected: false },
      { store: 'linux-system', detected: false },
      {
        store: 'nss',
        detected: true,
        targets: ['/tmp/profile-a', '/tmp/profile-b'],
        installTargets: ['/tmp/profile-a', '/tmp/profile-b'],
      },
    ],
  };
}

function fakeAdapter(
  id: StoreAdapter['id'],
  installed = new Set<string>(),
): StoreAdapter & {
  installed: Set<string>;
  installCalls: string[];
  installMechanisms: Array<string | undefined>;
  uninstallCalls: string[];
  uninstallMechanisms: Array<string | undefined>;
  failInstall: Set<string>;
  failUninstall: Set<string>;
  inconclusiveInstall: Set<string>;
  inconclusiveInspect: Set<string>;
  unknownTrust: Set<string>;
} {
  const adapter = {
    id,
    installed,
    installCalls: [] as string[],
    installMechanisms: [] as Array<string | undefined>,
    uninstallCalls: [] as string[],
    uninstallMechanisms: [] as Array<string | undefined>,
    failInstall: new Set<string>(),
    failUninstall: new Set<string>(),
    inconclusiveInstall: new Set<string>(),
    inconclusiveInspect: new Set<string>(),
    unknownTrust: new Set<string>(),
    async checkTrust(_pem, env) {
      const targets = env.stores.find((store) => store.store === id)
        ?.targets ?? ['default'];
      return targets.map((target) => ({
        target,
        state: this.unknownTrust.has(target)
          ? ('unknown' as const)
          : installed.has(target)
            ? ('trusted' as const)
            : ('untrusted' as const),
        ...(this.unknownTrust.has(target)
          ? { detail: `policy unavailable for ${target}` }
          : {}),
      }));
    },
    async inspectInstalled(_pem, target) {
      if (this.inconclusiveInspect.has(target)) return 'inconclusive' as const;
      return installed.has(target) ? ('present' as const) : ('absent' as const);
    },
    async install(_path, target, mechanism) {
      this.installCalls.push(target);
      this.installMechanisms.push(mechanism);
      if (this.failInstall.delete(target))
        throw new CertkitError(
          'STORE_WRITE_FAILED',
          `failed ${target}; manual command`,
        );
      if (this.inconclusiveInstall.delete(target))
        return {
          state: 'inconclusive' as const,
          detail: `read-back unavailable for ${target}`,
        };
      installed.add(target);
      return { state: 'verified' as const };
    },
    async uninstall(_pem, target, mechanism) {
      this.uninstallCalls.push(target);
      this.uninstallMechanisms.push(mechanism);
      if (this.failUninstall.delete(target))
        throw new CertkitError(
          'STORE_WRITE_FAILED',
          `failed removal ${target}; manual command`,
        );
      installed.delete(target);
    },
  };
  return adapter;
}

function dependencies(
  path: string,
  env: Environment,
  adapters: StoreAdapter[],
  overrides: Partial<TrustCommandDependencies> = {},
): TrustCommandDependencies {
  return {
    resolveCaDir: () => path,
    detect: async () => env,
    adapterFactory: () => adapters,
    ...guardOptions(),
    ...overrides,
  };
}

async function invoke(
  command:
    | ReturnType<typeof createInstallCommand>
    | ReturnType<typeof createUninstallCommand>,
  args: Record<string, unknown> = {},
): Promise<void> {
  await command.run?.({ args, cmd: command, rawArgs: [], data: {} } as never);
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

type TestState = {
  phase: string;
  ca: { serial: string; sha256: string };
  trustWrites: Array<{
    store: string;
    target: string;
    mechanism?: string;
    serial: string;
    sha256: string;
    timestamp: string;
  }>;
  pendingWrites: Array<{
    store: string;
    target: string;
    mechanism?: string;
    sha256: string;
    timestamp: string;
  }>;
};

function state(path: string): TestState {
  return JSON.parse(
    readFileSync(join(path, 'state.json'), 'utf8'),
  ) as TestState;
}

beforeEach(() => {
  previousHome = process.env.CERTKIT_HOME;
  process.exitCode = 0;
});

afterEach(() => {
  vi.restoreAllMocks();
  if (previousHome === undefined) delete process.env.CERTKIT_HOME;
  else process.env.CERTKIT_HOME = previousHome;
  process.exitCode = 0;
  for (const path of roots.splice(0))
    rmSync(path, { recursive: true, force: true });
});

describe('install command', () => {
  it('quotes hostile path segments for the sudo-prompt command string', () => {
    expect(shQuote("/tmp/ev il'$(touch /tmp/pwned)`/")).toBe(
      "'/tmp/ev il'\\''$(touch /tmp/pwned)`/'",
    );
  });

  it.skipIf(process.platform === 'win32')(
    'keeps hostile substitutions literal when the quoted argument is parsed by sh',
    () => {
      const root = fixture();
      const marker = join(root, 'shell-injection-ran');
      const hostile = `space '$(touch ${marker})' \`touch ${marker}\` $HOME`;
      const result = spawnSync(
        '/bin/sh',
        ['-c', `printf '%s' ${shQuote(hostile)}`],
        { encoding: 'utf8' },
      );

      expect(result.status).toBe(0);
      expect(result.stdout).toBe(hostile);
      expect(existsSync(marker)).toBe(false);
    },
  );

  it('creates the CA and records only a verified target receipt', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('macos-keychain');
    const result = output();

    await invoke(
      createInstallCommand(dependencies(path, macEnvironment(), [adapter])),
      {
        json: true,
      },
    );

    expect(process.exitCode).toBe(0);
    expect(JSON.parse(result.stdout[0] ?? '')).toMatchObject({
      schemaVersion: 1,
      results: [
        { store: 'macos-keychain', target: 'default', state: 'trusted' },
      ],
    });
    expect(adapter.installCalls).toEqual(['default']);
    expect(state(path).trustWrites).toMatchObject([
      { store: 'macos-keychain', target: 'default' },
    ]);
    expect(state(path).pendingWrites).toEqual([]);
  });

  it('uninstalls a Linux anchor using its recorded mechanism after detection changes', async () => {
    const path = join(fixture(), 'ca');
    const certPath = join(path, 'ca-cert.pem');
    const adapter = fakeAdapter('linux-system');
    const firstInstall = output();
    let failRebuild = true;
    adapter.install = async (_path, target, mechanism) => {
      adapter.installCalls.push(target);
      adapter.installMechanisms.push(mechanism);
      adapter.installed.add(target);
      if (failRebuild) {
        failRebuild = false;
        throw new CertkitError(
          'STORE_WRITE_FAILED',
          'simulated update-ca-certificates rebuild failure',
        );
      }
      return { state: 'verified' };
    };
    const originalTarget = linuxAnchorTarget(
      certPath,
      'update-ca-certificates',
    );
    const newlyDetectedTarget = linuxAnchorTarget(certPath, 'update-ca-trust');

    await invoke(
      createInstallCommand(
        dependencies(path, linuxEnvironment('update-ca-certificates'), [
          adapter,
        ]),
      ),
      { json: true },
    );

    expect(process.exitCode).toBe(1);
    expect(state(path).pendingWrites).toMatchObject([
      {
        store: 'linux-system',
        target: originalTarget,
        mechanism: 'update-ca-certificates',
      },
    ]);
    expect(state(path).trustWrites).toEqual([]);
    const failedResult = JSON.parse(firstInstall.stdout[0] ?? '') as {
      results: Array<Record<string, unknown>>;
    };
    expect(failedResult.results[0]).not.toHaveProperty('mechanism');

    process.exitCode = 0;
    await invoke(
      createInstallCommand(
        dependencies(path, linuxEnvironment('update-ca-certificates'), [
          adapter,
        ]),
      ),
      { json: true },
    );

    expect(state(path).trustWrites).toMatchObject([
      {
        store: 'linux-system',
        target: originalTarget,
        mechanism: 'update-ca-certificates',
      },
    ]);
    expect(adapter.installMechanisms).toEqual([
      'update-ca-certificates',
      'update-ca-certificates',
    ]);

    process.exitCode = 0;
    await invoke(
      createUninstallCommand(
        dependencies(path, linuxEnvironment('update-ca-trust'), [adapter]),
      ),
      { json: true },
    );

    expect(adapter.uninstallCalls).toEqual([
      newlyDetectedTarget,
      originalTarget,
    ]);
    expect(adapter.uninstallMechanisms).toEqual([
      'update-ca-trust',
      'update-ca-certificates',
    ]);
    expect(existsSync(path)).toBe(false);
  });

  it('plans Linux dry-run commands for the exact anchor target', () => {
    const certPath = '/tmp/certkit/ca-cert.pem';
    const environment = linuxEnvironment('update-ca-certificates');
    const targets = adapterTargets(environment, 'install', certPath);
    const target = linuxAnchorTarget(certPath, 'update-ca-certificates');

    expect(targets).toEqual([
      {
        store: 'linux-system',
        target,
      },
    ]);
    expect(targets[0]?.mechanism).toBe('update-ca-certificates');
    expect(planInstall(targets, certPath, true)).toEqual([
      {
        ...targets[0],
        command: `sudo 'install' '-m' '0644' '${certPath}' '${linuxAnchorTempTarget(target)}' && sudo 'mv' '-f' '--' '${linuxAnchorTempTarget(target)}' '${target}' && sudo 'update-ca-certificates'`,
        manual: `sudo 'install' '-m' '0644' '${certPath}' '${linuxAnchorTempTarget(target)}' && sudo 'mv' '-f' '--' '${linuxAnchorTempTarget(target)}' '${target}' && sudo 'update-ca-certificates'`,
      },
    ]);
    expect(
      planUninstall(targets, certPath, true).map(({ command }) => command),
    ).toEqual([
      `sudo 'rm' '-f' '--' '${target}' && sudo 'rm' '-f' '--' '${linuxAnchorTempTarget(target)}' && sudo 'update-ca-certificates'`,
    ]);
  });

  it('retries a present but untrusted target after a failed partial install', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('macos-keychain');
    let installed = false;
    let trusted = false;
    adapter.inspectInstalled = async () => (installed ? 'present' : 'absent');
    adapter.checkTrust = async () => [
      { target: 'default', state: trusted ? 'trusted' : 'untrusted' },
    ];
    adapter.install = async (_path, target) => {
      adapter.installCalls.push(target);
      installed = true;
      if (adapter.installCalls.length === 1)
        throw new CertkitError(
          'STORE_WRITE_FAILED',
          'simulated elevated command failure after certificate write',
        );
      trusted = true;
      return { state: 'verified' };
    };
    const result = output();

    await invoke(
      createInstallCommand(dependencies(path, macEnvironment(), [adapter])),
      { json: true },
    );

    expect(process.exitCode).toBe(1);
    expect(adapter.installCalls).toEqual(['default']);
    expect(await adapter.inspectInstalled('unused', 'default')).toBe('present');
    await expect(
      adapter.checkTrust('unused', macEnvironment()),
    ).resolves.toEqual([{ target: 'default', state: 'untrusted' }]);
    expect(state(path).pendingWrites).toHaveLength(1);
    expect(state(path).trustWrites).toEqual([]);

    process.exitCode = 0;
    await invoke(
      createInstallCommand(dependencies(path, macEnvironment(), [adapter])),
      { json: true },
    );

    expect(process.exitCode).toBe(0);
    expect(adapter.installCalls).toEqual(['default', 'default']);
    expect(state(path).pendingWrites).toEqual([]);
    expect(state(path).trustWrites).toHaveLength(1);
    expect(JSON.parse(result.stdout[1] ?? '')).toMatchObject({
      results: [
        { store: 'macos-keychain', target: 'default', state: 'trusted' },
      ],
    });
  });

  it('records a verified write even when effective trust remains unknown', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('macos-keychain');
    adapter.unknownTrust.add('default');
    const result = output();

    await invoke(
      createInstallCommand(dependencies(path, macEnvironment(), [adapter])),
      { json: true },
    );

    expect(process.exitCode).toBe(0);
    const outputJson = JSON.parse(result.stdout[0] ?? '');
    expect(outputJson).toMatchObject({
      results: [
        {
          store: 'macos-keychain',
          target: 'default',
          state: 'unknown',
          detail: 'policy unavailable for default',
        },
      ],
    });
    expect(outputJson.results[0]).not.toHaveProperty('error');
    expect(state(path).trustWrites).toHaveLength(1);
    expect(state(path).pendingWrites).toEqual([]);
    expect(adapter.installCalls).toEqual(['default']);
  });

  it('exits 1 when a verified install remains effectively untrusted', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('macos-keychain');
    adapter.checkTrust = async () => [
      {
        target: 'default',
        state: 'untrusted',
        detail: 'policy rejects the CA',
      },
    ];
    const result = output();

    await invoke(
      createInstallCommand(dependencies(path, macEnvironment(), [adapter])),
      { json: true },
    );

    expect(process.exitCode).toBe(1);
    expect(JSON.parse(result.stdout[0] ?? '')).toMatchObject({
      results: [
        {
          store: 'macos-keychain',
          target: 'default',
          state: 'untrusted',
          detail: 'policy rejects the CA',
        },
      ],
    });
    expect(state(path).trustWrites).toHaveLength(1);
    expect(state(path).pendingWrites).toEqual([]);
  });

  it('installs supported macOS targets and reports detected NSS targets as unsupported', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('macos-keychain');
    const result = output();

    await invoke(
      createInstallCommand(
        dependencies(path, macEnvironmentWithNss(), [adapter]),
      ),
      { json: true },
    );

    expect(process.exitCode).toBe(1);
    expect(adapter.installCalls).toEqual(['default']);
    expect(JSON.parse(result.stdout[0] ?? '')).toMatchObject({
      results: [
        { store: 'macos-keychain', target: 'default', state: 'trusted' },
        {
          store: 'nss',
          target: '/tmp/firefox-profile',
          state: 'unknown',
          error: { code: 'UNSUPPORTED_PLATFORM' },
        },
      ],
    });
    expect(state(path).trustWrites.map((write) => write.store)).toEqual([
      'macos-keychain',
    ]);
  });

  it('reports unsupported-only targets as a never-ran error without leaving a CA directory', async () => {
    const path = join(fixture(), 'ca');
    const result = output();

    await invoke(
      createInstallCommand(dependencies(path, twoDatabaseEnvironment(), [])),
      { json: true },
    );

    expect(process.exitCode).toBe(2);
    expect(JSON.parse(result.stdout[0] ?? '')).toMatchObject({
      schemaVersion: 1,
      error: {
        code: 'UNSUPPORTED_PLATFORM',
        message: expect.stringContaining(
          'nss (/tmp/profile-a), nss (/tmp/profile-b)',
        ),
      },
    });
    expect(existsSync(path)).toBe(false);
  });

  it('persists pending before a command and reconciles a crash before that command', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('macos-keychain');
    let crash = true;
    const deps = dependencies(path, macEnvironment(), [adapter], {
      onEvent(event) {
        if (event.type === 'install:pending' && crash) {
          crash = false;
          throw new Error('simulated process stop');
        }
      },
    });

    await invoke(createInstallCommand(deps), { json: true });
    expect(state(path).pendingWrites).toHaveLength(1);
    expect(adapter.installCalls).toEqual([]);

    await invoke(
      createInstallCommand(dependencies(path, macEnvironment(), [adapter])),
      {
        json: true,
      },
    );
    expect(state(path).pendingWrites).toEqual([]);
    expect(state(path).trustWrites).toHaveLength(1);
  });

  it('retries a present target after a crash before promotion for a fresh receipt', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('macos-keychain');
    let crash = true;

    await invoke(
      createInstallCommand(
        dependencies(path, macEnvironment(), [adapter], {
          onEvent(event) {
            if (event.type === 'install:receipt' && crash) {
              crash = false;
              throw new Error('simulated process stop');
            }
          },
        }),
      ),
      { json: true },
    );
    expect(state(path).pendingWrites).toHaveLength(1);

    await invoke(
      createInstallCommand(dependencies(path, macEnvironment(), [adapter])),
      {
        json: true,
      },
    );

    expect(adapter.installCalls).toEqual(['default', 'default']);
    expect(state(path).pendingWrites).toEqual([]);
    expect(state(path).trustWrites).toHaveLength(1);
  });

  it('keeps an uninspectable pending write and retries when the target is inspectable', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('macos-keychain');
    let crash = true;

    await invoke(
      createInstallCommand(
        dependencies(path, macEnvironment(), [adapter], {
          onEvent(event) {
            if (event.type === 'install:receipt' && crash) {
              crash = false;
              throw new Error('simulated process stop');
            }
          },
        }),
      ),
      { json: true },
    );
    expect(state(path).pendingWrites).toHaveLength(1);
    adapter.inconclusiveInspect.add('default');
    process.exitCode = 0;
    const uncertain = output();

    await invoke(
      createInstallCommand(dependencies(path, macEnvironment(), [adapter])),
      { json: true },
    );

    expect(process.exitCode).toBe(1);
    expect(adapter.installCalls).toEqual(['default']);
    expect(state(path).pendingWrites).toHaveLength(1);
    expect(JSON.parse(uncertain.stdout[0] ?? '')).toMatchObject({
      results: [
        {
          state: 'unknown',
          error: { code: 'STORE_WRITE_FAILED' },
        },
      ],
    });

    adapter.inconclusiveInspect.delete('default');
    process.exitCode = 0;
    await invoke(
      createInstallCommand(dependencies(path, macEnvironment(), [adapter])),
      { json: true },
    );

    expect(adapter.installCalls).toEqual(['default', 'default']);
    expect(state(path).pendingWrites).toEqual([]);
    expect(state(path).trustWrites).toHaveLength(1);
  });

  it('keeps a pending target unresolved after detection no longer reports it', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('nss');
    let crash = true;
    await invoke(
      createInstallCommand(
        dependencies(path, twoDatabaseEnvironment(), [adapter], {
          onEvent(event) {
            if (event.type === 'install:receipt' && crash) {
              crash = false;
              throw new Error('simulated process stop');
            }
          },
        }),
      ),
      { json: true },
    );
    expect(state(path).pendingWrites).toHaveLength(1);

    const noLongerDetected: Environment = {
      os: 'linux',
      wsl: false,
      stores: [
        { store: 'macos-keychain', detected: false },
        { store: 'windows-root', detected: false },
        { store: 'linux-system', detected: false },
        { store: 'nss', detected: false, targets: [], installTargets: [] },
      ],
    };
    process.exitCode = 0;
    const result = output();
    await invoke(
      createInstallCommand(dependencies(path, noLongerDetected, [adapter])),
      {
        json: true,
      },
    );

    expect(process.exitCode).toBe(1);
    expect(adapter.installCalls).toEqual(['/tmp/profile-a']);
    expect(state(path).pendingWrites).toHaveLength(1);
    expect(state(path).trustWrites).toEqual([]);
    expect(JSON.parse(result.stdout[0] ?? '')).toMatchObject({
      results: [
        {
          store: 'nss',
          target: '/tmp/profile-a',
          state: 'unknown',
          error: { code: 'STORE_WRITE_FAILED' },
          detail: expect.stringContaining('no longer detected'),
        },
      ],
    });
  });

  it('resumes after target A was promoted and before target B became pending', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('nss');
    let crash = true;
    await invoke(
      createInstallCommand(
        dependencies(path, twoDatabaseEnvironment(), [adapter], {
          onEvent(event) {
            if (
              event.type === 'install:promoted' &&
              event.target === '/tmp/profile-a' &&
              crash
            ) {
              crash = false;
              throw new Error('simulated process stop');
            }
          },
        }),
      ),
      { json: true },
    );
    expect(state(path).trustWrites.map((write) => write.target)).toEqual([
      '/tmp/profile-a',
    ]);
    expect(state(path).pendingWrites).toEqual([]);

    process.exitCode = 0;
    await invoke(
      createInstallCommand(
        dependencies(path, twoDatabaseEnvironment(), [adapter]),
      ),
      {
        json: true,
      },
    );
    expect(adapter.installCalls).toEqual(['/tmp/profile-a', '/tmp/profile-b']);
    expect(state(path).trustWrites.map((write) => write.target)).toEqual([
      '/tmp/profile-a',
      '/tmp/profile-b',
    ]);
  });

  it('retries only the failed database after partial success', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('nss');
    adapter.failInstall.add('/tmp/profile-b');
    const first = output();

    await invoke(
      createInstallCommand(
        dependencies(path, twoDatabaseEnvironment(), [adapter]),
      ),
      {
        json: true,
      },
    );

    expect(process.exitCode).toBe(1);
    expect(JSON.parse(first.stdout[0] ?? '')).toMatchObject({
      schemaVersion: 1,
      results: [
        { store: 'nss', target: '/tmp/profile-a', state: 'trusted' },
        {
          store: 'nss',
          target: '/tmp/profile-b',
          error: {
            code: 'STORE_WRITE_FAILED',
            message: expect.stringContaining('manual command'),
          },
        },
      ],
    });
    expect(state(path).trustWrites.map((write) => write.target)).toEqual([
      '/tmp/profile-a',
    ]);
    expect(state(path).pendingWrites).toEqual([]);

    process.exitCode = 0;
    await invoke(
      createInstallCommand(
        dependencies(path, twoDatabaseEnvironment(), [adapter]),
      ),
      {
        json: true,
      },
    );
    expect(adapter.installCalls).toEqual([
      '/tmp/profile-a',
      '/tmp/profile-b',
      '/tmp/profile-b',
    ]);
    expect(state(path).trustWrites.map((write) => write.target)).toEqual([
      '/tmp/profile-a',
      '/tmp/profile-b',
    ]);
  });

  it('keeps inconclusive receipts pending and retries them', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('macos-keychain');
    adapter.inconclusiveInstall.add('default');
    const first = output();

    await invoke(
      createInstallCommand(dependencies(path, macEnvironment(), [adapter])),
      {
        json: true,
      },
    );
    expect(process.exitCode).toBe(1);
    expect(JSON.parse(first.stdout[0] ?? '')).toMatchObject({
      results: [{ target: 'default', state: 'unknown' }],
    });
    expect(state(path).pendingWrites).toHaveLength(1);
    expect(state(path).trustWrites).toEqual([]);

    process.exitCode = 0;
    await invoke(
      createInstallCommand(dependencies(path, macEnvironment(), [adapter])),
      {
        json: true,
      },
    );
    expect(adapter.installCalls).toEqual(['default', 'default']);
    expect(state(path).pendingWrites).toEqual([]);
    expect(state(path).trustWrites).toHaveLength(1);
  });

  it('prints a WSL warning before attempting Linux trust operations', async () => {
    const path = join(fixture(), 'ca');
    const env = twoDatabaseEnvironment();
    env.wsl = true;
    const adapter = fakeAdapter('nss');
    const result = output();

    await invoke(createInstallCommand(dependencies(path, env, [adapter])), {
      json: true,
    });

    expect(result.stderr[0]).toMatch(/WSL.*Windows side/i);
    expect(adapter.installCalls).toHaveLength(2);
  });

  it('dry-run prints a safe user-domain command for a fresh home without creating state', async () => {
    const path = join(fixture(), "ev il'$(touch /tmp/pwned)", 'ca');
    const result = output();

    await invoke(
      createInstallCommand(
        dependencies(path, macEnvironment(), [fakeAdapter('macos-keychain')]),
      ),
      {
        'dry-run': true,
        json: true,
      },
    );

    expect(process.exitCode).toBe(0);
    expect(existsSync(path)).toBe(false);
    expect(result.stderr).toEqual([]);
    expect(JSON.parse(result.stdout[0] ?? '')).toMatchObject({
      schemaVersion: 1,
      dryRun: true,
      commands: [
        {
          store: 'macos-keychain',
          target: 'default',
          command: expect.stringContaining('<ca-cert.pem>'),
          manual: expect.stringContaining('<ca-cert.pem>'),
        },
      ],
    });
    const command = JSON.parse(result.stdout[0] ?? '').commands[0] as {
      command: string;
      manual: string;
    };
    expect(command.command).toContain(`'-k' '${loginKeychainPath}'`);
    expect(command.command).not.toContain('sudo ');
    expect(command.manual).toBe(command.command);
    expect(command.command).toContain("'<ca-cert.pem>'");
  });

  it('registers Windows current-user install and removal commands by default', async () => {
    const path = join(fixture(), 'home with spaces', 'ca');
    const result = output();
    const originalPlatform = process.platform;
    Object.defineProperty(process, 'platform', { value: 'win32' });
    try {
      const dependencies: TrustCommandDependencies = {
        resolveCaDir: () => path,
        detect: async () => windowsEnvironment(),
      };
      await invoke(createInstallCommand(dependencies), {
        'dry-run': true,
        json: true,
      });
      await invoke(createUninstallCommand(dependencies), {
        'dry-run': true,
        json: true,
      });
    } finally {
      Object.defineProperty(process, 'platform', { value: originalPlatform });
    }

    expect(existsSync(path)).toBe(false);
    expect(JSON.parse(result.stdout[0] ?? '')).toMatchObject({
      commands: [
        {
          store: 'windows-root',
          target: 'default',
          command: 'certutil -user -addstore Root "<ca-cert.pem>"',
          manual: 'certutil -user -addstore Root "<ca-cert.pem>"',
        },
      ],
      unsupported: [],
    });
    expect(JSON.parse(result.stdout[1] ?? '')).toMatchObject({
      commands: [
        {
          store: 'windows-root',
          target: 'default',
          command: 'certutil -user -delstore Root "<sha1-thumbprint>"',
          manual: 'certutil -user -delstore Root "<sha1-thumbprint>"',
        },
      ],
      unsupported: [],
    });
  });

  it('registers NSS install and removal dry-run plans on every OS', async () => {
    const path = join(fixture(), 'ca');
    const target = '/home/test/.mozilla/firefox/profile.default';
    const env: Environment = {
      os: 'linux',
      wsl: false,
      stores: [
        { store: 'macos-keychain', detected: false },
        { store: 'windows-root', detected: false },
        { store: 'linux-system', detected: false },
        {
          store: 'nss',
          detected: true,
          targets: [target, '/etc/pki/nssdb'],
          installTargets: [target, '/etc/pki/nssdb'],
        },
      ],
    };
    const dependencies: TrustCommandDependencies = {
      resolveCaDir: () => path,
      detect: async () => env,
    };
    const result = output();
    const originalPlatform = process.platform;
    try {
      for (const platform of ['darwin', 'win32', 'linux'] as const) {
        Object.defineProperty(process, 'platform', { value: platform });
        await invoke(createInstallCommand(dependencies), {
          'dry-run': true,
          json: true,
        });
        await invoke(createUninstallCommand(dependencies), {
          'dry-run': true,
          json: true,
        });
      }
    } finally {
      Object.defineProperty(process, 'platform', { value: originalPlatform });
    }

    expect(existsSync(path)).toBe(false);
    for (const line of result.stdout) {
      const report = JSON.parse(line) as {
        commands: Array<{
          store: string;
          target: string;
          command: string;
          manual: string;
        }>;
      };
      expect(report.commands).toHaveLength(1);
      expect(report.commands[0]).toMatchObject({ store: 'nss', target });
    }
    expect(result.stdout).toHaveLength(6);
    expect(result.stdout.join('\n')).not.toContain('/etc/pki/nssdb');
    expect(result.stdout[0]).toContain("'-A'");
    expect(result.stdout[0]).toContain("'certkit development CA <sha256>'");
    expect(result.stdout[1]).toContain("'-D'");
    expect(result.stdout[1]).toContain("'certkit development CA <sha256>'");
  });

  it('NSS removal guidance requires fingerprint inspection and stops on duplicates', async () => {
    const path = join(fixture(), 'ca');
    await certificateFor(['localhost'], { caDir: path });
    const db = join(fixture(), 'nssdb');

    const [plan] = planUninstall(
      [{ store: 'nss', target: db }],
      join(path, 'ca-cert.pem'),
      true,
      state(path).ca.sha256,
    );

    expect(plan.manual).toContain('certutil');
    expect(plan.manual).toContain('-L');
    expect(plan.manual).toContain('SHA-256 fingerprint');
    expect(plan.manual).toContain('more than one entry');
    expect(plan.manual).toContain('stop');
    expect(plan.manual).toContain(plan.command);
    expect(plan.command).toContain('-D');
  });

  it('uses the exact certificate SHA-1 thumbprint in Windows removal plans', async () => {
    const path = join(fixture(), 'ca');
    await certificateFor(['localhost'], { caDir: path });
    const sha1 = new X509Certificate(
      readFileSync(join(path, 'ca-cert.pem'), 'utf8'),
    ).fingerprint
      .replaceAll(':', '')
      .toUpperCase();

    expect(
      planUninstall(
        [{ store: 'windows-root', target: 'default' }],
        join(path, 'ca-cert.pem'),
        true,
        state(path).ca.sha256,
      ),
    ).toEqual([
      {
        store: 'windows-root',
        target: 'default',
        command: `certutil -user -delstore Root "${sha1}"`,
        manual: `certutil -user -delstore Root "${sha1}"`,
      },
    ]);
  });

  it('states that macOS may request native authentication without collecting a password', async () => {
    const path = join(fixture(), 'ca');
    const result = output();

    await invoke(
      createInstallCommand(
        dependencies(path, macEnvironment(), [fakeAdapter('macos-keychain')]),
      ),
      { 'dry-run': true },
    );

    expect(result.stdout).toContain(
      'macOS may request native user authentication; Certkit never collects a password.',
    );
    expect(existsSync(path)).toBe(false);
  });

  it('dry-run reports detected targets outside the registered adapter set', async () => {
    const path = join(fixture(), 'ca');
    const result = output();

    await invoke(
      createInstallCommand(
        dependencies(path, macEnvironmentWithNss(), [
          fakeAdapter('macos-keychain'),
        ]),
      ),
      { 'dry-run': true, json: true },
    );

    expect(process.exitCode).toBe(0);
    expect(JSON.parse(result.stdout[0] ?? '')).toMatchObject({
      commands: [{ store: 'macos-keychain', target: 'default' }],
      unsupported: [
        {
          store: 'nss',
          target: '/tmp/firefox-profile',
          state: 'unknown',
          error: { code: 'UNSUPPORTED_PLATFORM' },
        },
      ],
    });
    expect(existsSync(path)).toBe(false);
  });

  it('quotes the CA path in dry-run commands when the identity already exists', async () => {
    const path = join(fixture(), "ev il'$(touch /tmp/pwned)", 'ca');
    await certificateFor(['localhost'], { caDir: path });
    const statePath = join(path, 'state.json');
    const caState = state(path);
    caState.pendingWrites.push({
      store: 'nss',
      target: '/tmp/profile-unresolved',
      sha256: caState.ca.sha256,
      timestamp: new Date().toISOString(),
    });
    writeFileSync(statePath, `${JSON.stringify(caState, null, 2)}\n`);
    const before = readFileSync(statePath);
    const result = output();

    await invoke(
      createInstallCommand(
        dependencies(path, macEnvironment(), [fakeAdapter('macos-keychain')]),
      ),
      {
        'dry-run': true,
        json: true,
      },
    );

    const commands = JSON.parse(result.stdout[0] ?? '') as {
      commands: Array<{ command: string; manual: string }>;
    };
    expect(commands.commands[0]?.command).toContain("'\\''");
    expect(commands.commands[0]?.command).toContain(
      `'-k' '${loginKeychainPath}'`,
    );
    expect(commands.commands[0]?.command).toContain(
      shQuote(join(path, 'ca-cert.pem')),
    );
    expect(commands.commands[0]?.manual).toBe(commands.commands[0]?.command);
    expect(commands.unresolved).toMatchObject([
      {
        store: 'nss',
        target: '/tmp/profile-unresolved',
        state: 'unknown',
      },
    ]);
    expect(readFileSync(statePath)).toEqual(before);
  });

  it('dry-run prints ordered trust removal and fingerprint-scoped deletion commands', async () => {
    const path = join(fixture(), 'ca');
    const result = output();

    await invoke(
      createUninstallCommand(
        dependencies(path, macEnvironment(), [fakeAdapter('macos-keychain')]),
      ),
      { 'dry-run': true, json: true },
    );

    const commands = JSON.parse(result.stdout[0] ?? '').commands as Array<{
      command: string;
      manual: string;
    }>;
    const expected = [
      ['security', 'remove-trusted-cert', '<ca-cert.pem>'],
      ['security', 'delete-certificate', '-Z', '<sha256>', loginKeychainPath],
    ].map((argv) => argv.map(shQuote).join(' '));
    expect(commands.map(({ command }) => command)).toEqual(expected);
    expect(commands.map(({ manual }) => manual)).toEqual(expected);
  });
});

describe('uninstall command', () => {
  it('does not start retirement when every detected uninstall target is unsupported', async () => {
    const path = join(fixture(), 'ca');
    await certificateFor(['localhost'], { caDir: path });
    const statePath = join(path, 'state.json');
    const before = readFileSync(statePath);
    const result = output();

    await invoke(
      createUninstallCommand(dependencies(path, twoDatabaseEnvironment(), [])),
      { json: true },
    );

    expect(process.exitCode).toBe(2);
    expect(JSON.parse(result.stdout[0] ?? '')).toMatchObject({
      error: {
        code: 'UNSUPPORTED_PLATFORM',
        message: expect.stringContaining(
          'nss (/tmp/profile-a), nss (/tmp/profile-b)',
        ),
      },
    });
    expect(readFileSync(statePath)).toEqual(before);
    expect(existsSync(join(path, 'ca-cert.pem'))).toBe(true);
  });

  it('cleans a validated interrupted trust-settings export from an older run', async () => {
    const path = join(fixture(), 'ca');
    await certificateFor(['localhost'], { caDir: path });
    const exportDir = join(path, '.certkit-trust-a1b2c3');
    mkdirSync(exportDir, { mode: 0o700 });
    writeFileSync(join(exportDir, 'admin-settings.plist'), '<plist/>', {
      mode: 0o600,
    });
    const adapter = fakeAdapter('macos-keychain');

    await invoke(
      createUninstallCommand(dependencies(path, macEnvironment(), [adapter])),
      { json: true },
    );

    expect(process.exitCode).toBe(0);
    expect(existsSync(exportDir)).toBe(false);
    expect(existsSync(path)).toBe(false);
  });

  it.skipIf(process.platform === 'win32')(
    'preserves a symlink that resembles an interrupted trust export directory',
    async () => {
      const root = fixture();
      const path = join(root, 'ca');
      await certificateFor(['localhost'], { caDir: path });
      const foreignDir = join(root, 'foreign');
      mkdirSync(foreignDir);
      const foreignFile = join(foreignDir, 'keep.txt');
      writeFileSync(foreignFile, 'foreign bytes');
      const exportLink = join(path, '.certkit-trust-a1b2c3');
      symlinkSync(foreignDir, exportLink, 'dir');
      const adapter = fakeAdapter('macos-keychain');
      const result = output();

      await invoke(
        createUninstallCommand(dependencies(path, macEnvironment(), [adapter])),
        { json: true },
      );

      expect(process.exitCode).toBe(1);
      expect(JSON.parse(result.stdout[0] ?? '')).toMatchObject({
        error: { code: 'CA_UNREADABLE' },
      });
      expect(readFileSync(foreignFile, 'utf8')).toBe('foreign bytes');
      expect(lstatSync(exportLink).isSymbolicLink()).toBe(true);
      expect(existsSync(join(path, 'ca-cert.pem'))).toBe(true);
      expect(existsSync(join(path, 'state.json'))).toBe(true);
    },
  );

  it('removes supported targets and retains identity for a detected unsupported NSS target', async () => {
    const path = join(fixture(), 'ca');
    await certificateFor(['localhost'], { caDir: path });
    const caState = state(path);
    caState.trustWrites.push({
      store: 'macos-keychain',
      target: 'default',
      serial: caState.ca.serial,
      sha256: caState.ca.sha256,
      timestamp: new Date().toISOString(),
    });
    writeFileSync(
      join(path, 'state.json'),
      `${JSON.stringify(caState, null, 2)}\n`,
    );
    const adapter = fakeAdapter('macos-keychain', new Set(['default']));
    const result = output();

    await invoke(
      createUninstallCommand(
        dependencies(path, macEnvironmentWithNss(), [adapter]),
      ),
      { json: true },
    );

    expect(process.exitCode).toBe(1);
    expect(adapter.uninstallCalls).toEqual(['default']);
    expect(JSON.parse(result.stdout[0] ?? '')).toMatchObject({
      results: [
        { store: 'macos-keychain', target: 'default', state: 'untrusted' },
        {
          store: 'nss',
          target: '/tmp/firefox-profile',
          state: 'unknown',
          error: { code: 'UNSUPPORTED_PLATFORM' },
        },
      ],
    });
    expect(state(path).phase).toBe('retiring');
    expect(state(path).trustWrites).toMatchObject([
      { store: 'nss', target: '/tmp/firefox-profile' },
    ]);
    expect(existsSync(join(path, 'ca-cert.pem'))).toBe(true);
  });

  it('retains certless retirement state when a detected target cannot be fingerprint-scanned', async () => {
    const path = join(fixture(), 'ca');
    await certificateFor(['localhost'], { caDir: path });
    const caState = state(path);
    caState.phase = 'retiring';
    writeFileSync(
      join(path, 'state.json'),
      `${JSON.stringify(caState, null, 2)}\n`,
    );
    unlinkSync(join(path, 'ca-cert.pem'));
    const adapter = fakeAdapter('macos-keychain', new Set(['default']));
    const result = output();

    await invoke(
      createUninstallCommand(
        dependencies(path, macEnvironmentWithNss(), [adapter]),
      ),
      { json: true },
    );

    expect(process.exitCode).toBe(1);
    expect(adapter.uninstallCalls).toEqual([]);
    expect(JSON.parse(result.stdout[0] ?? '')).toMatchObject({
      results: [
        {
          store: 'macos-keychain',
          target: 'default',
          state: 'unknown',
          error: { code: 'CA_UNREADABLE' },
        },
        {
          store: 'nss',
          target: '/tmp/firefox-profile',
          state: 'unknown',
          error: { code: 'UNSUPPORTED_PLATFORM' },
        },
      ],
    });
    expect(existsSync(join(path, 'state.json'))).toBe(true);
    expect(existsSync(join(path, 'ca-key.pem'))).toBe(true);
    expect(existsSync(join(path, 'ca-cert.pem'))).toBe(false);
  });

  it('untrusts and retires a CA even when its signing key is damaged', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('macos-keychain');
    await invoke(
      createInstallCommand(dependencies(path, macEnvironment(), [adapter])),
      { json: true },
    );
    writeFileSync(join(path, 'ca-key.pem'), 'damaged key bytes', {
      mode: 0o600,
    });

    await invoke(
      createUninstallCommand(dependencies(path, macEnvironment(), [adapter])),
      { json: true },
    );

    expect(process.exitCode).toBe(0);
    expect(adapter.uninstallCalls).toEqual(['default']);
    expect(existsSync(path)).toBe(false);
  });

  it('journals detected targets with the retiring phase before removal starts', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('macos-keychain');
    await certificateFor(['localhost'], { caDir: path });
    adapter.installed.add('default');

    await invoke(
      createUninstallCommand(
        dependencies(path, macEnvironment(), [adapter], {
          onEvent(event) {
            if (event.type === 'uninstall:retiring')
              throw new Error('simulated process stop');
          },
        }),
      ),
      { json: true },
    );

    expect(state(path).phase).toBe('retiring');
    expect(state(path).trustWrites).toMatchObject([
      { store: 'macos-keychain', target: 'default' },
    ]);
    expect(adapter.uninstallCalls).toEqual([]);

    const noLongerDetected = macEnvironment();
    noLongerDetected.stores = noLongerDetected.stores.map((store) => ({
      ...store,
      detected: false,
    }));
    process.exitCode = 0;
    await invoke(
      createUninstallCommand(dependencies(path, noLongerDetected, [adapter])),
      { json: true },
    );

    expect(adapter.uninstallCalls).toEqual(['default']);
    expect(process.exitCode).toBe(0);
    expect(existsSync(path)).toBe(false);
  });

  it('marks retiring before removals and resumes after key and cert deletion without the key', async () => {
    for (const crashAt of [
      'uninstall:target-removed',
      'uninstall:file-removed:ca-key.pem',
      'uninstall:file-removed:ca-cert.pem',
    ]) {
      const path = join(fixture(), 'ca');
      const adapter = fakeAdapter('macos-keychain');
      await invoke(
        createInstallCommand(dependencies(path, macEnvironment(), [adapter])),
        {
          json: true,
        },
      );
      let crashed = false;
      const remove = createUninstallCommand(
        dependencies(path, macEnvironment(), [adapter], {
          onEvent(event) {
            if (
              ((crashAt === 'uninstall:target-removed' &&
                event.type === crashAt) ||
                `${event.type}:${event.filename ?? ''}` === crashAt) &&
              !crashed
            ) {
              crashed = true;
              throw new Error('simulated process stop');
            }
          },
        }),
      );

      await invoke(remove, { json: true });
      expect(crashed).toBe(true);
      expect(state(path).phase).toBe('retiring');

      process.exitCode = 0;
      await invoke(
        createUninstallCommand(dependencies(path, macEnvironment(), [adapter])),
        {
          json: true,
        },
      );
      expect(process.exitCode).toBe(0);
      expect(existsSync(join(path, 'state.json'))).toBe(false);
      expect(existsSync(path)).toBe(false);
    }
  });

  it('keeps partial uninstall progress and retries only the unresolved record', async () => {
    const path = join(fixture(), 'ca');
    const env = twoDatabaseEnvironment();
    const adapter = fakeAdapter('nss');
    await invoke(createInstallCommand(dependencies(path, env, [adapter])), {
      json: true,
    });
    adapter.failUninstall.add('/tmp/profile-b');
    const first = output();

    await invoke(createUninstallCommand(dependencies(path, env, [adapter])), {
      json: true,
    });

    expect(process.exitCode).toBe(1);
    expect(state(path).phase).toBe('retiring');
    expect(state(path).trustWrites.map((write) => write.target)).toEqual([
      '/tmp/profile-b',
    ]);
    expect(existsSync(join(path, 'ca-cert.pem'))).toBe(true);
    expect(JSON.parse(first.stdout.at(-1) ?? '')).toMatchObject({
      results: [
        { store: 'nss', target: '/tmp/profile-a', state: 'untrusted' },
        {
          store: 'nss',
          target: '/tmp/profile-b',
          error: { code: 'STORE_WRITE_FAILED' },
        },
      ],
    });

    process.exitCode = 0;
    unlinkSync(join(path, 'ca-key.pem'));
    await invoke(createUninstallCommand(dependencies(path, env, [adapter])), {
      json: true,
    });
    expect(process.exitCode).toBe(0);
    expect(existsSync(path)).toBe(false);
  });

  it('deletes only known cache files and preserves foreign nested content', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('macos-keychain');
    await invoke(
      createInstallCommand(dependencies(path, macEnvironment(), [adapter])),
      {
        json: true,
      },
    );
    await certificateFor(['localhost'], { caDir: path });
    const generatedCache = readdirSync(path).filter((name) =>
      /^leaf-[a-f\d]{16}/i.test(name),
    );
    expect(generatedCache).toHaveLength(3);
    const nested = join(path, 'foreign', 'keep.txt');
    mkdirSync(join(path, 'foreign'));
    writeFileSync(nested, 'foreign bytes');
    const unowned = `${'d'.repeat(64)}.pem`;
    writeFileSync(join(path, unowned), 'unowned bytes', { mode: 0o600 });
    for (const name of [
      `leaf-${'a'.repeat(16)}.pem`,
      `leaf-${'b'.repeat(16)}-key.pem`,
      `leaf-${'c'.repeat(16)}.meta.json`,
      '.certkit-00000000-0000-4000-8000-000000000000.tmp',
      '.leaf-key-00000000-0000-4000-8000-000000000000.tmp',
      '.state-00000000-0000-4000-8000-000000000000.tmp',
    ])
      writeFileSync(join(path, name), 'owned cache', { mode: 0o600 });

    await invoke(
      createUninstallCommand(dependencies(path, macEnvironment(), [adapter])),
      {
        json: true,
      },
    );

    expect(process.exitCode).toBe(0);
    expect(readFileSync(nested, 'utf8')).toBe('foreign bytes');
    expect(existsSync(join(path, 'foreign'))).toBe(true);
    expect(existsSync(join(path, 'state.json'))).toBe(false);
    expect(existsSync(join(path, 'ca-key.pem'))).toBe(false);
    expect(existsSync(join(path, 'ca-cert.pem'))).toBe(false);
    expect(generatedCache.every((name) => !existsSync(join(path, name)))).toBe(
      true,
    );
    expect(existsSync(join(path, `leaf-${'a'.repeat(16)}.pem`))).toBe(false);
    expect(existsSync(join(path, `leaf-${'b'.repeat(16)}-key.pem`))).toBe(
      false,
    );
    expect(existsSync(join(path, `leaf-${'c'.repeat(16)}.meta.json`))).toBe(
      false,
    );
    expect(existsSync(join(path, unowned))).toBe(true);
    expect(readdirSync(path).sort()).toEqual([unowned, 'foreign']);
  });

  it('records a detected target before failed removal and resumes it after detection disappears', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('macos-keychain');
    await certificateFor(['localhost'], { caDir: path });
    adapter.installed.add('default');
    adapter.failUninstall.add('default');

    await invoke(
      createUninstallCommand(dependencies(path, macEnvironment(), [adapter])),
      {
        json: true,
      },
    );

    expect(process.exitCode).toBe(1);
    expect(state(path).trustWrites).toMatchObject([
      { store: 'macos-keychain', target: 'default' },
    ]);

    const noLongerDetected = macEnvironment();
    noLongerDetected.stores = noLongerDetected.stores.map((store) => ({
      ...store,
      detected: false,
    }));
    process.exitCode = 0;
    await invoke(
      createUninstallCommand(dependencies(path, noLongerDetected, [adapter])),
      {
        json: true,
      },
    );

    expect(adapter.uninstallCalls).toEqual(['default', 'default']);
    expect(process.exitCode).toBe(0);
    expect(existsSync(path)).toBe(false);
  });

  it('finishes empty-directory cleanup after a crash immediately after state removal', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('macos-keychain');
    await invoke(
      createInstallCommand(dependencies(path, macEnvironment(), [adapter])),
      {
        json: true,
      },
    );
    let crash = true;

    await invoke(
      createUninstallCommand(
        dependencies(path, macEnvironment(), [adapter], {
          onEvent(event) {
            if (event.type === 'uninstall:state-removed' && crash) {
              crash = false;
              throw new Error('simulated process stop');
            }
          },
        }),
      ),
      { json: true },
    );
    expect(existsSync(join(path, 'state.json'))).toBe(false);
    expect(existsSync(path)).toBe(true);

    process.exitCode = 0;
    await invoke(
      createUninstallCommand(dependencies(path, macEnvironment(), [adapter])),
      {
        json: true,
      },
    );
    expect(process.exitCode).toBe(0);
    expect(existsSync(path)).toBe(false);
  });

  it('preserves owned cache files without identity state and reports manual fingerprint recovery', async () => {
    const path = join(fixture(), 'orphan-ca');
    mkdirSync(path, { mode: 0o700 });
    const orphan = join(path, `leaf-${'e'.repeat(16)}.pem`);
    writeFileSync(orphan, 'cache bytes', { mode: 0o600 });
    const result = output();

    await invoke(
      createUninstallCommand(dependencies(path, macEnvironment(), [])),
      {
        json: true,
      },
    );

    expect(process.exitCode).toBe(1);
    expect(readFileSync(orphan, 'utf8')).toBe('cache bytes');
    expect(JSON.parse(result.stdout[0] ?? '')).toEqual({
      schemaVersion: 1,
      error: {
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('fingerprint'),
      },
    });
  });

  it('is a no-op without CA state and dry-run leaves existing state byte-identical', async () => {
    const missing = join(fixture(), 'missing-ca');
    const missingOutput = output();
    await invoke(
      createUninstallCommand(dependencies(missing, macEnvironment(), [])),
      {
        json: true,
      },
    );
    expect(process.exitCode).toBe(0);
    expect(existsSync(missing)).toBe(false);
    expect(JSON.parse(missingOutput.stdout[0] ?? '')).toEqual({
      schemaVersion: 1,
      results: [],
    });

    const path = join(fixture(), 'ca');
    await certificateFor(['localhost'], { caDir: path });
    const statePath = join(path, 'state.json');
    const caState = state(path);
    caState.pendingWrites.push({
      store: 'nss',
      target: '/tmp/profile-unresolved',
      sha256: caState.ca.sha256,
      timestamp: new Date().toISOString(),
    });
    writeFileSync(statePath, `${JSON.stringify(caState, null, 2)}\n`);
    const before = readFileSync(statePath);
    process.exitCode = 0;
    const dryRun = output();
    await invoke(
      createUninstallCommand(dependencies(path, macEnvironment(), [])),
      {
        'dry-run': true,
        json: true,
      },
    );
    expect(process.exitCode).toBe(0);
    expect(readFileSync(statePath)).toEqual(before);
    expect(JSON.parse(dryRun.stdout[0] ?? '')).toMatchObject({
      schemaVersion: 1,
      dryRun: true,
      commands: expect.any(Array),
      unresolved: [
        {
          store: 'nss',
          target: '/tmp/profile-unresolved',
          state: 'unknown',
        },
      ],
    });
  });

  it('emits pure failure JSON for a command that cannot start', async () => {
    const result = output();
    const command = createInstallCommand({
      resolveCaDir: () => join(fixture(), 'ca'),
      detect: async () => {
        throw new CertkitError('UNSUPPORTED_PLATFORM', 'no detected store');
      },
      adapterFactory: () => [],
    });

    await invoke(command, { json: true });

    expect(process.exitCode).toBe(2);
    expect(result.stderr).toEqual([]);
    expect(JSON.parse(result.stdout[0] ?? '')).toEqual({
      schemaVersion: 1,
      error: { code: 'UNSUPPORTED_PLATFORM', message: 'no detected store' },
    });
  });
});

describe('trust target planning', () => {
  it('rejects duplicate adapter registrations', () => {
    expect(() =>
      adaptersById([fakeAdapter('nss'), fakeAdapter('nss')]),
    ).toThrow(/More than one adapter registered for nss/);
  });

  it('plans no NSS targets when detection lists are absent', () => {
    const env: Environment = {
      os: 'linux',
      wsl: false,
      stores: [{ store: 'nss', detected: true }],
    };

    expect(adapterTargets(env, 'install')).toEqual([]);
    expect(adapterTargets(env, 'uninstall')).toEqual([]);
  });

  it('falls back to the default Linux target without a CA path or known mechanism', () => {
    expect(
      adapterTargets(linuxEnvironment('update-ca-certificates'), 'install'),
    ).toEqual([{ store: 'linux-system', target: 'default' }]);
    expect(
      adapterTargets(
        linuxEnvironment('unknown-mechanism'),
        'install',
        '/ca.pem',
      ),
    ).toEqual([{ store: 'linux-system', target: 'default' }]);
  });

  it('reports unknown when the adapter omits the requested trust target', async () => {
    const adapter = fakeAdapter('nss');
    adapter.checkTrust = async () => [
      { target: '/tmp/other-a', state: 'trusted' },
      { target: '/tmp/other-b', state: 'untrusted' },
    ];

    await expect(
      targetTrustState(adapter, 'unused', twoDatabaseEnvironment(), {
        store: 'nss',
        target: '/tmp/profile-a',
      }),
    ).resolves.toEqual({
      state: 'unknown',
      detail: 'The target trust state is unavailable.',
    });
  });

  it('reports unknown when the trust probe crashes', async () => {
    const adapter = fakeAdapter('nss');
    adapter.checkTrust = async () => {
      throw new Error('probe crashed');
    };

    await expect(
      targetTrustState(adapter, 'unused', twoDatabaseEnvironment(), {
        store: 'nss',
        target: '/tmp/profile-a',
      }),
    ).resolves.toEqual({
      state: 'unknown',
      detail: 'The target trust state is unavailable.',
    });
  });

  it('treats a crashing presence probe as inconclusive', async () => {
    const adapter = fakeAdapter('nss');
    adapter.inspectInstalled = async () => {
      throw new Error('inspect crashed');
    };

    await expect(
      inspectInstalled(adapter, 'unused', '/tmp/profile-a'),
    ).resolves.toBe('inconclusive');
  });

  it('maps non-Error failures to a generic store-write error', () => {
    expect(toErrorResult('string failure')).toEqual({
      code: 'STORE_WRITE_FAILED',
      message: 'Trust operation failed.',
    });
  });

  it('prints human-readable results with detail and error suffixes', () => {
    const result = output();

    emitResults(
      [
        {
          store: 'nss',
          target: '/tmp/profile-a',
          state: 'unknown',
          detail: 'probe failed',
          error: { code: 'STORE_WRITE_FAILED', message: 'write failed' },
        },
      ],
      false,
    );

    expect(result.stdout).toEqual([
      'nss (/tmp/profile-a): unknown — probe failed — write failed',
    ]);
  });

  it('uses the real NSS nickname in install plans when the CA identity exists', async () => {
    const path = join(fixture(), 'ca');
    await certificateFor(['localhost'], { caDir: path });
    const certPath = join(path, 'ca-cert.pem');
    const db = join(fixture(), 'nssdb');

    const [plan] = planInstall([{ store: 'nss', target: db }], certPath, true);

    expect(plan?.command).toContain(
      nssCertificateNickname(readFileSync(certPath, 'utf8')),
    );
    expect(plan?.command).not.toContain('<sha256>');
    expect(plan?.command).toContain(`'-d' 'sql:${db}'`);
    expect(plan?.manual).toContain(plan?.command ?? '');

    const bogus = join(fixture(), 'bogus.pem');
    writeFileSync(bogus, 'not a certificate');
    const [symbolic] = planInstall([{ store: 'nss', target: db }], bogus, true);
    expect(symbolic?.command).toContain('certkit development CA <sha256>');
  });

  it('plans no install commands for unsupported target shapes', () => {
    expect(
      planInstall(
        [{ store: 'macos-keychain', target: 'custom' }],
        '/ca.pem',
        false,
      ),
    ).toEqual([]);
    expect(
      planInstall(
        [{ store: 'linux-system', target: 'default' }],
        '/ca.pem',
        false,
      ),
    ).toEqual([]);
  });

  it('plans no uninstall commands for unsupported target shapes', () => {
    expect(
      planUninstall(
        [{ store: 'macos-keychain', target: 'custom' }],
        '/ca.pem',
        false,
      ),
    ).toEqual([]);
    expect(
      planUninstall(
        [{ store: 'linux-system', target: 'default' }],
        '/ca.pem',
        false,
      ),
    ).toEqual([]);
  });

  it('keeps symbolic removal identities when the recorded fingerprint mismatches', async () => {
    const path = join(fixture(), 'ca');
    await certificateFor(['localhost'], { caDir: path });
    const certPath = join(path, 'ca-cert.pem');
    const mismatch = 'f'.repeat(64);

    const [nss] = planUninstall(
      [{ store: 'nss', target: '/tmp/nssdb' }],
      certPath,
      true,
      mismatch,
    );
    expect(nss?.command).toContain('certkit development CA <sha256>');

    const [windows] = planUninstall(
      [{ store: 'windows-root', target: 'default' }],
      certPath,
      true,
      mismatch,
    );
    expect(windows?.command).toBe(
      'certutil -user -delstore Root "<sha1-thumbprint>"',
    );
  });

  it('prints an empty dry-run plan with unresolved and unsupported targets', () => {
    const result = output();

    emitDryRun(
      [],
      false,
      [{ store: 'nss', target: '/tmp/profile-a' }],
      [{ store: 'linux-system', target: 'default' }],
    );

    expect(result.stdout).toEqual([
      'No registered trust-store commands for the detected targets.',
      'nss (/tmp/profile-a): unknown — A trust write outcome is unresolved; dry-run does not inspect or reconcile it.',
      'linux-system (default): unknown — No registered linux-system adapter is available for default; it was not modified or verified. See docs/trust-matrix.md for the manual path.',
    ]);
  });

  it('omits the macOS authentication note when no macOS command is planned', () => {
    const result = output();

    emitDryRun(
      [
        {
          store: 'nss',
          target: '/tmp/nssdb',
          command: 'certutil -A',
          manual: 'run certutil -A',
        },
      ],
      false,
    );

    expect(result.stdout).toEqual([
      'nss (/tmp/nssdb)',
      '  command: certutil -A',
      '  manual: run certutil -A',
    ]);
  });

  it('falls back to ambient CA directory and platform detection', () => {
    const home = fixture();
    process.env.CERTKIT_HOME = home;

    const resolved = resolveDependencies({});

    expect(resolved.resolveCaDir()).toBe(home);
    expect(resolved.detect).toBe(detect);
    if (process.platform === 'win32') expect(resolved.fsGuard).toBeDefined();
    else expect(resolved.fsGuard).toBeUndefined();
  });
});
