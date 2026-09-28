import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createInstallCommand } from '../../src/cli/commands/install.js';
import type { TrustCommandDependencies } from '../../src/cli/commands/trust.js';
import { createUninstallCommand } from '../../src/cli/commands/uninstall.js';
import { shQuote } from '../../src/cli/elevate.js';
import { certificateFor } from '../../src/core/certificate.js';
import { CertkitError } from '../../src/core/errors.js';
import type { Environment } from '../../src/platforms/detect.js';
import type { StoreAdapter } from '../../src/platforms/store.js';

const roots: string[] = [];
let previousHome: string | undefined;

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
  uninstallCalls: string[];
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
    uninstallCalls: [] as string[],
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
    async install(_path, target) {
      this.installCalls.push(target);
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
    async uninstall(_pem, target) {
      this.uninstallCalls.push(target);
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
    serial: string;
    sha256: string;
    timestamp: string;
  }>;
  pendingWrites: Array<{
    store: string;
    target: string;
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

  it('records a verified write even when effective trust remains unknown', async () => {
    const path = join(fixture(), 'ca');
    const adapter = fakeAdapter('macos-keychain');
    adapter.unknownTrust.add('default');
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
          state: 'unknown',
          detail: 'policy unavailable for default',
        },
      ],
    });
    expect(state(path).trustWrites).toHaveLength(1);
    expect(state(path).pendingWrites).toEqual([]);
    expect(adapter.installCalls).toEqual(['default']);
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

  it('reconciles a store write after a crash before promotion without writing twice', async () => {
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

    expect(adapter.installCalls).toEqual(['default']);
    expect(state(path).pendingWrites).toEqual([]);
    expect(state(path).trustWrites).toHaveLength(1);
  });

  it('keeps an uninspectable pending write without issuing a duplicate install', async () => {
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

    expect(adapter.installCalls).toEqual(['default']);
    expect(state(path).pendingWrites).toEqual([]);
    expect(state(path).trustWrites).toHaveLength(1);
  });

  it('reconciles a pending target even after detection no longer reports it', async () => {
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

    expect(process.exitCode).toBe(0);
    expect(adapter.installCalls).toEqual(['/tmp/profile-a']);
    expect(state(path).pendingWrites).toEqual([]);
    expect(state(path).trustWrites.map((write) => write.target)).toEqual([
      '/tmp/profile-a',
    ]);
    expect(JSON.parse(result.stdout[0] ?? '')).toMatchObject({
      results: [
        {
          store: 'nss',
          target: '/tmp/profile-a',
          state: 'not-detected',
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

  it('dry-run prints symbolic commands for a fresh home without creating state', async () => {
    const path = join(fixture(), "ev il'$(touch /tmp/pwned)", 'ca');
    const result = output();

    await invoke(
      createInstallCommand(dependencies(path, macEnvironment(), [])),
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
          elevated: expect.stringContaining('<ca-cert.pem>'),
          manual: expect.stringContaining('sudo '),
        },
      ],
    });
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
      createInstallCommand(dependencies(path, macEnvironment(), [])),
      {
        'dry-run': true,
        json: true,
      },
    );

    const commands = JSON.parse(result.stdout[0] ?? '') as {
      commands: Array<{ elevated: string }>;
    };
    expect(commands.commands[0]?.elevated).toContain("'\\''");
    expect(commands.unresolved).toMatchObject([
      {
        store: 'nss',
        target: '/tmp/profile-unresolved',
        state: 'unknown',
      },
    ]);
    expect(readFileSync(statePath)).toEqual(before);
  });
});

describe('uninstall command', () => {
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
