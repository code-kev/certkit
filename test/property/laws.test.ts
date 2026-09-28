import { createHash, X509Certificate } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import fc from 'fast-check';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createInstallCommand } from '../../src/cli/commands/install.js';
import type { TrustCommandDependencies } from '../../src/cli/commands/trust.js';
import { createUninstallCommand } from '../../src/cli/commands/uninstall.js';
import { certificateFor } from '../../src/core/certificate.js';
import { CertkitError } from '../../src/core/errors.js';
import { type ValidName, validateNames } from '../../src/core/validate.js';
import type { Environment } from '../../src/platforms/detect.js';
import { createLinuxAdapter } from '../../src/platforms/linux.js';
import {
  createNssAdapter,
  nssCertificateNickname,
} from '../../src/platforms/nss.js';
import type { RunResult } from '../../src/platforms/run.js';
import type { StoreAdapter } from '../../src/platforms/store.js';

/** Fixed seed makes every counterexample reproducible; fast-check prints it on failure. */
const SEED = 20260929;
const DAY_MS = 86_400_000;
fc.configureGlobal({ seed: SEED });

const roots: string[] = [];

function fixture(): string {
  const path = mkdtempSync(join(tmpdir(), 'certkit-laws-'));
  roots.push(path);
  return path;
}

beforeEach(() => {
  process.exitCode = 0;
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  process.exitCode = 0;
  for (const path of roots.splice(0))
    rmSync(path, { recursive: true, force: true });
});

const SHORTHAND_IPV4 = [
  '127.1',
  '0x7f000001',
  '2130706433',
  '017700000001',
] as const;
const SHELL_METACHARACTERS = /[\s\0;|&$`'"<>()\\[\]{}*]/u;

function value(name: ValidName): string {
  return name.kind === 'dns' ? name.ascii : name.ip;
}

function bare(name: ValidName): string {
  return name.kind === 'dns' ? name.ascii.replace(/^\*\./, '') : name.ip;
}

describe('law (a): name containment and idempotence', () => {
  it('either throws a typed error or returns a shell-inert, stable name', () => {
    fc.assert(
      fc.property(
        fc.array(fc.string({ unit: 'binary', maxLength: 24 }), {
          maxLength: 6,
        }),
        (names) => {
          let result: ValidName[];
          try {
            result = validateNames(names);
          } catch (error) {
            expect(error).toBeInstanceOf(CertkitError);
            expect((error as CertkitError).code).toBe('INVALID_NAME');
            return;
          }
          expect(names.length).toBeGreaterThan(0);
          for (const name of result) {
            expect(bare(name)).not.toMatch(SHELL_METACHARACTERS);
            expect(validateNames([value(name)])).toEqual([name]);
          }
        },
      ),
      { numRuns: 2_000 },
    );
  });
});

describe('law (b): IDN round-trip', () => {
  it('punycode output is stable under re-validation', () => {
    fc.assert(
      fc.property(
        fc.string({ unit: 'grapheme', maxLength: 16 }),
        fc.constantFrom('', '.test', '.example.com'),
        (input, suffix) => {
          let result: ValidName[];
          try {
            result = validateNames([`${input}${suffix}`]);
          } catch {
            return;
          }
          const name = result[0];
          if (name?.kind !== 'dns') return;
          expect(validateNames([name.ascii])).toEqual([name]);
          expect(name.ascii).toBe(name.ascii.toLowerCase());
        },
      ),
      { numRuns: 2_000 },
    );
  });
});

describe('law (c): cache idempotency while fresh', () => {
  const label = fc
    .array(
      fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789'.split('')),
      { minLength: 1, maxLength: 10 },
    )
    .map((chars) => chars.join(''));
  const dns = fc
    .tuple(label, fc.constantFrom('test', 'example.com', 'internal'))
    .map(([host, suffix]) => `${host}.${suffix}`);
  const nameSet = fc.uniqueArray(
    fc.oneof(
      dns,
      dns.map((host) => `*.${host}`),
      fc.ipV4(),
      fc.ipV6(),
      fc.constantFrom('münich.test', 'xn--mnich-kva.test'),
    ),
    { minLength: 1, maxLength: 4 },
  );

  it('same names + same options + fresh entry yields byte-identical PEMs', async () => {
    const dir = join(fixture(), 'ca');
    await fc.assert(
      fc.asyncProperty(nameSet, async (names) => {
        const first = await certificateFor(names, {
          caDir: dir,
          validityDays: 30,
        });
        const second = await certificateFor(names, {
          caDir: dir,
          validityDays: 30,
        });
        expect(second).toEqual(first);
        const different = await certificateFor(names, {
          caDir: dir,
          validityDays: 31,
        });
        expect(different.cert).not.toBe(first.cert);
        expect(different.caCert).toBe(first.caCert);
      }),
      { numRuns: 40 },
    );
  });

  it('regenerates only once the clock crosses the renewal window', async () => {
    vi.useFakeTimers();
    const dir = join(fixture(), 'ca');
    const first = await certificateFor(['localhost'], {
      caDir: dir,
      validityDays: 60,
    });
    const meta = JSON.parse(
      readFileSync(
        join(dir, `leaf-${stemFor(['localhost'])}.meta.json`),
        'utf8',
      ),
    ) as { expiresAt: string };
    vi.setSystemTime(Date.parse(meta.expiresAt) - 31 * DAY_MS);
    await expect(
      certificateFor(['localhost'], { caDir: dir, validityDays: 60 }),
    ).resolves.toEqual(first);
    vi.setSystemTime(Date.parse(meta.expiresAt) - 29 * DAY_MS);
    const renewed = await certificateFor(['localhost'], {
      caDir: dir,
      validityDays: 60,
    });
    expect(renewed.cert).not.toBe(first.cert);
  });

  it('never reuses a serial across distinct cached entries', async () => {
    const dir = join(fixture(), 'ca');
    const serials = new Set<string>();
    for (const names of [['a.test'], ['b.test'], ['c.test'], ['d.test']]) {
      const bundle = await certificateFor(names, {
        caDir: dir,
        validityDays: 30,
      });
      serials.add(new X509Certificate(bundle.cert).serialNumber.toLowerCase());
    }
    expect(serials.size).toBe(4);
  });
});

describe('law (d): uninstall is idempotent', () => {
  const profile = fc
    .tuple(
      fc.array(fc.constantFrom(...'abcdefghij'.split('')), {
        minLength: 1,
        maxLength: 8,
      }),
      fc.nat(99),
    )
    .map(([chars, index]) => `/tmp/${chars.join('')}-${index}/profile`);

  it('uninstall composed with itself equals a single uninstall', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uniqueArray(profile, { minLength: 1, maxLength: 3 }),
        async (targets) => {
          const dir = join(fixture(), 'ca');
          const adapter = fakeAdapter('nss');
          const environment = nssEnvironment(targets);
          const dependencies = trustDependencies(dir, environment, [adapter]);
          await invoke(createInstallCommand(dependencies));
          process.exitCode = 0;
          await invoke(createUninstallCommand(dependencies));
          const once = snapshot(dir);
          process.exitCode = 0;
          await invoke(createUninstallCommand(dependencies));
          expect(snapshot(dir)).toEqual(once);
        },
      ),
      { numRuns: 15 },
    );
  });

  it('converges after an interrupted retire', async () => {
    const dir = join(fixture(), 'ca');
    const adapter = fakeAdapter('macos-keychain');
    const environment = macEnvironment();
    await invoke(
      createInstallCommand(trustDependencies(dir, environment, [adapter])),
    );
    expect(process.exitCode).toBe(0);

    let crashed = false;
    process.exitCode = 0;
    await invoke(
      createUninstallCommand(
        trustDependencies(dir, environment, [adapter], {
          onEvent(event) {
            if (
              !crashed &&
              event.type === 'uninstall:file-removed' &&
              event.filename === 'ca-key.pem'
            ) {
              crashed = true;
              throw new Error('simulated process stop');
            }
          },
        }),
      ),
    );
    expect(crashed).toBe(true);
    expect(stateOf(dir)?.phase).toBe('retiring');

    process.exitCode = 0;
    await invoke(
      createUninstallCommand(trustDependencies(dir, environment, [adapter])),
    );
    expect(process.exitCode).toBe(0);
    expect(existsSync(dir)).toBe(false);
  });
});

describe('law (e): IP normalization', () => {
  it('raw IPv6 literals classify as IP', () => {
    fc.assert(
      fc.property(fc.ipV6(), (address) => {
        const name = validateNames([address])[0];
        expect(name?.kind).toBe('ip');
      }),
      { numRuns: 5_000 },
    );
  });

  it('shorthand IPv4 forms normalize then classify as IP', () => {
    fc.assert(
      fc.property(fc.ipV4Extended(), (address) => {
        const name = validateNames([address])[0];
        expect(name?.kind).toBe('ip');
        expect(validateNames([value(name as ValidName)])).toEqual([name]);
      }),
      { numRuns: 5_000 },
    );
    for (const address of SHORTHAND_IPV4) {
      expect(validateNames([address])[0]?.kind).toBe('ip');
    }
  });
});

describe('law (ii): hostile paths stay discrete argv elements', () => {
  beforeEach(() => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  const hostileCharacter = fc.constantFrom(
    ...' abz09$&|;`\'"<>(){}[]*?!~#%=+@,.-_'.split(''),
  );
  const hostileSegment = fc
    .array(hostileCharacter, { minLength: 3, maxLength: 24 })
    .map((chars) => chars.join(''));

  it('NSS install and uninstall pass each whole path as its own element', async () => {
    await fc.assert(
      fc.asyncProperty(hostileSegment, async (segment) => {
        const root = fixture();
        const dir = join(root, segment, 'ca');
        const target = join(root, 'profile', segment);
        const caCertPath = join(dir, 'ca-cert.pem');
        const calls: string[][] = [];
        const adapter = instrumentedNss(caCertPath, calls);
        const environment = nssEnvironment([target]);
        const dependencies: TrustCommandDependencies = {
          resolveCaDir: () => dir,
          detect: async () => environment,
          adapterFactory: () => [adapter],
        };
        await invoke(createInstallCommand(dependencies), { json: true });
        process.exitCode = 0;
        await invoke(createUninstallCommand(dependencies), { json: true });
        process.exitCode = 0;

        const wholeValues = [caCertPath, target, `sql:${target}`];
        const recorded = calls.flat();
        expect(recorded.length).toBeGreaterThan(0);
        for (const element of recorded) {
          if (!element.includes(segment)) continue;
          expect(wholeValues).toContain(element);
          expect(element.startsWith('-')).toBe(false);
        }
        expect(recorded).toContain(caCertPath);
        expect(recorded).toContain(`sql:${target}`);
      }),
      { numRuns: 25 },
    );
  });

  it('Linux elevation receives whole paths, never flag-concatenated values', async () => {
    const segment = 'ev il\'$(touch pwned)`;x"';
    const root = fixture();
    const dir = join(root, segment, 'ca');
    const caCertPath = join(dir, 'ca-cert.pem');
    const elevated: string[][] = [];
    const environment: Environment = {
      os: 'linux',
      wsl: false,
      stores: [
        { store: 'macos-keychain', detected: false },
        { store: 'windows-root', detected: false },
        {
          store: 'linux-system',
          detected: true,
          detail: 'update-ca-certificates',
        },
        { store: 'nss', detected: false, targets: [], installTargets: [] },
      ],
    };
    const dependencies: TrustCommandDependencies = {
      resolveCaDir: () => dir,
      detect: async () => environment,
      adapterFactory: (certPath) => [
        createLinuxAdapter({
          caCertPath: certPath,
          run: async () => ({ code: 1, stdout: '', stderr: '' }),
          elevate: async (argv) => {
            elevated.push(argv);
          },
        }),
      ],
    };
    await invoke(createInstallCommand(dependencies), { json: true });

    expect(elevated.length).toBeGreaterThan(0);
    for (const argv of elevated) {
      for (const element of argv) {
        if (!element.includes(segment)) continue;
        expect([caCertPath, `${caCertPath}.certkit-tmp`]).toContain(element);
        expect(element.startsWith('-')).toBe(false);
      }
    }
    expect(elevated.flat()).toContain(caCertPath);
  });
});

/** Leaf cache key: sha256 of the sorted lowercase name set, truncated to 16. */
function stemFor(names: string[]): string {
  const normalized = [
    ...new Set(names.map((name) => name.toLowerCase())),
  ].sort();
  return createHash('sha256')
    .update(normalized.join('\n'))
    .digest('hex')
    .slice(0, 16);
}

function snapshot(dir: string): string | null {
  return existsSync(join(dir, 'state.json'))
    ? readFileSync(join(dir, 'state.json'), 'utf8')
    : null;
}

function stateOf(dir: string): { phase: string } | null {
  const text = snapshot(dir);
  return text ? (JSON.parse(text) as { phase: string }) : null;
}

function macEnvironment(): Environment {
  return {
    os: 'macos',
    wsl: false,
    stores: [
      { store: 'macos-keychain', detected: true },
      { store: 'windows-root', detected: false },
      { store: 'linux-system', detected: false },
      { store: 'nss', detected: false, targets: [], installTargets: [] },
    ],
  };
}

function nssEnvironment(targets: string[]): Environment {
  return {
    os: 'linux',
    wsl: false,
    stores: [
      { store: 'macos-keychain', detected: false },
      { store: 'windows-root', detected: false },
      { store: 'linux-system', detected: false },
      {
        store: 'nss',
        detected: targets.length > 0,
        targets,
        installTargets: targets,
      },
    ],
  };
}

function trustDependencies(
  dir: string,
  environment: Environment,
  adapters: StoreAdapter[],
  overrides: Partial<TrustCommandDependencies> = {},
): TrustCommandDependencies {
  return {
    resolveCaDir: () => dir,
    detect: async () => environment,
    adapterFactory: () => adapters,
    ...overrides,
  };
}

async function invoke(
  command: ReturnType<typeof createInstallCommand>,
  args: Record<string, unknown> = {},
): Promise<void> {
  await command.run?.({ args, cmd: command, rawArgs: [], data: {} } as never);
}

function fakeAdapter(id: StoreAdapter['id']): StoreAdapter & {
  installed: Set<string>;
} {
  return {
    id,
    installed: new Set<string>(),
    async checkTrust() {
      return [{ state: 'trusted' as const, target: 'default' }];
    },
    async inspectInstalled(_pem: string, target: string) {
      return this.installed.has(target)
        ? ('present' as const)
        : ('absent' as const);
    },
    async install(_path: string, target: string) {
      this.installed.add(target);
      return { state: 'verified' as const };
    },
    async uninstall(_pem: string, target: string) {
      this.installed.delete(target);
    },
  };
}

function instrumentedNss(caCertPath: string, calls: string[][]): StoreAdapter {
  let installed = false;
  const run = async (argv: string[]): Promise<RunResult> => {
    calls.push([...argv]);
    const args = argv.slice(1);
    if (args[0] === '-A') {
      installed = true;
      return { code: 0, stdout: '', stderr: '' };
    }
    if (args[0] === '-D') {
      installed = false;
      return { code: 0, stdout: '', stderr: '' };
    }
    const pem = readFileSync(caCertPath, 'utf8');
    if (args.includes('-a')) return { code: 0, stdout: pem, stderr: '' };
    const header =
      'Certificate Nickname                                         Trust Attributes\n                                                             SSL,S/MIME,JAR/XPI\n\n';
    const nickname = nssCertificateNickname(pem);
    return {
      code: 0,
      stdout: installed ? `${header}${nickname}    C,,\n` : header,
      stderr: '',
    };
  };
  return createNssAdapter({
    run,
    resolveCertutil: async () => process.execPath,
    fs: { mkdir: async () => {}, hasDatabaseFile: () => true },
  });
}
