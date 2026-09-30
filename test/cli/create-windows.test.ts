import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { FsGuard } from '../../src/core/cadir.js';

// The create command builds its Windows guard internally; substitute a no-op
// so the simulated win32 path never shells out to icacls on this host.
vi.mock('../../src/platforms/fsguard.js', () => ({
  createWindowsFsGuard: (): FsGuard => ({
    protectDirectory() {},
    assertProtectedDirectory() {},
    assertProtectedFile() {},
  }),
}));

// The trust check is optional; stub the lazy API boundary so its success and
// failure branches are deterministic and platform-independent.
vi.mock('../../src/cli/options.js', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('../../src/cli/options.js')>();
  return {
    ...actual,
    loadApi: vi.fn() as unknown as typeof actual.loadApi,
  };
});

import { createCommand } from '../../src/cli/commands/create.js';
import { loadApi } from '../../src/cli/options.js';

const loadApiMock = vi.mocked(loadApi);
const roots: string[] = [];
let previousHome: string | undefined;

function fixture(): string {
  const root = mkdtempSync(join(tmpdir(), 'certkit-create-windows-'));
  roots.push(root);
  return root;
}

function home(root: string): { caDir: string; outputDir: string } {
  const caDir = join(root, 'ca');
  process.env.CERTKIT_HOME = caDir;
  const outputDir = join(root, 'out');
  mkdirSync(outputDir);
  return { caDir, outputDir };
}

async function invoke(args: Record<string, unknown>): Promise<void> {
  await createCommand.run?.({
    args: { _: [], ...args },
    cmd: createCommand,
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

function stubStatus(stores: Array<{ state: string }>): void {
  loadApiMock.mockResolvedValue({
    caDir: () => process.env.CERTKIT_HOME ?? '',
    status: async () => ({ stores }),
  } as never);
}

beforeEach(() => {
  previousHome = process.env.CERTKIT_HOME;
  process.exitCode = 0;
  loadApiMock.mockReset();
});

afterEach(() => {
  vi.restoreAllMocks();
  if (previousHome === undefined) delete process.env.CERTKIT_HOME;
  else process.env.CERTKIT_HOME = previousHome;
  process.exitCode = 0;
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe('create command on simulated Windows', () => {
  it('creates outputs through the protected placement path and prints the untrusted hint', async () => {
    const { outputDir } = home(fixture());
    stubStatus([{ state: 'untrusted' }]);
    const result = output();
    const originalPlatform = process.platform;
    Object.defineProperty(process, 'platform', { value: 'win32' });

    try {
      await invoke({ _: ['localhost'], output: outputDir, json: true });
    } finally {
      Object.defineProperty(process, 'platform', { value: originalPlatform });
    }

    expect(process.exitCode).toBe(0);
    const parsed = JSON.parse(result.stdout[0] ?? '') as {
      schemaVersion: number;
      names: string[];
      files: { cert: string; key: string };
    };
    expect(parsed).toMatchObject({ schemaVersion: 1, names: ['localhost'] });
    expect(readFileSync(parsed.files.cert, 'utf8')).toContain(
      '-----BEGIN CERTIFICATE-----',
    );
    expect(readFileSync(parsed.files.key, 'utf8')).toContain(
      '-----BEGIN PRIVATE KEY-----',
    );
    expect(result.stderr).toEqual(['CA not trusted — run `certkit install`']);
  });
});

describe('create command trust check', () => {
  it('skips the untrusted hint when no store reports untrusted', async () => {
    const { outputDir } = home(fixture());
    stubStatus([]);
    const result = output();

    await invoke({ _: ['localhost'], output: outputDir, json: true });

    expect(process.exitCode).toBe(0);
    expect(result.stderr).toEqual([]);
    expect(existsSync(join(outputDir, 'localhost.pem'))).toBe(true);
  });

  it('still succeeds when the optional trust check fails', async () => {
    const { outputDir } = home(fixture());
    loadApiMock.mockRejectedValue(new Error('api unavailable'));
    const result = output();

    await invoke({ _: ['localhost'], output: outputDir, json: true });

    expect(process.exitCode).toBe(0);
    expect(result.stderr).toEqual([]);
    expect(existsSync(join(outputDir, 'localhost-key.pem'))).toBe(true);
  });
});
