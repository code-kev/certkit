import { spawn } from 'node:child_process';
import fs, {
  appendFileSync,
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { homedir, tmpdir } from 'node:os';
import { join, win32 } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  type FsGuard,
  readState as readStateCore,
  resolveCaDir,
  type StateFile,
  withLock as withLockCore,
  writePrivateKey as writePrivateKeyCore,
  writeStateAtomic as writeStateAtomicCore,
} from '../../src/core/cadir.js';
import { CertkitError } from '../../src/core/errors.js';
import { createWindowsFsGuard } from '../../src/platforms/fsguard.js';

const workerDir = process.env.CERTKIT_LOCK_RACE_DIR;
const originalPlatformDescriptor = Object.getOwnPropertyDescriptor(
  process,
  'platform',
);
let tempRoot = '';

function fileOptions(fsGuard?: FsGuard): { fsGuard?: FsGuard } {
  return process.platform === 'win32'
    ? { fsGuard: fsGuard ?? createWindowsFsGuard() }
    : fsGuard
      ? { fsGuard }
      : {};
}

function readState(
  dir: string,
  options?: { fsGuard?: FsGuard },
): StateFile | null {
  return readStateCore(dir, fileOptions(options?.fsGuard));
}

function writeStateAtomic(
  dir: string,
  value: StateFile,
  options?: { fsGuard?: FsGuard },
): void {
  writeStateAtomicCore(dir, value, fileOptions(options?.fsGuard));
}

function writePrivateKey(
  dir: string,
  filename: string,
  contents: string,
  options?: { fsGuard?: FsGuard },
): string {
  return writePrivateKeyCore(
    dir,
    filename,
    contents,
    fileOptions(options?.fsGuard),
  );
}

function withLock<T>(
  dir: string,
  fn: () => Promise<T>,
  options?: {
    fsGuard?: FsGuard;
    timeoutMs?: number;
    removeDirectoryIfEmpty?: boolean;
  },
): Promise<T> {
  return withLockCore(dir, fn, {
    ...fileOptions(options?.fsGuard),
    ...options,
  });
}

function state(): StateFile {
  return {
    version: 1,
    phase: 'active',
    ca: {
      subject: 'certkit development CA',
      serial: '01020304',
      sha256: 'a'.repeat(64),
      createdAt: '2026-09-27T00:00:00.000Z',
      expiresAt: '2036-09-24T00:00:00.000Z',
    },
    trustWrites: [
      {
        store: 'nss',
        target: '/home/test/.pki/nssdb',
        mechanism: 'certutil',
        serial: '01020304',
        sha256: 'a'.repeat(64),
        timestamp: '2026-09-27T00:00:00.000Z',
      },
    ],
    pendingWrites: [
      {
        store: 'system',
        target: '/etc/ssl/certkit.pem',
        mechanism: 'update-ca-certificates',
        sha256: 'a'.repeat(64),
        timestamp: '2026-09-27T00:00:00.000Z',
      },
    ],
  };
}

function setPlatform(platform: NodeJS.Platform): void {
  Object.defineProperty(process, 'platform', {
    configurable: true,
    value: platform,
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(
  predicate: () => boolean,
  timeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline)
      throw new Error('timed out waiting for lock workers');
    await delay(5);
  }
}

function runLockWorker(dir: string, id: string): Promise<number> {
  const vitestCli = fileURLToPath(
    new URL('../../node_modules/vitest/vitest.mjs', import.meta.url),
  );
  const testFile = fileURLToPath(import.meta.url);
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    const child = spawn(
      process.execPath,
      [
        vitestCli,
        'run',
        testFile,
        '-t',
        'cadir lock race child',
        '--pool=forks',
        '--maxWorkers=1',
      ],
      {
        cwd: process.cwd(),
        env: {
          ...process.env,
          CERTKIT_LOCK_RACE_DIR: dir,
          CERTKIT_LOCK_RACE_ID: id,
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    child.stdout?.on('data', (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    child.once('error', reject);
    child.once('close', (code) => {
      if (code !== 0) {
        console.error(
          `Lock worker ${id} exited ${code ?? 'without a code'}\nstdout:\n${stdout}\nstderr:\n${stderr}`,
        );
      }
      resolve(code ?? 1);
    });
  });
}

beforeEach(async () => {
  tempRoot = await mkdtemp(join(tmpdir(), 'certkit-cadir-'));
  vi.stubEnv('CERTKIT_HOME', '');
  vi.stubEnv('XDG_CONFIG_HOME', '');
  vi.stubEnv('LOCALAPPDATA', '');
});

afterEach(async () => {
  vi.unstubAllEnvs();
  if (originalPlatformDescriptor)
    Object.defineProperty(process, 'platform', originalPlatformDescriptor);
  await rm(tempRoot, { recursive: true, force: true });
});

describe('CA directory and state', () => {
  it('resolves override, environment, and platform paths in precedence order', () => {
    const override = join(tempRoot, 'override');
    vi.stubEnv('CERTKIT_HOME', join(tempRoot, 'environment'));
    expect(resolveCaDir(override)).toBe(override);
    expect(resolveCaDir()).toBe(join(tempRoot, 'environment'));

    vi.stubEnv('CERTKIT_HOME', '');
    setPlatform('linux');
    expect(resolveCaDir()).toBe(join(homedir(), '.config', 'certkit'));
    vi.stubEnv('XDG_CONFIG_HOME', join(tempRoot, 'xdg'));
    expect(resolveCaDir()).toBe(join(tempRoot, 'xdg', 'certkit'));

    setPlatform('darwin');
    expect(resolveCaDir()).toBe(
      join(homedir(), 'Library', 'Application Support', 'certkit'),
    );

    setPlatform('win32');
    vi.stubEnv('LOCALAPPDATA', 'C:\\Users\\test\\AppData\\Local');
    expect(resolveCaDir()).toBe(
      win32.join('C:\\Users\\test\\AppData\\Local', 'certkit'),
    );
  });

  it('does not create a path while resolving it', () => {
    const path = join(tempRoot, 'does-not-exist');
    expect(resolveCaDir(path)).toBe(path);
    expect(existsSync(path)).toBe(false);
  });

  it('returns null for absent state and atomically round-trips the durable schema', () => {
    const dir = join(tempRoot, 'ca');
    expect(readState(dir)).toBeNull();
    writeStateAtomic(dir, state());
    expect(readState(dir)).toEqual(state());
    if (process.platform !== 'win32') {
      expect(lstatSync(dir).mode & 0o777).toBe(0o700);
      expect(lstatSync(join(dir, 'state.json')).mode & 0o777).toBe(0o600);
    }
  });

  it('rejects malformed state instead of treating it as an empty CA', () => {
    const dir = join(tempRoot, 'ca');
    writeStateAtomic(dir, state());
    writeFileSync(join(dir, 'state.json'), '{"version":1,"phase":"unknown"}');
    expect(() => readState(dir)).toThrowError(
      expect.objectContaining({ code: 'CA_UNREADABLE' }),
    );
  });

  it('rejects a symlink at the CA directory final component', () => {
    const realDir = join(tempRoot, 'real-ca');
    const linkedDir = join(tempRoot, 'linked-ca');
    mkdirSync(realDir, { mode: 0o700 });
    symlinkSync(
      realDir,
      linkedDir,
      process.platform === 'win32' ? 'junction' : 'dir',
    );
    expect(() => writeStateAtomic(linkedDir, state())).toThrowError(
      expect.objectContaining({ code: 'CA_UNREADABLE' }),
    );
  });

  it('allows a symlinked ancestor and rejects an exposed CA directory', () => {
    const realParent = join(tempRoot, 'real-parent');
    const linkedParent = join(tempRoot, 'linked-parent');
    mkdirSync(realParent, { mode: 0o700 });
    symlinkSync(
      realParent,
      linkedParent,
      process.platform === 'win32' ? 'junction' : 'dir',
    );
    const dir = join(linkedParent, 'ca');
    writeStateAtomic(dir, state());
    expect(readState(dir)).toEqual(state());

    if (process.platform !== 'win32') {
      chmodSync(dir, 0o755);
      expect(() => readState(dir)).toThrowError(
        expect.objectContaining({ code: 'CA_UNREADABLE' }),
      );
      expect(() =>
        writePrivateKey(dir, 'ca-key.pem', 'private key'),
      ).toThrowError(expect.objectContaining({ code: 'CA_UNREADABLE' }));
    }
  });

  it.skipIf(process.platform === 'win32')(
    'rejects a CA directory owned by another user',
    () => {
      const dir = join(tempRoot, 'ca');
      writeStateAtomic(dir, state());
      const uid = process.getuid?.();
      if (uid === undefined) return;
      const getuid = vi.spyOn(process, 'getuid').mockReturnValue(uid + 1);
      try {
        expect(() => readState(dir)).toThrowError(
          expect.objectContaining({ code: 'CA_UNREADABLE' }),
        );
      } finally {
        getuid.mockRestore();
      }
    },
  );

  it('rejects a regular file used as a CA directory and a symlink state target', () => {
    const notADirectory = join(tempRoot, 'not-a-directory');
    writeFileSync(notADirectory, 'foreign data');
    expect(() => writeStateAtomic(notADirectory, state())).toThrowError(
      expect.objectContaining({ code: 'CA_UNREADABLE' }),
    );

    if (process.platform !== 'win32') {
      const dir = join(tempRoot, 'ca');
      const elsewhere = join(tempRoot, 'elsewhere.json');
      mkdirSync(dir, { mode: 0o700 });
      writeFileSync(elsewhere, JSON.stringify(state()), { mode: 0o600 });
      symlinkSync(elsewhere, join(dir, 'state.json'));
      expect(() => writeStateAtomic(dir, state())).toThrowError(
        expect.objectContaining({ code: 'CA_UNREADABLE' }),
      );
      expect(readFileSync(elsewhere, 'utf8')).toBe(JSON.stringify(state()));
    }

    const directoryStatePath = join(tempRoot, 'ca-with-state-directory');
    mkdirSync(directoryStatePath, { mode: 0o700 });
    mkdirSync(join(directoryStatePath, 'state.json'), { mode: 0o700 });
    expect(() => readState(directoryStatePath)).toThrowError(
      expect.objectContaining({ code: 'CA_UNREADABLE' }),
    );
  });

  it('requires a protected CA directory before creating a private key', () => {
    const dir = join(tempRoot, 'missing');
    expect(() =>
      writePrivateKey(dir, 'ca-key.pem', 'private key'),
    ).toThrowError(expect.objectContaining({ code: 'CA_UNREADABLE' }));
  });

  it('creates private keys exclusively with restrictive permissions', () => {
    const dir = join(tempRoot, 'ca');
    writeStateAtomic(dir, state());
    const keyPath = writePrivateKey(dir, 'ca-key.pem', 'private key');
    expect(readFileSync(keyPath, 'utf8')).toBe('private key');
    if (process.platform !== 'win32')
      expect(lstatSync(keyPath).mode & 0o777).toBe(0o600);
    expect(() =>
      writePrivateKey(dir, 'ca-key.pem', 'replacement'),
    ).toThrowError(expect.objectContaining({ code: 'CA_UNREADABLE' }));
    expect(readFileSync(keyPath, 'utf8')).toBe('private key');
  });

  it.skipIf(process.platform === 'win32')(
    'rejects a private-key symlink without following it',
    () => {
      const dir = join(tempRoot, 'ca');
      const foreignKey = join(tempRoot, 'foreign-key.pem');
      writeStateAtomic(dir, state());
      writeFileSync(foreignKey, 'foreign key bytes', { mode: 0o600 });
      symlinkSync(foreignKey, join(dir, 'ca-key.pem'));
      expect(() =>
        writePrivateKey(dir, 'ca-key.pem', 'replacement bytes'),
      ).toThrowError(expect.objectContaining({ code: 'CA_UNREADABLE' }));
      expect(readFileSync(foreignKey, 'utf8')).toBe('foreign key bytes');
    },
  );

  it('calls the injected guard before directory and key writes', () => {
    const guard: FsGuard = {
      protectDirectory: vi.fn(),
      assertProtectedDirectory: vi.fn(),
      assertProtectedFile: vi.fn(),
    };
    const dir = join(tempRoot, 'ca');
    writeStateAtomic(dir, state(), { fsGuard: guard });
    writePrivateKey(dir, 'ca-key.pem', 'private key', { fsGuard: guard });
    expect(guard.protectDirectory).toHaveBeenCalledWith(dir);
    expect(guard.assertProtectedDirectory).toHaveBeenCalledWith(dir);
    expect(guard.assertProtectedFile).toHaveBeenCalledWith(
      expect.stringContaining('ca-key.pem'),
    );
  });
});

describe('CA directory lock', () => {
  it('serializes concurrent operations and returns each operation result', async () => {
    const dir = join(tempRoot, 'ca');
    const events: string[] = [];
    const first = withLock(
      dir,
      async () => {
        events.push('first-enter');
        await delay(40);
        events.push('first-exit');
        return 1;
      },
      { timeoutMs: 1000 },
    );
    await delay(5);
    const second = withLock(
      dir,
      async () => {
        events.push('second-enter');
        return events.includes('first-exit') ? 2 : 0;
      },
      { timeoutMs: 1000 },
    );
    await expect(Promise.all([first, second])).resolves.toEqual([1, 2]);
    expect(events).toEqual(['first-enter', 'first-exit', 'second-enter']);
    expect(existsSync(join(dir, '.lock'))).toBe(false);
  });

  it('times out on a live lock with the path and manual recovery command', async () => {
    const dir = join(tempRoot, 'ca');
    let releaseLock!: () => void;
    const holder = withLock(
      dir,
      () => new Promise<void>((resolve) => (releaseLock = resolve)),
      { timeoutMs: 1000 },
    );
    await waitFor(() => existsSync(join(dir, '.lock')), 1000);
    await expect(
      withLock(dir, async () => undefined, { timeoutMs: 15 }),
    ).rejects.toMatchObject({
      code: 'CA_UNREADABLE',
      message: expect.stringContaining(join(dir, '.lock')),
    });
    const manualCommand = process.platform === 'win32' ? 'Remove-Item' : 'rm ';
    await expect(
      withLock(dir, async () => undefined, { timeoutMs: 15 }),
    ).rejects.toThrow(manualCommand);
    releaseLock();
    await holder;
    expect(existsSync(join(dir, '.lock'))).toBe(false);
  });

  it('waits for a nonempty lock record to finish before treating it as malformed', async () => {
    const dir = join(tempRoot, 'ca');
    mkdirSync(dir, { mode: 0o700 });
    const lockPath = join(dir, '.lock');
    const record = {
      pid: process.pid + 10_000,
      startedAt: new Date().toISOString(),
    };
    writeFileSync(lockPath, '{"pid":', { mode: 0o600 });
    const completion = setTimeout(() => {
      writeFileSync(lockPath, `${JSON.stringify(record)}\n`);
    }, 5);

    try {
      await expect(
        withLock(dir, async () => 'acquired', { timeoutMs: 80 }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Timed out waiting for the CA lock'),
      });
      expect(JSON.parse(readFileSync(lockPath, 'utf8'))).toEqual(record);
    } finally {
      clearTimeout(completion);
      rmSync(lockPath, { force: true });
    }
  });

  it('never removes a stale lock and rejects malformed lock contents', async () => {
    const dir = join(tempRoot, 'ca');
    mkdirSync(dir, { mode: 0o700 });
    const lockPath = join(dir, '.lock');
    writeFileSync(
      lockPath,
      JSON.stringify({
        pid: process.pid + 10_000_000,
        startedAt: '2000-01-01T00:00:00.000Z',
      }),
      {
        mode: 0o600,
      },
    );
    await expect(
      withLock(dir, async () => undefined, { timeoutMs: 10 }),
    ).rejects.toMatchObject({
      code: 'CA_UNREADABLE',
    });
    expect(existsSync(lockPath)).toBe(true);

    writeFileSync(lockPath, 'not json');
    await expect(
      withLock(dir, async () => undefined, { timeoutMs: 100 }),
    ).rejects.toMatchObject({
      code: 'CA_UNREADABLE',
      message: expect.stringContaining(lockPath),
    });
    expect(existsSync(lockPath)).toBe(true);

    rmSync(lockPath);
    mkdirSync(lockPath);
    await expect(
      withLock(dir, async () => undefined, { timeoutMs: 100 }),
    ).rejects.toMatchObject({
      code: 'CA_UNREADABLE',
      message: expect.stringContaining(lockPath),
    });
  });

  it('retries acquisition when a lock disappears before its record can be read', async () => {
    const dir = join(tempRoot, 'ca');
    mkdirSync(dir, { mode: 0o700 });
    const lockPath = join(dir, '.lock');
    writeFileSync(
      lockPath,
      JSON.stringify({
        pid: process.pid,
        startedAt: new Date().toISOString(),
      }),
      { mode: 0o600 },
    );
    let removed = false;
    const guard: FsGuard = {
      protectDirectory: () => undefined,
      assertProtectedDirectory: () => undefined,
      assertProtectedFile: (path) => {
        if (!removed && path === lockPath) {
          removed = true;
          rmSync(path);
        }
      },
    };

    await expect(
      withLock(dir, async () => 'acquired', { fsGuard: guard }),
    ).resolves.toBe('acquired');
    expect(removed).toBe(true);
    expect(existsSync(lockPath)).toBe(false);
  });

  it('bounds repeated lock-disappearance retries by the configured timeout', async () => {
    const dir = join(tempRoot, 'ca');
    mkdirSync(dir, { mode: 0o700 });
    const lockPath = join(dir, '.lock');
    const foreignPid = process.pid + 1;
    const timeoutMs = 30;
    const churnMs = 120;
    const startedAt = Date.now();
    let replacedLocks = 0;
    const writeContendedLock = () =>
      writeFileSync(
        lockPath,
        JSON.stringify({
          pid: foreignPid,
          startedAt: new Date().toISOString(),
        }),
        { mode: 0o600 },
      );
    let removedLocks = 0;
    const open = fs.openSync;
    fs.openSync = ((path, flags, mode) => {
      if (
        path === lockPath &&
        flags === 'wx' &&
        Date.now() - startedAt < churnMs &&
        !existsSync(lockPath)
      ) {
        replacedLocks += 1;
        writeContendedLock();
      }
      return open(path, flags, mode);
    }) as typeof fs.openSync;
    syncBuiltinESMExports();
    const guard: FsGuard = {
      protectDirectory: () => undefined,
      assertProtectedDirectory: () => undefined,
      assertProtectedFile: (path) => {
        if (path !== lockPath) return;
        const record = JSON.parse(readFileSync(path, 'utf8')) as {
          pid: number;
        };
        if (record.pid !== foreignPid) return;
        removedLocks += 1;
        rmSync(path);
      },
    };

    try {
      await expect(
        withLock(dir, async () => 'acquired', {
          fsGuard: guard,
          timeoutMs,
        }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Timed out waiting for the CA lock'),
      });
      expect(replacedLocks).toBeGreaterThan(1);
      expect(removedLocks).toBe(replacedLocks);
      expect(Date.now() - startedAt).toBeLessThan(timeoutMs * 3);
    } finally {
      fs.openSync = open;
      syncBuiltinESMExports();
      rmSync(lockPath, { force: true });
    }
  });

  it('keeps the lock if closing its descriptor fails', async () => {
    const dir = join(tempRoot, 'ca');
    const close = fs.closeSync;
    fs.closeSync = (fd) => {
      close(fd);
      throw new Error('simulated close failure');
    };
    syncBuiltinESMExports();

    try {
      await expect(withLock(dir, async () => undefined)).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
      });
      expect(existsSync(join(dir, '.lock'))).toBe(true);
    } finally {
      fs.closeSync = close;
      syncBuiltinESMExports();
      rmSync(join(dir, '.lock'), { force: true });
    }
  });
});

it.skipIf(!workerDir)('cadir lock race child', async () => {
  if (!workerDir) return;
  const dir = workerDir;
  const id = process.env.CERTKIT_LOCK_RACE_ID;
  if (!id) throw new Error('lock race worker id is missing');
  appendFileSync(join(dir, 'ready'), `${id}\n`);
  const releasePath = join(dir, 'release');
  while (!existsSync(releasePath)) await delay(5);
  await withLock(
    dir,
    async () => {
      const current = readState(dir);
      if (!current) throw new Error('lock race state is missing');
      appendFileSync(join(dir, 'events'), `enter ${id}\n`);
      await delay(35);
      current.ca.serial = String(Number(current.ca.serial) + 1);
      writeStateAtomic(dir, current);
      appendFileSync(join(dir, 'events'), `leave ${id}\n`);
    },
    { timeoutMs: 20_000 },
  );
});

it.skipIf(workerDir)(
  'serializes a controlled multi-process state increment race',
  async () => {
    const dir = join(tempRoot, 'race');
    mkdirSync(dir, { mode: 0o700 });
    const workerCount = 3;
    const rounds = 2;
    for (let round = 0; round < rounds; round += 1) {
      const roundDir = join(dir, String(round));
      mkdirSync(roundDir, { mode: 0o700 });
      const initialState = state();
      initialState.ca.serial = '0';
      writeStateAtomic(roundDir, initialState);
      writeFileSync(join(roundDir, 'events'), '');
      const workers = Array.from({ length: workerCount }, (_, index) =>
        runLockWorker(roundDir, `${round}-${index}`),
      );
      await waitFor(
        () =>
          existsSync(join(roundDir, 'ready')) &&
          readFileSync(join(roundDir, 'ready'), 'utf8').trim().split('\n')
            .length === workerCount,
        20_000,
      );
      writeFileSync(join(roundDir, 'release'), 'go');
      expect(await Promise.all(workers)).toEqual(Array(workerCount).fill(0));
      expect(readState(roundDir)?.ca.serial).toBe(String(workerCount));
      const events = readFileSync(join(roundDir, 'events'), 'utf8')
        .trim()
        .split('\n');
      expect(events).toHaveLength(workerCount * 2);
      for (let index = 0; index < events.length; index += 2) {
        expect(events[index]).toMatch(/^enter /);
        expect(events[index + 1]).toMatch(/^leave /);
      }
    }
  },
  30_000,
);

describe('Windows ACL guard', () => {
  it('establishes the ACL with icacls and accepts the current user grant', () => {
    const path = 'C:\\Users\\test\\AppData\\Local\\certkit';
    const calls: Array<{ command: string; args: readonly string[] }> = [];
    const run = (command: string, args: readonly string[]) => {
      calls.push({ command, args });
      if (command === 'whoami') return '"DOMAIN\\test","S-1-5-21-1-2-3-1001"';
      if (args.includes('/inheritance:r'))
        return 'Successfully processed 1 files; Failed processing 0 files';
      return 'O:S-1-5-21-1-2-3-1001G:S-1-5-21-1-2-3-1001D:AI(A;OICI;FA;;;S-1-5-21-1-2-3-1001)';
    };
    const guard = createWindowsFsGuard(run);
    expect(() => guard.protectDirectory(path)).not.toThrow();
    expect(calls[1]).toEqual({
      command: 'icacls',
      args: [
        path,
        '/inheritance:r',
        '/grant:r',
        '*S-1-5-21-1-2-3-1001:(OI)(CI)F',
      ],
    });
  });

  it('fails closed when an explicit Everyone grant survives ACL establishment', () => {
    const path = 'C:\\Users\\test\\AppData\\Local\\certkit';
    const run = (command: string, args: readonly string[]) => {
      if (command === 'whoami') return '"DOMAIN\\test","S-1-5-21-1-2-3-1001"';
      if (args.includes('/inheritance:r'))
        return 'Successfully processed 1 files; Failed processing 0 files';
      return 'O:S-1-5-21-1-2-3-1001G:S-1-5-21-1-2-3-1001D:AI(A;OICI;FA;;;S-1-5-21-1-2-3-1001)(A;CI;RX;;;WD)';
    };
    const guard = createWindowsFsGuard(run);
    expect(() => guard.protectDirectory(path)).toThrowError(
      expect.objectContaining({ code: 'CA_UNREADABLE' }),
    );
  });

  it.each([
    ['SYSTEM', 'SY'],
    ['Administrators', 'BA'],
  ])('fails closed on an unverified explicit %s grant', (_name, alias) => {
    const path = 'C:\\Users\\test\\AppData\\Local\\certkit';
    const run = (command: string, args: readonly string[]) => {
      if (command === 'whoami') return '"DOMAIN\\test","S-1-5-21-1-2-3-1001"';
      if (args.includes('/inheritance:r'))
        return 'Successfully processed 1 files; Failed processing 0 files';
      return `O:S-1-5-21-1-2-3-1001G:S-1-5-21-1-2-3-1001D:AI(A;OICI;FA;;;S-1-5-21-1-2-3-1001)(A;CI;FA;;;${alias})`;
    };
    const guard = createWindowsFsGuard(run);
    expect(() => guard.protectDirectory(path)).toThrowError(
      expect.objectContaining({ code: 'CA_UNREADABLE' }),
    );
  });

  it('fails closed on a broad non-self grant on a drive-root path', () => {
    const path = 'C:\\';
    const run = (command: string, args: readonly string[]) => {
      if (command === 'whoami') return '"DOMAIN\\test","S-1-5-21-1-2-3-1001"';
      if (args.includes('/inheritance:r'))
        return 'Successfully processed 1 files; Failed processing 0 files';
      return 'O:S-1-5-21-1-2-3-1001G:S-1-5-21-1-2-3-1001D:AI(A;OICI;FA;;;WD)';
    };
    const guard = createWindowsFsGuard(run);
    expect(() => guard.protectDirectory(path)).toThrowError(
      expect.objectContaining({ code: 'CA_UNREADABLE' }),
    );
  });

  it('fails closed on an ACL entry it cannot parse', () => {
    const path = 'C:\\Users\\test\\AppData\\Local\\certkit';
    const run = (command: string, args: readonly string[]) => {
      if (command === 'whoami') return '"DOMAIN\\test","S-1-5-21-1-2-3-1001"';
      if (args.includes('/inheritance:r'))
        return 'Successfully processed 1 files; Failed processing 0 files';
      return 'D:AI(A;OICI;FA);unparsed;';
    };
    const guard = createWindowsFsGuard(run);
    expect(() => guard.protectDirectory(path)).toThrowError(
      expect.objectContaining({ code: 'CA_UNREADABLE' }),
    );
  });

  it('fails closed on an SDDL string without a DACL', () => {
    const path = 'C:\\Users\\test\\AppData\\Local\\certkit';
    const run = (command: string, args: readonly string[]) => {
      if (command === 'whoami') return '"DOMAIN\\test","S-1-5-21-1-2-3-1001"';
      if (args.includes('/inheritance:r'))
        return 'Successfully processed 1 files; Failed processing 0 files';
      return 'O:S-1-5-18G:S-1-5-18';
    };
    const guard = createWindowsFsGuard(run);
    expect(() => guard.protectDirectory(path)).toThrowError(
      expect.objectContaining({ code: 'CA_UNREADABLE' }),
    );
  });

  it('fails closed when icacls cannot establish the ACL', () => {
    const run = (command: string) => {
      if (command === 'whoami') return '"DOMAIN\\test","S-1-5-21-1-2-3-1001"';
      throw new Error('icacls failed');
    };
    const guard = createWindowsFsGuard(run);
    expect(() =>
      guard.protectDirectory('C:\\Users\\test\\certkit'),
    ).toThrowError(expect.objectContaining({ code: 'CA_UNREADABLE' }));
  });
});

describe('CA directory hardening edges', () => {
  it('requires an FsGuard for CA directory protection on Windows', () => {
    setPlatform('win32');
    expect(() =>
      writeStateAtomicCore(join(tempRoot, 'ca'), state(), {}),
    ).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(
          'Windows CA directory protection is unavailable',
        ),
      }),
    );
  });

  it('creates a CA directory without POSIX hardening on Windows', () => {
    setPlatform('win32');
    const dir = join(tempRoot, 'ca');
    const guard: FsGuard = {
      protectDirectory: () => undefined,
      assertProtectedDirectory: () => undefined,
      assertProtectedFile: () => undefined,
    };

    writeStateAtomicCore(dir, state(), { fsGuard: guard });

    expect(readStateCore(dir, { fsGuard: guard })).toEqual(state());
  });

  it('falls back to the default profile Local AppData on Windows', () => {
    setPlatform('win32');
    expect(resolveCaDir()).toBe(
      win32.join(homedir(), 'AppData', 'Local', 'certkit'),
    );
  });

  it('wraps guard failures and rethrows guard CertkitErrors', () => {
    const dir = join(tempRoot, 'ca');
    const plainFailure: FsGuard = {
      protectDirectory: () => {
        throw new Error('icacls exited 5');
      },
      assertProtectedDirectory: () => undefined,
      assertProtectedFile: () => undefined,
    };
    expect(() =>
      writeStateAtomic(dir, state(), { fsGuard: plainFailure }),
    ).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(
          'Filesystem protection could not be verified',
        ),
      }),
    );

    const certkitFailure: FsGuard = {
      protectDirectory: () => {
        throw new CertkitError('CA_UNREADABLE', 'guard rejected the directory');
      },
      assertProtectedDirectory: () => undefined,
      assertProtectedFile: () => undefined,
    };
    expect(() =>
      writeStateAtomic(dir, state(), { fsGuard: certkitFailure }),
    ).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: 'guard rejected the directory',
      }),
    );
  });

  it.skipIf(process.platform === 'win32')(
    'rejects a state file with loose permissions',
    () => {
      const dir = join(tempRoot, 'ca');
      writeStateAtomic(dir, state());
      chmodSync(join(dir, 'state.json'), 0o644);

      expect(() => readState(dir)).toThrowError(
        expect.objectContaining({
          code: 'CA_UNREADABLE',
          message: expect.stringContaining('CA file permissions are not 0600'),
        }),
      );
    },
  );

  it.skipIf(process.platform === 'win32')(
    'wraps a CA directory creation failure',
    () => {
      const parent = join(tempRoot, 'blocked');
      mkdirSync(parent, { mode: 0o700 });
      chmodSync(parent, 0o500);
      try {
        expect(() =>
          writeStateAtomic(join(parent, 'ca'), state()),
        ).toThrowError(
          expect.objectContaining({
            code: 'CA_UNREADABLE',
            message: expect.stringContaining('Could not create CA directory'),
          }),
        );
      } finally {
        chmodSync(parent, 0o700);
      }
    },
  );

  it.each([
    ['a non-record state', 'null'],
    [
      'a write record that is not an object',
      JSON.stringify({ ...state(), trustWrites: [null] }),
    ],
    ['an unsupported version', JSON.stringify({ ...state(), version: 2 })],
    ['a missing CA record', JSON.stringify({ ...state(), ca: null })],
    [
      'a non-string CA subject',
      JSON.stringify({ ...state(), ca: { ...state().ca, subject: 42 } }),
    ],
    [
      'a non-hash CA fingerprint',
      JSON.stringify({ ...state(), ca: { ...state().ca, sha256: 'nope' } }),
    ],
    [
      'a pending write without a fingerprint',
      JSON.stringify({
        ...state(),
        pendingWrites: [
          { store: 'nss', target: '/x', timestamp: '2026-01-01T00:00:00.000Z' },
        ],
      }),
    ],
  ])('rejects malformed state with %s', (_description, json) => {
    const dir = join(tempRoot, 'ca');
    mkdirSync(dir, { mode: 0o700 });
    writeFileSync(join(dir, 'state.json'), json, { mode: 0o600 });

    expect(() => readState(dir)).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('unsupported or malformed schema'),
      }),
    );
  });

  it('rejects an unparseable state file', () => {
    const dir = join(tempRoot, 'ca');
    mkdirSync(dir, { mode: 0o700 });
    writeFileSync(join(dir, 'state.json'), '{invalid json', { mode: 0o600 });

    expect(() => readState(dir)).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Could not read CA state'),
      }),
    );
  });

  it('refuses to write malformed state', () => {
    const dir = join(tempRoot, 'ca');

    expect(() =>
      writeStateAtomic(dir, { ...state(), phase: 'unknown' } as StateFile),
    ).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(
          'Refusing to write malformed CA state',
        ),
      }),
    );
    expect(existsSync(dir)).toBe(false);
  });

  it('cleans up the temp file when guard verification fails during a state write', () => {
    const dir = join(tempRoot, 'ca');
    const guard: FsGuard = {
      protectDirectory: () => undefined,
      assertProtectedDirectory: () => undefined,
      assertProtectedFile: (path) => {
        if (path.includes('.state-')) throw new Error('temp rejected');
      },
    };

    expect(() =>
      writeStateAtomic(dir, state(), { fsGuard: guard }),
    ).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(
          'Filesystem protection could not be verified',
        ),
      }),
    );
    expect(readdirSync(dir).some((name) => name.includes('.state-'))).toBe(
      false,
    );
  });

  it('wraps a state rename failure', () => {
    const dir = join(tempRoot, 'ca');
    const rename = fs.renameSync;
    fs.renameSync = ((target, destination) => {
      if (String(destination).endsWith('state.json'))
        throw new Error('cross-device link');
      return rename(target, destination);
    }) as typeof fs.renameSync;
    syncBuiltinESMExports();
    try {
      expect(() => writeStateAtomic(dir, state())).toThrowError(
        expect.objectContaining({
          code: 'CA_UNREADABLE',
          message: expect.stringContaining(
            'Could not atomically write CA state',
          ),
        }),
      );
    } finally {
      fs.renameSync = rename;
      syncBuiltinESMExports();
    }
    expect(readdirSync(dir).some((name) => name.includes('.state-'))).toBe(
      false,
    );
  });

  it.each(['', '.', '..', join('one', 'two'), 'one\\two'])(
    'rejects a multi-component private key filename %p',
    (filename) => {
      const dir = join(tempRoot, 'ca');
      writeStateAtomic(dir, state());

      expect(() => writePrivateKey(dir, filename, 'key')).toThrowError(
        expect.objectContaining({
          code: 'CA_UNREADABLE',
          message: expect.stringContaining('single path component'),
        }),
      );
    },
  );

  it('cleans up the key file when guard verification fails during a key write', () => {
    const dir = join(tempRoot, 'ca');
    writeStateAtomic(dir, state());
    const guard: FsGuard = {
      protectDirectory: () => undefined,
      assertProtectedDirectory: () => undefined,
      assertProtectedFile: (path) => {
        if (path.endsWith('ca-key.pem')) throw new Error('key rejected');
      },
    };

    expect(() =>
      writePrivateKey(dir, 'ca-key.pem', 'key', { fsGuard: guard }),
    ).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(
          'Filesystem protection could not be verified',
        ),
      }),
    );
    expect(existsSync(join(dir, 'ca-key.pem'))).toBe(false);
  });

  it.skipIf(process.platform === 'win32')(
    'wraps a private key creation failure in an unwritable directory',
    () => {
      const dir = join(tempRoot, 'ca');
      writeStateAtomic(dir, state());
      chmodSync(dir, 0o500);
      try {
        expect(() => writePrivateKey(dir, 'ca-key.pem', 'key')).toThrowError(
          expect.objectContaining({
            code: 'CA_UNREADABLE',
            message: expect.stringContaining(
              'Could not create protected CA key',
            ),
          }),
        );
      } finally {
        chmodSync(dir, 0o700);
      }
    },
  );

  it.skipIf(process.platform === 'win32')(
    'rethrows a CertkitError from post-creation directory inspection',
    () => {
      const target = join(tempRoot, 'ca');
      const lstat = fs.lstatSync;
      let inspections = 0;
      fs.lstatSync = ((path, options) => {
        if (path === target) {
          inspections += 1;
          if (inspections > 1)
            throw Object.assign(new Error('denied'), { code: 'EACCES' });
        }
        return lstat(path, options);
      }) as typeof fs.lstatSync;
      syncBuiltinESMExports();
      try {
        expect(() => writeStateAtomic(target, state())).toThrowError(
          expect.objectContaining({
            code: 'CA_UNREADABLE',
            message: expect.stringContaining(
              'Cannot inspect CA filesystem entry',
            ),
          }),
        );
      } finally {
        fs.lstatSync = lstat;
        syncBuiltinESMExports();
      }
    },
  );

  it.skipIf(process.platform === 'win32')(
    'wraps a state temp file creation failure in an unwritable directory',
    () => {
      const dir = join(tempRoot, 'ca');
      mkdirSync(dir, { mode: 0o700 });
      chmodSync(dir, 0o500);
      try {
        expect(() => writeStateAtomic(dir, state())).toThrowError(
          expect.objectContaining({
            code: 'CA_UNREADABLE',
            message: expect.stringContaining(
              'Could not atomically write CA state',
            ),
          }),
        );
      } finally {
        chmodSync(dir, 0o700);
      }
    },
  );
});

describe('CA directory lock edges', () => {
  it.each([-1, Number.NaN])(
    'rejects an invalid lock timeout %s',
    async (timeoutMs) => {
      await expect(
        withLock(join(tempRoot, 'ca'), async () => undefined, { timeoutMs }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Lock timeout must be non-negative'),
      });
    },
  );

  it.each([
    ['a JSON array', '[1]'],
    [
      'a zero pid',
      JSON.stringify({ pid: 0, startedAt: new Date().toISOString() }),
    ],
    [
      'a non-integer pid',
      JSON.stringify({ pid: 1.5, startedAt: new Date().toISOString() }),
    ],
    ['an invalid timestamp', JSON.stringify({ pid: 1, startedAt: 'never' })],
    ['newline-terminated garbage', 'garbage\n'],
  ])(
    'rejects a contended lock holding %s without waiting',
    async (_description, contents) => {
      const dir = join(tempRoot, 'ca');
      mkdirSync(dir, { mode: 0o700 });
      const lockPath = join(dir, '.lock');
      writeFileSync(lockPath, contents, { mode: 0o600 });
      try {
        await expect(
          withLock(dir, async () => undefined, { timeoutMs: 50 }),
        ).rejects.toMatchObject({
          code: 'CA_UNREADABLE',
          message: expect.stringContaining('unreadable or malformed'),
        });
      } finally {
        rmSync(lockPath, { force: true });
      }
    },
  );

  it('removes its fresh lock when guard verification fails', async () => {
    const dir = join(tempRoot, 'ca');
    mkdirSync(dir, { mode: 0o700 });
    const lockPath = join(dir, '.lock');
    const guard: FsGuard = {
      protectDirectory: () => undefined,
      assertProtectedDirectory: () => undefined,
      assertProtectedFile: (path) => {
        if (path === lockPath)
          throw new CertkitError('CA_UNREADABLE', 'lock rejected');
      },
    };

    await expect(
      withLock(dir, async () => undefined, { fsGuard: guard }),
    ).rejects.toMatchObject({
      code: 'CA_UNREADABLE',
      message: 'lock rejected',
    });
    expect(existsSync(lockPath)).toBe(false);
  });

  it('wraps a lock record write failure', async () => {
    const dir = join(tempRoot, 'ca');
    mkdirSync(dir, { mode: 0o700 });
    const write = fs.writeFileSync;
    fs.writeFileSync = ((
      target: unknown,
      data?: unknown,
      options?: unknown,
    ) => {
      if (typeof target === 'number') throw new Error('disk full');
      return (write as (t: unknown, d?: unknown, o?: unknown) => void)(
        target,
        data,
        options,
      );
    }) as typeof fs.writeFileSync;
    syncBuiltinESMExports();
    try {
      await expect(
        withLock(dir, async () => undefined, { timeoutMs: 1000 }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Could not create CA lock'),
      });
    } finally {
      fs.writeFileSync = write;
      syncBuiltinESMExports();
    }
    expect(existsSync(join(dir, '.lock'))).toBe(false);
  });

  it.skipIf(process.platform === 'win32')(
    'wraps a lock creation failure from an unwritable directory',
    async () => {
      const dir = join(tempRoot, 'ca');
      mkdirSync(dir, { mode: 0o700 });
      chmodSync(dir, 0o500);
      try {
        await expect(
          withLock(dir, async () => undefined, { timeoutMs: 50 }),
        ).rejects.toMatchObject({
          code: 'CA_UNREADABLE',
          message: expect.stringContaining('Could not create CA lock'),
        });
      } finally {
        chmodSync(dir, 0o700);
      }
    },
  );

  it('reports a lock release failure when the lock cannot be removed', async () => {
    const dir = join(tempRoot, 'ca');
    mkdirSync(dir, { mode: 0o700 });
    const lockPath = join(dir, '.lock');
    const unlink = fs.unlinkSync;
    fs.unlinkSync = ((path) => {
      if (path === lockPath) throw new Error('unlink failed');
      return unlink(path);
    }) as typeof fs.unlinkSync;
    syncBuiltinESMExports();
    try {
      await expect(
        withLock(dir, async () => 'done', { timeoutMs: 1000 }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Could not release CA lock'),
      });
    } finally {
      fs.unlinkSync = unlink;
      syncBuiltinESMExports();
      rmSync(lockPath, { force: true });
    }
  });

  it('suggests Remove-Item for manual lock recovery on Windows', async () => {
    setPlatform('win32');
    const dir = join(tempRoot, 'ca');
    mkdirSync(dir, { mode: 0o700 });
    const lockPath = join(dir, '.lock');
    writeFileSync(
      lockPath,
      JSON.stringify({
        pid: process.pid + 10_000,
        startedAt: new Date().toISOString(),
      }),
      { mode: 0o600 },
    );
    const guard: FsGuard = {
      protectDirectory: () => undefined,
      assertProtectedDirectory: () => undefined,
      assertProtectedFile: () => undefined,
    };
    try {
      await expect(
        withLockCore(dir, async () => undefined, {
          timeoutMs: 15,
          fsGuard: guard,
        }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Remove-Item'),
      });
    } finally {
      rmSync(lockPath, { force: true });
    }
  });

  it('treats an uninspectable contended lock as changed and retries until timeout', async () => {
    const dir = join(tempRoot, 'ca');
    mkdirSync(dir, { mode: 0o700 });
    const lockPath = join(dir, '.lock');
    writeFileSync(
      lockPath,
      JSON.stringify({
        pid: process.pid + 10_000,
        startedAt: new Date().toISOString(),
      }),
      { mode: 0o600 },
    );
    const lstat = fs.lstatSync;
    let tripped = false;
    fs.lstatSync = ((path, options) => {
      if (!tripped && path === lockPath) {
        tripped = true;
        throw new Error('stat failed');
      }
      return lstat(path, options);
    }) as typeof fs.lstatSync;
    syncBuiltinESMExports();
    try {
      await expect(
        withLock(dir, async () => undefined, { timeoutMs: 20 }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Timed out waiting for the CA lock'),
      });
      expect(tripped).toBe(true);
    } finally {
      fs.lstatSync = lstat;
      syncBuiltinESMExports();
      rmSync(lockPath, { force: true });
    }
  });

  it('removes the CA directory after the lock when empty and requested', async () => {
    const dir = join(tempRoot, 'ca');

    await expect(
      withLock(dir, async () => 'done', { removeDirectoryIfEmpty: true }),
    ).resolves.toBe('done');
    expect(existsSync(dir)).toBe(false);
  });

  it('keeps a nonempty CA directory on a removal request', async () => {
    const dir = join(tempRoot, 'ca');
    mkdirSync(dir, { mode: 0o700 });
    writeFileSync(join(dir, 'keep'), 'data', { mode: 0o600 });

    await expect(
      withLock(dir, async () => 'done', { removeDirectoryIfEmpty: true }),
    ).resolves.toBe('done');
    expect(existsSync(join(dir, 'keep'))).toBe(true);
  });

  it('ignores a CA directory that vanishes during removal', async () => {
    const dir = join(tempRoot, 'ca');
    const rmdir = fs.rmdirSync;
    fs.rmdirSync = (() => {
      throw Object.assign(new Error('gone'), { code: 'ENOENT' });
    }) as typeof fs.rmdirSync;
    syncBuiltinESMExports();
    try {
      await expect(
        withLock(dir, async () => 'done', { removeDirectoryIfEmpty: true }),
      ).resolves.toBe('done');
    } finally {
      fs.rmdirSync = rmdir;
      syncBuiltinESMExports();
    }
  });

  it('reports a CA directory removal failure that is not emptiness', async () => {
    const dir = join(tempRoot, 'ca');
    const rmdir = fs.rmdirSync;
    fs.rmdirSync = (() => {
      throw Object.assign(new Error('busy'), { code: 'EACCES' });
    }) as typeof fs.rmdirSync;
    syncBuiltinESMExports();
    try {
      await expect(
        withLock(dir, async () => 'done', { removeDirectoryIfEmpty: true }),
      ).rejects.toMatchObject({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Could not release CA lock'),
      });
    } finally {
      fs.rmdirSync = rmdir;
      syncBuiltinESMExports();
    }
  });
});
