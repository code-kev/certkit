import { spawn } from 'node:child_process';
import fs, {
  appendFileSync,
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
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
  options?: { fsGuard?: FsGuard; timeoutMs?: number },
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
);

describe('Windows ACL guard', () => {
  it('uses icacls argv and accepts the current user grant', () => {
    const path = 'C:\\Users\\test\\AppData\\Local\\certkit';
    const calls: Array<{ command: string; args: readonly string[] }> = [];
    const run = (command: string, args: readonly string[]) => {
      calls.push({ command, args });
      if (command === 'whoami') return '"DOMAIN\\test","S-1-5-21-1-2-3-1001"';
      if (args.includes('/inheritance:r'))
        return 'Successfully processed 1 files; Failed processing 0 files';
      return [
        '                  DOMAIN\\test:(OI)(CI)(F)',
        'Successfully processed 1 files; Failed processing 0 files',
      ].join('\r\n');
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
      return [
        '                  DOMAIN\\test:(OI)(CI)(F)',
        '                  Everyone:(RX)',
        'Successfully processed 1 files; Failed processing 0 files',
      ].join('\r\n');
    };
    const guard = createWindowsFsGuard(run);
    expect(() => guard.protectDirectory(path)).toThrowError(
      expect.objectContaining({ code: 'CA_UNREADABLE' }),
    );
  });

  it.each([
    ['SYSTEM', 'NT AUTHORITY\\SYSTEM'],
    ['Administrators', 'BUILTIN\\Administrators'],
  ])('fails closed on an unverified explicit %s grant', (_name, principal) => {
    const path = 'C:\\Users\\test\\AppData\\Local\\certkit';
    const run = (command: string, args: readonly string[]) => {
      if (command === 'whoami') return '"DOMAIN\\test","S-1-5-21-1-2-3-1001"';
      if (args.includes('/inheritance:r'))
        return 'Successfully processed 1 files; Failed processing 0 files';
      return [
        `${path} ${principal}:(F)`,
        '                  DOMAIN\\test:(OI)(CI)(F)',
        'Successfully processed 1 files; Failed processing 0 files',
      ].join('\r\n');
    };
    const guard = createWindowsFsGuard(run);
    expect(() => guard.protectDirectory(path)).toThrowError(
      expect.objectContaining({ code: 'CA_UNREADABLE' }),
    );
  });

  it('does not skip a broad first ACE on a drive-root path', () => {
    const path = 'C:\\';
    const run = (command: string, args: readonly string[]) => {
      if (command === 'whoami') return '"DOMAIN\\test","S-1-5-21-1-2-3-1001"';
      if (args.includes('/inheritance:r'))
        return 'Successfully processed 1 files; Failed processing 0 files';
      return [
        `${path}Everyone:(OI)(CI)(F)`,
        '                  DOMAIN\\test:(OI)(CI)(F)',
        'Successfully processed 1 files; Failed processing 0 files',
      ].join('\r\n');
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
      return [
        `${path} Everyone:unparsed-grant`,
        '                  DOMAIN\\test:(OI)(CI)(F)',
        'Successfully processed 1 files; Failed processing 0 files',
      ].join('\r\n');
    };
    const guard = createWindowsFsGuard(run);
    expect(() => guard.protectDirectory(path)).toThrowError(
      expect.objectContaining({ code: 'CA_UNREADABLE' }),
    );
  });

  it('fails closed on an unrecognized nonempty ACL line', () => {
    const path = 'C:\\Users\\test\\AppData\\Local\\certkit';
    const run = (command: string, args: readonly string[]) => {
      if (command === 'whoami') return '"DOMAIN\\test","S-1-5-21-1-2-3-1001"';
      if (args.includes('/inheritance:r'))
        return 'Successfully processed 1 files; Failed processing 0 files';
      return [
        'Everyone F',
        '                  DOMAIN\\test:(OI)(CI)(F)',
        'Successfully processed 1 files; Failed processing 0 files',
      ].join('\r\n');
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
