import { randomUUID } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { basename, join, win32 } from 'node:path';
import { CertkitError } from './errors.js';

export interface StateFile {
  version: 1;
  phase: 'initializing' | 'active' | 'retiring';
  ca: {
    subject: string;
    serial: string;
    sha256: string;
    createdAt: string;
    expiresAt: string;
  };
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
}

export interface FsGuard {
  protectDirectory(path: string): void;
  assertProtectedDirectory(path: string): void;
  assertProtectedFile(path: string): void;
}

export interface FileOptions {
  fsGuard?: FsGuard;
}

export interface LockOptions extends FileOptions {
  timeoutMs?: number;
  removeDirectoryIfEmpty?: boolean;
}

interface LockFile {
  pid: number;
  startedAt: string;
}

class IncompleteLockRecordError extends Error {}

interface UnknownWriteRecord {
  store?: unknown;
  target?: unknown;
  mechanism?: unknown;
  serial?: unknown;
  sha256?: unknown;
  timestamp?: unknown;
}

interface UnknownCaRecord {
  subject?: unknown;
  serial?: unknown;
  sha256?: unknown;
  createdAt?: unknown;
  expiresAt?: unknown;
}

interface UnknownStateRecord {
  version?: unknown;
  phase?: unknown;
  ca?: unknown;
  trustWrites?: unknown;
  pendingWrites?: unknown;
}

interface UnknownLockRecord {
  pid?: unknown;
  startedAt?: unknown;
}

interface CaDirEnvironment {
  CERTKIT_HOME?: string;
  LOCALAPPDATA?: string;
  XDG_CONFIG_HOME?: string;
}

function unreadable(
  path: string,
  detail: string,
  cause?: unknown,
): CertkitError {
  return new CertkitError(
    'CA_UNREADABLE',
    `${detail}: ${path}`,
    cause === undefined ? undefined : { cause },
  );
}

function isMissing(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'ENOENT'
  );
}

function isNotEmpty(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error.code === 'ENOTEMPTY' || error.code === 'EEXIST')
  );
}

function getFsGuard(guard?: FsGuard): FsGuard | undefined {
  if (process.platform === 'win32' && !guard) {
    throw new CertkitError(
      'CA_UNREADABLE',
      'Windows CA directory protection is unavailable; provide an FsGuard that establishes and verifies the directory ACL.',
    );
  }
  return guard;
}

function callGuard(action: () => void, path: string): void {
  try {
    action();
  } catch (error) {
    if (error instanceof CertkitError) throw error;
    throw unreadable(
      path,
      'Filesystem protection could not be verified',
      error,
    );
  }
}

function inspectPath(
  path: string,
  expected: 'directory' | 'file',
): ReturnType<typeof lstatSync> {
  let stat: ReturnType<typeof lstatSync>;
  try {
    stat = lstatSync(path);
  } catch (error) {
    throw unreadable(path, 'Cannot inspect CA filesystem entry', error);
  }
  if (stat.isSymbolicLink())
    throw unreadable(path, 'Symlink write targets are not allowed');
  if (expected === 'directory' ? !stat.isDirectory() : !stat.isFile()) {
    throw unreadable(path, `CA filesystem entry is not a regular ${expected}`);
  }
  if (process.platform !== 'win32') {
    const uid = process.getuid?.();
    if (uid !== undefined && stat.uid !== uid)
      throw unreadable(
        path,
        'CA filesystem entry is not owned by the current user',
      );
    if (expected === 'directory' && (stat.mode & 0o077) !== 0) {
      throw unreadable(
        path,
        'CA directory permissions allow group or other access',
      );
    }
    if (expected === 'file' && (stat.mode & 0o777) !== 0o600) {
      throw unreadable(path, 'CA file permissions are not 0600');
    }
  }
  return stat;
}

function inspectExisting(
  path: string,
  expected: 'directory' | 'file',
): ReturnType<typeof lstatSync> | null {
  try {
    return inspectPath(path, expected);
  } catch (error) {
    if (error instanceof CertkitError && isMissing(error.cause)) return null;
    throw error;
  }
}

function assertDirectory(path: string, guard?: FsGuard): void {
  inspectPath(path, 'directory');
  if (guard) callGuard(() => guard.assertProtectedDirectory(path), path);
}

function ensureDirectory(path: string, guard?: FsGuard): void {
  const fsGuard = getFsGuard(guard);
  const before = inspectExisting(path, 'directory');
  if (!before) {
    try {
      mkdirSync(path, { recursive: true, mode: 0o700 });
      if (process.platform !== 'win32') {
        inspectPath(path, 'directory');
        chmodSync(path, 0o700);
      }
    } catch (error) {
      if (error instanceof CertkitError) throw error;
      throw unreadable(path, 'Could not create CA directory', error);
    }
  }
  if (fsGuard) callGuard(() => fsGuard.protectDirectory(path), path);
  assertDirectory(path, fsGuard);
}

function isTimestamp(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    Number.isFinite(Date.parse(value))
  );
}

function isHash(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f\d]{64}$/i.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isWrite(value: unknown, pending: boolean): boolean {
  if (!isRecord(value)) return false;
  const write = value as unknown as UnknownWriteRecord;
  const common =
    typeof write.store === 'string' &&
    write.store.length > 0 &&
    typeof write.target === 'string' &&
    write.target.length > 0 &&
    isHash(write.sha256) &&
    isTimestamp(write.timestamp) &&
    (write.mechanism === undefined ||
      (typeof write.mechanism === 'string' && write.mechanism.length > 0));
  return (
    common &&
    (pending || (typeof write.serial === 'string' && write.serial.length > 0))
  );
}

function isStateFile(value: unknown): value is StateFile {
  if (!isRecord(value)) return false;
  const state = value as unknown as UnknownStateRecord;
  if (state.version !== 1) return false;
  if (!['initializing', 'active', 'retiring'].includes(String(state.phase)))
    return false;
  if (!isRecord(state.ca)) return false;
  const ca = state.ca as unknown as UnknownCaRecord;
  if (
    typeof ca.subject !== 'string' ||
    !ca.subject ||
    typeof ca.serial !== 'string' ||
    !ca.serial ||
    !isHash(ca.sha256) ||
    !isTimestamp(ca.createdAt) ||
    !isTimestamp(ca.expiresAt)
  ) {
    return false;
  }
  return (
    Array.isArray(state.trustWrites) &&
    state.trustWrites.every((write) => isWrite(write, false)) &&
    Array.isArray(state.pendingWrites) &&
    state.pendingWrites.every((write) => isWrite(write, true))
  );
}

export function resolveCaDir(override?: string): string {
  if (override) return override;
  const env = process.env as CaDirEnvironment;
  const configured = env.CERTKIT_HOME;
  if (configured) return configured;
  if (process.platform === 'win32') {
    const localAppData = env.LOCALAPPDATA;
    const root = localAppData || win32.join(homedir(), 'AppData', 'Local');
    return win32.join(root, 'certkit');
  }
  if (process.platform === 'darwin')
    return join(homedir(), 'Library', 'Application Support', 'certkit');
  const configHome = env.XDG_CONFIG_HOME || join(homedir(), '.config');
  return join(configHome, 'certkit');
}

export function readState(
  dir: string,
  options: FileOptions = {},
): StateFile | null {
  if (!inspectExisting(dir, 'directory')) return null;
  const guard = getFsGuard(options.fsGuard);
  assertDirectory(dir, guard);
  const path = join(dir, 'state.json');
  const stat = inspectExisting(path, 'file');
  if (!stat) return null;
  if (guard) callGuard(() => guard.assertProtectedFile(path), path);
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8')) as unknown;
  } catch (error) {
    throw unreadable(path, 'Could not read CA state', error);
  }
  if (!isStateFile(parsed))
    throw unreadable(path, 'CA state has an unsupported or malformed schema');
  return parsed;
}

export function writeStateAtomic(
  dir: string,
  state: StateFile,
  options: FileOptions = {},
): void {
  if (!isStateFile(state))
    throw unreadable(
      join(dir, 'state.json'),
      'Refusing to write malformed CA state',
    );
  const guard = getFsGuard(options.fsGuard);
  ensureDirectory(dir, guard);
  const path = join(dir, 'state.json');
  inspectExisting(path, 'file');
  const tempPath = join(dir, `.state-${randomUUID()}.tmp`);
  let fd: number | undefined;
  let created = false;
  try {
    fd = openSync(tempPath, 'wx', 0o600);
    created = true;
    inspectPath(tempPath, 'file');
    if (guard) callGuard(() => guard.assertProtectedFile(tempPath), tempPath);
    writeFileSync(fd, `${JSON.stringify(state, null, 2)}\n`, 'utf8');
    closeSync(fd);
    fd = undefined;
    renameSync(tempPath, path);
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    if (created) {
      try {
        unlinkSync(tempPath);
      } catch {
        // Cleanup is best effort; the original failure is more useful.
      }
    }
    if (error instanceof CertkitError) throw error;
    throw unreadable(path, 'Could not atomically write CA state', error);
  }
}

export function writePrivateKey(
  dir: string,
  filename: string,
  contents: string | Uint8Array,
  options: FileOptions = {},
): string {
  if (
    !filename ||
    filename === '.' ||
    filename === '..' ||
    basename(filename) !== filename ||
    win32.basename(filename) !== filename
  ) {
    throw unreadable(
      dir,
      'Private key filename must be a single path component',
    );
  }
  const guard = getFsGuard(options.fsGuard);
  assertDirectory(dir, guard);
  const path = join(dir, filename);
  if (inspectExisting(path, 'file'))
    throw unreadable(path, 'Refusing to overwrite an existing CA key');
  let fd: number | undefined;
  let created = false;
  try {
    fd = openSync(path, 'wx', 0o600);
    created = true;
    inspectPath(path, 'file');
    if (guard) callGuard(() => guard.assertProtectedFile(path), path);
    writeFileSync(fd, contents);
    closeSync(fd);
    fd = undefined;
    return path;
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    if (created) {
      try {
        unlinkSync(path);
      } catch {
        // Cleanup is best effort; the original failure is more useful.
      }
    }
    if (error instanceof CertkitError) throw error;
    throw unreadable(path, 'Could not create protected CA key', error);
  }
}

function lockRecord(path: string, guard?: FsGuard): LockFile {
  inspectPath(path, 'file');
  if (guard) callGuard(() => guard.assertProtectedFile(path), path);
  let contents: string;
  try {
    contents = readFileSync(path, 'utf8');
  } catch (error) {
    throw unreadable(path, 'CA lock is unreadable or malformed', error);
  }
  let value: unknown;
  try {
    value = JSON.parse(contents) as unknown;
  } catch (error) {
    const cause =
      error instanceof SyntaxError && !contents.endsWith('\n')
        ? new IncompleteLockRecordError(error.message)
        : error;
    throw unreadable(path, 'CA lock is unreadable or malformed', cause);
  }
  if (!isRecord(value))
    throw unreadable(path, 'CA lock is unreadable or malformed');
  const lock = value as unknown as UnknownLockRecord;
  if (
    typeof lock.pid !== 'number' ||
    !Number.isSafeInteger(lock.pid) ||
    lock.pid < 1 ||
    !isTimestamp(lock.startedAt)
  ) {
    throw unreadable(path, 'CA lock is unreadable or malformed');
  }
  return lock as LockFile;
}

function lockIdentity(path: string): string | undefined {
  try {
    const stat = lstatSync(path);
    return `${stat.dev}:${stat.ino}:${stat.birthtimeMs}:${stat.mtimeMs}`;
  } catch {
    return undefined;
  }
}

async function initializedLockRecord(
  path: string,
  guard?: FsGuard,
  deadline = Date.now() + 15_000,
): Promise<LockFile> {
  const graceDeadline = Math.min(Date.now() + 250, deadline);
  for (;;) {
    try {
      return lockRecord(path, guard);
    } catch (error) {
      if (
        error instanceof CertkitError &&
        error.cause instanceof IncompleteLockRecordError
      ) {
        const remaining = graceDeadline - Date.now();
        if (remaining > 0) {
          await sleep(Math.min(5, remaining));
          continue;
        }
      }
      throw error;
    }
  }
}

function lockRemovalCommand(path: string): string {
  if (process.platform === 'win32')
    return `Remove-Item -LiteralPath '${path.replaceAll("'", "''")}' -Force`;
  return `rm -- '${path.replaceAll("'", "'\\''")}'`;
}

function lockTimeout(path: string): CertkitError {
  return unreadable(
    path,
    `Timed out waiting for the CA lock. After confirming no Certkit process is running, remove it manually with: ${lockRemovalCommand(path)}`,
  );
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function withLock<T>(
  dir: string,
  fn: () => Promise<T>,
  options: LockOptions = {},
): Promise<T> {
  const timeoutMs = options.timeoutMs ?? 15_000;
  if (!Number.isFinite(timeoutMs) || timeoutMs < 0)
    throw new CertkitError(
      'CA_UNREADABLE',
      'Lock timeout must be non-negative.',
    );
  const guard = getFsGuard(options.fsGuard);
  ensureDirectory(dir, guard);
  const path = join(dir, '.lock');
  const deadline = Date.now() + timeoutMs;
  let fd: number | undefined;

  while (fd === undefined) {
    try {
      fd = openSync(path, 'wx', 0o600);
      writeFileSync(
        fd,
        `${JSON.stringify({
          pid: process.pid,
          startedAt: new Date().toISOString(),
        })}\n`,
        'utf8',
      );
      inspectPath(path, 'file');
      if (guard) callGuard(() => guard.assertProtectedFile(path), path);
    } catch (error) {
      if (fd !== undefined) {
        closeSync(fd);
        fd = undefined;
        try {
          unlinkSync(path);
        } catch {
          // Cleanup is best effort; the original failure is more useful.
        }
        if (error instanceof CertkitError) throw error;
        throw unreadable(path, 'Could not create CA lock', error);
      }
      if (
        typeof error !== 'object' ||
        error === null ||
        !('code' in error) ||
        error.code !== 'EEXIST'
      ) {
        throw unreadable(path, 'Could not create CA lock', error);
      }
      // Snapshot identity before inspecting: on Windows the guard's icacls
      // outlives the lock when the holder releases mid-inspection, and a new
      // holder may have recreated it by the time we check. A changed or
      // missing lock means the inspected instance is gone, so retry.
      const identity = lockIdentity(path);
      try {
        await initializedLockRecord(path, guard, deadline);
      } catch (error) {
        if (
          error instanceof CertkitError &&
          (isMissing(error.cause) || lockIdentity(path) !== identity)
        ) {
          const remaining = deadline - Date.now();
          if (remaining <= 0) throw lockTimeout(path);
          await sleep(Math.min(50, remaining));
          continue;
        }
        throw error;
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        throw lockTimeout(path);
      }
      await sleep(Math.min(50, remaining));
    }
  }

  let operation: { ok: true; value: T } | { ok: false; error: unknown };
  try {
    operation = { ok: true, value: await fn() };
  } catch (error) {
    operation = { ok: false, error };
  }
  let releaseError: unknown;
  let closed = false;
  try {
    closeSync(fd);
    closed = true;
  } catch (error) {
    releaseError = error;
  }
  if (closed) {
    try {
      unlinkSync(path);
    } catch (error) {
      releaseError ??= error;
    }
    if (
      releaseError === undefined &&
      operation.ok &&
      options.removeDirectoryIfEmpty
    ) {
      try {
        rmdirSync(dir);
      } catch (error) {
        if (!isMissing(error) && !isNotEmpty(error)) releaseError = error;
      }
    }
  }
  if (releaseError !== undefined)
    throw unreadable(path, 'Could not release CA lock', releaseError);
  if (!operation.ok) throw operation.error;
  return operation.value;
}
