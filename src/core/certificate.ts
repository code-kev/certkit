import '../reflect-metadata.js';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  X509Certificate as NodeX509Certificate,
  randomUUID,
} from 'node:crypto';
import {
  closeSync,
  lstatSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { userInfo } from 'node:os';
import { basename, join } from 'node:path';
import {
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  SubjectAlternativeNameExtension,
  X509Certificate,
} from '@peculiar/x509';
import {
  type FileOptions,
  type FsGuard,
  readState,
  resolveCaDir,
  type StateFile,
  withLock,
  writePrivateKey,
  writeStateAtomic,
} from './cadir.js';
import { type CaMaterial, mintCa, mintLeaf } from './certgen.js';
import { CertkitError } from './errors.js';
import { type ValidName, validateNames } from './validate.js';

const DEFAULT_VALIDITY_DAYS = 825;
const DAY_MS = 86_400_000;

export interface CertificateOptions {
  validityDays?: number;
  caDir?: string;
}

export interface CertificateBundle {
  readonly cert: string;
  readonly key: string;
  readonly caCert: string;
}

interface LockedContext extends FileOptions {
  dir: string;
}

interface LeafMetadata {
  names: string[];
  validityDays: number;
  expiresAt: string;
}

interface ParsedCertificateOptions {
  validityDays: number;
  caDir?: string;
}

function invalidOptions(message: string): CertkitError {
  return new CertkitError('INVALID_OPTIONS', message);
}

function parseOptions(options?: CertificateOptions): ParsedCertificateOptions {
  if (
    options !== undefined &&
    (typeof options !== 'object' || options === null || Array.isArray(options))
  ) {
    throw invalidOptions('Certificate options must be an object.');
  }
  const value = options as CertificateOptions | undefined;
  const validityDays =
    value?.validityDays === undefined
      ? DEFAULT_VALIDITY_DAYS
      : value.validityDays;
  if (
    !Number.isInteger(validityDays) ||
    validityDays < 1 ||
    validityDays > DEFAULT_VALIDITY_DAYS
  ) {
    throw invalidOptions(
      `Leaf validity must be an integer between 1 and ${DEFAULT_VALIDITY_DAYS} days.`,
    );
  }
  if (value?.caDir !== undefined && typeof value.caDir !== 'string') {
    throw invalidOptions('caDir must be a string when provided.');
  }
  return value?.caDir === undefined
    ? { validityDays }
    : { validityDays, caDir: value.caDir };
}

function fileOptions(fsGuard?: FsGuard): FileOptions {
  return fsGuard ? { fsGuard } : {};
}

function normalizedNameSet(validNames: ValidName[]): {
  names: string[];
  validNames: ValidName[];
} {
  const byName = new Map<string, ValidName>();
  for (const name of validNames) {
    const value = name.kind === 'dns' ? name.ascii : name.ip;
    const normalized = value.toLowerCase();
    byName.set(
      normalized,
      name.kind === 'dns'
        ? { kind: 'dns', ascii: normalized }
        : { kind: 'ip', ip: normalized },
    );
  }
  const names = [...byName.keys()].sort();
  return {
    names,
    validNames: names.map((name) => byName.get(name) as ValidName),
  };
}

function isMissing(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'ENOENT'
  );
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

function assertProtectedFile(path: string, fsGuard?: FsGuard): void {
  try {
    fsGuard?.assertProtectedFile(path);
  } catch (cause) {
    if (cause instanceof CertkitError) throw cause;
    throw unreadable(
      path,
      'Filesystem protection could not be verified',
      cause,
    );
  }
}

function readCaFile(
  dir: string,
  filename: string,
  fsGuard?: FsGuard,
): string | null {
  const path = join(dir, filename);
  let stat: ReturnType<typeof lstatSync>;
  try {
    stat = lstatSync(path);
  } catch (error) {
    if (isMissing(error)) return null;
    throw unreadable(path, 'Cannot inspect CA material', error);
  }
  if (stat.isSymbolicLink() || !stat.isFile())
    throw unreadable(path, 'CA material is not a regular file');
  if (process.platform !== 'win32') {
    const uid = process.getuid?.();
    if (uid !== undefined && stat.uid !== uid)
      throw unreadable(path, 'CA material is not owned by the current user');
    if ((stat.mode & 0o777) !== 0o600)
      throw unreadable(path, 'CA material permissions are not 0600');
  }
  assertProtectedFile(path, fsGuard);
  try {
    return readFileSync(path, 'utf8');
  } catch (error) {
    throw unreadable(path, 'Could not read CA material', error);
  }
}

function caState(ca: CaMaterial, phase: StateFile['phase']): StateFile {
  const certificate = new NodeX509Certificate(ca.certPem);
  return {
    version: 1,
    phase,
    ca: {
      subject: ca.subject,
      serial: ca.serial,
      sha256: createHash('sha256').update(certificate.raw).digest('hex'),
      createdAt: new Date().toISOString(),
      expiresAt: ca.expiresAt,
    },
    trustWrites: [],
    pendingWrites: [],
  };
}

function keyMatchesCertificate(
  keyPem: string,
  certificatePem: string,
): boolean {
  const certificate = new NodeX509Certificate(certificatePem);
  const key = createPublicKey(createPrivateKey(keyPem));
  return Buffer.from(key.export({ format: 'der', type: 'spki' })).equals(
    Buffer.from(certificate.publicKey.export({ format: 'der', type: 'spki' })),
  );
}

function validatedCa(
  state: StateFile,
  keyPem: string,
  certPem: string,
  dir: string,
): CaMaterial {
  try {
    const cert = new X509Certificate(certPem);
    const nativeCert = new NodeX509Certificate(certPem);
    const fingerprint = createHash('sha256')
      .update(nativeCert.raw)
      .digest('hex');
    if (
      !nativeCert.ca ||
      nativeCert.issuer !== nativeCert.subject ||
      !nativeCert.verify(nativeCert.publicKey) ||
      !keyMatchesCertificate(keyPem, certPem) ||
      state.ca.subject !== cert.subject ||
      state.ca.serial.toLowerCase() !== cert.serialNumber.toLowerCase() ||
      state.ca.sha256.toLowerCase() !== fingerprint ||
      state.ca.expiresAt !== cert.notAfter.toISOString()
    ) {
      throw new Error('CA key, certificate, and state metadata do not match');
    }
    return {
      keyPem,
      certPem,
      subject: cert.subject,
      serial: cert.serialNumber,
      expiresAt: cert.notAfter.toISOString(),
    };
  } catch (cause) {
    throw unreadable(dir, 'CA key, certificate, or state is invalid', cause);
  }
}

function removeProtectedFile(
  dir: string,
  filename: string,
  description: string,
  fsGuard?: FsGuard,
): void {
  const path = join(dir, filename);
  let stat: ReturnType<typeof lstatSync>;
  try {
    stat = lstatSync(path);
  } catch (error) {
    if (isMissing(error)) return;
    throw unreadable(path, 'Cannot inspect interrupted CA material', error);
  }
  if (stat.isSymbolicLink() || !stat.isFile())
    throw unreadable(path, `${description} is not a regular file`);
  if (process.platform !== 'win32') {
    const uid = process.getuid?.();
    if (uid !== undefined && stat.uid !== uid)
      throw unreadable(path, `${description} is not user-owned`);
    if ((stat.mode & 0o777) !== 0o600)
      throw unreadable(path, `${description} permissions are not 0600`);
  }
  assertProtectedFile(path, fsGuard);
  try {
    unlinkSync(path);
  } catch (error) {
    throw unreadable(path, `Could not remove ${description}`, error);
  }
}

function cleanStaleTemps(dir: string, fsGuard?: FsGuard): void {
  let files: string[];
  try {
    files = readdirSync(dir);
  } catch (cause) {
    throw unreadable(dir, 'Could not inspect temporary files', cause);
  }
  const temp =
    /^\.(?:certkit|leaf-key|state)-[a-f\d]{8}-[a-f\d]{4}-4[a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}\.tmp$/i;
  for (const filename of files) {
    if (temp.test(filename))
      removeProtectedFile(dir, filename, 'Stale temporary file', fsGuard);
  }
}

function writeAtomicFile(
  dir: string,
  filename: string,
  contents: string,
  fsGuard?: FsGuard,
): void {
  const path = join(dir, filename);
  const tempPath = join(dir, `.certkit-${randomUUID()}.tmp`);
  let fd: number | undefined;
  try {
    fd = openSync(tempPath, 'wx', 0o600);
    assertProtectedFile(tempPath, fsGuard);
    writeFileSync(fd, contents, 'utf8');
    closeSync(fd);
    fd = undefined;
    replaceFile(tempPath, path);
  } catch (cause) {
    if (fd !== undefined) closeSync(fd);
    try {
      unlinkSync(tempPath);
    } catch {
      // Keep the original write error.
    }
    if (cause instanceof CertkitError) throw cause;
    throw unreadable(path, 'Could not atomically write CA file', cause);
  }
}

function writePrivateKeyAtomic(
  dir: string,
  filename: string,
  contents: string,
  fsGuard?: FsGuard,
): void {
  const tempName = `.leaf-key-${randomUUID()}.tmp`;
  const tempPath = writePrivateKey(
    dir,
    tempName,
    contents,
    fileOptions(fsGuard),
  );
  try {
    replaceFile(tempPath, join(dir, filename));
  } catch (cause) {
    try {
      unlinkSync(tempPath);
    } catch {
      // Keep the original write error.
    }
    if (cause instanceof CertkitError) throw cause;
    throw unreadable(
      join(dir, filename),
      'Could not replace private key',
      cause,
    );
  }
}

function replaceFile(tempPath: string, path: string): void {
  try {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink())
      throw unreadable(path, 'Write target is a symbolic link');
    else if (!stat.isFile())
      throw unreadable(path, 'Write target is not a regular file');
  } catch (error) {
    if (!isMissing(error)) throw error;
  }
  renameSync(tempPath, path);
}

function leafPaths(
  dir: string,
  names: string[],
): {
  cert: string;
  key: string;
  meta: string;
} {
  const key = names.join('\n');
  const hash = createHash('sha256').update(key).digest('hex').slice(0, 16);
  const stem = `leaf-${hash}`;
  return {
    cert: join(dir, `${stem}.pem`),
    key: join(dir, `${stem}-key.pem`),
    meta: join(dir, `${stem}.meta.json`),
  };
}

function readCacheFile(path: string, fsGuard?: FsGuard): string | null {
  let stat: ReturnType<typeof lstatSync>;
  try {
    stat = lstatSync(path);
  } catch (error) {
    if (isMissing(error)) return null;
    return null;
  }
  if (stat.isSymbolicLink() || !stat.isFile()) return null;
  if (process.platform !== 'win32') {
    const uid = process.getuid?.();
    if (uid !== undefined && stat.uid !== uid) return null;
    if ((stat.mode & 0o777) !== 0o600) return null;
  }
  assertProtectedFile(path, fsGuard);
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

function isLeafMetadata(value: unknown): value is LeafMetadata {
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    return false;
  const meta = value as Partial<LeafMetadata>;
  return (
    Array.isArray(meta.names) &&
    meta.names.every((name) => typeof name === 'string') &&
    typeof meta.validityDays === 'number' &&
    typeof meta.expiresAt === 'string' &&
    Number.isFinite(Date.parse(meta.expiresAt))
  );
}

function matchesNames(cert: X509Certificate, names: string[]): boolean {
  const sans = cert.getExtension(SubjectAlternativeNameExtension)?.names;
  if (!sans) return false;
  const actual = sans
    .toJSON()
    .map((name) =>
      name.type === 'dns' || name.type === 'ip' ? name.value.toLowerCase() : '',
    )
    .sort();
  return (
    actual.length === names.length &&
    actual.every((name, index) => name === names[index])
  );
}

function cachedLeaf(
  dir: string,
  names: string[],
  validityDays: number,
  ca: CaMaterial,
  fsGuard?: FsGuard,
): CertificateBundle | null {
  const paths = leafPaths(dir, names);
  const certPem = readCacheFile(paths.cert, fsGuard);
  const keyPem = readCacheFile(paths.key, fsGuard);
  const metaText = readCacheFile(paths.meta, fsGuard);
  if (!certPem || !keyPem || !metaText) return null;
  try {
    const metaValue: unknown = JSON.parse(metaText);
    if (!isLeafMetadata(metaValue)) return null;
    const meta = metaValue;
    const cert = new X509Certificate(certPem);
    const nativeCert = new NodeX509Certificate(certPem);
    const nativeCa = new NodeX509Certificate(ca.certPem);
    const sansMatch = matchesNames(cert, names);
    const usages = cert.getExtension(ExtendedKeyUsageExtension)?.usages;
    if (
      JSON.stringify(meta.names) !== JSON.stringify(names) ||
      meta.validityDays !== validityDays ||
      meta.expiresAt !== cert.notAfter.toISOString() ||
      cert.notAfter.getTime() - cert.notBefore.getTime() !==
        validityDays * DAY_MS ||
      cert.issuer !== ca.subject ||
      !nativeCert.verify(nativeCa.publicKey) ||
      !keyMatchesCertificate(keyPem, certPem) ||
      !sansMatch ||
      !usages?.includes(ExtendedKeyUsage.serverAuth)
    ) {
      return null;
    }
    const renewalWindow = Math.min(30 * DAY_MS, (validityDays * DAY_MS) / 2);
    if (cert.notAfter.getTime() - Date.now() < renewalWindow) return null;
    return { cert: certPem, key: keyPem, caCert: ca.certPem };
  } catch {
    return null;
  }
}

async function mintAndCacheLeaf(
  dir: string,
  names: string[],
  validNames: ValidName[],
  validityDays: number,
  ca: CaMaterial,
  fsGuard?: FsGuard,
): Promise<CertificateBundle> {
  const leaf = await mintLeaf(ca, validNames, validityDays);
  const paths = leafPaths(dir, names);
  writePrivateKeyAtomic(dir, basename(paths.key), leaf.keyPem, fsGuard);
  writeAtomicFile(dir, basename(paths.cert), leaf.certPem, fsGuard);
  writeAtomicFile(
    dir,
    basename(paths.meta),
    `${JSON.stringify({ names, validityDays, expiresAt: leaf.expiresAt })}\n`,
    fsGuard,
  );
  return { cert: leaf.certPem, key: leaf.keyPem, caCert: ca.certPem };
}

function existingEntry(dir: string, filename: string): boolean {
  try {
    lstatSync(join(dir, filename));
    return true;
  } catch (error) {
    if (isMissing(error)) return false;
    throw unreadable(
      join(dir, filename),
      'Cannot inspect CA directory entry',
      error,
    );
  }
}

async function createCa(
  dir: string,
  fsGuard?: FsGuard,
): Promise<{
  material: CaMaterial;
  state: StateFile;
}> {
  const env = process.env as NodeJS.ProcessEnv & {
    USER?: string;
    USERNAME?: string;
  };
  let marker: string;
  try {
    marker = userInfo().username || env.USER || env.USERNAME || 'user';
  } catch {
    marker = env.USER || env.USERNAME || 'user';
  }
  const generated = await mintCa(marker);
  const state = caState(generated, 'initializing');
  writeStateAtomic(dir, state, fileOptions(fsGuard));
  writePrivateKey(dir, 'ca-key.pem', generated.keyPem, fileOptions(fsGuard));
  writeAtomicFile(dir, 'ca-cert.pem', generated.certPem, fsGuard);
  const keyPem = readCaFile(dir, 'ca-key.pem', fsGuard);
  const certPem = readCaFile(dir, 'ca-cert.pem', fsGuard);
  if (!keyPem || !certPem)
    throw unreadable(dir, 'New CA material is incomplete');
  const material = validatedCa(state, keyPem, certPem, dir);
  state.phase = 'active';
  writeStateAtomic(dir, state, fileOptions(fsGuard));
  return { material, state };
}

async function loadCa(
  dir: string,
  fsGuard?: FsGuard,
): Promise<{ material: CaMaterial; state: StateFile }> {
  const state = readState(dir, fileOptions(fsGuard));
  if (!state) {
    if (existingEntry(dir, 'ca-key.pem') || existingEntry(dir, 'ca-cert.pem')) {
      throw unreadable(dir, 'CA material exists without a state file');
    }
    return createCa(dir, fsGuard);
  }
  if (state.phase === 'retiring') {
    throw new CertkitError(
      'CA_UNREADABLE',
      'CA retirement is in progress; resume it with `certkit uninstall`.',
    );
  }

  const keyPem = readCaFile(dir, 'ca-key.pem', fsGuard);
  const certPem = readCaFile(dir, 'ca-cert.pem', fsGuard);
  if (state.phase === 'active') {
    if (!keyPem || !certPem)
      throw unreadable(dir, 'Active CA key or certificate is missing');
    return { material: validatedCa(state, keyPem, certPem, dir), state };
  }

  if (keyPem && certPem) {
    let material: CaMaterial | null = null;
    try {
      material = validatedCa(state, keyPem, certPem, dir);
    } catch {
      // A state marked initializing is safe to restart after an incomplete write.
    }
    if (material) {
      state.phase = 'active';
      writeStateAtomic(dir, state, fileOptions(fsGuard));
      return { material, state };
    }
  }
  removeProtectedFile(dir, 'ca-key.pem', 'Interrupted CA material', fsGuard);
  removeProtectedFile(dir, 'ca-cert.pem', 'Interrupted CA material', fsGuard);
  return createCa(dir, fsGuard);
}

export function caDir(options?: Pick<CertificateOptions, 'caDir'>): string {
  if (
    options !== undefined &&
    (typeof options !== 'object' || options === null || Array.isArray(options))
  ) {
    throw invalidOptions('caDir options must be an object.');
  }
  if (options?.caDir !== undefined && typeof options.caDir !== 'string') {
    throw invalidOptions('caDir must be a string when provided.');
  }
  return resolveCaDir(options?.caDir);
}

export async function certificateFor(
  names: string[],
  options?: CertificateOptions,
  dependencies: FileOptions = {},
): Promise<CertificateBundle> {
  if (!Array.isArray(names) || names.some((name) => typeof name !== 'string')) {
    throw new CertkitError(
      'INVALID_NAME',
      'Names must be an array of strings.',
    );
  }
  const parsedOptions = parseOptions(options);
  const nameSet = normalizedNameSet(validateNames(names));
  const dir = resolveCaDir(parsedOptions.caDir);
  return withLock(
    dir,
    () =>
      certificateForLocked(
        nameSet.validNames,
        { validityDays: parsedOptions.validityDays },
        { dir, ...fileOptions(dependencies.fsGuard) },
      ),
    fileOptions(dependencies.fsGuard),
  );
}

export async function certificateForLocked(
  validNames: ValidName[],
  options: Pick<CertificateOptions, 'validityDays'>,
  { dir, fsGuard }: LockedContext,
): Promise<CertificateBundle> {
  const validityDays = options.validityDays ?? DEFAULT_VALIDITY_DAYS;
  const nameSet = normalizedNameSet(validNames);
  const { material: ca } = await loadCa(dir, fsGuard);
  cleanStaleTemps(dir, fsGuard);
  const cached = cachedLeaf(dir, nameSet.names, validityDays, ca, fsGuard);
  if (cached) return cached;
  return mintAndCacheLeaf(
    dir,
    nameSet.names,
    nameSet.validNames,
    validityDays,
    ca,
    fsGuard,
  );
}
