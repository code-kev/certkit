import { randomUUID } from 'node:crypto';
import {
  closeSync,
  fstatSync,
  linkSync,
  lstatSync,
  openSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { type CommandDef, defineCommand } from 'citty';
import {
  type FileOptions,
  type FsGuard,
  withLock,
  writePrivateKey,
} from '../../core/cadir.js';
import {
  type CertificateBundle,
  caDir,
  certificateForLocked,
} from '../../core/certificate.js';
import { CertkitError } from '../../core/errors.js';
import { validateNames } from '../../core/validate.js';
import { createWindowsFsGuard } from '../../platforms/fsguard.js';
import { jsonOutput, loadApi } from '../options.js';

type Args = {
  name: {
    type: 'positional';
    description: 'DNS names, wildcards, or IP addresses';
    required: false;
  };
  output: {
    type: 'string';
    alias: 'o';
    description: 'Existing output directory';
  };
  'validity-days': {
    type: 'string';
    description: 'Leaf certificate lifetime in days';
  };
  force: { type: 'boolean'; description: 'Overwrite existing regular files' };
  json: { type: 'boolean'; description: 'Print JSON' };
};

interface OutputPaths {
  cert: string;
  key: string;
}

interface WriteOptions {
  force: boolean;
  caDir: string;
  fsGuard?: FsGuard;
  platform?: NodeJS.Platform;
  rename?: typeof renameSync;
}

const args: Args = {
  name: {
    type: 'positional',
    description: 'DNS names, wildcards, or IP addresses',
    required: false,
  },
  output: {
    type: 'string',
    alias: 'o',
    description: 'Existing output directory',
  },
  'validity-days': {
    type: 'string',
    description: 'Leaf certificate lifetime in days',
  },
  force: { type: 'boolean', description: 'Overwrite existing regular files' },
  json: { type: 'boolean', description: 'Print JSON' },
};

function invalidOptions(message: string): CertkitError {
  return new CertkitError('INVALID_OPTIONS', message);
}

function missing(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'ENOENT'
  );
}

function sanitizeName(name: string): string {
  let value = name.startsWith('*.') ? `_wildcard.${name.slice(2)}` : name;
  value = value
    .replaceAll(':', '-')
    .replace(/[<>"/\\|?*]/g, '')
    .replace(/[. ]+$/, '');
  if (/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(value))
    value = `_${value}`;
  if (!value)
    throw new CertkitError('INVALID_NAME', 'Name cannot form a filename.');
  return value;
}

function outputPaths(names: string[], directory: string): OutputPaths {
  const first = names[0];
  if (!first)
    throw new CertkitError('INVALID_NAME', 'At least one name is required.');
  const suffix = names.length > 1 ? `+${names.length - 1}` : '';
  const filename = `${sanitizeName(first)}${suffix}.pem`;
  return {
    cert: join(directory, filename),
    key: join(directory, `${filename.slice(0, -4)}-key.pem`),
  };
}

function inspectOutput(path: string): boolean {
  let stat: ReturnType<typeof lstatSync>;
  try {
    stat = lstatSync(path);
  } catch (error) {
    if (missing(error)) return false;
    throw new CertkitError(
      'CA_UNREADABLE',
      `Cannot inspect output path: ${path}`,
      {
        cause: error,
      },
    );
  }
  if (stat.isSymbolicLink())
    throw new CertkitError(
      'CA_UNREADABLE',
      `Refusing a symbolic-link output path: ${path}`,
    );
  if (!stat.isFile())
    throw new CertkitError(
      'CA_UNREADABLE',
      `Output path is not a regular file: ${path}`,
    );
  return true;
}

function checkOutputPaths(paths: OutputPaths, force: boolean): void {
  const existing = [paths.cert, paths.key].filter(inspectOutput);
  if (existing.length && !force) {
    throw new CertkitError(
      'CA_UNREADABLE',
      `Output already exists: ${existing.join(', ')}. Use --force to overwrite.`,
    );
  }
}

function assertSameVolume(sourceDir: string, outputDir: string): void {
  try {
    if (statSync(sourceDir).dev !== statSync(outputDir).dev)
      throw new Error('different volumes');
  } catch (cause) {
    throw new CertkitError(
      'CA_UNREADABLE',
      `Cannot preserve the protected Windows key ACL when placing files in ${outputDir}. Choose an output directory on the same volume as ${sourceDir}, then retry.`,
      { cause },
    );
  }
}

function assertRegularOutput(path: string): void {
  let stat: ReturnType<typeof lstatSync>;
  try {
    stat = lstatSync(path);
  } catch (cause) {
    throw new CertkitError(
      'CA_UNREADABLE',
      `Cannot inspect placed output: ${path}`,
      {
        cause,
      },
    );
  }
  if (stat.isSymbolicLink() || !stat.isFile())
    throw new CertkitError(
      'CA_UNREADABLE',
      `Placed output is not a regular file: ${path}`,
    );
}

function preflightWindowsKeyPlacement(
  caDir: string,
  outputDir: string,
  force: boolean,
  fsGuard: FsGuard | undefined,
  rename: typeof renameSync,
): void {
  if (!fsGuard)
    throw new CertkitError(
      'CA_UNREADABLE',
      'Windows private-key placement requires filesystem protection checks.',
    );
  assertSameVolume(caDir, outputDir);

  const source = join(caDir, `.leaf-key-${randomUUID()}.tmp`);
  const target = join(outputDir, `.certkit-${randomUUID()}.tmp`);
  let sourceExists = false;
  let targetExists = false;
  let failure: unknown;
  try {
    writePrivateKey(caDir, basename(source), '', { fsGuard });
    sourceExists = true;
    if (force) {
      const fd = openSync(target, 'wx', 0o600);
      targetExists = true;
      closeSync(fd);
      rename(source, target);
      sourceExists = false;
    } else {
      linkSync(source, target);
      targetExists = true;
      assertRegularOutput(target);
      fsGuard.assertProtectedFile(target);
      unlinkSync(source);
      sourceExists = false;
    }
    assertRegularOutput(target);
    fsGuard.assertProtectedFile(target);
  } catch (cause) {
    failure = cause;
  }

  for (const [path, exists] of [
    [source, sourceExists],
    [target, targetExists],
  ] as const) {
    if (!exists) continue;
    try {
      unlinkSync(path);
    } catch (cause) {
      if (!missing(cause)) failure ??= cause;
    }
  }

  if (failure !== undefined)
    throw new CertkitError(
      'CA_UNREADABLE',
      `Could not verify protected Windows key placement in ${outputDir}. Key bytes were not placed. Inspect and restrict the destination with icacls, then retry.`,
      { cause: failure },
    );
}

function writeCertTemp(path: string, contents: string): void {
  let fd: number | undefined;
  try {
    fd = openSync(path, 'wx', 0o644);
    writeFileSync(fd, contents, 'utf8');
    closeSync(fd);
    fd = undefined;
  } catch (cause) {
    if (fd !== undefined) closeSync(fd);
    try {
      unlinkSync(path);
    } catch {
      // Keep the original write error.
    }
    throw new CertkitError(
      'CA_UNREADABLE',
      `Could not stage certificate output: ${path}`,
      {
        cause,
      },
    );
  }
}

function writeOutputKeyTemp(
  path: string,
  contents: string,
  fsGuard?: FsGuard,
): void {
  let fd: number | undefined;
  try {
    fd = openSync(path, 'wx', 0o600);
    const stat = fstatSync(fd);
    if (!stat.isFile() || (stat.mode & 0o777) !== 0o600)
      throw new CertkitError(
        'CA_UNREADABLE',
        `Private-key output is not protected with mode 0600: ${path}`,
      );
    const uid = process.getuid?.();
    if (uid !== undefined && stat.uid !== uid)
      throw new CertkitError(
        'CA_UNREADABLE',
        `Private-key output is not user-owned: ${path}`,
      );
    fsGuard?.assertProtectedFile(path);
    writeFileSync(fd, contents, 'utf8');
    closeSync(fd);
    fd = undefined;
  } catch (cause) {
    if (fd !== undefined) closeSync(fd);
    try {
      unlinkSync(path);
    } catch {
      // Keep the original write error.
    }
    if (cause instanceof CertkitError) throw cause;
    throw new CertkitError(
      'CA_UNREADABLE',
      `Could not stage private-key output: ${path}`,
      {
        cause,
      },
    );
  }
}

function removeTemp(path: string | undefined): void {
  if (!path) return;
  try {
    unlinkSync(path);
  } catch (error) {
    if (!missing(error)) throw error;
  }
}

function publish(
  temporary: string,
  target: string,
  force: boolean,
  rename: typeof renameSync,
  onPublished: () => void,
): void {
  if (force) {
    rename(temporary, target);
    onPublished();
  } else {
    linkSync(temporary, target);
    onPublished();
    unlinkSync(temporary);
  }
}

// Exported for focused filesystem-contract tests; the CLI supplies real defaults.
export function writeCertificateFiles(
  paths: OutputPaths,
  bundle: Pick<CertificateBundle, 'cert' | 'key'>,
  options: WriteOptions,
): void {
  const platform = options.platform ?? process.platform;
  const rename = options.rename ?? renameSync;
  const outputDir = dirname(paths.cert);
  checkOutputPaths(paths, options.force);
  if (platform === 'win32')
    preflightWindowsKeyPlacement(
      options.caDir,
      outputDir,
      options.force,
      options.fsGuard,
      rename,
    );

  const certTemp = join(outputDir, `.certkit-${randomUUID()}.tmp`);
  let keyTemp: string | undefined;
  let certTempExists = false;
  let keyReplaced = false;
  let certReplaced = false;
  let failed = false;
  let failure: unknown;
  try {
    writeCertTemp(certTemp, bundle.cert);
    certTempExists = true;
    if (platform === 'win32') {
      const filename = `.leaf-key-${randomUUID()}.tmp`;
      keyTemp = writePrivateKey(
        options.caDir,
        filename,
        bundle.key,
        options.fsGuard ? { fsGuard: options.fsGuard } : {},
      );
    } else {
      keyTemp = join(outputDir, `.leaf-key-${randomUUID()}.tmp`);
      writeOutputKeyTemp(keyTemp, bundle.key, options.fsGuard);
    }
    publish(keyTemp, paths.key, options.force, rename, () => {
      keyReplaced = true;
    });
    keyTemp = undefined;
    assertRegularOutput(paths.key);
    if (platform === 'win32') options.fsGuard?.assertProtectedFile(paths.key);
    publish(certTemp, paths.cert, options.force, rename, () => {
      certReplaced = true;
    });
    certTempExists = false;
  } catch (cause) {
    failed = true;
    failure = cause;
  }

  const cleanupFailures: Array<{ path: string; cause: unknown }> = [];
  for (const path of [keyTemp, certTempExists ? certTemp : undefined]) {
    if (!path) continue;
    try {
      removeTemp(path);
    } catch (cause) {
      cleanupFailures.push({ path, cause });
    }
  }
  if (failed || cleanupFailures.length) {
    if (
      !keyReplaced &&
      !certReplaced &&
      failure instanceof CertkitError &&
      cleanupFailures.length === 0
    ) {
      throw failure;
    }
    const action = options.force ? 'replaced' : 'created';
    const progress = [
      ...(keyReplaced ? [`key output was ${action} at ${paths.key}`] : []),
      ...(certReplaced
        ? [`certificate output was ${action} at ${paths.cert}`]
        : []),
    ];
    const base = progress.length
      ? `Could not complete certificate output placement; ${progress.join('; ')}.`
      : 'Could not write certificate outputs; neither output was replaced.';
    const detail = failure instanceof Error ? ` ${failure.message}` : '';
    const cleanup = cleanupFailures
      .map(({ path }) => ` Temporary file may remain at ${path}.`)
      .join('');
    throw new CertkitError('CA_UNREADABLE', `${base}${detail}${cleanup}`, {
      cause: failure ?? cleanupFailures[0]?.cause,
    });
  }
}

function outputDirectory(value: string | undefined): string {
  const path = resolve(value ?? process.cwd());
  try {
    if (!statSync(path).isDirectory()) throw new Error('not a directory');
  } catch {
    throw invalidOptions(`Output directory must already exist: ${path}`);
  }
  return path;
}

function message(error: unknown): { code: string; text: string } {
  if (error instanceof CertkitError)
    return { code: error.code, text: error.message };
  return { code: 'CLI_ERROR', text: 'Could not create certificate files.' };
}

function reportError(error: unknown, json: boolean): void {
  const result = message(error);
  if (json) {
    console.log(
      JSON.stringify({
        schemaVersion: 1,
        error: { code: result.code, message: result.text },
      }),
    );
  } else {
    console.error(`certkit: ${result.code}: ${result.text}`);
  }
  process.exitCode =
    result.code === 'INVALID_NAME' ||
    result.code === 'NAME_LIMIT' ||
    result.code === 'INVALID_OPTIONS'
      ? 2
      : 1;
}

export const createCommand: CommandDef<Args> = defineCommand({
  meta: { name: 'create', description: 'Create a local HTTPS certificate' },
  args,
  async run({ args }) {
    const json = jsonOutput === true || args.json === true;
    try {
      const names = args._;
      const force = args.force === true;
      const validNames = validateNames(names);
      const normalizedNames = validNames.map((name) =>
        name.kind === 'dns' ? name.ascii : name.ip,
      );
      const directory = outputDirectory(args.output);
      const paths = outputPaths(names, directory);
      const validityDays =
        args['validity-days'] === undefined
          ? 825
          : Number(args['validity-days']);
      if (
        !Number.isInteger(validityDays) ||
        validityDays < 1 ||
        validityDays > 825
      ) {
        throw invalidOptions(
          'Validity days must be an integer between 1 and 825.',
        );
      }

      // Catch collisions before CA generation, then recheck immediately before writes.
      checkOutputPaths(paths, force);
      const directoryPath = caDir();
      const fsGuard =
        process.platform === 'win32' ? createWindowsFsGuard() : undefined;
      const fileOptions: FileOptions = fsGuard ? { fsGuard } : {};
      await withLock(
        directoryPath,
        async () => {
          checkOutputPaths(paths, force);
          if (process.platform === 'win32')
            assertSameVolume(directoryPath, directory);
          const certificate = await certificateForLocked(
            validNames,
            { validityDays },
            { dir: directoryPath, ...fileOptions },
          );
          writeCertificateFiles(paths, certificate, {
            force,
            caDir: directoryPath,
            ...(fsGuard ? { fsGuard } : {}),
          });
        },
        fileOptions,
      );

      if (json) {
        console.log(
          JSON.stringify({
            schemaVersion: 1,
            names: normalizedNames,
            files: paths,
          }),
        );
      } else {
        console.log(`Created certificate: ${JSON.stringify(paths.cert)}`);
        console.log(`Created private key: ${JSON.stringify(paths.key)}`);
      }
      try {
        const { status } = await loadApi();
        const report = await status();
        if (report.stores.some((store) => store.state === 'untrusted'))
          console.error('CA not trusted — run `certkit install`');
      } catch {
        // A failed optional trust check does not undo successfully written files.
      }
    } catch (error) {
      reportError(error, json);
    }
  },
});
