import {
  existsSync,
  lstatSync,
  readdirSync,
  rmdirSync,
  unlinkSync,
} from 'node:fs';
import { join } from 'node:path';
import { type CommandDef, defineCommand } from 'citty';
import {
  type LockOptions,
  readState,
  type StateFile,
  withLock,
  writeStateAtomic,
} from '../../core/cadir.js';
import { readCaForUninstallLocked } from '../../core/certificate.js';
import { CertkitError } from '../../core/errors.js';
import { elevate } from '../elevate.js';
import { jsonOutput } from '../options.js';
import {
  adaptersById,
  adapterTargets,
  caRecordTargets,
  emitDryRun,
  emitEvent,
  emitFailure,
  emitResults,
  fileOptions,
  inspectInstalled,
  planUninstall,
  resolveDependencies,
  type TrustCommandDependencies,
  type TrustResult,
  type TrustTarget,
  targetTrustState,
  toErrorResult,
  trustCaPath,
  uniqueTargets,
  unsupportedTargetResult,
  unsupportedTargetsMessage,
  warnWsl,
} from './trust.js';

type Args = {
  'dry-run': {
    type: 'boolean';
    description: 'Print commands without changing state';
  };
  json: { type: 'boolean'; description: 'Print JSON' };
};

const args: Args = {
  'dry-run': {
    type: 'boolean',
    description: 'Print commands without changing state',
  },
  json: { type: 'boolean', description: 'Print JSON' },
};

function sameTarget(
  write: { store: string; target: string },
  target: TrustTarget,
): boolean {
  return write.store === target.store && write.target === target.target;
}

function removeTargetRecords(state: StateFile, target: TrustTarget): boolean {
  const trustCount = state.trustWrites.length;
  const pendingCount = state.pendingWrites.length;
  state.trustWrites = state.trustWrites.filter(
    (write) => !sameTarget(write, target),
  );
  state.pendingWrites = state.pendingWrites.filter(
    (write) => !sameTarget(write, target),
  );
  return (
    trustCount !== state.trustWrites.length ||
    pendingCount !== state.pendingWrites.length
  );
}

function recordTargetForRemoval(
  state: StateFile,
  target: TrustTarget,
): boolean {
  if (
    state.trustWrites.some((write) => sameTarget(write, target)) ||
    state.pendingWrites.some((write) => sameTarget(write, target))
  )
    return false;
  state.trustWrites.push({
    store: target.store,
    target: target.target,
    serial: state.ca.serial,
    sha256: state.ca.sha256,
    timestamp: new Date().toISOString(),
  });
  return true;
}

function missing(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'ENOENT'
  );
}

function ownedCacheOrTemp(filename: string): boolean {
  return (
    /^leaf-[a-f\d]{16}(?:-key)?\.pem$/i.test(filename) ||
    /^leaf-[a-f\d]{16}\.meta\.json$/i.test(filename) ||
    /^\.(?:certkit|leaf-key|state)-[a-f\d]{8}-[a-f\d]{4}-4[a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}\.tmp$/i.test(
      filename,
    )
  );
}

function ownedTrustExportTempDirectory(filename: string): boolean {
  return /^\.certkit-trust-[a-z\d]{6}$/i.test(filename);
}

function hasOrphanedOwnedFiles(dir: string): boolean {
  return readdirSync(dir).some(
    (filename) =>
      ownedCacheOrTemp(filename) || ownedTrustExportTempDirectory(filename),
  );
}

function removeTrustExportTempDirectory(
  dir: string,
  filename: string,
  dependencies: TrustCommandDependencies,
): void {
  const exportDir = join(dir, filename);
  let directoryStat: ReturnType<typeof lstatSync>;
  try {
    directoryStat = lstatSync(exportDir);
  } catch (error) {
    throw new CertkitError(
      'CA_UNREADABLE',
      `Could not inspect interrupted trust export directory ${exportDir}.`,
      { cause: error },
    );
  }
  const currentUid = process.getuid?.();
  if (
    directoryStat.isSymbolicLink() ||
    !directoryStat.isDirectory() ||
    (process.platform !== 'win32' &&
      ((directoryStat.mode & 0o777) !== 0o700 ||
        (currentUid !== undefined && directoryStat.uid !== currentUid)))
  )
    throw new CertkitError(
      'CA_UNREADABLE',
      `Refusing to remove an unsafe interrupted trust export directory: ${exportDir}`,
    );

  dependencies.fsGuard?.assertProtectedDirectory(exportDir);
  const entries = readdirSync(exportDir);
  if (entries.some((entry) => entry !== 'admin-settings.plist'))
    throw new CertkitError(
      'CA_UNREADABLE',
      `Refusing to remove unexpected contents from interrupted trust export directory: ${exportDir}`,
    );
  if (entries.length === 1) {
    const exportPath = join(exportDir, 'admin-settings.plist');
    const exportStat = lstatSync(exportPath);
    if (
      exportStat.isSymbolicLink() ||
      !exportStat.isFile() ||
      (process.platform !== 'win32' &&
        process.getuid?.() !== undefined &&
        exportStat.uid !== process.getuid?.())
    )
      throw new CertkitError(
        'CA_UNREADABLE',
        `Refusing to remove an unsafe interrupted trust export file: ${exportPath}`,
      );
    dependencies.fsGuard?.assertProtectedFile(exportPath);
    unlinkSync(exportPath);
  }
  try {
    rmdirSync(exportDir);
  } catch (error) {
    throw new CertkitError(
      'CA_UNREADABLE',
      `Could not remove interrupted trust export directory ${exportDir}.`,
      { cause: error },
    );
  }
}

function removeOwnedFile(
  dir: string,
  filename: string,
  dependencies: TrustCommandDependencies,
): boolean {
  const path = join(dir, filename);
  let stat: ReturnType<typeof lstatSync>;
  try {
    stat = lstatSync(path);
  } catch (error) {
    if (missing(error)) return false;
    throw new CertkitError(
      'CA_UNREADABLE',
      `Could not inspect owned CA file ${path}.`,
      { cause: error },
    );
  }
  if (stat.isSymbolicLink() || !stat.isFile())
    throw new CertkitError(
      'CA_UNREADABLE',
      `Refusing to remove a non-regular owned CA file: ${path}`,
    );
  if (process.platform !== 'win32') {
    const uid = process.getuid?.();
    if (uid !== undefined && stat.uid !== uid)
      throw new CertkitError(
        'CA_UNREADABLE',
        `Refusing to remove a CA file not owned by the current user: ${path}`,
      );
    // The signing key is never read during retirement, so a damaged mode must not block its deletion.
    if (filename !== 'ca-key.pem' && (stat.mode & 0o777) !== 0o600)
      throw new CertkitError(
        'CA_UNREADABLE',
        `Refusing to remove a CA file without 0600 permissions: ${path}`,
      );
  }
  dependencies.fsGuard?.assertProtectedFile(path);
  try {
    unlinkSync(path);
    return true;
  } catch (error) {
    throw new CertkitError(
      'CA_UNREADABLE',
      `Could not remove CA file ${path}.`,
      {
        cause: error,
      },
    );
  }
}

async function removeOwnedFiles(
  dir: string,
  dependencies: TrustCommandDependencies,
  state: StateFile,
): Promise<void> {
  if (state.trustWrites.length || state.pendingWrites.length)
    throw new CertkitError(
      'CA_UNREADABLE',
      'CA trust-removal records remain; recovery state was retained.',
    );
  const names = readdirSync(dir);
  const ordered = [
    ...names.filter(ownedCacheOrTemp),
    ...names.filter(ownedTrustExportTempDirectory),
    'ca-key.pem',
    'ca-cert.pem',
    'state.json',
  ];
  for (const filename of ordered) {
    if (!names.includes(filename)) continue;
    if (ownedTrustExportTempDirectory(filename)) {
      removeTrustExportTempDirectory(dir, filename, dependencies);
      await emitEvent(dependencies, {
        type: 'uninstall:file-removed',
        filename,
      });
      continue;
    }
    if (removeOwnedFile(dir, filename, dependencies)) {
      await emitEvent(
        dependencies,
        filename === 'state.json'
          ? { type: 'uninstall:state-removed' }
          : { type: 'uninstall:file-removed', filename },
      );
    }
  }
}

async function runUninstall(
  dependencies: TrustCommandDependencies,
  dryRun: boolean,
  json: boolean,
): Promise<void> {
  const deps = resolveDependencies(dependencies);
  const environment = await deps.detect();
  warnWsl(environment);
  const dir = deps.resolveCaDir();
  const certPath = trustCaPath(dir);
  const currentTargets = adapterTargets(environment, 'uninstall');
  const adapterMap = adaptersById(deps.adapterFactory(certPath, elevate));
  if (dryRun) {
    const state = readState(dir, fileOptions(deps));
    const targets = uniqueTargets([
      ...currentTargets,
      ...(state ? caRecordTargets(state) : []),
    ]);
    emitDryRun(
      planUninstall(
        targets.filter((target) => adapterMap.has(target.store)),
        certPath,
        existsSync(certPath),
        state?.ca.sha256,
      ),
      json,
      (state?.pendingWrites ?? []).map((write) => ({
        store: write.store as TrustTarget['store'],
        target: write.target,
      })),
      targets.filter((target) => !adapterMap.has(target.store)),
    );
    process.exitCode = 0;
    return;
  }

  if (!existsSync(dir)) {
    emitResults([], json);
    process.exitCode = 0;
    return;
  }

  const results: TrustResult[] = [];
  let failed = false;
  let unsupportedOnlyTargets: TrustTarget[] = [];
  const lockOptions: LockOptions = fileOptions(deps);
  await withLock(
    dir,
    async () => {
      const material = readCaForUninstallLocked(dir, lockOptions);
      if (!material) {
        if (hasOrphanedOwnedFiles(dir))
          throw new CertkitError(
            'CA_UNREADABLE',
            'Certkit-owned cache or temporary files remain without CA identity state; they were preserved. Inspect trust stores by certificate fingerprint, then remove only files whose ownership you can establish.',
          );
        lockOptions.removeDirectoryIfEmpty = true;
        return;
      }
      const state = material.state;
      const targets = uniqueTargets([
        ...currentTargets,
        ...caRecordTargets(state),
      ]);
      if (
        targets.length > 0 &&
        !targets.some((target) => adapterMap.has(target.store))
      ) {
        results.push(...targets.map(unsupportedTargetResult));
        failed = true;
        unsupportedOnlyTargets = targets;
        return;
      }
      if (!material.certPem) {
        const unsupportedTargets = targets.filter(
          (target) => !adapterMap.has(target.store),
        );
        if (unsupportedTargets.length > 0) {
          results.push(
            ...targets.map((target) =>
              !adapterMap.has(target.store)
                ? unsupportedTargetResult(target)
                : {
                    ...target,
                    state: 'unknown' as const,
                    error: {
                      code: 'CA_UNREADABLE' as const,
                      message:
                        'The CA certificate is missing, so this detected target cannot be fingerprint-scanned; recovery state was retained.',
                    },
                  },
            ),
          );
          failed = true;
          return;
        }
      }

      let stateChanged = false;
      if (state.phase !== 'retiring') {
        state.phase = 'retiring';
        stateChanged = true;
      }

      if (material.certPem) {
        for (const target of targets)
          stateChanged = recordTargetForRemoval(state, target) || stateChanged;
      }
      if (stateChanged) writeStateAtomic(dir, state, lockOptions);
      await emitEvent(deps, { type: 'uninstall:retiring' });

      if (material.certPem) {
        for (const target of targets) {
          const adapter = adapterMap.get(target.store);
          if (!adapter) {
            results.push(unsupportedTargetResult(target));
            failed = true;
            continue;
          }
          try {
            await adapter.uninstall(material.certPem, target.target);
            const present = await inspectInstalled(
              adapter,
              material.certPem,
              target.target,
            );
            if (present !== 'absent')
              throw new CertkitError(
                'STORE_WRITE_FAILED',
                present === 'present'
                  ? `The CA remains at ${target.store} target ${target.target}; rerun certkit uninstall or use the manual removal command.`
                  : `Removal from ${target.store} target ${target.target} could not be verified; rerun certkit uninstall or use the manual removal command.`,
              );
            if (removeTargetRecords(state, target))
              writeStateAtomic(dir, state, lockOptions);
            results.push({ ...target, state: 'untrusted' });
            await emitEvent(deps, {
              type: 'uninstall:target-removed',
              ...target,
            });
          } catch (error) {
            const installed = await inspectInstalled(
              adapter,
              material.certPem,
              target.target,
            );
            const trust =
              installed === 'present'
                ? await targetTrustState(
                    adapter,
                    material.certPem,
                    environment,
                    target,
                  )
                : undefined;
            results.push({
              ...target,
              state:
                installed === 'absent'
                  ? 'untrusted'
                  : (trust?.state ?? 'unknown'),
              error: toErrorResult(error),
            });
            failed = true;
          }
        }
      }

      if (failed || state.trustWrites.length || state.pendingWrites.length)
        return;
      await removeOwnedFiles(dir, deps, state);
      lockOptions.removeDirectoryIfEmpty = true;
    },
    lockOptions,
  );

  if (unsupportedOnlyTargets.length > 0) {
    emitFailure(
      new CertkitError(
        'UNSUPPORTED_PLATFORM',
        unsupportedTargetsMessage(unsupportedOnlyTargets),
      ),
      json,
    );
    return;
  }
  emitResults(results, json);
  process.exitCode = failed ? 1 : 0;
}

export function createUninstallCommand(
  dependencies: TrustCommandDependencies = {},
): CommandDef<Args> {
  return defineCommand({
    meta: {
      name: 'uninstall',
      description: 'Remove the local CA from trust stores',
    },
    args,
    async run({ args: commandArgs }) {
      const json = jsonOutput || commandArgs.json === true;
      try {
        await runUninstall(dependencies, commandArgs['dry-run'] === true, json);
      } catch (error) {
        emitFailure(error, json);
      }
    },
  });
}

export const uninstallCommand: CommandDef<Args> = createUninstallCommand();
