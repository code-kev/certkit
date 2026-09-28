import { existsSync } from 'node:fs';
import { type CommandDef, defineCommand } from 'citty';
import {
  type LockOptions,
  readState,
  type StateFile,
  withLock,
  writeStateAtomic,
} from '../../core/cadir.js';
import { ensureCaForInstallLocked } from '../../core/certificate.js';
import { CertkitError } from '../../core/errors.js';
import type { StoreAdapter } from '../../platforms/store.js';
import { elevate } from '../elevate.js';
import { jsonOutput } from '../options.js';
import {
  adaptersById,
  adapterTargets,
  emitDryRun,
  emitEvent,
  emitFailure,
  emitResults,
  fileOptions,
  inspectInstalled,
  planInstall,
  resolveDependencies,
  type TrustCommandDependencies,
  type TrustResult,
  type TrustTarget,
  targetTrustState,
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

function pendingRecord(state: StateFile, target: TrustTarget) {
  return state.pendingWrites.find((write) => sameTarget(write, target));
}

function trustRecord(state: StateFile, target: TrustTarget) {
  return state.trustWrites.find((write) => sameTarget(write, target));
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

function promoteTarget(state: StateFile, target: TrustTarget): void {
  const pending = pendingRecord(state, target);
  const previous = trustRecord(state, target);
  const mechanism = pending?.mechanism ?? previous?.mechanism;
  state.trustWrites = state.trustWrites.filter(
    (write) => !sameTarget(write, target),
  );
  state.pendingWrites = state.pendingWrites.filter(
    (write) => !sameTarget(write, target),
  );
  state.trustWrites.push({
    store: target.store,
    target: target.target,
    ...(mechanism ? { mechanism } : {}),
    serial: state.ca.serial,
    sha256: state.ca.sha256,
    timestamp:
      pending?.timestamp ?? previous?.timestamp ?? new Date().toISOString(),
  });
}

function makePending(state: StateFile, target: TrustTarget): void {
  const previous = pendingRecord(state, target);
  state.pendingWrites = state.pendingWrites.filter(
    (write) => !sameTarget(write, target),
  );
  state.pendingWrites.push({
    store: target.store,
    target: target.target,
    ...(previous?.mechanism ? { mechanism: previous.mechanism } : {}),
    sha256: state.ca.sha256,
    timestamp: new Date().toISOString(),
  });
}

async function runInstall(
  dependencies: TrustCommandDependencies,
  dryRun: boolean,
  json: boolean,
): Promise<void> {
  const deps = resolveDependencies(dependencies);
  const environment = await deps.detect();
  warnWsl(environment);
  const dir = deps.resolveCaDir();
  const certPath = trustCaPath(dir);
  const currentTargets = adapterTargets(environment, 'install');
  const adapterMap = adaptersById(deps.adapterFactory(certPath, elevate));
  if (dryRun) {
    const state = readState(dir, fileOptions(deps));
    emitDryRun(
      planInstall(
        currentTargets.filter((target) => adapterMap.has(target.store)),
        certPath,
        existsSync(certPath),
      ),
      json,
      (state?.pendingWrites ?? []).map((write) => ({
        store: write.store as TrustTarget['store'],
        target: write.target,
      })),
      currentTargets.filter((target) => !adapterMap.has(target.store)),
    );
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
      const existing = readState(dir, lockOptions);
      const pendingTargets = (existing?.pendingWrites ?? []).map((write) => ({
        store: write.store as TrustTarget['store'],
        target: write.target,
      }));
      const targets = uniqueTargets([...currentTargets, ...pendingTargets]);
      if (
        targets.length > 0 &&
        !targets.some((target) => adapterMap.has(target.store))
      ) {
        results.push(...targets.map(unsupportedTargetResult));
        failed = true;
        unsupportedOnlyTargets = targets;
        lockOptions.removeDirectoryIfEmpty = true;
        return;
      }

      const material = await ensureCaForInstallLocked(dir, lockOptions);
      const state = material.state;
      const currentKeys = new Set(
        currentTargets.map((target) => `${target.store}\0${target.target}`),
      );
      for (const target of targets) {
        const active = currentKeys.has(`${target.store}\0${target.target}`);
        const hasRecoveryRecord =
          Boolean(pendingRecord(state, target)) ||
          Boolean(trustRecord(state, target));
        const adapter = adapterMap.get(target.store);
        if (!adapter) {
          results.push(unsupportedTargetResult(target));
          failed = true;
          continue;
        }
        const installed = await inspectInstalled(
          adapter,
          material.certPem,
          target.target,
        );

        if (installed === 'present') {
          promoteTarget(state, target);
          writeStateAtomic(dir, state, lockOptions);
          await emitEvent(deps, { type: 'install:promoted', ...target });
          if (!active) {
            results.push({
              ...target,
              state: 'not-detected',
              detail:
                'Reconciled the recorded target; it is no longer detected.',
            });
          } else {
            results.push({
              ...target,
              ...(await targetTrustState(
                adapter,
                material.certPem,
                environment,
                target,
              )),
            });
          }
          continue;
        }

        if (installed === 'absent') {
          if (removeTargetRecords(state, target))
            writeStateAtomic(dir, state, lockOptions);
          if (!active) {
            results.push({
              ...target,
              state: 'not-detected',
              detail: 'The recorded target was inspected and the CA is absent.',
            });
            continue;
          }
        } else if (!active || hasRecoveryRecord) {
          const detail =
            'The recorded target could not be inspected; its recovery record remains pending.';
          results.push({
            ...target,
            state: 'unknown',
            detail,
            error: { code: 'STORE_WRITE_FAILED', message: detail },
          });
          failed = true;
          continue;
        }

        makePending(state, target);
        writeStateAtomic(dir, state, lockOptions);
        await emitEvent(deps, { type: 'install:pending', ...target });

        let receipt: Awaited<ReturnType<StoreAdapter['install']>>;
        try {
          receipt = await adapter.install(certPath, target.target);
        } catch (error) {
          const afterFailure = await inspectInstalled(
            adapter,
            material.certPem,
            target.target,
          );
          if (afterFailure === 'absent' && removeTargetRecords(state, target))
            writeStateAtomic(dir, state, lockOptions);
          results.push({
            ...target,
            state: afterFailure === 'absent' ? 'untrusted' : 'unknown',
            error: {
              code:
                error instanceof CertkitError
                  ? error.code
                  : 'STORE_WRITE_FAILED',
              message:
                error instanceof Error
                  ? error.message
                  : 'Trust installation failed; use the documented manual trust command.',
            },
          });
          failed = true;
          continue;
        }

        await emitEvent(deps, { type: 'install:receipt', ...target });
        if (receipt.state === 'inconclusive') {
          results.push({
            ...target,
            state: 'unknown',
            ...(receipt.detail ? { detail: receipt.detail } : {}),
            error: {
              code: 'STORE_WRITE_FAILED',
              message:
                receipt.detail ??
                'The target read-back was inconclusive; rerun `certkit install`.',
            },
          });
          failed = true;
          continue;
        }

        promoteTarget(state, target);
        writeStateAtomic(dir, state, lockOptions);
        await emitEvent(deps, { type: 'install:promoted', ...target });
        const observed = await targetTrustState(
          adapter,
          material.certPem,
          environment,
          target,
        );
        results.push({ ...target, ...observed });
        if (observed.state === 'untrusted') failed = true;
      }
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

export function createInstallCommand(
  dependencies: TrustCommandDependencies = {},
): CommandDef<Args> {
  return defineCommand({
    meta: {
      name: 'install',
      description: 'Install the local CA into trust stores',
    },
    args,
    async run({ args: commandArgs }) {
      const json = jsonOutput || commandArgs.json === true;
      try {
        await runInstall(dependencies, commandArgs['dry-run'] === true, json);
      } catch (error) {
        emitFailure(error, json);
      }
    },
  });
}

export const installCommand: CommandDef<Args> = createInstallCommand();
