import { join } from 'node:path';
import type { FsGuard, StateFile } from '../../core/cadir.js';
import { caDir } from '../../core/certificate.js';
import { CertkitError, type ErrorCode } from '../../core/errors.js';
import { detect, type Environment } from '../../platforms/detect.js';
import { createWindowsFsGuard } from '../../platforms/fsguard.js';
import {
  createMacosAdapter,
  macosDeleteCertificateArgv,
  macosInstallArgv,
  macosRemoveTrustArgv,
} from '../../platforms/macos.js';
import { run } from '../../platforms/run.js';
import type { StoreAdapter } from '../../platforms/store.js';
import { elevate, shQuote } from '../elevate.js';

export type TrustStore = StoreAdapter['id'];

export interface TrustTarget {
  store: TrustStore;
  target: string;
}

export type TrustLifecycleEvent =
  | { type: 'install:pending'; store: TrustStore; target: string }
  | { type: 'install:receipt'; store: TrustStore; target: string }
  | { type: 'install:promoted'; store: TrustStore; target: string }
  | { type: 'uninstall:retiring' }
  | { type: 'uninstall:target-removed'; store: TrustStore; target: string }
  | { type: 'uninstall:file-removed'; filename: string }
  | { type: 'uninstall:state-removed' };

export interface TrustCommandDependencies {
  resolveCaDir?: () => string;
  detect?: () => Promise<Environment>;
  adapterFactory?: (
    caCertPath: string,
    elevateCommand: typeof elevate,
  ) => StoreAdapter[];
  fsGuard?: FsGuard;
  onEvent?: (event: TrustLifecycleEvent) => void | Promise<void>;
}

export interface TrustResult {
  store: TrustStore;
  target: string;
  state: 'trusted' | 'untrusted' | 'unknown' | 'not-detected';
  error?: { code: ErrorCode; message: string };
  detail?: string;
}

export interface DryRunCommand {
  store: TrustStore;
  target: string;
  elevated: string;
  manual: string;
}

interface DryRunUncertainty extends TrustTarget {
  state: 'unknown';
  detail: string;
}

function defaultAdapterFactory(
  caCertPath: string,
  elevateCommand: typeof elevate = elevate,
): StoreAdapter[] {
  if (process.platform !== 'darwin') return [];
  return [
    createMacosAdapter({
      caCertPath,
      run,
      elevate: async (argv) => {
        await elevateCommand(argv);
        return { code: 0, stdout: '', stderr: '' };
      },
    }),
  ];
}

export function adaptersById(
  adapters: StoreAdapter[],
): Map<TrustStore, StoreAdapter> {
  const result = new Map<TrustStore, StoreAdapter>();
  for (const adapter of adapters) {
    if (result.has(adapter.id))
      throw new CertkitError(
        'INVALID_OPTIONS',
        `More than one adapter registered for ${adapter.id}.`,
      );
    result.set(adapter.id, adapter);
  }
  return result;
}

export function adapterTargets(
  environment: Environment,
  action: 'install' | 'uninstall',
): TrustTarget[] {
  const targets: TrustTarget[] = [];
  for (const store of environment.stores) {
    if (store.store === 'nss') {
      const values =
        action === 'install'
          ? (store.installTargets ?? [])
          : (store.targets ?? []);
      for (const target of values) targets.push({ store: store.store, target });
    } else if (store.detected) {
      targets.push({ store: store.store, target: 'default' });
    }
  }
  return targets;
}

export function caRecordTargets(state: StateFile): TrustTarget[] {
  const writes = [...state.trustWrites, ...state.pendingWrites];
  const targets = new Map<string, TrustTarget>();
  for (const write of writes) {
    const target = { store: write.store as TrustStore, target: write.target };
    targets.set(`${target.store}\0${target.target}`, target);
  }
  return [...targets.values()];
}

function withTargetDetected(
  environment: Environment,
  target: TrustTarget,
): Environment {
  return {
    ...environment,
    stores: environment.stores.map((store) =>
      store.store === target.store
        ? {
            ...store,
            detected: true,
            targets: [target.target],
            installTargets: [target.target],
          }
        : store,
    ),
  };
}

export async function targetTrustState(
  adapter: StoreAdapter,
  certPem: string,
  environment: Environment,
  target: TrustTarget,
): Promise<{ state: TrustResult['state']; detail?: string }> {
  try {
    const results = await adapter.checkTrust(
      certPem,
      withTargetDetected(environment, target),
    );
    const result =
      results.find((item) => item.target === target.target) ??
      (results.length === 1 ? results[0] : undefined);
    if (!result)
      return {
        state: 'unknown',
        detail: 'The target trust state is unavailable.',
      };
    return {
      state: result.state,
      ...(result.detail ? { detail: result.detail } : {}),
    };
  } catch {
    return {
      state: 'unknown',
      detail: 'The target trust state is unavailable.',
    };
  }
}

export async function inspectInstalled(
  adapter: StoreAdapter,
  certPem: string,
  target: string,
): Promise<'present' | 'absent' | 'inconclusive'> {
  try {
    return await adapter.inspectInstalled(certPem, target);
  } catch {
    return 'inconclusive';
  }
}

export async function emitEvent(
  dependencies: TrustCommandDependencies,
  event: TrustLifecycleEvent,
): Promise<void> {
  await dependencies.onEvent?.(event);
}

export function fileOptions(dependencies: TrustCommandDependencies): {
  fsGuard?: FsGuard;
} {
  return dependencies.fsGuard ? { fsGuard: dependencies.fsGuard } : {};
}

export function toErrorResult(error: unknown): {
  code: ErrorCode;
  message: string;
} {
  if (error instanceof CertkitError)
    return { code: error.code, message: error.message };
  return {
    code: 'STORE_WRITE_FAILED',
    message: error instanceof Error ? error.message : 'Trust operation failed.',
  };
}

function failureExitCode(code: ErrorCode): 1 | 2 {
  return code === 'INVALID_NAME' ||
    code === 'NAME_LIMIT' ||
    code === 'INVALID_OPTIONS' ||
    code === 'UNSUPPORTED_PLATFORM'
    ? 2
    : 1;
}

export function emitFailure(error: unknown, json: boolean): void {
  const details = toErrorResult(error);
  if (json) {
    console.log(JSON.stringify({ schemaVersion: 1, error: details }));
  } else {
    console.error(`certkit: ${details.code}: ${details.message}`);
  }
  process.exitCode = failureExitCode(details.code);
}

export function emitResults(results: TrustResult[], json: boolean): void {
  if (json) {
    console.log(JSON.stringify({ schemaVersion: 1, results }));
    return;
  }
  for (const result of results) {
    const error = result.error ? ` — ${result.error.message}` : '';
    const detail = result.detail ? ` — ${result.detail}` : '';
    console.log(
      `${result.store} (${result.target}): ${result.state}${detail}${error}`,
    );
  }
}

export function planInstall(
  targets: TrustTarget[],
  caCertPath: string,
  certificateExists: boolean,
): DryRunCommand[] {
  const path = certificateExists ? caCertPath : '<ca-cert.pem>';
  return targets.flatMap((target) => {
    if (target.store !== 'macos-keychain' || target.target !== 'default')
      return [];
    const argv = macosInstallArgv(path);
    const elevated = argv.map(shQuote).join(' ');
    return [{ ...target, elevated, manual: `sudo ${elevated}` }];
  });
}

export function planUninstall(
  targets: TrustTarget[],
  caCertPath: string,
  certificateExists: boolean,
  sha256?: string,
): DryRunCommand[] {
  const path = certificateExists ? caCertPath : '<ca-cert.pem>';
  const fingerprint = sha256 ?? '<sha256>';
  return targets.flatMap((target) => {
    if (target.store !== 'macos-keychain' || target.target !== 'default')
      return [];
    return [
      macosRemoveTrustArgv(path),
      macosDeleteCertificateArgv(fingerprint),
    ].map((argv) => {
      const elevated = argv.map(shQuote).join(' ');
      return { ...target, elevated, manual: `sudo ${elevated}` };
    });
  });
}

export function emitDryRun(
  commands: DryRunCommand[],
  json: boolean,
  unresolvedTargets: TrustTarget[] = [],
): void {
  const unresolved: DryRunUncertainty[] = unresolvedTargets.map((target) => ({
    ...target,
    state: 'unknown',
    detail:
      'A trust write outcome is unresolved; dry-run does not inspect or reconcile it.',
  }));
  if (json) {
    console.log(
      JSON.stringify({ schemaVersion: 1, dryRun: true, commands, unresolved }),
    );
    return;
  }
  if (!commands.length) {
    console.log('No registered trust-store commands for the detected targets.');
  } else {
    for (const command of commands) {
      console.log(`${command.store} (${command.target})`);
      console.log(`  elevated: ${command.elevated}`);
      console.log(`  manual: ${command.manual}`);
    }
  }
  for (const target of unresolved)
    console.log(
      `${target.store} (${target.target}): unknown — ${target.detail}`,
    );
}

export function warnWsl(environment: Environment): void {
  if (environment.wsl)
    console.error(
      'WSL detected: browser trust lives on the Windows side; Linux-store success does not cover Windows browsers. See docs/trust-matrix.md.',
    );
}

export function trustCaPath(dir: string): string {
  return join(dir, 'ca-cert.pem');
}

export function resolveDependencies(
  dependencies: TrustCommandDependencies,
): Required<
  Pick<TrustCommandDependencies, 'resolveCaDir' | 'detect' | 'adapterFactory'>
> &
  TrustCommandDependencies {
  const resolved = {
    resolveCaDir: dependencies.resolveCaDir ?? (() => caDir()),
    detect: dependencies.detect ?? detect,
    adapterFactory:
      dependencies.adapterFactory ??
      ((caCertPath, elevateCommand) =>
        defaultAdapterFactory(caCertPath, elevateCommand)),
    ...dependencies,
  };
  if (resolved.fsGuard || process.platform !== 'win32') return resolved;
  return { ...resolved, fsGuard: createWindowsFsGuard() };
}

export function uniqueTargets(targets: TrustTarget[]): TrustTarget[] {
  const unique = new Map<string, TrustTarget>();
  for (const target of targets)
    unique.set(`${target.store}\0${target.target}`, target);
  return [...unique.values()];
}
