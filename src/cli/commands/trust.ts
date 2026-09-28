import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { FsGuard, StateFile } from '../../core/cadir.js';
import { caDir } from '../../core/certificate.js';
import { CertkitError, type ErrorCode } from '../../core/errors.js';
import { detect, type Environment } from '../../platforms/detect.js';
import { createWindowsFsGuard } from '../../platforms/fsguard.js';
import {
  createLinuxAdapter,
  isLinuxTrustMechanism,
  linuxAnchorTarget,
  linuxInstallArgv,
  linuxUninstallArgv,
} from '../../platforms/linux.js';
import {
  createMacosAdapter,
  macosDeleteCertificateArgv,
  macosInstallArgv,
  macosLoginKeychainPath,
  macosRemoveTrustArgv,
} from '../../platforms/macos.js';
import {
  createNssAdapter,
  nssCertificateNickname,
} from '../../platforms/nss.js';
import { run } from '../../platforms/run.js';
import type { StoreAdapter } from '../../platforms/store.js';
import {
  createWindowsAdapter,
  windowsDeleteCertificateArgv,
  windowsInstallArgv,
} from '../../platforms/windows.js';
import { type elevate, shQuote } from '../elevate.js';

export type TrustStore = StoreAdapter['id'];

export interface TrustTarget {
  store: TrustStore;
  target: string;
  mechanism?: string;
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

export function trustTarget(
  store: TrustStore,
  target: string,
  mechanism?: string,
): TrustTarget {
  const value = { store, target } as TrustTarget;
  if (mechanism)
    Object.defineProperty(value, 'mechanism', { value: mechanism });
  return value;
}

export interface DryRunCommand {
  store: TrustStore;
  target: string;
  command: string;
  manual: string;
}

interface DryRunUncertainty extends TrustTarget {
  state: 'unknown';
  detail: string;
}

function defaultAdapterFactory(
  caCertPath: string,
  elevateCommand: typeof elevate,
): StoreAdapter[] {
  const adapters: StoreAdapter[] = [];
  if (process.platform === 'darwin')
    adapters.push(createMacosAdapter({ caCertPath, run }));
  if (process.platform === 'win32')
    adapters.push(createWindowsAdapter({ run }));
  if (process.platform === 'linux')
    adapters.push(
      createLinuxAdapter({ caCertPath, run, elevate: elevateCommand }),
    );
  adapters.push(createNssAdapter({ run }));
  return adapters;
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
  caCertPath?: string,
): TrustTarget[] {
  const targets: TrustTarget[] = [];
  for (const store of environment.stores) {
    if (store.store === 'nss') {
      const values =
        action === 'install'
          ? (store.installTargets ?? [])
          : (store.targets ?? []);
      for (const target of values)
        if (resolve(target) !== '/etc/pki/nssdb')
          targets.push({ store: store.store, target });
    } else if (store.store === 'linux-system' && store.detected) {
      const mechanism = store.detail;
      const target =
        caCertPath && isLinuxTrustMechanism(mechanism)
          ? linuxAnchorTarget(caCertPath, mechanism)
          : 'default';
      targets.push(trustTarget(store.store, target, mechanism));
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
    const target = trustTarget(
      write.store as TrustStore,
      write.target,
      write.mechanism,
    );
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
            ...(target.mechanism ? { detail: target.mechanism } : {}),
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
  mechanism?: string,
): Promise<'present' | 'absent' | 'inconclusive'> {
  try {
    return await adapter.inspectInstalled(certPem, target, mechanism);
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
  if (results.some((result) => result.store === 'macos-keychain'))
    console.log(
      'macOS may request native user authentication; Certkit never collects a password.',
    );
}

export function unsupportedTargetResult(target: TrustTarget): TrustResult {
  return {
    ...target,
    state: 'unknown',
    error: {
      code: 'UNSUPPORTED_PLATFORM',
      message: `No registered ${target.store} adapter is available for ${target.target}; it was not modified or verified. See docs/trust-matrix.md for the manual path.`,
    },
  };
}

export function unsupportedTargetsMessage(targets: TrustTarget[]): string {
  const formatted = targets
    .map(({ store, target }) => `${store} (${target})`)
    .join(', ');
  return `No registered adapter is available for ${formatted}. No trust changes were made; see docs/trust-matrix.md for manual paths.`;
}

export function planInstall(
  targets: TrustTarget[],
  caCertPath: string,
  certificateExists: boolean,
): DryRunCommand[] {
  const path = certificateExists ? caCertPath : '<ca-cert.pem>';
  return targets.flatMap((target) => {
    if (target.store === 'nss') {
      let nickname = 'certkit development CA <sha256>';
      if (certificateExists) {
        try {
          nickname = nssCertificateNickname(readFileSync(path, 'utf8'));
        } catch {
          // Keep a symbolic nickname when the CA identity cannot be read.
        }
      }
      const command = [
        'certutil',
        '-A',
        '-n',
        nickname,
        '-t',
        'C,,',
        '-d',
        `sql:${target.target}`,
        '-i',
        path,
      ]
        .map(shQuote)
        .join(' ');
      return [
        {
          ...target,
          command,
          manual: `Install Mozilla NSS certutil manually if needed, then run: ${command}`,
        },
      ];
    }
    if (
      target.store === 'linux-system' &&
      isLinuxTrustMechanism(target.mechanism) &&
      target.target !== 'default'
    ) {
      const command = linuxInstallArgv(
        caCertPath,
        target.target,
        target.mechanism,
      )
        .map((argv) => `sudo ${argv.map(shQuote).join(' ')}`)
        .join(' && ');
      return [{ ...target, command, manual: command }];
    }
    if (target.target !== 'default') return [];
    if (target.store === 'windows-root') {
      const argv = windowsInstallArgv(path);
      const command = `${argv.slice(0, -1).join(' ')} "${path}"`;
      return [{ ...target, command, manual: command }];
    }
    if (target.store !== 'macos-keychain') return [];
    const command = macosInstallArgv(path, macosLoginKeychainPath())
      .map(shQuote)
      .join(' ');
    return [{ ...target, command, manual: command }];
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
    if (target.store === 'nss') {
      let nickname = 'certkit development CA <sha256>';
      if (certificateExists && sha256) {
        try {
          const caCertPem = readFileSync(path, 'utf8');
          const certificate = new X509Certificate(caCertPem);
          const actual = certificate.fingerprint256
            .replaceAll(':', '')
            .toLowerCase();
          if (actual === sha256.toLowerCase())
            nickname = nssCertificateNickname(caCertPem);
        } catch {
          // Keep a symbolic nickname when the CA identity cannot be verified.
        }
      }
      const command = [
        'certutil',
        '-D',
        '-n',
        nickname,
        '-d',
        `sql:${target.target}`,
      ]
        .map(shQuote)
        .join(' ');
      return [
        {
          ...target,
          command,
          manual: `Remove only the matching CA after checking its fingerprint: ${command}`,
        },
      ];
    }
    if (
      target.store === 'linux-system' &&
      isLinuxTrustMechanism(target.mechanism) &&
      target.target !== 'default'
    ) {
      const command = linuxUninstallArgv(target.target, target.mechanism)
        .map((argv) => `sudo ${argv.map(shQuote).join(' ')}`)
        .join(' && ');
      return [{ ...target, command, manual: command }];
    }
    if (target.target !== 'default') return [];
    if (target.store === 'windows-root') {
      let sha1 = '<sha1-thumbprint>';
      if (certificateExists && sha256) {
        try {
          const certificate = new X509Certificate(readFileSync(path));
          const actualSha256 = certificate.fingerprint256
            .replaceAll(':', '')
            .toLowerCase();
          if (actualSha256 === sha256.toLowerCase())
            sha1 = certificate.fingerprint.replaceAll(':', '').toUpperCase();
        } catch {
          // Keep a symbolic thumbprint when the CA identity cannot be verified.
        }
      }
      const argv = windowsDeleteCertificateArgv(sha1);
      const command = `${argv.slice(0, -1).join(' ')} "${sha1}"`;
      return [{ ...target, command, manual: command }];
    }
    if (target.store !== 'macos-keychain') return [];
    return [
      macosRemoveTrustArgv(path),
      macosDeleteCertificateArgv(fingerprint, macosLoginKeychainPath()),
    ].map((argv) => {
      const command = argv.map(shQuote).join(' ');
      return { ...target, command, manual: command };
    });
  });
}

export function emitDryRun(
  commands: DryRunCommand[],
  json: boolean,
  unresolvedTargets: TrustTarget[] = [],
  unsupportedTargets: TrustTarget[] = [],
): void {
  const unresolved: DryRunUncertainty[] = unresolvedTargets.map((target) => ({
    ...target,
    state: 'unknown',
    detail:
      'A trust write outcome is unresolved; dry-run does not inspect or reconcile it.',
  }));
  const unsupported = unsupportedTargets.map(unsupportedTargetResult);
  if (json) {
    console.log(
      JSON.stringify({
        schemaVersion: 1,
        dryRun: true,
        commands,
        unresolved,
        unsupported,
      }),
    );
    return;
  }
  if (!commands.length) {
    console.log('No registered trust-store commands for the detected targets.');
  } else {
    for (const command of commands) {
      console.log(`${command.store} (${command.target})`);
      console.log(`  command: ${command.command}`);
      console.log(`  manual: ${command.manual}`);
    }
    if (commands.some((command) => command.store === 'macos-keychain'))
      console.log(
        'macOS may request native user authentication; Certkit never collects a password.',
      );
  }
  for (const target of unresolved)
    console.log(
      `${target.store} (${target.target}): unknown — ${target.detail}`,
    );
  for (const target of unsupported)
    console.log(
      `${target.store} (${target.target}): unknown — ${target.error?.message}`,
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
  for (const target of targets) {
    const key = `${target.store}\0${target.target}`;
    unique.set(
      key,
      trustTarget(
        target.store,
        target.target,
        target.mechanism ?? unique.get(key)?.mechanism,
      ),
    );
  }
  return [...unique.values()];
}
