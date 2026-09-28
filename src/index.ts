import './reflect-metadata.js';
import { join } from 'node:path';
import {
  type CertificateBundle,
  type CertificateOptions,
  caDir,
  certificateFor as certificateForCore,
  readCaForStatus,
} from './core/certificate.js';
import { detect } from './platforms/detect.js';
import { createWindowsFsGuard } from './platforms/fsguard.js';
import { createLinuxAdapter } from './platforms/linux.js';
import { createMacosAdapter } from './platforms/macos.js';
import { run } from './platforms/run.js';
import { createWindowsAdapter } from './platforms/windows.js';

export type { ErrorCode } from './core/errors.js';
export { CertkitError } from './core/errors.js';
export type { CertificateBundle, CertificateOptions };
export { caDir };

export interface StatusReport {
  readonly caDir: string;
  readonly ca: null | {
    readonly subject: string;
    readonly serial: string;
    readonly expiresAt: string;
  };
  readonly stores: ReadonlyArray<{
    readonly store: 'macos-keychain' | 'windows-root' | 'linux-system' | 'nss';
    readonly state: 'trusted' | 'untrusted' | 'unknown' | 'not-detected';
    readonly target?: string;
    readonly detail?: string;
  }>;
}

export async function status(
  options?: Pick<CertificateOptions, 'caDir'>,
): Promise<StatusReport> {
  const dir = caDir(options);
  const material = readCaForStatus(
    dir,
    process.platform === 'win32' ? { fsGuard: createWindowsFsGuard() } : {},
  );
  const environment = await detect();
  const results =
    material && environment.os === 'macos'
      ? await createMacosAdapter({
          caCertPath: join(dir, 'ca-cert.pem'),
          run,
          elevate: async () => {
            throw new Error('status cannot elevate');
          },
        }).checkTrust(material.certPem, environment)
      : material && environment.os === 'windows'
        ? await createWindowsAdapter({
            run,
          }).checkTrust(material.certPem, environment)
        : material &&
            environment.os === 'linux' &&
            environment.stores.some(
              (store) => store.store === 'linux-system' && store.detected,
            )
          ? await createLinuxAdapter({
              caCertPath: join(dir, 'ca-cert.pem'),
              run,
            }).checkTrust(material.certPem, environment)
          : [];
  const activeAdapterStore =
    environment.os === 'macos'
      ? 'macos-keychain'
      : environment.os === 'windows'
        ? 'windows-root'
        : environment.os === 'linux'
          ? 'linux-system'
          : undefined;

  const stores: StatusReport['stores'][number][] = [];
  for (const detectedStore of environment.stores) {
    const adapterResults =
      detectedStore.store === activeAdapterStore ? results : [];
    const pendingWrites =
      material?.state.pendingWrites.filter(
        (write) => write.store === detectedStore.store,
      ) ?? [];
    const targets =
      detectedStore.store === 'nss' ? (detectedStore.targets ?? []) : [];
    const entries: Array<{
      state: StatusReport['stores'][number]['state'];
      target?: string;
      detail?: string;
    }> = material
      ? adapterResults.length
        ? adapterResults
        : targets.length
          ? targets.map((target) => ({
              state: 'not-detected' as const,
              target,
            }))
          : [{ state: 'not-detected' as const }]
      : targets.length
        ? targets.map((target) => ({
            state: 'untrusted' as const,
            target,
          }))
        : [
            {
              state: detectedStore.detected
                ? ('untrusted' as const)
                : ('not-detected' as const),
            },
          ];

    for (const write of pendingWrites) {
      if (!entries.some((entry) => entry.target === write.target))
        entries.push({ state: 'unknown', target: write.target });
    }

    for (const entry of entries) {
      const target = entry.target;
      const pending = material?.state.pendingWrites.some(
        (write) =>
          write.store === detectedStore.store && write.target === target,
      );
      stores.push({
        store: detectedStore.store,
        state: pending ? 'unknown' : entry.state,
        ...(target === undefined ? {} : { target }),
        ...(entry.detail
          ? {
              detail: pending
                ? `${entry.detail}; trust write outcome is unresolved.`
                : entry.detail,
            }
          : pending
            ? { detail: 'Trust write outcome is unresolved.' }
            : {}),
      });
    }
  }

  return {
    caDir: dir,
    ca: material
      ? {
          subject: material.state.ca.subject,
          serial: material.state.ca.serial,
          expiresAt: material.state.ca.expiresAt,
        }
      : null,
    stores,
  };
}

export function certificateFor(
  names: string[],
  options?: CertificateOptions,
): Promise<CertificateBundle> {
  return certificateForCore(
    names,
    options,
    process.platform === 'win32' ? { fsGuard: createWindowsFsGuard() } : {},
  );
}
