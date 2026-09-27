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
import { createMacosAdapter } from './platforms/macos.js';
import { run } from './platforms/run.js';

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
      : [];

  const stores: StatusReport['stores'][number][] = [];
  for (const detectedStore of environment.stores) {
    const adapterResults =
      detectedStore.store === 'macos-keychain' ? results : [];
    const pendingWrites =
      material?.state.pendingWrites.filter(
        (write) => write.store === detectedStore.store,
      ) ?? [];
    const entries: Array<{
      state: StatusReport['stores'][number]['state'];
      target?: string;
      detail?: string;
    }> = material
      ? adapterResults.length
        ? adapterResults
        : pendingWrites.length
          ? pendingWrites.map((write) => ({
              state: 'unknown' as const,
              target: write.target,
            }))
          : [{ state: 'not-detected' as const }]
      : [
          {
            state: detectedStore.detected
              ? ('untrusted' as const)
              : ('not-detected' as const),
          },
        ];

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
