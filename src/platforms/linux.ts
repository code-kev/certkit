import { createHash, X509Certificate } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { CertkitError } from '../core/errors.js';
import type { Environment } from './detect.js';
import type { RunResult } from './run.js';
import type { StoreAdapter } from './store.js';

export type LinuxTrustMechanism =
  | 'update-ca-certificates'
  | 'update-ca-trust'
  | 'trust-anchor';

type Command = (argv: string[]) => Promise<RunResult>;
type Elevate = (argv: string[]) => Promise<void>;

interface LinuxAdapterDependencies {
  caCertPath: string;
  run: Command;
  elevate?: Elevate;
  fs?: {
    readFile: (path: string) => Promise<string>;
    lstat: (path: string) => Promise<{
      isFile(): boolean;
      isSymbolicLink(): boolean;
    }>;
  };
}

const mechanisms: LinuxTrustMechanism[] = [
  'update-ca-certificates',
  'update-ca-trust',
  'trust-anchor',
];
const pemCertificate =
  /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

function fingerprint(pem: string): string {
  return new X509Certificate(pem).fingerprint256
    .replaceAll(':', '')
    .toLowerCase();
}

function certificateFingerprints(contents: string): string[] | undefined {
  const certificates = contents.match(pemCertificate) ?? [];
  if (contents.replace(pemCertificate, '').trim()) return undefined;
  try {
    return certificates.map(fingerprint);
  } catch {
    return undefined;
  }
}

function fingerprints(contents: string): Set<string> | undefined {
  const values = certificateFingerprints(contents);
  return values === undefined ? undefined : new Set(values);
}

function missing(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'ENOENT'
  );
}

function writeFailure(message: string): CertkitError {
  return new CertkitError('STORE_WRITE_FAILED', message);
}

export function linuxAnchorTarget(
  caCertPath: string,
  mechanism: LinuxTrustMechanism,
): string {
  if (mechanism === 'trust-anchor') return caCertPath;
  const name = createHash('sha256')
    .update(resolve(caCertPath))
    .digest('hex')
    .slice(0, 16);
  return mechanism === 'update-ca-certificates'
    ? `/usr/local/share/ca-certificates/certkit-${name}.crt`
    : `/etc/pki/ca-trust/source/anchors/certkit-${name}.pem`;
}

export function linuxAnchorTempTarget(target: string): string {
  return `${target}.certkit-tmp`;
}

export function linuxActiveStorePath(mechanism: LinuxTrustMechanism): string {
  if (mechanism === 'update-ca-certificates')
    return '/etc/ssl/certs/ca-certificates.crt';
  if (mechanism === 'update-ca-trust')
    return '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem';
  return 'trust-anchor';
}

export function linuxInstallArgv(
  caCertPath: string,
  target: string,
  mechanism: LinuxTrustMechanism,
): string[][] {
  if (mechanism === 'trust-anchor') return [['trust', 'anchor', target]];
  const tempTarget = linuxAnchorTempTarget(target);
  return [
    ['install', '-m', '0644', caCertPath, tempTarget],
    ['mv', '-f', '--', tempTarget, target],
    mechanism === 'update-ca-certificates'
      ? ['update-ca-certificates']
      : ['update-ca-trust', 'extract'],
  ];
}

export function linuxUninstallArgv(
  target: string,
  mechanism: LinuxTrustMechanism,
): string[][] {
  if (mechanism === 'trust-anchor')
    return [['trust', 'anchor', '--remove', target]];
  const tempTarget = linuxAnchorTempTarget(target);
  return [
    ['rm', '-f', '--', target],
    ['rm', '-f', '--', tempTarget],
    mechanism === 'update-ca-certificates'
      ? ['update-ca-certificates']
      : ['update-ca-trust', 'extract'],
  ];
}

export function isLinuxTrustMechanism(
  value: string | undefined,
): value is LinuxTrustMechanism {
  return (
    value !== undefined && mechanisms.includes(value as LinuxTrustMechanism)
  );
}

export function createLinuxAdapter(
  dependencies: LinuxAdapterDependencies,
): StoreAdapter {
  const fs: NonNullable<LinuxAdapterDependencies['fs']> = dependencies.fs ?? {
    readFile: (target) => readFile(target, 'utf8'),
    lstat,
  };
  const readAnchor = async (
    target: string,
  ): Promise<string | null | undefined> => {
    try {
      const metadata = await fs.lstat(target);
      if (metadata.isSymbolicLink() || !metadata.isFile()) return undefined;
      return await fs.readFile(target);
    } catch (error) {
      return missing(error) ? null : undefined;
    }
  };
  const readActiveStore = async (
    mechanism: LinuxTrustMechanism,
  ): Promise<string | undefined> => {
    try {
      if (mechanism === 'trust-anchor') {
        const result = await dependencies.run([
          'trust',
          'list',
          '--filter=ca-anchors',
          '--format=pem',
        ]);
        return result.code === 0 ? result.stdout : undefined;
      }
      return await fs.readFile(linuxActiveStorePath(mechanism));
    } catch {
      return undefined;
    }
  };
  const resolveMechanism = (
    target: string,
    selected?: string,
  ): LinuxTrustMechanism | undefined => {
    if (selected !== undefined)
      return isLinuxTrustMechanism(selected) &&
        linuxAnchorTarget(dependencies.caCertPath, selected) === target
        ? selected
        : undefined;
    return mechanisms.find(
      (mechanism) =>
        linuxAnchorTarget(dependencies.caCertPath, mechanism) === target,
    );
  };
  const anchorState = async (
    caCertPem: string,
    target: string,
  ): Promise<'present' | 'absent' | 'different' | 'inconclusive'> => {
    const contents = await readAnchor(target);
    if (contents === null) return 'absent';
    if (contents === undefined) return 'inconclusive';
    const hashes = certificateFingerprints(contents);
    if (!hashes || hashes.length !== 1) return 'different';
    return hashes[0] === fingerprint(caCertPem) ? 'present' : 'different';
  };
  const elevateCommands = async (
    commands: string[][],
    message: string,
  ): Promise<void> => {
    if (!dependencies.elevate) throw writeFailure(message);
    for (const argv of commands) {
      try {
        await dependencies.elevate(argv);
      } catch {
        throw writeFailure(message);
      }
    }
  };
  const activeContains = async (
    caCertPem: string,
    mechanism: LinuxTrustMechanism,
  ): Promise<boolean | undefined> => {
    const contents = await readActiveStore(mechanism);
    return contents === undefined
      ? undefined
      : fingerprints(contents)?.has(fingerprint(caCertPem));
  };

  return {
    id: 'linux-system',

    async inspectInstalled(caCertPem, target, selectedMechanism) {
      const mechanism = resolveMechanism(target, selectedMechanism);
      if (!mechanism) return 'inconclusive';
      try {
        if (mechanism === 'trust-anchor') {
          const present = await activeContains(caCertPem, mechanism);
          return present === undefined
            ? 'inconclusive'
            : present
              ? 'present'
              : 'absent';
        }
        const anchor = await anchorState(caCertPem, target);
        if (anchor === 'present') return 'present';
        if (anchor === 'inconclusive') return 'inconclusive';
        const temporary = await anchorState(
          caCertPem,
          linuxAnchorTempTarget(target),
        );
        return temporary === 'present'
          ? 'present'
          : temporary === 'inconclusive'
            ? 'inconclusive'
            : 'absent';
      } catch {
        return 'inconclusive';
      }
    },

    async checkTrust(caCertPem: string, env: Environment) {
      const store = env.stores.find((item) => item.store === 'linux-system');
      if (env.os !== 'linux' || !store?.detected)
        return [{ state: 'not-detected' as const, target: 'default' }];
      if (!isLinuxTrustMechanism(store.detail))
        return [
          {
            state: 'unknown' as const,
            target: 'default',
            detail: 'The detected Linux trust mechanism is unsupported.',
          },
        ];
      const target =
        store.targets?.[0] ??
        linuxAnchorTarget(dependencies.caCertPath, store.detail);
      try {
        const present = await activeContains(caCertPem, store.detail);
        if (present === undefined)
          return [
            {
              state: 'unknown' as const,
              target,
              detail: 'The active Linux trust store could not be inspected.',
            },
          ];
        return [
          {
            state: present ? ('trusted' as const) : ('untrusted' as const),
            target,
          },
        ];
      } catch {
        return [
          {
            state: 'unknown' as const,
            target,
            detail: 'The active Linux trust store could not be inspected.',
          },
        ];
      }
    },

    async install(caCertPath, target, selectedMechanism) {
      const mechanism = resolveMechanism(target, selectedMechanism);
      if (!mechanism)
        throw writeFailure('The Linux trust target is not recognized.');
      try {
        if (mechanism !== 'trust-anchor') {
          const anchor = await anchorState(
            await fs.readFile(caCertPath),
            target,
          );
          if (anchor === 'different')
            throw writeFailure(
              `The Linux anchor target ${target} contains a different certificate.`,
            );
          if (anchor === 'inconclusive')
            throw writeFailure(
              'The Linux anchor target could not be inspected; its contents were preserved.',
            );
          if (anchor === 'absent') {
            const temporaryTarget = linuxAnchorTempTarget(target);
            const temporary = await anchorState(
              await fs.readFile(caCertPath),
              temporaryTarget,
            );
            if (temporary === 'different')
              throw writeFailure(
                'The temporary Linux anchor target contains a different certificate; its contents were preserved.',
              );
            if (temporary === 'inconclusive')
              throw writeFailure(
                'The temporary Linux anchor target could not be inspected; its contents were preserved.',
              );
            const fileCommands =
              temporary === 'present'
                ? [['mv', '-f', '--', temporaryTarget, target]]
                : linuxInstallArgv(caCertPath, target, mechanism).slice(0, 2);
            await elevateCommands(
              fileCommands,
              'Could not write the Linux system trust anchor; rerun `certkit install`.',
            );
          }
          const rebuild = linuxInstallArgv(caCertPath, target, mechanism).slice(
            2,
          );
          await elevateCommands(
            rebuild,
            'Could not rebuild the Linux system trust store; the anchor remains pending for recovery.',
          );
        } else {
          await elevateCommands(
            linuxInstallArgv(caCertPath, target, mechanism),
            'Could not add the CA to the Linux system trust store; rerun `certkit install`.',
          );
        }

        const present = await activeContains(
          await fs.readFile(caCertPath),
          mechanism,
        );
        if (present === undefined)
          return {
            state: 'inconclusive',
            detail:
              'The Linux trust command succeeded, but active-store read-back was unavailable; rerun `certkit install`.',
          };
        if (!present)
          throw writeFailure(
            'The Linux system trust store did not contain the CA after rebuilding; the anchor remains pending for recovery.',
          );
        return { state: 'verified' };
      } catch (error) {
        if (error instanceof CertkitError) throw error;
        throw writeFailure(
          'Could not verify the Linux system trust install; rerun `certkit install`.',
        );
      }
    },

    async uninstall(caCertPem, target, selectedMechanism) {
      const mechanism = resolveMechanism(target, selectedMechanism);
      if (!mechanism)
        throw writeFailure(
          'The recorded Linux trust target is not recognized.',
        );
      try {
        if (mechanism === 'trust-anchor') {
          if (fingerprint(await fs.readFile(target)) !== fingerprint(caCertPem))
            throw writeFailure(
              'The recorded trust-anchor path does not match the CA fingerprint; recovery data was retained.',
            );
          const present = await activeContains(caCertPem, mechanism);
          if (present === undefined)
            throw writeFailure(
              'The active Linux trust store could not be inspected; recovery data was retained.',
            );
          if (present)
            await elevateCommands(
              linuxUninstallArgv(target, mechanism),
              'Could not remove the CA from the Linux system trust store; recovery data was retained.',
            );
        } else {
          const anchor = await anchorState(caCertPem, target);
          if (anchor === 'inconclusive')
            throw writeFailure(
              'The Linux anchor target could not be inspected; recovery data was retained.',
            );
          if (anchor === 'different')
            throw writeFailure(
              'The Linux anchor target does not contain exactly the recorded CA certificate; no file was removed. Inspect it manually, then rerun `certkit uninstall`; recovery data was retained.',
            );
          const temporary = await anchorState(
            caCertPem,
            linuxAnchorTempTarget(target),
          );
          if (temporary === 'inconclusive')
            throw writeFailure(
              'The temporary Linux anchor target could not be inspected; recovery data was retained.',
            );
          if (temporary === 'different')
            throw writeFailure(
              'The temporary Linux anchor target does not contain exactly the recorded CA certificate; no file was removed. Inspect it manually, then rerun `certkit uninstall`; recovery data was retained.',
            );
          if (anchor === 'present')
            await elevateCommands(
              [['rm', '--', target]],
              'Could not remove the matching Linux trust anchor; recovery data was retained.',
            );
          if (temporary === 'present')
            await elevateCommands(
              [['rm', '--', linuxAnchorTempTarget(target)]],
              'Could not remove the matching temporary Linux trust anchor; recovery data was retained.',
            );
        }
        if (mechanism !== 'trust-anchor')
          await elevateCommands(
            linuxUninstallArgv(target, mechanism).slice(2),
            'Could not remove the CA from the Linux system trust store; recovery data was retained.',
          );
        const remains = await activeContains(caCertPem, mechanism);
        if (remains === undefined || remains)
          throw writeFailure(
            remains
              ? 'The CA remains in the active Linux trust store after removal; recovery data was retained.'
              : 'The Linux active trust store could not be read after removal; recovery data was retained.',
          );
      } catch (error) {
        if (error instanceof CertkitError) throw error;
        throw writeFailure(
          'Could not complete Linux CA removal; recovery data was retained.',
        );
      }
    },
  };
}
