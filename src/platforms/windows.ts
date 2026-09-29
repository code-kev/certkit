import { X509Certificate } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { CertkitError } from '../core/errors.js';
import type { Environment } from './detect.js';
import type { RunResult } from './run.js';
import type { StoreAdapter } from './store.js';

const DEFAULT_TARGET = 'default';
const ENUMERATE_ROOT_ARGV = [
  'powershell.exe',
  '-NoLogo',
  '-NoProfile',
  '-NonInteractive',
  '-Command',
  "$ErrorActionPreference = 'Stop'; Get-ChildItem -LiteralPath Cert:\\CurrentUser\\Root -ErrorAction Stop | ForEach-Object { [Convert]::ToBase64String($_.RawData) }",
];

export function windowsInstallArgv(caCertPath: string): string[] {
  return ['certutil', '-user', '-addstore', 'Root', caCertPath];
}

export function windowsDeleteCertificateArgv(sha1: string): string[] {
  return ['certutil', '-user', '-delstore', 'Root', sha1];
}

type Command = (
  argv: string[],
  opts?: { timeoutMs?: number },
) => Promise<RunResult>;

interface WindowsAdapterDependencies {
  run: Command;
  // certutil pops a GUI consent dialog for add/delstore and has no timeout
  // of its own; where the dialog cannot be seen (CI, SSH, session 0) it hangs
  // forever. The write is bounded instead of refused outright: an interactive
  // session without TTYs (a scheduled task with a visible desktop) can still
  // approve the dialog, and a truly headless session gets a typed error once
  // the budget lapses instead of a silent hang.
  consentTimeoutMs?: number;
}

const DEFAULT_CONSENT_TIMEOUT_MS = 180_000;

function isConsentTimeout(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error as { code?: string }).code === 'COMMAND_TIMEOUT'
  );
}

function consentTimeoutFailure(): CertkitError {
  return writeFailure(
    'Windows showed a consent dialog that was not approved in time; this session may not be able to display it. Approve the dialog in the interactive session, or re-run from an interactive terminal (not CI, SSH, or a pipe).',
  );
}

function certificateHashes(pem: string): { sha256: string; sha1: string } {
  const certificate = new X509Certificate(pem);
  return {
    sha256: certificate.fingerprint256.replaceAll(':', '').toLowerCase(),
    sha1: certificate.fingerprint.replaceAll(':', '').toUpperCase(),
  };
}

function certificateHashesFromStore(
  output: string,
): Array<{ sha256: string; sha1: string }> | undefined {
  const hashes: Array<{ sha256: string; sha1: string }> = [];
  for (const line of output.split(/\r?\n/)) {
    if (!line) continue;
    if (
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
        line,
      )
    )
      return undefined;
    try {
      const certificate = new X509Certificate(
        `-----BEGIN CERTIFICATE-----\n${line}\n-----END CERTIFICATE-----`,
      );
      hashes.push({
        sha256: certificate.fingerprint256.replaceAll(':', '').toLowerCase(),
        sha1: certificate.fingerprint.replaceAll(':', '').toUpperCase(),
      });
    } catch {
      return undefined;
    }
  }
  return hashes;
}

async function enumerateRoot(run: Command) {
  const result = await run([...ENUMERATE_ROOT_ARGV]);
  return result.code === 0
    ? certificateHashesFromStore(result.stdout)
    : undefined;
}

function readbackContainsThumbprint(output: string, sha1: string): boolean {
  return [
    ...output.matchAll(/^\s*Cert Hash\(sha1\):\s*([\da-f: ]+)\s*$/gim),
  ].some(([, value]) => value?.replaceAll(/[:\s]/g, '').toUpperCase() === sha1);
}

function writeFailure(message: string): CertkitError {
  return new CertkitError('STORE_WRITE_FAILED', message);
}

function assertDefaultTarget(target: string): void {
  if (target !== DEFAULT_TARGET)
    throw writeFailure('The Windows adapter only supports target "default".');
}

export function createWindowsAdapter(
  dependencies: WindowsAdapterDependencies,
): StoreAdapter {
  const { run } = dependencies;
  const consentTimeoutMs =
    dependencies.consentTimeoutMs ?? DEFAULT_CONSENT_TIMEOUT_MS;
  return {
    id: 'windows-root',

    async inspectInstalled(caCertPem, target) {
      assertDefaultTarget(target);
      try {
        const expected = certificateHashes(caCertPem).sha256;
        const certificates = await enumerateRoot(run);
        if (!certificates) return 'inconclusive';
        return certificates.some(({ sha256 }) => sha256 === expected)
          ? 'present'
          : 'absent';
      } catch {
        return 'inconclusive';
      }
    },

    async checkTrust(caCertPem: string, env: Environment) {
      if (
        env.os !== 'windows' ||
        !env.stores.some(
          (store) => store.store === 'windows-root' && store.detected,
        )
      )
        return [{ state: 'not-detected', target: DEFAULT_TARGET }];

      try {
        const expected = certificateHashes(caCertPem).sha256;
        const certificates = await enumerateRoot(run);
        if (!certificates)
          return [
            {
              state: 'unknown',
              target: DEFAULT_TARGET,
              detail:
                'The current-user Windows Root store could not be inspected.',
            },
          ];
        return [
          {
            state: certificates.some(({ sha256 }) => sha256 === expected)
              ? 'trusted'
              : 'untrusted',
            target: DEFAULT_TARGET,
          },
        ];
      } catch {
        return [
          {
            state: 'unknown',
            target: DEFAULT_TARGET,
            detail:
              'The current-user Windows Root store could not be inspected.',
          },
        ];
      }
    },

    async install(certPath, target) {
      assertDefaultTarget(target);
      try {
        const { sha1 } = certificateHashes(await readFile(certPath, 'utf8'));
        const added = await run(windowsInstallArgv(certPath), {
          timeoutMs: consentTimeoutMs,
        });
        if (added.code !== 0)
          throw writeFailure(
            'Could not add the CA to the current-user Windows Root store.',
          );
        const readback = await run([
          'certutil',
          '-user',
          '-store',
          'Root',
          sha1,
        ]).catch(() => undefined);
        if (
          readback?.code !== 0 ||
          !readbackContainsThumbprint(readback.stdout, sha1)
        )
          return {
            state: 'inconclusive',
            detail:
              'The add command succeeded, but the current-user Root store read-back did not confirm the certificate thumbprint; rerun `certkit install`.',
          };
        return { state: 'verified' };
      } catch (error) {
        if (error instanceof CertkitError) throw error;
        if (isConsentTimeout(error)) throw consentTimeoutFailure();
        throw writeFailure(
          'Could not verify the current-user Windows Root store install; rerun `certkit install`.',
        );
      }
    },

    async uninstall(caCertPem, target) {
      assertDefaultTarget(target);
      try {
        const expected = certificateHashes(caCertPem);
        const certificates = await enumerateRoot(run);
        if (!certificates)
          throw writeFailure(
            'Could not inspect the current-user Windows Root store; CA recovery data was retained.',
          );
        const match = certificates.find(
          ({ sha256 }) => sha256 === expected.sha256,
        );
        if (!match) return;

        const removed = await run(windowsDeleteCertificateArgv(match.sha1), {
          timeoutMs: consentTimeoutMs,
        });
        if (removed.code !== 0)
          throw writeFailure(
            'Could not remove the CA from the current-user Windows Root store; CA recovery data was retained.',
          );
        const remaining = await enumerateRoot(run);
        if (
          !remaining ||
          remaining.some(({ sha256 }) => sha256 === expected.sha256)
        )
          throw writeFailure(
            'The CA remains in the current-user Windows Root store after removal; CA recovery data was retained.',
          );
      } catch (error) {
        if (error instanceof CertkitError) throw error;
        if (isConsentTimeout(error)) throw consentTimeoutFailure();
        throw writeFailure(
          'Could not complete Windows CA removal; CA recovery data was retained.',
        );
      }
    },
  };
}
