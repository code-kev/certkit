import { X509Certificate } from 'node:crypto';
import { access, mkdtemp, readFile, rm, rmdir } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import path from 'node:path';
import { CertkitError } from '../core/errors.js';
import type { Environment } from './detect.js';
import type { RunResult } from './run.js';
import type { StoreAdapter } from './store.js';

const SUBJECT = 'certkit development CA';
const DEFAULT_TARGET = 'default';
const TRUST_NOT_ACCEPTED = /CSSMERR_TP_NOT_TRUSTED|kSecTrustResultDeny/i;
const NO_TRUST_SETTINGS = /No Trust Settings were found/i;

type Command = (argv: string[]) => Promise<RunResult>;

interface MacosAdapterDependencies {
  caCertPath: string;
  run: Command;
  keychainPath?: string;
  /** Accepted for existing status callers; macOS trust commands never elevate. */
  elevate?: Command;
}

function certificateHashes(pem: string): { sha256: string; sha1: string } {
  const certificate = new X509Certificate(pem);
  return {
    sha256: certificate.fingerprint256.replaceAll(':', '').toLowerCase(),
    sha1: certificate.fingerprint.replaceAll(':', '').toLowerCase(),
  };
}

function matchedFingerprint(
  output: string,
  sha256: string,
): boolean | undefined {
  const certificates =
    output.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
    ) ?? [];
  try {
    return certificates.some((pem) => certificateHashes(pem).sha256 === sha256);
  } catch {
    // A malformed keychain read cannot establish either presence or absence.
    return undefined;
  }
}

async function findCertificate(
  run: Command,
  sha256: string,
  keychainPath: string,
): Promise<boolean | undefined> {
  const result = await run([
    'security',
    'find-certificate',
    '-a',
    '-c',
    SUBJECT,
    '-p',
    keychainPath,
  ]);
  return result.code === 0
    ? matchedFingerprint(result.stdout, sha256)
    : undefined;
}

function parseUserKeychainList(output: string): string[] | undefined {
  const paths: string[] = [];
  for (const line of output.split(/\r?\n/)) {
    const entry = line.trim();
    if (!entry) continue;
    if (!entry.startsWith('"') || !entry.endsWith('"')) return undefined;
    const rawPath = entry.slice(1, -1);
    if (/(^|[^\\])"/u.test(rawPath)) return undefined;
    const keychainPath = rawPath.replaceAll('\\"', '"');
    if (!keychainPath) return undefined;
    paths.push(keychainPath);
  }
  return paths;
}

async function userKeychainSearchContains(
  run: Command,
  keychainPath: string,
): Promise<boolean | undefined> {
  const result = await run(['security', 'list-keychains', '-d', 'user']);
  if (result.code !== 0) return undefined;
  return parseUserKeychainList(result.stdout)?.includes(keychainPath);
}

async function keychainExists(
  keychainPath: string,
): Promise<boolean | undefined> {
  try {
    await access(keychainPath);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ENOENT'
      ? false
      : undefined;
  }
}

function storeWriteFailure(message: string): CertkitError {
  return new CertkitError('STORE_WRITE_FAILED', message);
}

function uninstallRecoveryFailure(message: string): CertkitError {
  return storeWriteFailure(
    `${message} Run \`certkit uninstall --dry-run\` for the manual recovery commands.`,
  );
}

function assertDefaultTarget(target: string): void {
  if (target !== DEFAULT_TARGET)
    throw storeWriteFailure(
      'The macOS adapter only supports target "default".',
    );
}

export function macosLoginKeychainPath(): string {
  return path.join(homedir(), 'Library', 'Keychains', 'login.keychain-db');
}

export function macosInstallArgv(
  caCertPath: string,
  keychainPath: string,
): string[] {
  return [
    'security',
    'add-trusted-cert',
    '-r',
    'trustRoot',
    '-p',
    'ssl',
    '-k',
    keychainPath,
    caCertPath,
  ];
}

export function macosRemoveTrustArgv(caCertPath: string): string[] {
  return ['security', 'remove-trusted-cert', caCertPath];
}

export function macosDeleteCertificateArgv(
  sha256: string,
  keychainPath: string,
): string[] {
  return ['security', 'delete-certificate', '-Z', sha256, keychainPath];
}

async function userTrustContains(run: Command, sha1: string): Promise<boolean> {
  // Uninstall exports trust settings to verify removal; read-only status never exports them.
  // Keep the private file outside the CA directory so an interrupted export cannot block retirement.
  const exportDir = await mkdtemp(path.join(tmpdir(), 'certkit-trust-'));
  const exportPath = path.join(exportDir, 'user-settings.plist');
  try {
    const result = await run(['security', 'trust-settings-export', exportPath]);
    if (result.code !== 0) {
      if (NO_TRUST_SETTINGS.test(`${result.stdout}\n${result.stderr}`))
        return false;
      throw uninstallRecoveryFailure(
        'Could not read macOS user trust settings; CA recovery data was retained.',
      );
    }
    const plist = await readFile(exportPath, 'utf8');
    if (!/<plist\b[\s\S]*<dict\b/i.test(plist))
      throw uninstallRecoveryFailure(
        'macOS returned unreadable user trust settings; CA recovery data was retained.',
      );
    return [...plist.matchAll(/<key>\s*([\da-f]{40})\s*<\/key>/gi)].some(
      ([, hash]) => hash?.toLowerCase() === sha1,
    );
  } finally {
    await rm(exportPath, { force: true });
    await rmdir(exportDir);
  }
}

export function createMacosAdapter(
  dependencies: MacosAdapterDependencies,
): StoreAdapter {
  const { caCertPath, run } = dependencies;
  const keychainPath = dependencies.keychainPath ?? macosLoginKeychainPath();
  return {
    id: 'macos-keychain',

    async inspectInstalled(caCertPem, target) {
      assertDefaultTarget(target);
      try {
        const present = await findCertificate(
          run,
          certificateHashes(caCertPem).sha256,
          keychainPath,
        );
        return present === undefined
          ? 'inconclusive'
          : present
            ? 'present'
            : 'absent';
      } catch {
        return 'inconclusive';
      }
    },

    async checkTrust(caCertPem: string, env: Environment) {
      if (
        env.os !== 'macos' ||
        !env.stores.some(
          (store) => store.store === 'macos-keychain' && store.detected,
        )
      )
        return [{ state: 'not-detected', target: DEFAULT_TARGET }];

      try {
        const expected = certificateHashes(caCertPem);
        if (
          certificateHashes(await readFile(caCertPath, 'utf8')).sha256 !==
          expected.sha256
        )
          return [
            {
              state: 'unknown',
              target: DEFAULT_TARGET,
              detail:
                'The current CA path does not match the supplied CA identity.',
            },
          ];

        const exists = await keychainExists(keychainPath);
        if (exists === false)
          return [
            {
              state: 'not-detected',
              target: DEFAULT_TARGET,
              detail: 'The current user login keychain is unavailable.',
            },
          ];
        if (exists === undefined)
          return [
            {
              state: 'unknown',
              target: DEFAULT_TARGET,
              detail: 'The current user login keychain could not be inspected.',
            },
          ];

        const inSearchList = await userKeychainSearchContains(
          run,
          keychainPath,
        );
        if (inSearchList === undefined)
          return [
            {
              state: 'unknown',
              target: DEFAULT_TARGET,
              detail: 'The macOS user keychain list could not be read.',
            },
          ];
        if (!inSearchList)
          return [
            {
              state: 'not-detected',
              target: DEFAULT_TARGET,
              detail:
                'The login keychain is not in the user keychain search list.',
            },
          ];

        const present = await findCertificate(
          run,
          expected.sha256,
          keychainPath,
        );
        if (present === undefined)
          return [
            {
              state: 'unknown',
              target: DEFAULT_TARGET,
              detail: 'The login keychain certificate read was inconclusive.',
            },
          ];

        const verification = await run([
          'security',
          'verify-cert',
          '-c',
          caCertPath,
          '-p',
          'ssl',
          '-l',
          '-L',
        ]);
        if (verification.code === 0 && present)
          return [{ state: 'trusted', target: DEFAULT_TARGET }];
        if (
          verification.code !== 0 &&
          TRUST_NOT_ACCEPTED.test(
            `${verification.stdout}\n${verification.stderr}`,
          )
        )
          return [
            {
              state: 'untrusted',
              target: DEFAULT_TARGET,
              detail:
                'The current CA is not accepted by the default SSL policy.',
            },
          ];
        return [
          {
            state: 'unknown',
            target: DEFAULT_TARGET,
            detail: present
              ? 'The default SSL trust result could not be established.'
              : 'The SSL result is inconclusive and no matching CA fingerprint was found in the login keychain.',
          },
        ];
      } catch {
        // Read-only probe failures cannot be reported as trusted or untrusted.
        return [
          {
            state: 'unknown',
            target: DEFAULT_TARGET,
            detail:
              'The current macOS SSL trust result could not be established.',
          },
        ];
      }
    },

    async install(caPath, target) {
      assertDefaultTarget(target);
      try {
        const { sha256 } = certificateHashes(await readFile(caPath, 'utf8'));
        const exists = await keychainExists(keychainPath);
        if (exists !== true)
          throw storeWriteFailure(
            `The macOS login keychain ${keychainPath} is unavailable. Restore it and add it to the user keychain search list, then rerun \`certkit install\`; use \`certkit install --dry-run\` for the manual command.`,
          );
        const inSearchList = await userKeychainSearchContains(
          run,
          keychainPath,
        );
        if (inSearchList !== true)
          throw storeWriteFailure(
            `The macOS login keychain ${keychainPath} is ${inSearchList === false ? 'not in' : 'not confirmed in'} the user keychain search list. Add it to that list and rerun \`certkit install\`; use \`certkit install --dry-run\` for the manual command.`,
          );

        const added = await run(macosInstallArgv(caPath, keychainPath));
        if (added.code !== 0)
          throw storeWriteFailure(
            'Could not add the CA to the macOS login keychain. macOS may request native user authentication; approve its dialog and rerun `certkit install`. Certkit never collects a password. Use `certkit install --dry-run` for the manual command.',
          );

        const present = await findCertificate(run, sha256, keychainPath).catch(
          () => undefined,
        );
        if (present === undefined)
          return {
            state: 'inconclusive',
            detail:
              'The add command succeeded, but the login keychain read-back was unavailable; rerun `certkit install`.',
          };
        if (!present)
          throw storeWriteFailure(
            'The macOS login keychain did not contain the installed CA after the add command; rerun `certkit install`.',
          );
        return { state: 'verified' };
      } catch (error) {
        if (error instanceof CertkitError) throw error;
        throw storeWriteFailure(
          'Could not verify the macOS login keychain install; rerun `certkit install` or use the manual trust command.',
        );
      }
    },

    async uninstall(caCertPem, target) {
      assertDefaultTarget(target);
      try {
        const identity = certificateHashes(caCertPem);
        if (
          certificateHashes(await readFile(caCertPath, 'utf8')).sha256 !==
          identity.sha256
        )
          throw uninstallRecoveryFailure(
            'The macOS CA path does not match the requested fingerprint; CA recovery data was retained.',
          );

        const loginHasCa = await findCertificate(
          run,
          identity.sha256,
          keychainPath,
        );
        if (loginHasCa === undefined)
          throw uninstallRecoveryFailure(
            'Could not read the macOS login keychain; CA recovery data was retained.',
          );

        if (await userTrustContains(run, identity.sha1)) {
          const removed = await run(macosRemoveTrustArgv(caCertPath));
          if (removed.code !== 0)
            throw uninstallRecoveryFailure(
              'Could not remove the macOS user trust setting; CA recovery data was retained. macOS may request native user authentication; Certkit never collects a password.',
            );
          if (await userTrustContains(run, identity.sha1))
            throw uninstallRecoveryFailure(
              'The macOS user trust setting remains after removal; CA recovery data was retained.',
            );
        }

        if (loginHasCa) {
          const deleted = await run(
            macosDeleteCertificateArgv(identity.sha256, keychainPath),
          );
          if (deleted.code !== 0)
            throw uninstallRecoveryFailure(
              'Could not delete the CA from the macOS login keychain; CA recovery data was retained. macOS may request native user authentication; Certkit never collects a password.',
            );
          if (
            (await findCertificate(run, identity.sha256, keychainPath)) !==
            false
          )
            throw uninstallRecoveryFailure(
              'The CA remains in the macOS login keychain after deletion; CA recovery data was retained.',
            );
        }
      } catch (error) {
        if (error instanceof CertkitError) throw error;
        throw uninstallRecoveryFailure(
          'Could not complete macOS CA removal; CA recovery data was retained.',
        );
      }
    },
  };
}
