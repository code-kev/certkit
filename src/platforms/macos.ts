import { X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, rm, rmdir } from 'node:fs/promises';
import path from 'node:path';
import { CertkitError } from '../core/errors.js';
import type { Environment } from './detect.js';
import type { RunResult } from './run.js';
import type { StoreAdapter } from './store.js';

const SYSTEM_KEYCHAIN = '/Library/Keychains/System.keychain';
const SUBJECT = 'certkit development CA';
const DEFAULT_TARGET = 'default';
const TRUST_NOT_ACCEPTED = /CSSMERR_TP_NOT_TRUSTED|kSecTrustResultDeny/i;
const NO_TRUST_SETTINGS = /No Trust Settings were found/i;

type Command = (argv: string[]) => Promise<RunResult>;

interface MacosAdapterDependencies {
  caCertPath: string;
  run: Command;
  elevate: Command;
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
  keychain?: string,
): Promise<boolean | undefined> {
  const argv = [
    'security',
    'find-certificate',
    '-a',
    '-c',
    SUBJECT,
    '-p',
    ...(keychain ? [keychain] : []),
  ];
  const result = await run(argv);
  return result.code === 0
    ? matchedFingerprint(result.stdout, sha256)
    : undefined;
}

function storeWriteFailure(message: string): CertkitError {
  return new CertkitError('STORE_WRITE_FAILED', message);
}

function assertDefaultTarget(target: string): void {
  if (target !== DEFAULT_TARGET)
    throw storeWriteFailure(
      'The macOS adapter only supports target "default".',
    );
}

async function adminTrustContains(
  run: Command,
  caCertPath: string,
  sha1: string,
): Promise<boolean> {
  // Uninstall may export settings for verification; read-only status never does.
  const exportDir = await mkdtemp(
    path.join(path.dirname(caCertPath), '.certkit-trust-'),
  );
  const exportPath = path.join(exportDir, 'admin-settings.plist');
  try {
    const result = await run([
      'security',
      'trust-settings-export',
      '-d',
      exportPath,
    ]);
    if (result.code !== 0) {
      if (NO_TRUST_SETTINGS.test(`${result.stdout}\n${result.stderr}`))
        return false;
      throw storeWriteFailure(
        'Could not read macOS admin trust settings; CA recovery data was retained.',
      );
    }
    const plist = await readFile(exportPath, 'utf8');
    if (!/<plist\b[\s\S]*<dict\b/i.test(plist))
      throw storeWriteFailure(
        'macOS returned unreadable admin trust settings; CA recovery data was retained.',
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
  const { caCertPath, run, elevate } = dependencies;
  return {
    id: 'macos-keychain',

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

        const present = await findCertificate(run, expected.sha256);
        if (present === undefined)
          return [
            {
              state: 'unknown',
              target: DEFAULT_TARGET,
              detail: 'The default macOS keychain list could not be read.',
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
              : 'The SSL result is inconclusive and no matching CA fingerprint was found.',
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

    async install(caCertPath, target) {
      assertDefaultTarget(target);
      try {
        const { sha256 } = certificateHashes(
          await readFile(caCertPath, 'utf8'),
        );
        const added = await elevate([
          'security',
          'add-trusted-cert',
          '-d',
          '-r',
          'trustRoot',
          '-k',
          SYSTEM_KEYCHAIN,
          caCertPath,
        ]);
        if (added.code !== 0)
          throw storeWriteFailure(
            'Could not add the CA to the macOS System keychain; rerun `certkit install` or use the manual trust command.',
          );

        const present = await findCertificate(
          run,
          sha256,
          SYSTEM_KEYCHAIN,
        ).catch(() => undefined);
        if (present === undefined)
          return {
            state: 'inconclusive',
            detail:
              'The add command succeeded, but the System keychain read-back was unavailable; rerun `certkit install`.',
          };
        if (!present)
          throw storeWriteFailure(
            'The macOS System keychain did not contain the installed CA after the add command; rerun `certkit install`.',
          );
        return { state: 'verified' };
      } catch (error) {
        if (error instanceof CertkitError) throw error;
        throw storeWriteFailure(
          'Could not verify the macOS System keychain install; rerun `certkit install` or use the manual trust command.',
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
          throw storeWriteFailure(
            'The macOS CA path does not match the requested fingerprint; CA recovery data was retained.',
          );

        const systemHasCa = await findCertificate(
          run,
          identity.sha256,
          SYSTEM_KEYCHAIN,
        );
        if (systemHasCa === undefined)
          throw storeWriteFailure(
            'Could not read the macOS System keychain; CA recovery data was retained.',
          );

        if (await adminTrustContains(run, caCertPath, identity.sha1)) {
          const removed = await elevate([
            'security',
            'remove-trusted-cert',
            '-d',
            caCertPath,
          ]);
          if (removed.code !== 0)
            throw storeWriteFailure(
              'Could not remove the macOS admin trust setting; CA recovery data was retained.',
            );
          if (await adminTrustContains(run, caCertPath, identity.sha1))
            throw storeWriteFailure(
              'The macOS admin trust setting remains after removal; CA recovery data was retained.',
            );
        }

        if (systemHasCa) {
          const deleted = await elevate([
            'security',
            'delete-certificate',
            '-Z',
            identity.sha256,
            SYSTEM_KEYCHAIN,
          ]);
          if (deleted.code !== 0)
            throw storeWriteFailure(
              'Could not delete the CA from the macOS System keychain; CA recovery data was retained.',
            );
          if (
            (await findCertificate(run, identity.sha256, SYSTEM_KEYCHAIN)) !==
            false
          )
            throw storeWriteFailure(
              'The CA remains in the macOS System keychain after deletion; CA recovery data was retained.',
            );
        }
      } catch (error) {
        if (error instanceof CertkitError) throw error;
        throw storeWriteFailure(
          'Could not complete macOS CA removal; CA recovery data was retained.',
        );
      }
    },
  };
}
