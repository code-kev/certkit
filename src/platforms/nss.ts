import { X509Certificate } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { CertkitError } from '../core/errors.js';
import type { Environment } from './detect.js';
import { type RunResult, resolveNssCertutil } from './run.js';
import type { StoreAdapter } from './store.js';

type Command = (argv: string[]) => Promise<RunResult>;

interface NssAdapterFs {
  mkdir: (
    path: string,
    options: { recursive: true; mode: number },
  ) => Promise<unknown>;
  hasDatabaseFile: (target: string) => boolean;
}

interface NssAdapterDependencies {
  run: Command;
  resolveCertutil?: () => Promise<string | null>;
  fs?: NssAdapterFs;
}

const defaultFs: NssAdapterFs = {
  mkdir: (path, options) => mkdir(path, options),
  hasDatabaseFile: (target) => existsSync(join(target, 'cert9.db')),
};

const DEFAULT_TARGET = 'default';
const SYSTEM_NSS_DB = '/etc/pki/nssdb';
const pemCertificate =
  /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const manualCertutil =
  'Install Mozilla NSS certutil manually, then rerun the command. Certkit does not install NSS tools automatically; see docs/trust-matrix.md.';

function certificateFingerprint(pem: string): string {
  return new X509Certificate(pem).fingerprint256
    .replaceAll(':', '')
    .toLowerCase();
}

export function nssCertificateNickname(caCertPem: string): string {
  return `certkit development CA ${certificateFingerprint(caCertPem).slice(0, 12)}`;
}

function fingerprintBlocks(output: string): string[] | undefined {
  const certificates = output.match(pemCertificate) ?? [];
  if (output.replace(pemCertificate, '').trim()) return undefined;
  try {
    return certificates.map(certificateFingerprint);
  } catch {
    return undefined;
  }
}

function nicknameRows(output: string, nickname: string): string[] | undefined {
  if (!/Certificate Nickname\b[\s\S]*?SSL,S\/MIME,JAR\/XPI/i.test(output))
    return undefined;
  const rows: string[] = [];
  for (const line of output.split(/\r?\n/)) {
    const row = /^\s*(.*?)\s+([A-Za-z,]+)\s*$/.exec(line);
    if (!row) continue;
    if (row[1] === nickname) rows.push(row[2] ?? '');
  }
  return rows;
}

function hasSslTrust(flags: string): boolean {
  return (flags.split(',')[0] ?? '').includes('C');
}

function sqlDatabase(target: string): string {
  return `sql:${target}`;
}

function writeFailure(message: string): CertkitError {
  return new CertkitError('STORE_WRITE_FAILED', message);
}

// resolve() alone misses the literal path on Windows (drive-letter prefix).
export function isSystemNssDb(target: string): boolean {
  return target === SYSTEM_NSS_DB || resolve(target) === SYSTEM_NSS_DB;
}

function assertWritableTarget(target: string): void {
  if (isSystemNssDb(target))
    throw writeFailure(
      'Automatic writes to /etc/pki/nssdb are disabled; use the documented manual trust instructions.',
    );
}

export function createNssAdapter(
  dependencies: NssAdapterDependencies,
): StoreAdapter {
  const fs: NssAdapterFs = dependencies.fs ?? defaultFs;
  let certutil: Promise<string | null> | undefined;
  const resolveCertutil = () =>
    (certutil ??= (dependencies.resolveCertutil ?? resolveNssCertutil)());
  const command = async (args: string[]): Promise<RunResult> => {
    const executable = await resolveCertutil();
    if (!executable)
      throw new CertkitError('UNSUPPORTED_PLATFORM', manualCertutil);
    return dependencies.run([executable, ...args]);
  };
  const ensureDatabaseDirectory = async (target: string): Promise<void> => {
    if (!(await resolveCertutil()))
      throw new CertkitError('UNSUPPORTED_PLATFORM', manualCertutil);
    try {
      await fs.mkdir(target, { recursive: true, mode: 0o700 });
    } catch {
      throw writeFailure(
        'Could not initialize the NSS database directory; no certificate was added.',
      );
    }
  };
  const listing = (target: string) =>
    command(['-L', '-d', sqlDatabase(target)]);
  const certificateDump = (nickname: string, target: string) =>
    command(['-L', '-n', nickname, '-d', sqlDatabase(target), '-a']);
  const removePriorExactCertificate = async (
    caCertPem: string,
    nickname: string,
    target: string,
  ): Promise<void> => {
    const listed = await listing(target);
    if (listed.code !== 0) return;
    const rows = nicknameRows(listed.stdout, nickname);
    if (!rows)
      throw writeFailure(
        'The NSS database listing was unreadable; existing certificates were preserved.',
      );
    if (!rows.length) return;
    if (rows.length !== 1)
      throw writeFailure(
        'The derived NSS certificate nickname is ambiguous; existing certificates were preserved.',
      );
    const dumped = await certificateDump(nickname, target);
    const fingerprints =
      dumped.code === 0 ? fingerprintBlocks(dumped.stdout) : undefined;
    const expected = certificateFingerprint(caCertPem);
    if (
      fingerprints?.filter((fingerprint) => fingerprint === expected).length !==
      1
    )
      throw writeFailure(
        'The derived NSS nickname does not contain exactly one matching CA fingerprint; existing certificates were preserved.',
      );
    const removed = await command([
      '-D',
      '-n',
      nickname,
      '-d',
      sqlDatabase(target),
    ]);
    if (removed.code !== 0)
      throw writeFailure(
        'Could not prepare the existing NSS certificate for an idempotent retry; CA recovery data was retained.',
      );
    const remaining = await listing(target);
    if (
      remaining.code !== 0 ||
      nicknameRows(remaining.stdout, nickname)?.length !== 0
    )
      throw writeFailure(
        'The existing NSS certificate could not be cleared for retry; CA recovery data was retained.',
      );
  };

  return {
    id: 'nss',

    async inspectInstalled(caCertPem, target) {
      try {
        const nickname = nssCertificateNickname(caCertPem);
        // certutil exits non-zero with SEC_ERROR_BAD_DATABASE for a directory
        // that exists but holds no database yet (a prospective Chromium target
        // or an import interrupted before initialization). That is an absent
        // certificate, not an uninspectable database; treat a missing database
        // file as absent so install can initialize it and retries can recover.
        if (!fs.hasDatabaseFile(target)) return 'absent';
        const listed = await listing(target);
        if (listed.code !== 0) return 'inconclusive';
        const rows = nicknameRows(listed.stdout, nickname);
        if (!rows) return 'inconclusive';
        if (!rows.length) return 'absent';
        if (rows.length !== 1) return 'inconclusive';
        const dumped = await certificateDump(nickname, target);
        if (dumped.code !== 0) return 'inconclusive';
        const fingerprints = fingerprintBlocks(dumped.stdout);
        if (!fingerprints) return 'inconclusive';
        const count = fingerprints.filter(
          (fingerprint) => fingerprint === certificateFingerprint(caCertPem),
        ).length;
        return count === 1 ? 'present' : 'inconclusive';
      } catch {
        return 'inconclusive';
      }
    },

    async checkTrust(caCertPem: string, env: Environment) {
      const store = env.stores.find((item) => item.store === 'nss');
      const targets = store?.targets ?? [];
      if (!store?.detected || !targets.length)
        return [{ state: 'not-detected' as const, target: DEFAULT_TARGET }];

      const nickname = nssCertificateNickname(caCertPem);
      const expected = certificateFingerprint(caCertPem);
      const results = [];
      for (const target of targets) {
        try {
          const listed = await listing(target);
          if (listed.code !== 0) throw new Error('list failed');
          const rows = nicknameRows(listed.stdout, nickname);
          if (!rows)
            throw new Error('The NSS database listing was unreadable.');
          if (!rows.length) {
            results.push({ state: 'untrusted' as const, target });
            continue;
          }
          if (rows.length !== 1)
            throw new Error('The NSS certificate nickname is ambiguous.');

          const dumped = await certificateDump(nickname, target);
          if (dumped.code !== 0) throw new Error('certificate dump failed');
          const fingerprints = fingerprintBlocks(dumped.stdout);
          if (!fingerprints)
            throw new Error('The NSS certificate dump was unreadable.');
          const matches = fingerprints.filter(
            (fingerprint) => fingerprint === expected,
          ).length;
          if (!matches) {
            results.push({ state: 'untrusted' as const, target });
          } else if (matches !== 1) {
            throw new Error('The NSS certificate fingerprint is ambiguous.');
          } else if (!hasSslTrust(rows[0] ?? '')) {
            results.push({
              state: 'untrusted' as const,
              target,
              detail: 'present without SSL trust',
            });
          } else {
            results.push({ state: 'trusted' as const, target });
          }
        } catch (error) {
          results.push({
            state: 'unknown' as const,
            target,
            detail:
              error instanceof CertkitError
                ? error.message
                : 'The NSS database could not be inspected.',
          });
        }
      }
      return results;
    },

    async install(caCertPath, target) {
      assertWritableTarget(target);
      try {
        const caCertPem = await readFile(caCertPath, 'utf8');
        const nickname = nssCertificateNickname(caCertPem);
        await ensureDatabaseDirectory(target);
        await removePriorExactCertificate(caCertPem, nickname, target);
        const added = await command([
          '-A',
          '-n',
          nickname,
          '-t',
          'C,,',
          '-d',
          sqlDatabase(target),
          '-i',
          caCertPath,
        ]);
        if (added.code !== 0)
          return {
            state: 'inconclusive',
            detail:
              'NSS certificate import did not complete; its database may have been initialized. Rerun `certkit install` to retry.',
          };

        const listed = await listing(target);
        if (listed.code !== 0)
          return {
            state: 'inconclusive',
            detail:
              'The NSS import succeeded, but its read-back was unavailable; rerun `certkit install`.',
          };
        const rows = nicknameRows(listed.stdout, nickname);
        if (rows?.length !== 1 || !hasSslTrust(rows[0] ?? ''))
          return {
            state: 'inconclusive',
            detail:
              'The NSS read-back did not confirm one matching nickname with SSL trust; rerun `certkit install`.',
          };

        const dumped = await certificateDump(nickname, target);
        if (dumped.code !== 0)
          return {
            state: 'inconclusive',
            detail:
              'The NSS import succeeded, but its certificate read-back was unavailable; rerun `certkit install`.',
          };
        const fingerprints = fingerprintBlocks(dumped.stdout);
        if (
          fingerprints?.filter(
            (fingerprint) => fingerprint === certificateFingerprint(caCertPem),
          ).length !== 1
        )
          return {
            state: 'inconclusive',
            detail:
              'The NSS read-back did not confirm the CA fingerprint; rerun `certkit install`.',
          };
        return { state: 'verified' };
      } catch (error) {
        if (error instanceof CertkitError) throw error;
        throw writeFailure(
          'Could not verify the NSS trust install; rerun `certkit install`.',
        );
      }
    },

    async uninstall(caCertPem, target) {
      assertWritableTarget(target);
      try {
        const nickname = nssCertificateNickname(caCertPem);
        const listed = await listing(target);
        if (listed.code !== 0)
          throw writeFailure(
            'Could not inspect the NSS database; CA recovery data was retained.',
          );
        const rows = nicknameRows(listed.stdout, nickname);
        if (!rows)
          throw writeFailure(
            'The NSS database listing was unreadable; CA recovery data was retained.',
          );
        if (!rows.length) return;
        if (rows.length !== 1)
          throw writeFailure(
            'The derived NSS certificate nickname is ambiguous; no certificate was removed and CA recovery data was retained.',
          );

        const dumped = await certificateDump(nickname, target);
        const fingerprints =
          dumped.code === 0 ? fingerprintBlocks(dumped.stdout) : undefined;
        const expected = certificateFingerprint(caCertPem);
        if (
          fingerprints?.filter((fingerprint) => fingerprint === expected)
            .length !== 1
        )
          throw writeFailure(
            'The NSS nickname dump did not contain exactly one matching CA fingerprint; no certificate was removed and CA recovery data was retained.',
          );

        const removed = await command([
          '-D',
          '-n',
          nickname,
          '-d',
          sqlDatabase(target),
        ]);
        if (removed.code !== 0)
          throw writeFailure(
            'Could not remove the matching CA from the NSS database; CA recovery data was retained.',
          );
        const remaining = await listing(target);
        if (
          remaining.code !== 0 ||
          nicknameRows(remaining.stdout, nickname)?.length !== 0
        )
          throw writeFailure(
            'The matching CA remains in the NSS database after removal; CA recovery data was retained.',
          );
      } catch (error) {
        if (error instanceof CertkitError) throw error;
        throw writeFailure(
          'Could not complete NSS CA removal; CA recovery data was retained.',
        );
      }
    },
  };
}
