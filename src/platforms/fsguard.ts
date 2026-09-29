import { execFileSync } from 'node:child_process';
import type { FsGuard } from '../core/cadir.js';
import { CertkitError } from '../core/errors.js';

export type CommandRunner = (
  command: string,
  args: readonly string[],
) => string;

function run(command: string, args: readonly string[]): string {
  try {
    return execFileSync(command, [...args], {
      encoding: 'utf8',
      windowsHide: true,
    });
  } catch (error) {
    throw new CertkitError(
      'CA_UNREADABLE',
      `Windows filesystem protection command failed: ${command}`,
      { cause: error },
    );
  }
}

function identity(runCommand: CommandRunner): { account: string; sid: string } {
  let output: string;
  try {
    output = runCommand('whoami', ['/user', '/fo', 'csv', '/nh']);
  } catch (error) {
    throw new CertkitError(
      'CA_UNREADABLE',
      'Could not determine the current Windows user for CA directory protection.',
      {
        cause: error,
      },
    );
  }
  const line = output.trim().split(/\r?\n/).find(Boolean) ?? '';
  const csv = line.match(/^"((?:[^"]|"")*)","((?:[^"]|"")*)"$/);
  const values = csv
    ? [csv[1]?.replaceAll('""', '"'), csv[2]?.replaceAll('""', '"')]
    : line.split(',').map((value) => value.trim());
  const account = values[0];
  const sid = values[1];
  if (!account || !sid || !/^S-\d-\d+(?:-\d+)+$/i.test(sid)) {
    throw new CertkitError(
      'CA_UNREADABLE',
      'Windows did not return a valid current-user SID for CA directory protection.',
    );
  }
  return { account, sid };
}

// ACL reads use Get-Acl's SDDL form: it is ASCII (SIDs), unlike icacls text
// output, which is emitted in the console OEM codepage and corrupts
// non-ASCII account names/paths when piped.
// Get-Acl .Sddl substitutes two-letter aliases for well-known SIDs.
const SDDL_ALIASES: Record<string, string> = {
  AN: 'S-1-5-7', // Anonymous
  AU: 'S-1-5-11', // Authenticated Users
  BA: 'S-1-5-32-544', // Administrators
  BU: 'S-1-5-32-545', // Users
  IU: 'S-1-5-4', // Interactive
  LS: 'S-1-5-19', // Local Service
  NS: 'S-1-5-20', // Network Service
  RD: 'S-1-5-32-555', // Remote Desktop Users
  SY: 'S-1-5-18', // LocalSystem
  WD: 'S-1-1-0', // Everyone
};

function aclSids(path: string, sddl: string): string[] {
  const daclStart = sddl.indexOf('D:');
  if (daclStart < 0)
    throw new CertkitError(
      'CA_UNREADABLE',
      `Could not parse the Windows ACL for ${path}.`,
    );
  const [dacl = ''] = sddl
    .slice(daclStart + 2)
    .replace(/^[A-Z]*/, '')
    .split('S:');
  const sids: string[] = [];
  for (const match of dacl.matchAll(/\(([^()]*)\)/g)) {
    const fields = match[1]?.split(';') ?? [];
    const principal = fields[5] ?? '';
    const sid = SDDL_ALIASES[principal.toUpperCase()] ?? principal;
    if (fields.length !== 6 || !/^S-\d-\d+(?:-\d+)+$/i.test(sid))
      throw new CertkitError(
        'CA_UNREADABLE',
        `Could not parse the Windows ACL for ${path}. Inspect and restrict it manually with: icacls "${path}"`,
      );
    sids.push(sid.toLowerCase());
  }
  return sids;
}

function verifyAcl(path: string, runCommand: CommandRunner): void {
  const current = identity(runCommand);
  let sddl: string;
  try {
    sddl = runCommand('powershell.exe', [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      `(Get-Acl -LiteralPath '${path.replaceAll("'", "''")}').Sddl`,
    ]).trim();
  } catch (error) {
    throw new CertkitError(
      'CA_UNREADABLE',
      `Could not re-read the Windows ACL for ${path}. Inspect and restrict it manually with: icacls "${path}"`,
      { cause: error },
    );
  }
  const sids = aclSids(path, sddl);
  const self = current.sid.toLowerCase();
  const unapproved = sids.filter((sid) => sid !== self);
  if (!sids.length || unapproved.length > 0) {
    const command = unapproved.length
      ? unapproved
          .map((sid) => `icacls "${path}" /remove:g "*${sid}"`)
          .join(' & ')
      : `icacls "${path}"`;
    throw new CertkitError(
      'CA_UNREADABLE',
      `Windows ACL for ${path} grants access to an unapproved principal. Inspect and remove it manually with: ${command}`,
    );
  }
}

export function createWindowsFsGuard(runCommand: CommandRunner = run): FsGuard {
  return {
    protectDirectory(path) {
      const { sid } = identity(runCommand);
      try {
        runCommand('icacls', [
          path,
          '/inheritance:r',
          '/grant:r',
          `*${sid}:(OI)(CI)F`,
        ]);
      } catch (error) {
        throw new CertkitError(
          'CA_UNREADABLE',
          `Could not establish the Windows CA directory ACL for ${path}. Inspect and restrict it manually with icacls, then retry.`,
          {
            cause: error,
          },
        );
      }
      verifyAcl(path, runCommand);
    },
    assertProtectedDirectory(path) {
      verifyAcl(path, runCommand);
    },
    assertProtectedFile(path) {
      verifyAcl(path, runCommand);
    },
  };
}
