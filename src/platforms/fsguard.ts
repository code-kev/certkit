import { execFileSync } from 'node:child_process';
import path from 'node:path';
import type { FsGuard } from '../core/cadir.js';
import { CertkitError } from '../core/errors.js';
import { commandEnvironment } from './run.js';

export type CommandRunner = (
  command: string,
  args: readonly string[],
) => string;

const DEFAULT_GRANT_SIDS = ['S-1-5-18', 'S-1-5-32-544'];

function run(command: string, args: readonly string[]): string {
  const system32 = path.win32.join(
    process.env['SystemRoot'] || 'C:\\Windows',
    'System32',
  );
  const executable =
    command === 'powershell.exe'
      ? path.win32.join(system32, 'WindowsPowerShell', 'v1.0', command)
      : path.win32.join(system32, `${command}.exe`);
  try {
    const env = commandEnvironment(executable);
    return execFileSync(executable, [...args], {
      encoding: 'utf8',
      windowsHide: true,
      ...(env ? { env } : {}),
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

function aclSids(path: string, output: string): string[] {
  const result = output.trim();
  const lines = result ? result.split(/\r?\n/) : [];
  if (lines.some((sid) => !/^S-\d-\d+(?:-\d+)+$/i.test(sid)))
    throw new CertkitError(
      'CA_UNREADABLE',
      `Could not parse the Windows ACL for ${path}. Inspect and restrict it manually with: icacls "${path}"`,
    );
  return lines.map((sid) => sid.toLowerCase());
}

function verifyAcl(path: string, runCommand: CommandRunner): void {
  const current = identity(runCommand);
  let output: string;
  try {
    output = runCommand('powershell.exe', [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      `$ErrorActionPreference = 'Stop'; (Get-Acl -LiteralPath '${path.replaceAll("'", "''")}').Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }`,
    ]).trim();
  } catch (error) {
    throw new CertkitError(
      'CA_UNREADABLE',
      `Could not re-read the Windows ACL for ${path}. Inspect and restrict it manually with: icacls "${path}"`,
      { cause: error },
    );
  }
  const sids = aclSids(path, output);
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
        const defaultGrants = DEFAULT_GRANT_SIDS.filter(
          (defaultSid) => defaultSid.toLowerCase() !== sid.toLowerCase(),
        );
        if (defaultGrants.length)
          runCommand('icacls', [
            path,
            '/remove:g',
            ...defaultGrants.map((defaultSid) => `*${defaultSid}`),
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
