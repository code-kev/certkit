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

function aclPrincipals(path: string, output: string): string[] {
  const normalizedPath = path.replaceAll('/', '\\').toLowerCase();
  const pathPrefix = /^[a-z]:\\$/i.test(normalizedPath)
    ? normalizedPath
    : normalizedPath.replace(/\\+$/, '');
  const principals: string[] = [];

  for (const rawLine of output.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const marker = line.indexOf(':(');
    if (marker < 0) {
      const linePath = line
        .replaceAll('/', '\\')
        .replace(/\\+$/, '')
        .toLowerCase();
      const isPathHeader = linePath === normalizedPath.replace(/\\+$/, '');
      const isSuccessFooter =
        /^Successfully processed \d+ files?; Failed processing 0 files?$/i.test(
          line,
        );
      if (!isPathHeader && !isSuccessFooter) {
        throw new CertkitError(
          'CA_UNREADABLE',
          `Could not parse a Windows ACL entry for ${path}: ${line}`,
        );
      }
      continue;
    }

    const rights = line.slice(marker + 1);
    if (!/^(?:\([^()\r\n]+\))+$/.test(rights)) {
      throw new CertkitError(
        'CA_UNREADABLE',
        `Could not parse a Windows ACL entry for ${path}: ${line}`,
      );
    }
    let principal = line.slice(0, marker).trim();
    const principalPrefix = principal.replaceAll('/', '\\').toLowerCase();
    if (principalPrefix.startsWith(pathPrefix)) {
      const suffix = principal.slice(pathPrefix.length);
      const driveRoot = /^[a-z]:\\$/i.test(pathPrefix);
      if (driveRoot || /^\s/.test(suffix)) principal = suffix.trim();
    }
    if (!principal) {
      throw new CertkitError(
        'CA_UNREADABLE',
        `Could not parse a Windows ACL principal for ${path}: ${line}`,
      );
    }
    principals.push(principal.toLowerCase());
  }
  return principals;
}

function verifyAcl(path: string, runCommand: CommandRunner): void {
  const current = identity(runCommand);
  let output: string;
  try {
    output = runCommand('icacls', [path]);
  } catch (error) {
    throw new CertkitError(
      'CA_UNREADABLE',
      `Could not re-read the Windows ACL for ${path}. Inspect and restrict it manually with: icacls "${path}"`,
      { cause: error },
    );
  }
  const principals = aclPrincipals(path, output);
  const self = new Set([
    current.account.toLowerCase(),
    `*${current.sid}`.toLowerCase(),
    current.sid.toLowerCase(),
  ]);
  const unapproved = principals.filter((principal) => !self.has(principal));
  if (!principals.length || unapproved.length > 0) {
    const command = unapproved.length
      ? unapproved
          .map((principal) => `icacls "${path}" /remove:g "${principal}"`)
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
