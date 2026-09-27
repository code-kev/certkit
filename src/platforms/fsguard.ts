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
  const pathPrefix = path
    .replaceAll('/', '\\')
    .replace(/\\+$/, '')
    .toLowerCase();
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .flatMap((line) => {
      const marker = line.indexOf(':(');
      if (marker < 0) return [];
      let principal = line.slice(0, marker).trim();
      const lowerLine = principal.toLowerCase();
      if (lowerLine.startsWith(pathPrefix)) {
        const suffix = principal.slice(pathPrefix.length);
        if (!suffix || !/^\s/.test(suffix)) return [];
        principal = suffix.trim();
      }
      return principal ? [principal.toLowerCase()] : [];
    });
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
  const systemDefaults = new Set([
    'nt authority\\system',
    'system',
    'builtin\\administrators',
    'administrators',
    '*s-1-5-18',
    's-1-5-18',
    '*s-1-5-32-544',
    's-1-5-32-544',
  ]);
  const unapproved = principals.filter(
    (principal) => !self.has(principal) && !systemDefaults.has(principal),
  );
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
