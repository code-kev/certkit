import { describe, expect, it, vi } from 'vitest';
import {
  type CommandRunner,
  createWindowsFsGuard,
} from '../../src/platforms/fsguard.js';

const mocks = vi.hoisted(() => ({ execFileSync: vi.fn() }));
vi.mock('node:child_process', () => ({ execFileSync: mocks.execFileSync }));

const path = 'C:\\Users\\test\\AppData\\Local\\certkit';
const whoamiCsv = '"DOMAIN\\test","S-1-5-21-1-2-3-1001"';
const selfSid = 'S-1-5-21-1-2-3-1001';
const selfSddl = `O:${selfSid}G:${selfSid}D:AI(A;OICI;FA;;;${selfSid})`;
const success = 'Successfully processed 1 files; Failed processing 0 files';

function runner(sddl: string, whoami: string = whoamiCsv): CommandRunner {
  return (command, args) => {
    if (command === 'whoami') return whoami;
    if (args.includes('/inheritance:r')) return success;
    return sddl;
  };
}

describe('Windows filesystem guard', () => {
  it('wraps execFileSync with hidden windows and wraps its failures', () => {
    mocks.execFileSync.mockImplementation(
      (command: string, args?: readonly string[]) =>
        command === 'whoami'
          ? whoamiCsv
          : args?.includes('/inheritance:r')
            ? success
            : selfSddl,
    );
    const guard = createWindowsFsGuard();

    expect(() => guard.protectDirectory(path)).not.toThrow();
    expect(mocks.execFileSync).toHaveBeenCalledWith(
      'whoami',
      ['/user', '/fo', 'csv', '/nh'],
      { encoding: 'utf8', windowsHide: true },
    );

    mocks.execFileSync.mockImplementation(() => {
      throw new Error('spawn failed');
    });
    expect(() => guard.protectDirectory(path)).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        cause: expect.objectContaining({
          message: expect.stringContaining(
            'Windows filesystem protection command failed: whoami',
          ),
        }),
      }),
    );
  });

  it('fails closed when the current Windows user cannot be determined', () => {
    const guard = createWindowsFsGuard(() => {
      throw new Error('whoami missing');
    });
    expect(() => guard.protectDirectory(path)).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(
          'Could not determine the current Windows user',
        ),
      }),
    );
  });

  it.each([
    ['an empty response', ''],
    ['a missing SID', '"DOMAIN\\test"'],
    ['a malformed SID', '"DOMAIN\\test","bogus"'],
  ])('rejects whoami output with %s', (_name, output) => {
    const guard = createWindowsFsGuard(runner(selfSddl, output));
    expect(() => guard.protectDirectory(path)).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('valid current-user SID'),
      }),
    );
  });

  it('reads the ACL as SDDL via PowerShell with a quoted literal path', () => {
    const seen: string[][] = [];
    const guard = createWindowsFsGuard((command, args) => {
      seen.push([command, ...args]);
      if (command === 'whoami') return whoamiCsv;
      return selfSddl;
    });
    const quoted = "C:\\Users\\o'brien\\certkit";

    expect(() => guard.assertProtectedDirectory(quoted)).not.toThrow();
    const ps = seen.find(([command]) => command === 'powershell.exe');
    expect(ps?.[1]).toBe('-NoLogo');
    expect(ps?.[5]).toBe(
      `(Get-Acl -LiteralPath 'C:\\Users\\o''brien\\certkit').Sddl`,
    );
  });

  it('accepts a self-only ACL regardless of account-name encoding', () => {
    // whoami account names with non-ASCII characters arrive mangled when the
    // console codepage is not UTF-8; the SID comparison must not depend on it.
    const guard = createWindowsFsGuard(
      runner(selfSddl, '"DOMAIN\\Jos\uFFFD","S-1-5-21-1-2-3-1001"'),
    );
    expect(() => guard.assertProtectedDirectory(path)).not.toThrow();
  });

  it('rejects SDDL without a DACL or with a malformed ACE', () => {
    for (const bad of [
      `O:${selfSid}G:${selfSid}`,
      `D:AI(A;OICI;FA;;bogus-sid;)`,
      `D:AI(A;OICI;FA)`,
    ]) {
      const guard = createWindowsFsGuard(runner(bad));
      expect(() => guard.assertProtectedDirectory(path)).toThrowError(
        expect.objectContaining({
          code: 'CA_UNREADABLE',
          message: expect.stringContaining('Could not parse the Windows ACL'),
        }),
      );
    }
  });

  it('fails closed with a bare icacls command when the DACL has no entries', () => {
    const guard = createWindowsFsGuard(runner(`O:${selfSid}G:${selfSid}D:`));
    expect(() => guard.assertProtectedDirectory(path)).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(`with: icacls "${path}"`),
      }),
    );
  });

  it('resolves well-known SDDL aliases to SIDs in remove commands', () => {
    // Real Get-Acl output aliases Everyone to WD, SYSTEM to SY, etc.
    const sddl = `O:${selfSid}G:${selfSid}D:AI(A;OICI;FA;;;${selfSid})(A;CI;RX;;;WD)`;
    const guard = createWindowsFsGuard(runner(sddl));
    expect(() => guard.assertProtectedDirectory(path)).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(
          `icacls "${path}" /remove:g "*s-1-1-0"`,
        ),
      }),
    );
  });

  it('ignores the SACL section when the DACL is self-only', () => {
    const sddl = `O:${selfSid}G:${selfSid}D:AI(A;OICI;FA;;;${selfSid})S:AI(AU;SA;FA;;;WD)`;
    const guard = createWindowsFsGuard(runner(sddl));
    expect(() => guard.assertProtectedDirectory(path)).not.toThrow();
  });

  it('treats a deny ACE for another principal as unapproved', () => {
    const sddl = `O:${selfSid}G:${selfSid}D:(A;OICI;FA;;;${selfSid})(D;;RX;;;BU)`;
    const guard = createWindowsFsGuard(runner(sddl));
    expect(() => guard.assertProtectedDirectory(path)).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('*s-1-5-32-545'),
      }),
    );
  });

  it('fails closed when the ACL cannot be re-read', () => {
    const guard = createWindowsFsGuard((command) => {
      if (command === 'whoami') return whoamiCsv;
      throw new Error('powershell denied');
    });
    expect(() => guard.assertProtectedDirectory(path)).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(
          `Could not re-read the Windows ACL for ${path}`,
        ),
      }),
    );
  });
});
