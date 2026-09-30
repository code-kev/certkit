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
const selfAcl = selfSid;
const success = 'Successfully processed 1 files; Failed processing 0 files';

function runner(aclOutput: string, whoami: string = whoamiCsv): CommandRunner {
  return (command, args) => {
    if (command === 'whoami') return whoami;
    if (args.includes('/inheritance:r')) return success;
    return aclOutput;
  };
}

describe('Windows filesystem guard', () => {
  it.each(['C:\\Windows', ''])(
    'uses native Windows executables with SystemRoot %j despite a colliding PATH and wraps failures',
    (systemRoot) => {
      vi.stubEnv('PATH', 'C:\\msys64\\usr\\bin;C:\\Git\\usr\\bin');
      vi.stubEnv('SystemRoot', systemRoot);
      const commands: string[] = [];
      mocks.execFileSync.mockImplementation(
        (command: string, args?: readonly string[]) => {
          commands.push(command);
          if (command.endsWith('\\whoami.exe')) return whoamiCsv;
          return args?.includes('/inheritance:r') ? success : selfAcl;
        },
      );
      const guard = createWindowsFsGuard();

      expect(() => guard.protectDirectory(path)).not.toThrow();
      expect(mocks.execFileSync).toHaveBeenCalledWith(
        'C:\\Windows\\System32\\whoami.exe',
        ['/user', '/fo', 'csv', '/nh'],
        { encoding: 'utf8', windowsHide: true },
      );
      expect(commands).toEqual([
        'C:\\Windows\\System32\\whoami.exe',
        'C:\\Windows\\System32\\icacls.exe',
        'C:\\Windows\\System32\\icacls.exe',
        'C:\\Windows\\System32\\whoami.exe',
        'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      ]);
      vi.unstubAllEnvs();

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
    },
  );

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
    const guard = createWindowsFsGuard(runner(selfAcl, output));
    expect(() => guard.protectDirectory(path)).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('valid current-user SID'),
      }),
    );
  });

  it('reads trustee SIDs via PowerShell with a quoted literal path', () => {
    const seen: string[][] = [];
    const guard = createWindowsFsGuard((command, args) => {
      seen.push([command, ...args]);
      if (command === 'whoami') return whoamiCsv;
      return selfAcl;
    });
    const quoted = "C:\\Users\\o'brien\\certkit";

    expect(() => guard.assertProtectedDirectory(quoted)).not.toThrow();
    const ps = seen.find(([command]) => command === 'powershell.exe');
    expect(ps?.[1]).toBe('-NoLogo');
    expect(ps?.[5]).toBe(
      `$ErrorActionPreference = 'Stop'; (Get-Acl -LiteralPath 'C:\\Users\\o''brien\\certkit').Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }`,
    );
  });

  it('removes known Windows default grants before strict ACL read-back', () => {
    const calls: Array<{ command: string; args: readonly string[] }> = [];
    const guard = createWindowsFsGuard((command, args) => {
      calls.push({ command, args });
      if (command === 'whoami') return whoamiCsv;
      if (command === 'powershell.exe') return selfSid;
      return success;
    });

    expect(() => guard.protectDirectory(path)).not.toThrow();
    expect(calls[1]).toEqual({
      command: 'icacls',
      args: [path, '/inheritance:r', '/grant:r', `*${selfSid}:(OI)(CI)F`],
    });
    expect(calls[2]).toEqual({
      command: 'icacls',
      args: [path, '/remove:g', '*S-1-5-18', '*S-1-5-32-544'],
    });
    expect(calls[3]?.command).toBe('whoami');
    expect(calls[4]?.command).toBe('powershell.exe');
  });

  it('preserves the LocalSystem self grant when pruning known default grants', () => {
    const systemSid = 'S-1-5-18';
    const calls: Array<{ command: string; args: readonly string[] }> = [];
    const guard = createWindowsFsGuard((command, args) => {
      calls.push({ command, args });
      if (command === 'whoami') return `"NT AUTHORITY\\SYSTEM","${systemSid}"`;
      if (command === 'powershell.exe') return systemSid;
      return success;
    });

    expect(() => guard.protectDirectory(path)).not.toThrow();
    expect(calls[1]?.args).toContain(`*${systemSid}:(OI)(CI)F`);
    expect(calls[2]).toEqual({
      command: 'icacls',
      args: [path, '/remove:g', '*S-1-5-32-544'],
    });
  });

  it('still rejects an unknown grant after pruning known default grants', () => {
    const guard = createWindowsFsGuard((command, _args) => {
      if (command === 'whoami') return whoamiCsv;
      if (command === 'powershell.exe') return `${selfSid}\nS-1-1-0`;
      return success;
    });

    expect(() => guard.protectDirectory(path)).toThrowError(
      expect.objectContaining({ code: 'CA_UNREADABLE' }),
    );
  });

  it('still rejects a deny ACE for a known SID after pruning its grants', () => {
    const guard = createWindowsFsGuard((command, _args) => {
      if (command === 'whoami') return whoamiCsv;
      if (command === 'powershell.exe') return `${selfSid}\nS-1-5-18`;
      return success;
    });

    expect(() => guard.protectDirectory(path)).toThrowError(
      expect.objectContaining({ code: 'CA_UNREADABLE' }),
    );
  });

  it('accepts a self-only ACL regardless of account-name encoding', () => {
    // whoami account names with non-ASCII characters arrive mangled when the
    // console codepage is not UTF-8; the SID comparison must not depend on it.
    const guard = createWindowsFsGuard(
      runner(selfAcl, '"DOMAIN\\Jos\uFFFD","S-1-5-21-1-2-3-1001"'),
    );
    expect(() => guard.assertProtectedDirectory(path)).not.toThrow();
  });

  it('rejects empty or malformed SID output', () => {
    for (const bad of [
      'not-a-sid',
      `${selfSid}\nLA`,
      `${selfSid}\n\n${selfSid}`,
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
    const guard = createWindowsFsGuard(runner(''));
    expect(() => guard.assertProtectedDirectory(path)).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(`with: icacls "${path}"`),
      }),
    );
  });

  it('translates the built-in Administrator SDDL alias to its stable SID', () => {
    const administratorSid = 'S-1-5-21-1873546008-824478411-1810063331-500';
    const administratorWhoami = `"DOMAIN\\Administrator","${administratorSid}"`;
    // This is the failing live shape: Get-Acl .Sddl says LA, while native
    // IdentityReference.Translate(SecurityIdentifier).Value emits the full SID.
    const administratorSddl = `O:BA G:BA D:PAI(A;OICI;FA;;;LA)`;
    const seen: string[][] = [];
    const guard = createWindowsFsGuard((command, args) => {
      seen.push([command, ...args]);
      if (command === 'whoami') return administratorWhoami;
      if (command === 'powershell.exe')
        return args[5]?.includes('.Sddl')
          ? administratorSddl
          : administratorSid;
      if (args.includes('/inheritance:r')) return success;
      return administratorSddl;
    });

    expect(() => guard.assertProtectedDirectory(path)).not.toThrow();
    const ps = seen.find(([command]) => command === 'powershell.exe');
    expect(ps?.[5]).toContain('.Access | ForEach-Object');
    expect(ps?.[5]).toContain(
      'Translate([Security.Principal.SecurityIdentifier]).Value',
    );
    expect(ps?.[5]).not.toContain('.Sddl');
  });

  it('reads only DACL access rules, leaving audit entries out of SID output', () => {
    const guard = createWindowsFsGuard(runner(selfAcl));
    expect(() => guard.assertProtectedDirectory(path)).not.toThrow();
  });

  it('treats a deny ACE for another principal as unapproved', () => {
    // .Access yields a trustee SID for every DACL rule, including denies.
    const acl = `${selfSid}\nS-1-5-32-545`;
    const guard = createWindowsFsGuard(runner(acl));
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
