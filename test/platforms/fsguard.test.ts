import { describe, expect, it, vi } from 'vitest';
import {
  type CommandRunner,
  createWindowsFsGuard,
} from '../../src/platforms/fsguard.js';

const mocks = vi.hoisted(() => ({ execFileSync: vi.fn() }));
vi.mock('node:child_process', () => ({ execFileSync: mocks.execFileSync }));

const path = 'C:\\Users\\test\\AppData\\Local\\certkit';
const whoamiCsv = '"DOMAIN\\test","S-1-5-21-1-2-3-1001"';
const selfAcl = [
  '                  DOMAIN\\test:(OI)(CI)(F)',
  'Successfully processed 1 files; Failed processing 0 files',
].join('\r\n');
const success = 'Successfully processed 1 files; Failed processing 0 files';

function runner(acl: string, whoami: string = whoamiCsv): CommandRunner {
  return (command, args) => {
    if (command === 'whoami') return whoami;
    if (args.includes('/inheritance:r')) return success;
    return acl;
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
            : selfAcl,
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
    const guard = createWindowsFsGuard(runner(selfAcl, output));
    expect(() => guard.protectDirectory(path)).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('valid current-user SID'),
      }),
    );
  });

  it('accepts unquoted whoami output and blank lines in icacls output', () => {
    const acl = [
      '',
      '                  DOMAIN\\test:(OI)(CI)(F)',
      '',
      success,
    ].join('\r\n');
    const guard = createWindowsFsGuard(
      runner(acl, 'DOMAIN\\test,S-1-5-21-1-2-3-1001'),
    );
    expect(() => guard.protectDirectory(path)).not.toThrow();
  });

  it('normalizes ACL path headers and accepts the SID principal form', () => {
    const acl = [
      'C:/Users/test/AppData/Local/certkit\\',
      '                  *S-1-5-21-1-2-3-1001:(OI)(CI)(F)',
      success,
    ].join('\r\n');
    const guard = createWindowsFsGuard(runner(acl));
    expect(() => guard.assertProtectedDirectory(path)).not.toThrow();
  });

  it('rejects an ACL entry with malformed rights', () => {
    const acl = [
      'Everyone:(F',
      '                  DOMAIN\\test:(OI)(CI)(F)',
      success,
    ].join('\r\n');
    const guard = createWindowsFsGuard(runner(acl));
    expect(() => guard.assertProtectedFile(`${path}\\ca.pem`)).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Could not parse a Windows ACL entry'),
      }),
    );
  });

  it('rejects an ACL entry whose principal strips to empty', () => {
    const guard = createWindowsFsGuard(runner(`C:\\:(F)\r\n${success}`));
    expect(() => guard.assertProtectedDirectory('C:\\')).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(
          'Could not parse a Windows ACL principal',
        ),
      }),
    );
  });

  it('fails closed with a bare icacls command when the ACL has no entries', () => {
    const guard = createWindowsFsGuard(runner(`${path}\r\n${success}`));
    expect(() => guard.assertProtectedDirectory(path)).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(`with: icacls "${path}"`),
      }),
    );
  });

  it('fails closed on a path-prefixed principal without a separator', () => {
    const acl = [`${path}Everyone:(F)`, selfAcl].join('\r\n');
    const guard = createWindowsFsGuard(runner(acl));
    expect(() => guard.assertProtectedDirectory(path)).toThrowError(
      expect.objectContaining({ code: 'CA_UNREADABLE' }),
    );
  });

  it('lists unapproved principals as manual remove commands', () => {
    const acl = [
      '                  DOMAIN\\test:(OI)(CI)(F)',
      '                  Everyone:(RX)',
      success,
    ].join('\r\n');
    const guard = createWindowsFsGuard(runner(acl));
    expect(() => guard.assertProtectedDirectory(path)).toThrowError(
      expect.objectContaining({
        code: 'CA_UNREADABLE',
        message: expect.stringContaining(
          `icacls "${path}" /remove:g "everyone"`,
        ),
      }),
    );
  });

  it('fails closed when the ACL cannot be re-read', () => {
    const guard = createWindowsFsGuard((command) => {
      if (command === 'whoami') return whoamiCsv;
      throw new Error('icacls denied');
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
