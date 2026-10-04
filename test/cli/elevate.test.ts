import { EventEmitter } from 'node:events';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('node:child_process', () => ({ spawn: vi.fn() }));

import { spawn } from 'node:child_process';
import { elevate } from '../../src/cli/elevate.js';

const spawnMock = vi.mocked(spawn);

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  spawnMock.mockReset();
});

describe('elevate', () => {
  it('rejects on Windows without invoking sudo', async () => {
    const originalPlatform = process.platform;
    Object.defineProperty(process, 'platform', { value: 'win32' });

    try {
      await expect(elevate(['security', 'x'])).rejects.toMatchObject({
        name: 'CertkitError',
        code: 'UNSUPPORTED_PLATFORM',
        message: 'Certkit has no elevated Windows trust-store command.',
      });
    } finally {
      Object.defineProperty(process, 'platform', { value: originalPlatform });
    }

    expect(spawnMock).not.toHaveBeenCalled();
  });

  it.each([
    ['linux', []],
    ['linux', ['']],
    ['linux', ['ok', 7]],
    ['darwin', []],
    ['darwin', ['']],
    ['darwin', ['ok', 7]],
    ['win32', []],
    ['win32', ['']],
    ['win32', ['ok', 7]],
  ])(
    'rejects invalid argv on %s (%s) without invoking sudo',
    async (platform, argv) => {
      const originalPlatform = process.platform;
      Object.defineProperty(process, 'platform', { value: platform });
      let result!: Promise<void>;
      try {
        result = elevate(argv as never);
      } finally {
        Object.defineProperty(process, 'platform', { value: originalPlatform });
      }

      await expect(result).rejects.toMatchObject({
        name: 'CertkitError',
        code: 'INVALID_OPTIONS',
        message: 'An elevated command is required.',
      });

      expect(spawnMock).not.toHaveBeenCalled();
    },
  );

  it.each([['macos', 'darwin']])(
    'rejects on %s (no elevated command exists)',
    async (_name, platform) => {
      const originalPlatform = process.platform;
      Object.defineProperty(process, 'platform', { value: platform });
      try {
        await expect(elevate(['security', 'x'])).rejects.toMatchObject({
          code: 'UNSUPPORTED_PLATFORM',
        });
      } finally {
        Object.defineProperty(process, 'platform', { value: originalPlatform });
      }
    },
  );

  describe('linux command execution', () => {
    function asLinux<T>(
      run: () => T,
      euid: number | null = 1000,
      uid = 1000,
    ): T {
      vi.stubGlobal('process', {
        ...process,
        platform: 'linux',
        geteuid: euid === null ? undefined : () => euid,
        getuid: () => uid,
      });
      try {
        return run();
      } finally {
        vi.unstubAllGlobals();
      }
    }

    function fakeChild(exitCode: number | null): EventEmitter {
      const child = new EventEmitter();
      queueMicrotask(() => child.emit('exit', exitCode));
      return child;
    }

    it('executes directly as effective root, preserving literal argv and stderr routing', async () => {
      const argv = [
        'install',
        '-m',
        '0644',
        "/tmp/space 'quote; $(echo unsafe).pem",
        '/tmp/anchor.crt',
      ];
      spawnMock.mockReturnValue(fakeChild(0) as never);
      await asLinux(
        () => expect(elevate(argv)).resolves.toBeUndefined(),
        0,
        1000,
      );
      expect(spawnMock).toHaveBeenCalledExactlyOnceWith(
        'install',
        argv.slice(1),
        {
          stdio: ['inherit', process.stderr.fd, 'inherit'],
        },
      );
    });

    it('still uses sudo when only the real UID is root', async () => {
      spawnMock.mockReturnValue(fakeChild(0) as never);
      await asLinux(
        () => expect(elevate(['update-ca-trust'])).resolves.toBeUndefined(),
        1000,
        0,
      );
      expect(spawnMock).toHaveBeenCalledWith('sudo', ['update-ca-trust'], {
        stdio: ['inherit', process.stderr.fd, 'inherit'],
      });
    });

    it('uses sudo when the effective UID API is unavailable', async () => {
      spawnMock.mockReturnValue(fakeChild(0) as never);
      await asLinux(
        () => expect(elevate(['update-ca-trust'])).resolves.toBeUndefined(),
        null,
      );
      expect(spawnMock).toHaveBeenCalledWith('sudo', ['update-ca-trust'], {
        stdio: ['inherit', process.stderr.fd, 'inherit'],
      });
    });

    it.each([1, null])(
      'rejects a failed root command (%s) with manual guidance that needs no sudo',
      async (code) => {
        spawnMock.mockReturnValue(fakeChild(code) as never);
        await asLinux(
          () =>
            expect(elevate(['update-ca-trust'])).rejects.toMatchObject({
              code: 'STORE_WRITE_FAILED',
              message:
                "The elevated command failed or was cancelled. Run it manually: 'update-ca-trust'",
            }),
          0,
        );
      },
    );

    it('rejects when the root command cannot be started, without sudo guidance', async () => {
      const child = new EventEmitter();
      queueMicrotask(() => child.emit('error', new Error('spawn ENOENT')));
      spawnMock.mockReturnValue(child as never);
      await asLinux(
        () =>
          expect(elevate(['update-ca-trust'])).rejects.toMatchObject({
            code: 'STORE_WRITE_FAILED',
            message:
              "The command could not be started. Run it manually: 'update-ca-trust'",
          }),
        0,
      );
    });

    it('elevates through plain sudo with inherited stdio', async () => {
      asLinux(() => {
        spawnMock.mockReturnValue(fakeChild(0) as never);
      });
      await asLinux(() =>
        expect(elevate(['update-ca-trust'])).resolves.toBeUndefined(),
      );
      expect(spawnMock).toHaveBeenCalledWith('sudo', ['update-ca-trust'], {
        stdio: ['inherit', process.stderr.fd, 'inherit'],
      });
    });

    it('rejects with the manual command when sudo exits nonzero', async () => {
      asLinux(() => {
        spawnMock.mockReturnValue(fakeChild(1) as never);
      });
      await asLinux(() =>
        expect(elevate(['update-ca-trust'])).rejects.toMatchObject({
          code: 'STORE_WRITE_FAILED',
          message: expect.stringContaining('sudo'),
        }),
      );
    });

    it('rejects when sudo itself is unavailable', async () => {
      asLinux(() => {
        const child = new EventEmitter();
        queueMicrotask(() => child.emit('error', new Error('spawn ENOENT')));
        spawnMock.mockReturnValue(child as never);
      });
      await asLinux(() =>
        expect(elevate(['update-ca-trust'])).rejects.toMatchObject({
          code: 'STORE_WRITE_FAILED',
          message: expect.stringContaining('sudo is unavailable'),
        }),
      );
    });
  });
});
