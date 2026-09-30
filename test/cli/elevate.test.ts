import { EventEmitter } from 'node:events';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('node:child_process', () => ({ spawn: vi.fn() }));

import { spawn } from 'node:child_process';
import { elevate } from '../../src/cli/elevate.js';

const spawnMock = vi.mocked(spawn);

afterEach(() => {
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
    ['linux', ['ok', 7]],
    ['darwin', []],
    ['darwin', ['ok', 7]],
    ['win32', []],
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

  describe('linux sudo branch', () => {
    function asLinux<T>(run: () => T): T {
      const originalPlatform = process.platform;
      Object.defineProperty(process, 'platform', { value: 'linux' });
      try {
        return run();
      } finally {
        Object.defineProperty(process, 'platform', {
          value: originalPlatform,
        });
      }
    }

    function fakeChild(exitCode: number): EventEmitter {
      const child = new EventEmitter();
      queueMicrotask(() => child.emit('exit', exitCode));
      return child;
    }

    it('elevates through plain sudo with inherited stdio', async () => {
      asLinux(() => {
        spawnMock.mockReturnValue(fakeChild(0) as never);
      });
      await asLinux(() =>
        expect(elevate(['update-ca-trust'])).resolves.toBeUndefined(),
      );
      expect(spawnMock).toHaveBeenCalledWith('sudo', ['update-ca-trust'], {
        stdio: 'inherit',
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
