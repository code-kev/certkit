import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('@expo/sudo-prompt', () => ({ exec: vi.fn() }));

import { exec } from '@expo/sudo-prompt';
import { elevate, shQuote } from '../../src/cli/elevate.js';
import { CertkitError } from '../../src/core/errors.js';

const execMock = vi.mocked(exec);

type ExecCallback = (error?: Error) => void;

function succeed(): void {
  execMock.mockImplementation(((
    _command: string,
    _options: unknown,
    callback: ExecCallback,
  ) => {
    callback();
  }) as never);
}

function fail(): void {
  execMock.mockImplementation(((
    _command: string,
    _options: unknown,
    callback: ExecCallback,
  ) => {
    callback(new Error('cancelled'));
  }) as never);
}

afterEach(() => {
  vi.restoreAllMocks();
  execMock.mockReset();
});

describe('elevate', () => {
  it('rejects on Windows without invoking sudo-prompt', async () => {
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

    expect(execMock).not.toHaveBeenCalled();
  });

  it.each([
    [[], 'empty'],
    [['ok', 7], 'non-string'],
  ])('rejects a %s command without invoking sudo-prompt', async (argv) => {
    await expect(elevate(argv as never)).rejects.toMatchObject({
      name: 'CertkitError',
      code: 'INVALID_OPTIONS',
      message: 'An elevated command is required.',
    });

    expect(execMock).not.toHaveBeenCalled();
  });

  it('resolves when the elevated command succeeds, quoting every argument', async () => {
    succeed();

    await expect(
      elevate(['security', "arg with 'quote'"]),
    ).resolves.toBeUndefined();

    expect(execMock).toHaveBeenCalledWith(
      `'security' ${shQuote("arg with 'quote'")}`,
      { name: 'Certkit' },
      expect.any(Function),
    );
  });

  it('rejects with the manual sudo command when the elevated command fails', async () => {
    fail();

    const rejection = elevate(['touch', '/tmp/x']);

    await expect(rejection).rejects.toBeInstanceOf(CertkitError);
    await expect(rejection).rejects.toMatchObject({
      code: 'STORE_WRITE_FAILED',
      message: `The elevated command failed or was cancelled. Run it manually with sudo: 'touch' ${shQuote('/tmp/x')}`,
    });
  });
});
