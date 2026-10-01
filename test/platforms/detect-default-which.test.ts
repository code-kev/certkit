import { constants } from 'node:fs';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { detect } from '../../src/platforms/detect.js';

vi.mock('../../src/platforms/run.js', () => ({
  run: vi.fn(async () => {
    throw new Error('which is unavailable');
  }),
}));

describe('default which probe', () => {
  it('treats a failing which probe as an absent command', async () => {
    const result = await detect({
      platform: 'linux',
      osRelease: async () => '',
      fs: {
        access: async () => {
          throw new Error('ENOENT');
        },
        readFile: async () => {
          throw new Error('ENOENT');
        },
        stat: async () => {
          throw new Error('ENOENT');
        },
      },
    });

    expect(result.os).toBe('linux');
    expect(
      result.stores.find((store) => store.store === 'linux-system'),
    ).toMatchObject({ detected: false });
  });

  it('detects a Linux trust utility from PATH when which fails', async () => {
    const originalPath = process.env.PATH;
    process.env.PATH = ['/fake/bin', '/fake/sbin'].join(path.delimiter);
    try {
      const result = await detect({
        platform: 'linux',
        osRelease: async () => '',
        fs: {
          access: async (target, mode) => {
            if (
              ['/fake/bin', '/fake/sbin'].some(
                (directory) =>
                  target === path.join(directory, 'update-ca-trust'),
              ) &&
              mode === constants.X_OK
            )
              return;
            throw new Error('ENOENT');
          },
          readFile: async () => {
            throw new Error('ENOENT');
          },
          stat: async (target) => {
            if (
              ['/fake/bin', '/fake/sbin'].some(
                (directory) =>
                  target === path.join(directory, 'update-ca-trust'),
              )
            )
              return {
                isDirectory: () => false,
                isFile: () => true,
              } as never;
            throw new Error('ENOENT');
          },
        },
      });

      expect(
        result.stores.find((store) => store.store === 'linux-system'),
      ).toMatchObject({ detected: true, detail: 'update-ca-trust' });
    } finally {
      if (originalPath === undefined) delete process.env.PATH;
      else process.env.PATH = originalPath;
    }
  });

  it('does not mistake a PATH directory for an executable file', async () => {
    const originalPath = process.env.PATH;
    process.env.PATH = ['/fake/bin'].join(path.delimiter);
    try {
      const result = await detect({
        platform: 'linux',
        osRelease: async () => '',
        fs: {
          access: async (target, mode) => {
            if (
              target === path.join('/fake/bin', 'update-ca-trust') &&
              mode === constants.X_OK
            )
              return;
            throw new Error('ENOENT');
          },
          readFile: async () => {
            throw new Error('ENOENT');
          },
          stat: async (target) => {
            if (target === path.join('/fake/bin', 'update-ca-trust'))
              return {
                isDirectory: () => true,
                isFile: () => false,
              } as never;
            throw new Error('ENOENT');
          },
        },
      });

      expect(
        result.stores.find((store) => store.store === 'linux-system'),
      ).toMatchObject({ detected: false });
    } finally {
      if (originalPath === undefined) delete process.env.PATH;
      else process.env.PATH = originalPath;
    }
  });
});
