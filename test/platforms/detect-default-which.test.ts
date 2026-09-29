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
});
