import { afterEach, describe, expect, it, vi } from 'vitest';

// Force color support on so both sides of the support checks are observable
// regardless of the test host's TTY.
vi.mock('picocolors', async (importOriginal) => {
  const actual = await importOriginal<typeof import('picocolors')>();
  return {
    ...actual,
    default: { ...actual.default, isColorSupported: true },
  };
});

import * as options from '../../src/cli/options.js';

afterEach(() => {
  options.setGlobalOptions({});
});

describe('CLI global options with color support', () => {
  it('enables colors unless the global or call flag opts out', () => {
    expect(options.colors().isColorSupported).toBe(true);
    expect(options.colors(false).isColorSupported).toBe(false);

    options.setGlobalOptions({ color: false });
    expect(options.colors().isColorSupported).toBe(false);

    options.setGlobalOptions({ color: true });
    expect(options.colors().isColorSupported).toBe(true);
  });
});
