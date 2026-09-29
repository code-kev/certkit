import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // icacls in the Windows guard dominates the per-test budget.
    testTimeout: process.platform === 'win32' ? 30_000 : 5_000,
    coverage: {
      thresholds: { lines: 90, branches: 85 },
    },
  },
});
