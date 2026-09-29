import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // icacls in the Windows guard dominates the per-test budget.
    testTimeout: process.platform === 'win32' ? 30_000 : 5_000,
    coverage: {
      // dist/ is generated output; reflect-metadata.ts is a side-effect-only
      // import v8 cannot instrument (it always reports 0%).
      exclude: ['dist/**', 'src/reflect-metadata.ts'],
      thresholds: { lines: 90, branches: 85 },
    },
  },
});
