import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    coverage: {
      thresholds: { lines: 90, branches: 85 },
    },
  },
});
