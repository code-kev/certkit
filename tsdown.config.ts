import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'integrations/vite': 'src/integrations/vite.ts',
    'cli/index': 'src/cli/index.ts',
    'reflect-metadata': 'src/reflect-metadata.ts',
  },
  dts: true,
  fixedExtension: false,
  publint: true,
  attw: true,
});
