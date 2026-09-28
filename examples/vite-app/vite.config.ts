import { certkit } from 'certkit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [certkit()],
  server: { https: {} },
});
