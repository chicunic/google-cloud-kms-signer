import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  test: {
    testTimeout: 30000,
    exclude: ['dist/**', 'node_modules/**'],
  },
});
