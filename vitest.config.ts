import { defineConfig } from 'vitest/config';
import { testEnv } from './test/env.js';

export default defineConfig({
  test: {
    env: testEnv,
    globalSetup: ['test/global-setup.ts'],
    fileParallelism: false,
    testTimeout: 20_000,
    hookTimeout: 30_000,
  },
});
