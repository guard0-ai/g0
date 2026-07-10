import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['tests/**/*.test.ts'],
    // Some suites do real host probing (openclaw deployment/hardening audits)
    // and legitimately take ~10s per test. vitest 3 enforces the 5s default
    // strictly, so raise the ceiling to accommodate the slow integration tests.
    testTimeout: 30000,
    hookTimeout: 30000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
    },
  },
});
