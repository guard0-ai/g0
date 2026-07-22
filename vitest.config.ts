import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['tests/**/*.test.ts'],
    // Perf gates (absolute wall-clock budgets) run in their own uncontended
    // job — `npm run test:perf` — because parallel suite workers saturate
    // the CPU and inflate spawn latency into false failures.
    exclude: ['**/node_modules/**', 'tests/perf/**'],
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
