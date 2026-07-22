import { defineConfig } from 'vitest/config';

// Perf gates with absolute wall-clock budgets (e.g. the g0-hook p95<100ms
// latency gate). Run via `npm run test:perf` — kept OUT of the parallel
// suite because contended workers inflate spawn latency into false reds.
export default defineConfig({
  test: {
    globals: true,
    include: ['tests/perf/**/*.test.ts'],
    fileParallelism: false,
    testTimeout: 300000,
    hookTimeout: 30000,
  },
});
