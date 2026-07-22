// Slim hot-path entry for Claude Code hooks (`g0-hook <event>`).
// No commander, no banner: the p95 < 100ms budget includes node startup, so
// the import graph here is runner + enforcement only. The `g0 hook`
// subcommand is the same runner behind the full CLI for manual use.
import { runHook } from './protect/hooks/runner.js';

const event = process.argv[2] === 'posttooluse' ? 'posttooluse' : 'pretooluse';
const chunks: Buffer[] = [];
process.stdin.on('data', (chunk) => chunks.push(chunk as Buffer));
process.stdin.on('end', () => {
  const result = runHook(event, Buffer.concat(chunks).toString('utf8'));
  if (result.stdout) process.stdout.write(result.stdout);
  process.exit(result.exitCode);
});
