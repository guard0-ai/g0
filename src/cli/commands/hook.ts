import { Command } from 'commander';
import { runHook } from '../../protect/hooks/runner.js';

export const hookCommand = new Command('hook')
  .description('Internal: Claude Code hook entrypoint (reads hook JSON on stdin)')
  .argument('<event>', 'pretooluse | posttooluse')
  .action(async (event: string) => {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
    const result = runHook(
      event === 'posttooluse' ? 'posttooluse' : 'pretooluse',
      Buffer.concat(chunks).toString('utf8'),
    );
    if (result.stdout) process.stdout.write(result.stdout);
    process.exitCode = result.exitCode;
  });
