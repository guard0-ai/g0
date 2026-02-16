import * as fs from 'node:fs';
import * as path from 'node:path';
import chalk from 'chalk';
import { Command } from 'commander';
import { runTests } from '../../testing/engine.js';
import { buildStaticContext } from '../../testing/targeting.js';
import { reportTestTerminal } from '../../reporters/test-terminal.js';
import { reportTestJson } from '../../reporters/test-json.js';
import { getAIProvider } from '../../ai/provider.js';
import { createSpinner } from '../ui.js';
import { ALL_MUTATOR_IDS, type MutatorId } from '../../testing/mutators.js';
import type { AttackCategory, TestTarget, VerbosePhase } from '../../types/test.js';

export const testCommand = new Command('test')
  .description('Run adversarial security tests against a live AI agent')
  .option('--target <url>', 'HTTP endpoint to test')
  .option('--mcp <command>', 'MCP server command to test via stdio')
  .option('--mcp-args <args>', 'Comma-separated args for MCP command')
  .option('--auto [path]', 'Enable smart targeting via static scan (optional: project path)')
  .option('--attacks <categories>', 'Filter attack categories (comma-separated)')
  .option('--payloads <ids>', 'Run specific payload IDs (comma-separated)')
  .option('--ai', 'Enable LLM-as-judge for inconclusive results')
  .option('--json', 'Output as JSON')
  .option('-o, --output <file>', 'Write output to file')
  .option('--timeout <ms>', 'Per-payload timeout in milliseconds', '30000')
  .option('--header <header>', 'HTTP header (key:value), can be repeated', collectHeaders, {})
  .option('--message-field <field>', 'HTTP request body field name for message')
  .option('--response-field <field>', 'HTTP response field name to extract')
  .option('--openai', 'Use OpenAI chat completions format')
  .option('--model <name>', 'Model name for direct model or OpenAI mode')
  .option('--system-prompt <text>', 'System prompt for the model under test')
  .option('--system-prompt-file <path>', 'Load system prompt from a file')
  .option('--provider <name>', 'Test an LLM API directly (openai, anthropic, google)')
  .option('--mutate [mutators]', 'Apply payload mutators (comma-separated: b64,r13,l33t,uconf,zw,spaced or "all")')
  .option('--verbose', 'Show request/response details during execution')
  .option('--upload', 'Upload results to Guard0 platform')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(async (options: {
    target?: string;
    mcp?: string;
    mcpArgs?: string;
    auto?: string | boolean;
    attacks?: string;
    payloads?: string;
    mutate?: string | boolean;
    ai?: boolean;
    json?: boolean;
    output?: string;
    timeout?: string;
    header?: Record<string, string>;
    messageField?: string;
    responseField?: string;
    openai?: boolean;
    model?: string;
    systemPrompt?: string;
    systemPromptFile?: string;
    provider?: string;
    verbose?: boolean;
    upload?: boolean;
    banner?: boolean;
  }) => {
    // Auto-detect provider from env vars when no target specified
    if (!options.target && !options.mcp && !options.provider) {
      if (process.env.ANTHROPIC_API_KEY) {
        options.provider = 'anthropic';
      } else if (process.env.OPENAI_API_KEY) {
        options.provider = 'openai';
      } else if (process.env.GOOGLE_API_KEY) {
        options.provider = 'google';
      } else {
        console.error(chalk.red('Error: No test target specified.'));
        console.error(chalk.dim('\nProvide a target, or set an API key for direct model testing:\n'));
        console.error(chalk.dim('  g0 test --target http://localhost:8000        # Test HTTP endpoint'));
        console.error(chalk.dim('  g0 test --mcp python server.py                # Test MCP server'));
        console.error(chalk.dim('  g0 test --system-prompt "You are an agent..."  # Test model directly (needs API key)'));
        console.error(chalk.dim('  g0 test --auto ./my-agent                     # Smart mode: scan + test\n'));
        console.error(chalk.dim('Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY for direct model testing.'));
        process.exit(1);
      }
      if (!options.json) {
        console.log(chalk.dim(`  Auto-detected ${options.provider} API key — testing model directly`));
      }
    }

    // Validate --provider value
    const validProviders = ['openai', 'anthropic', 'google'] as const;
    if (options.provider && !validProviders.includes(options.provider as typeof validProviders[number])) {
      console.error(chalk.red(`Error: Invalid provider "${options.provider}". Must be one of: ${validProviders.join(', ')}`));
      process.exit(1);
    }

    // Load system prompt from file if specified
    let systemPrompt = options.systemPrompt;
    if (options.systemPromptFile) {
      const promptPath = path.resolve(options.systemPromptFile);
      try {
        systemPrompt = fs.readFileSync(promptPath, 'utf-8').trim();
      } catch (err) {
        console.error(chalk.red(`Error: Cannot read system prompt file: ${promptPath}`));
        console.error(chalk.dim(err instanceof Error ? err.message : String(err)));
        process.exit(1);
      }
    }

    // Build target
    const timeoutMs = parseInt(options.timeout ?? '30000', 10);
    let target: TestTarget;

    if (options.provider) {
      const providerName = options.provider as 'openai' | 'anthropic' | 'google';
      target = {
        type: 'direct-model',
        endpoint: `direct://${providerName}`,
        provider: providerName,
        model: options.model,
        systemPrompt,
        timeout: timeoutMs,
        name: options.model
          ? `${providerName}/${options.model}`
          : providerName,
      };
    } else if (options.mcp) {
      target = {
        type: 'mcp-stdio',
        endpoint: options.mcp,
        args: options.mcpArgs?.split(',').map(a => a.trim()),
        name: `mcp:${options.mcp}`,
        timeout: timeoutMs,
      };
    } else {
      target = {
        type: 'http',
        endpoint: options.target!,
        headers: options.header,
        messageField: options.messageField,
        responseField: options.responseField,
        name: options.target,
        openai: options.openai,
        model: options.model,
        systemPrompt,
      };
    }

    // Parse attack categories
    const categories = options.attacks
      ? options.attacks.split(',').map(c => c.trim()) as AttackCategory[]
      : undefined;

    // Parse payload IDs
    const payloadIds = options.payloads
      ? options.payloads.split(',').map(id => id.trim())
      : undefined;

    // Parse mutators
    let mutators: MutatorId[] | undefined;
    if (options.mutate !== undefined) {
      if (options.mutate === true || options.mutate === 'all') {
        mutators = [...ALL_MUTATOR_IDS];
      } else if (typeof options.mutate === 'string') {
        mutators = options.mutate.split(',').map(m => m.trim()) as MutatorId[];
      }
    }

    // AI provider
    const aiProvider = options.ai ? getAIProvider() : null;
    if (options.ai && !aiProvider) {
      console.error(chalk.yellow('Warning: --ai flag set but no API key found (ANTHROPIC_API_KEY or OPENAI_API_KEY)'));
    }

    // Smart targeting: run static scan first
    let staticContext = undefined;
    if (options.auto !== undefined) {
      const scanPath = typeof options.auto === 'string' ? options.auto : '.';
      const resolvedPath = path.resolve(scanPath);

      const spinner = createSpinner('Running static scan for smart targeting...');
      spinner.start();

      try {
        // Dynamic import to avoid circular dependency
        const { runDiscovery, runGraphBuild } = await import('../../pipeline.js');
        const { runAnalysis } = await import('../../analyzers/engine.js');
        const discovery = await runDiscovery(resolvedPath);
        const graph = runGraphBuild(resolvedPath, discovery);
        const findings = runAnalysis(graph);
        staticContext = buildStaticContext(graph, findings);
        spinner.stop();
        console.log(chalk.green(`  Static scan complete: ${findings.length} findings, ${graph.tools.length} tools detected`));
      } catch (err) {
        spinner.stop();
        console.log(chalk.yellow('  Static scan failed, falling back to full payload set'));
        if (!options.json) {
          console.error(chalk.dim(`  ${err instanceof Error ? err.message : err}`));
        }
      }
    }

    // Verbose logging callback
    const onVerboseLog = options.verbose
      ? (payloadId: string, phase: VerbosePhase, detail: string) => {
          const prefix = phase === 'send' ? chalk.cyan('\u2192')
            : phase === 'receive' ? chalk.yellow('\u2190')
            : chalk.magenta('\u26a1');
          console.log(`${prefix} ${chalk.bold(payloadId)}: ${detail}`);
        }
      : undefined;

    // Run tests
    const spinner = createSpinner('Running adversarial tests...');
    let completed = 0;

    if (!options.json && !options.verbose) {
      spinner.start();
    }

    try {
      const result = await runTests({
        target,
        categories,
        payloadIds,
        mutators,
        staticContext,
        aiProvider,
        timeout: timeoutMs,
        verbose: options.verbose,
        onVerboseLog,
        onProgress: (done, total) => {
          completed = done;
          if (!options.json && !options.verbose) {
            spinner.text = `Running adversarial tests... (${done}/${total})`;
          }
        },
      });

      if (!options.json && !options.verbose) {
        spinner.stop();
      }

      // Output
      if (options.json) {
        const json = reportTestJson(result, options.output);
        if (!options.output) {
          console.log(json);
        } else {
          console.log(`Test results written to: ${options.output}`);
        }
      } else {
        reportTestTerminal(result);
        if (options.output) {
          reportTestJson(result, options.output);
        }
      }

      // Upload to platform
      const { shouldUpload } = await import('../../platform/upload.js');
      const uploadDecision = await shouldUpload(options.upload);
      if (uploadDecision.upload) {
        try {
          if (uploadDecision.isAuto && !options.json) {
            console.log('\n  Auto-uploading (authenticated)...');
          }
          const { uploadResults, collectProjectMeta, collectMachineMeta, detectCIMeta } = await import('../../platform/upload.js');
          const projectPath = typeof options.auto === 'string' ? options.auto : '.';
          const response = await uploadResults({
            type: 'test',
            project: collectProjectMeta(path.resolve(projectPath)),
            machine: collectMachineMeta(),
            ci: detectCIMeta(),
            result,
          });
          if (response && !options.json) {
            console.log(`\n  Uploaded to: ${response.url}`);
          }
        } catch (err) {
          if (!options.json) {
            console.error(`  Upload failed: ${err instanceof Error ? err.message : err}`);
          }
        }
      }

      // Exit code: 1 if any critical vulnerability
      if (result.summary.overallStatus === 'fail') {
        process.exit(1);
      }
    } catch (error) {
      if (!options.json && !options.verbose) {
        spinner.stop();
      }
      console.error(chalk.red('Test execution failed:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

function collectHeaders(value: string, previous: Record<string, string>): Record<string, string> {
  const [key, ...rest] = value.split(':');
  if (key && rest.length > 0) {
    previous[key.trim()] = rest.join(':').trim();
  }
  return previous;
}
