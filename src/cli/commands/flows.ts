import * as path from 'node:path';
import * as fs from 'node:fs';
import { Command } from 'commander';
import { runDiscovery, runGraphBuild } from '../../pipeline.js';
import { analyzeFlows } from '../../flows/analyzer.js';
import { reportFlowsTerminal } from '../../reporters/flows-terminal.js';
import { reportFlowsJson } from '../../reporters/flows-json.js';
import { loadConfig } from '../../config/loader.js';
import { createSpinner } from '../ui.js';
import { isRemoteUrl, parseTarget, cloneRepo } from '../../remote/clone.js';

export const flowsCommand = new Command('flows')
  .description('Analyze agent execution flows and detect toxic data paths')
  .argument('[path]', 'Path to the agent project or remote URL', '.')
  .option('--json', 'Output as JSON')
  .option('-o, --output <file>', 'Write output to file')
  .option('--config <file>', 'Path to config file (default: .g0.yaml)')
  .option('--upload', 'Upload results to Guard0 platform')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(async (targetPath: string, options: {
    json?: boolean;
    output?: string;
    config?: string;
    upload?: boolean;
    banner?: boolean;
  }) => {
    let resolvedPath: string;
    let cleanup: (() => void) | undefined;

    if (isRemoteUrl(targetPath)) {
      const target = parseTarget(targetPath);
      const cloneSpinner = createSpinner(`Cloning ${target.owner}/${target.repo}...`);
      cloneSpinner.start();
      try {
        const result = await cloneRepo(target);
        resolvedPath = result.tempDir;
        cleanup = result.cleanup;
        cloneSpinner.stop();
      } catch (err) {
        cloneSpinner.stop();
        console.error(`Clone failed: ${err instanceof Error ? err.message : err}`);
        process.exit(1);
      }
    } else {
      resolvedPath = path.resolve(targetPath);
      if (!fs.existsSync(resolvedPath)) {
        console.error(`Error: Path does not exist: ${resolvedPath}`);
        process.exit(1);
      }
    }

    let config;
    try {
      config = loadConfig(resolvedPath, options.config) ?? undefined;
    } catch (err) {
      console.error(`Config error: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    }

    const excludePaths = config?.exclude_paths ?? [];

    const spinner = createSpinner('Analyzing flows...');
    spinner.start();

    try {
      const discovery = await runDiscovery(resolvedPath, excludePaths);
      const graph = runGraphBuild(resolvedPath, discovery);
      const result = analyzeFlows(graph);

      spinner.stop();

      if (options.json) {
        const json = reportFlowsJson(result, options.output);
        if (!options.output) {
          console.log(json);
        } else {
          console.log(`Flow analysis written to: ${options.output}`);
        }
      } else {
        reportFlowsTerminal(result);
        if (options.output) {
          reportFlowsJson(result, options.output);
          console.log(`JSON flow analysis also written to: ${options.output}`);
        }
      }
      // Upload to platform
      const { shouldUpload } = await import('../../platform/upload.js');
      const uploadDecision = await shouldUpload(options.upload);
      if (uploadDecision.upload) {
        try {
          if (uploadDecision.isAuto) {
            console.log('\n  Auto-uploading (authenticated)...');
          }
          const { uploadResults, collectProjectMeta, collectMachineMeta, detectCIMeta } = await import('../../platform/upload.js');
          const response = await uploadResults({
            type: 'flows',
            project: collectProjectMeta(resolvedPath),
            machine: collectMachineMeta(),
            ci: detectCIMeta(),
            result,
          });
          if (response) {
            console.log(`\n  Uploaded to: ${response.url}`);
          }
        } catch (err) {
          console.error(`  Upload failed: ${err instanceof Error ? err.message : err}`);
        }
      }
    } catch (error) {
      spinner.stop();
      console.error('Flow analysis failed:', error instanceof Error ? error.message : error);
      process.exit(1);
    } finally {
      cleanup?.();
    }
  });
