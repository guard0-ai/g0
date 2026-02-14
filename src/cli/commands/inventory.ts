import * as path from 'node:path';
import * as fs from 'node:fs';
import { Command } from 'commander';
import { runDiscovery, runGraphBuild } from '../../pipeline.js';
import { buildInventory } from '../../inventory/builder.js';
import { reportInventoryTerminal } from '../../reporters/inventory-terminal.js';
import { reportInventoryJson } from '../../reporters/inventory-json.js';
import { reportInventoryMarkdown } from '../../reporters/inventory-markdown.js';
import { reportInventoryCycloneDX } from '../../reporters/inventory-cyclonedx.js';
import { diffInventory } from '../../inventory/differ.js';
import { reportInventoryDiffTerminal } from '../../reporters/inventory-diff-terminal.js';
import { reportInventoryDiffMarkdown } from '../../reporters/inventory-diff-markdown.js';
import { loadConfig } from '../../config/loader.js';
import { createSpinner } from '../ui.js';
import { isRemoteUrl, parseTarget, cloneRepo } from '../../remote/clone.js';
import type { InventoryResult } from '../../types/inventory.js';

export const inventoryCommand = new Command('inventory')
  .description('Generate an AI Agent Bill of Materials (AI-BOM)')
  .argument('[path]', 'Path to the agent project or remote URL', '.')
  .option('--json', 'Output as JSON')
  .option('--markdown', 'Output as Markdown')
  .option('--cyclonedx [file]', 'Output as CycloneDX 1.6 SBOM')
  .option('--diff <baseline>', 'Diff against a baseline inventory JSON')
  .option('-o, --output <file>', 'Write output to file')
  .option('--config <file>', 'Path to config file (default: .g0.yaml)')
  .option('--upload', 'Upload results to Guard0 platform')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(async (targetPath: string, options: {
    json?: boolean;
    markdown?: boolean;
    cyclonedx?: string | boolean;
    diff?: string;
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

    const spinner = createSpinner('Building inventory...');
    spinner.start();

    try {
      const discovery = await runDiscovery(resolvedPath, excludePaths);
      const graph = runGraphBuild(resolvedPath, discovery);
      const inventory = buildInventory(graph);

      spinner.stop();

      // Diff mode
      if (options.diff) {
        const baselinePath = path.resolve(options.diff);
        if (!fs.existsSync(baselinePath)) {
          console.error(`Baseline not found: ${baselinePath}`);
          process.exit(1);
        }
        const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf-8')) as InventoryResult;
        const diff = diffInventory(inventory, baseline);

        if (options.markdown) {
          const md = reportInventoryDiffMarkdown(diff, options.output);
          if (!options.output) console.log(md);
          else console.log(`Diff written to: ${options.output}`);
        } else if (options.json) {
          const json = JSON.stringify(diff, null, 2);
          if (options.output) {
            fs.writeFileSync(options.output, json, 'utf-8');
            console.log(`Diff written to: ${options.output}`);
          } else {
            console.log(json);
          }
        } else {
          reportInventoryDiffTerminal(diff);
        }
        return;
      }

      // CycloneDX mode
      if (options.cyclonedx !== undefined) {
        const outFile = typeof options.cyclonedx === 'string' ? options.cyclonedx : options.output;
        const json = reportInventoryCycloneDX(inventory, outFile ?? undefined);
        if (!outFile) {
          console.log(json);
        } else {
          console.log(`CycloneDX SBOM written to: ${outFile}`);
        }
        return;
      }

      if (options.json) {
        const json = reportInventoryJson(inventory, options.output);
        if (!options.output) {
          console.log(json);
        } else {
          console.log(`Inventory written to: ${options.output}`);
        }
      } else if (options.markdown) {
        const md = reportInventoryMarkdown(inventory, options.output);
        if (!options.output) {
          console.log(md);
        } else {
          console.log(`Inventory written to: ${options.output}`);
        }
      } else {
        reportInventoryTerminal(inventory);
        if (options.output) {
          reportInventoryJson(inventory, options.output);
          console.log(`JSON inventory also written to: ${options.output}`);
        }
      }

      // Upload to platform
      if (options.upload) {
        try {
          const { uploadResults, collectProjectMeta, collectMachineMeta, detectCIMeta } = await import('../../platform/upload.js');
          const response = await uploadResults({
            type: 'inventory',
            project: collectProjectMeta(resolvedPath),
            machine: collectMachineMeta(),
            ci: detectCIMeta(),
            result: inventory,
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
      console.error('Inventory failed:', error instanceof Error ? error.message : error);
      process.exit(1);
    } finally {
      cleanup?.();
    }
  });
