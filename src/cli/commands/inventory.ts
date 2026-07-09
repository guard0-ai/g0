import * as path from 'node:path';
import * as fs from 'node:fs';
import { Command } from 'commander';
import { runDiscovery, runGraphBuild } from '../../pipeline.js';
import { buildInventory } from '../../inventory/builder.js';
import { reportInventoryTerminal } from '../../reporters/inventory-terminal.js';
import { reportInventoryJson } from '../../reporters/inventory-json.js';
import { reportInventoryMarkdown } from '../../reporters/inventory-markdown.js';
import { toCycloneDX, type BomMeta } from '../../inventory/cyclonedx.js';
import { signBomHash, loadPrivateKey, generateKeyPair } from '../../inventory/sign.js';
import { randomUUID } from 'node:crypto';
import { diffInventory } from '../../inventory/differ.js';
import { reportInventoryDiffTerminal } from '../../reporters/inventory-diff-terminal.js';
import { reportInventoryDiffMarkdown } from '../../reporters/inventory-diff-markdown.js';
import { loadConfig } from '../../config/loader.js';
import { createSpinner } from '../ui.js';
import { isRemoteUrl, parseTarget, cloneRepo } from '../../remote/clone.js';
import { G0_VERSION } from '../../utils/version.js';
import type { InventoryResult } from '../../types/inventory.js';

export const inventoryCommand = new Command('inventory')
  .description('Generate an AI Agent Bill of Materials (AI-BOM)')
  .argument('[path]', 'Path to the agent project or remote URL', '.')
  .option('--json', 'Output as JSON')
  .option('--markdown', 'Output as Markdown')
  .option('--cyclonedx', 'Output a signed CycloneDX 1.6 AI-BOM')
  .option('--sign-key <pem>', 'Sign the CycloneDX AI-BOM with an ed25519 private key (PEM)')
  .option('--gen-key <prefix>', 'Generate an ed25519 keypair (<prefix>.key / <prefix>.pub) and exit')
  .option('--diff <baseline>', 'Diff against a baseline inventory JSON')
  .option('-o, --output <file>', 'Write output to file')
  .option('--config <file>', 'Path to config file (default: .g0.yaml)')
  // v2: --upload removed — use Guard0 Platform for platform integration
  .option('--no-banner', 'Suppress the g0 banner')
  .action(async (targetPath: string, options: {
    json?: boolean;
    markdown?: boolean;
    cyclonedx?: boolean;
    signKey?: string;
    genKey?: string;
    diff?: string;
    output?: string;
    config?: string;
    upload?: boolean;
    banner?: boolean;
  }) => {
    // Key generation is a standalone utility — no scan needed.
    if (options.genKey) {
      const { privateKeyPem, publicKeyPem } = generateKeyPair();
      fs.writeFileSync(`${options.genKey}.key`, privateKeyPem, { mode: 0o600 });
      fs.writeFileSync(`${options.genKey}.pub`, publicKeyPem, { mode: 0o644 });
      console.log(`Keypair written: ${options.genKey}.key (private, keep safe) / ${options.genKey}.pub (public)`);
      return;
    }
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
      const inventory = buildInventory(graph, discovery);

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

      // CycloneDX 1.6 AI-BOM mode (optionally signed)
      if (options.cyclonedx) {
        const meta: BomMeta = {
          projectName: path.basename(resolvedPath),
          toolVersion: G0_VERSION,
          timestamp: new Date().toISOString(),
          serialNumber: `urn:uuid:${randomUUID()}`,
        };
        const bom = toCycloneDX(inventory, meta);
        const bomHash = bom.properties.find(p => p.name === 'g0:bomHash')?.value ?? '';

        if (options.signKey) {
          try {
            const priv = loadPrivateKey(path.resolve(options.signKey));
            bom.signature = signBomHash(bomHash, priv, meta.timestamp);
          } catch (err) {
            console.error(`Signing failed: ${err instanceof Error ? err.message : err}`);
            process.exit(1);
          }
        }

        const json = JSON.stringify(bom, null, 2);
        if (options.output) {
          fs.writeFileSync(options.output, json + '\n', 'utf-8');
          console.log(`CycloneDX AI-BOM written to: ${options.output}`);
          console.log(`  bomHash: ${bomHash}${options.signKey ? '  (signed)' : ''}`);
        } else {
          console.log(json);
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

      // v2: Upload removed — use Guard0 Platform for cloud features
    } catch (error) {
      spinner.stop();
      console.error('Inventory failed:', error instanceof Error ? error.message : error);
      process.exit(1);
    } finally {
      cleanup?.();
    }
  });
