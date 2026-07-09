import * as path from 'node:path';
import * as fs from 'node:fs';
import * as os from 'node:os';
import { Command } from 'commander';
import chalk from 'chalk';
import { runScan } from '../../pipeline.js';
import { loadConfig } from '../../config/loader.js';
import { createSpinner } from '../ui.js';
import { createEvidenceRecord } from '../../governance/evidence-collector.js';
import { buildAttestationPack } from '../../governance/attestation.js';
import { signBomHash, loadPrivateKey } from '../../inventory/sign.js';
import { G0_VERSION } from '../../utils/version.js';

export const attestCommand = new Command('attest')
  .description('Generate a signed, standards-mapped attestation pack from a scan')
  .argument('[path]', 'Path to the agent project', '.')
  .option('--sign-key <pem>', 'Sign the attestation with an ed25519 private key (PEM)')
  .option('--no-evidence', 'Do not persist a durable evidence record under ~/.g0/evidence')
  .option('-o, --output <file>', 'Write the attestation JSON to a file')
  .option('--config <file>', 'Path to config file (default: .g0.yaml)')
  .action(async (targetPath: string, options: {
    signKey?: string;
    evidence?: boolean;
    output?: string;
    config?: string;
  }) => {
    const resolvedPath = path.resolve(targetPath);
    if (!fs.existsSync(resolvedPath)) {
      console.error(`Error: Path does not exist: ${resolvedPath}`);
      process.exit(1);
    }

    let config;
    try {
      config = loadConfig(resolvedPath, options.config) ?? undefined;
    } catch (err) {
      console.error(`Config error: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    }

    const spinner = createSpinner('Generating attestation...');
    spinner.start();

    try {
      const result = await runScan({ targetPath: resolvedPath, config });

      // Persist a durable evidence record (linked from the pack) unless opted out.
      let evidence: { id: string; sha256: string } | undefined;
      if (options.evidence !== false) {
        const standards = [...new Set(
          result.findings.flatMap(f => Object.keys(f.standards ?? {})),
        )];
        const record = createEvidenceRecord(
          'scan',
          `g0 scan ${path.basename(resolvedPath)}`,
          `Score ${result.score.overall} (${result.score.grade}), ${result.findings.length} findings`,
          {
            score: result.score.overall,
            grade: result.score.grade,
            findings: result.findings.length,
          },
          standards,
        );
        evidence = { id: record.id, sha256: record.sha256 };
      }

      const pack = buildAttestationPack({
        project: path.basename(resolvedPath),
        score: result.score,
        findings: result.findings,
        toolVersion: G0_VERSION,
        hostname: os.hostname(),
        generatedAt: new Date().toISOString(),
        evidence,
      });

      if (options.signKey) {
        try {
          const priv = loadPrivateKey(path.resolve(options.signKey));
          pack.signature = signBomHash(pack.contentHash, priv, pack.generatedAt);
        } catch (err) {
          spinner.stop();
          console.error(`Signing failed: ${err instanceof Error ? err.message : err}`);
          process.exit(1);
        }
      }

      spinner.stop();

      const json = JSON.stringify(pack, null, 2);
      if (options.output) {
        fs.writeFileSync(options.output, json + '\n', 'utf-8');
        console.log(chalk.bold('\n  Attestation Pack'));
        console.log(chalk.dim('  ' + '─'.repeat(60)));
        console.log(`  Project:   ${pack.project}`);
        console.log(`  Score:     ${pack.scan.score}/100 (${pack.scan.grade})`);
        console.log(`  Standards: ${pack.standards.length} mapped`);
        for (const s of pack.standards) {
          console.log(`    ${s.name}: ${s.controls.length} control(s), ${s.findingCount} finding(s)`);
        }
        console.log(`  Content hash: ${pack.contentHash.slice(0, 16)}...${pack.signature ? '  (signed)' : ''}`);
        if (evidence) console.log(`  Evidence: ${evidence.id}`);
        console.log(`\n  Written to: ${options.output}\n`);
      } else {
        console.log(json);
      }
    } catch (error) {
      spinner.stop();
      console.error('Attestation failed:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });
