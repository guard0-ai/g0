import * as path from 'node:path';
import * as fs from 'node:fs';
import { Command } from 'commander';
import { runScan } from '../../pipeline.js';
import { reportTerminal } from '../../reporters/terminal.js';
import { reportJson } from '../../reporters/json.js';
import { reportHtml } from '../../reporters/html.js';
import { reportSarif } from '../../reporters/sarif.js';
import { reportComplianceHtml, SUPPORTED_STANDARDS } from '../../reporters/compliance-html.js';
import { loadConfig } from '../../config/loader.js';
import { createSpinner } from '../ui.js';
import { isRemoteUrl, parseTarget, cloneRepo } from '../../remote/clone.js';
import type { Severity } from '../../types/common.js';

export const scanCommand = new Command('scan')
  .description('Assess an AI agent project for security issues')
  .argument('[path]', 'Path to the agent project or remote URL', '.')
  .option('--json', 'Output as JSON')
  .option('--html [file]', 'Output as HTML report')
  .option('--sarif [file]', 'Output as SARIF 2.1.0')
  .option('-o, --output <file>', 'Write JSON output to file')
  .option('-q, --quiet', 'Suppress terminal output')
  .option('--severity <level>', 'Minimum severity to report (critical|high|medium|low)')
  .option('--config <file>', 'Path to config file (default: .g0.yaml)')
  .option('--rules <ids>', 'Only run specific rules (comma-separated)')
  .option('--exclude-rules <ids>', 'Skip specific rules (comma-separated)')
  .option('--frameworks <ids>', 'Only check specific frameworks (comma-separated)')
  .option('--min-confidence <level>', 'Minimum confidence to report (high|medium|low)')
  .option('--ai', 'Enable AI-powered analysis (requires ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY)')
  .option('--model <model>', 'AI model to use (e.g., claude-sonnet-4-5-20250929, gpt-5-mini, gemini-2.5-flash)')
  .option('--report <standard>', `Generate compliance report (${SUPPORTED_STANDARDS.join('|')})`)
  .option('--upload', 'Upload results to Guard0 platform')
  .option('--include-tests', 'Include test files in agent graph (normally excluded)')
  .option('--show-all', 'Show all findings including suppressed utility-code ones')
  .option('--ruleset <tier>', 'Rule pack tier: recommended (~200 high-signal), extended (~800), or all (default)')
  .option('--preset <name>', 'Scan policy preset: strict, balanced, or permissive')
  .option('--ai-consensus <n>', 'Run AI FP detection N times and use majority vote', parseInt)
  .option('--openclaw-hardening [url]', 'Live hardening audit against OpenClaw instance (default: http://localhost:8080)')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(async (targetPath: string, options: {
    json?: boolean;
    html?: string | boolean;
    sarif?: string | boolean;
    output?: string;
    quiet?: boolean;
    severity?: string;
    config?: string;
    rules?: string;
    excludeRules?: string;
    frameworks?: string;
    minConfidence?: string;
    ai?: boolean;
    model?: string;
    report?: string;
    upload?: boolean;
    includeTests?: boolean;
    showAll?: boolean;
    ruleset?: string;
    openclawHardening?: string | boolean;
    banner?: boolean;
    preset?: string;
    aiConsensus?: number;
  }) => {
    let resolvedPath: string;
    let cleanup: (() => void) | undefined;

    // Handle remote URLs
    if (isRemoteUrl(targetPath)) {
      const target = parseTarget(targetPath);
      const spinner = options.quiet ? null : createSpinner(`Cloning ${target.owner}/${target.repo}...`);
      spinner?.start();
      try {
        const result = await cloneRepo(target);
        resolvedPath = result.tempDir;
        cleanup = result.cleanup;
        spinner?.stop();
        if (!options.quiet) {
          console.log(`  Cloned ${target.url} to temporary directory`);
        }
      } catch (err) {
        spinner?.stop();
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

    // Load config
    let config;
    try {
      config = loadConfig(resolvedPath, options.config) ?? undefined;
    } catch (err) {
      console.error(`Config error: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    }

    // CLI --preset overrides config file preset
    if (options.preset) {
      const validPresets = ['strict', 'balanced', 'permissive'];
      if (!validPresets.includes(options.preset)) {
        console.error(`Invalid preset: ${options.preset}. Available: ${validPresets.join(', ')}`);
        process.exit(1);
      }
      if (!config) config = {};
      config.preset = options.preset as any;
      // Re-load with preset applied
      const { resolvePreset } = await import('../../config/presets/index.js');
      const { deepMergeConfig } = await import('../../config/merge.js');
      const preset = resolvePreset(options.preset as any);
      config = deepMergeConfig(preset, config);
    }

    const spinner = options.quiet ? null : createSpinner('Scanning agent project...');
    spinner?.start();

    try {
      const result = await runScan({
        targetPath: resolvedPath,
        config,
        severity: options.severity as Severity | undefined,
        rules: options.rules?.split(',').map(s => s.trim()),
        excludeRules: options.excludeRules?.split(',').map(s => s.trim()),
        frameworks: options.frameworks?.split(',').map(s => s.trim()),
        aiAnalysis: options.ai,
        aiModel: options.model,
        includeTests: options.includeTests,
        showAll: options.showAll,
        ruleset: options.ruleset as 'recommended' | 'extended' | 'all' | undefined,
      });
      spinner?.stop();

      // Apply confidence filtering (default: hide low-confidence findings)
      const confidenceOrder: Record<string, number> = { high: 0, medium: 1, low: 2 };
      const minLevel = options.minConfidence
        ? (confidenceOrder[options.minConfidence] ?? 2)
        : 1; // default = medium (hides low-confidence)
      const allFindings = result.findings;
      result.findings = allFindings.filter(f => (confidenceOrder[f.confidence] ?? 2) <= minLevel);
      const hiddenLowConfidence = allFindings.length - result.findings.length;

      if (options.sarif) {
        const sarifPath = typeof options.sarif === 'string'
          ? options.sarif
          : undefined;
        const sarif = reportSarif(result, sarifPath);
        if (!sarifPath) {
          console.log(sarif);
        } else if (!options.quiet) {
          console.log(`SARIF report written to: ${sarifPath}`);
        }
      } else if (options.json) {
        const json = reportJson(result, options.output);
        if (!options.output) {
          console.log(json);
        }
      } else if (options.html) {
        const htmlPath = typeof options.html === 'string'
          ? options.html
          : path.join(resolvedPath, 'g0-report.html');
        reportHtml(result, htmlPath);
        if (!options.quiet) {
          console.log(`HTML report written to: ${htmlPath}`);
        }
      } else {
        // Show upload nudge when not uploading and not already authenticated
        const showNudge = options.upload === undefined;
        let nudge = false;
        if (showNudge) {
          try {
            const { isAuthenticated } = await import('../../platform/auth.js');
            nudge = !isAuthenticated();
          } catch { nudge = true; }
        }
        reportTerminal(result, { showBanner: options.banner !== false, showUploadNudge: nudge, hiddenLowConfidence });
      }

      // Also write JSON if --output specified alongside terminal
      if (options.output && !options.json) {
        reportJson(result, options.output);
      }

      // Generate compliance report
      if (options.report) {
        const reportPath = path.join(resolvedPath, `g0-${options.report}-report.html`);
        try {
          reportComplianceHtml(result, options.report, reportPath);
          if (!options.quiet) {
            console.log(`\n  Compliance report (${options.report}) written to: ${reportPath}`);
          }
        } catch (err) {
          console.error(`  Report generation failed: ${err instanceof Error ? err.message : err}`);
        }
      }

      // Upload to platform
      const { shouldUpload } = await import('../../platform/upload.js');
      const uploadDecision = await shouldUpload(options.upload);
      if (uploadDecision.upload) {
        try {
          if (uploadDecision.isAuto && !options.quiet) {
            console.log('\n  Auto-uploading (authenticated)...');
          }
          const { uploadResults, collectProjectMeta, collectMachineMeta, detectCIMeta } = await import('../../platform/upload.js');
          // Cap upload payload to avoid exceeding DB limits
          const MAX_UPLOAD_FINDINGS = 5000;
          // Build lightweight graph for architecture page (strip large fields like AST, content, parameters)
          const lightGraph = result.graph ? {
            agents: (result.graph.agents ?? []).map(a => ({
              id: a.id, name: a.name, framework: a.framework, file: a.file, line: a.line,
              tools: a.tools, modelId: a.modelId, delegationTargets: a.delegationTargets,
              delegationEnabled: a.delegationEnabled,
            })),
            tools: (result.graph.tools ?? []).map(t => ({
              id: t.id, name: t.name, framework: t.framework, file: t.file, line: t.line,
              hasSideEffects: t.hasSideEffects, capabilities: t.capabilities,
            })),
            models: (result.graph.models ?? []).map(m => ({
              id: m.id, name: m.name, provider: m.provider, framework: m.framework, file: m.file, line: m.line,
            })),
            vectorDBs: (result.graph.vectorDBs ?? []).map(v => ({
              id: v.id, name: v.name, framework: v.framework, file: v.file, line: v.line,
            })),
            interAgentLinks: result.graph.interAgentLinks ?? [],
            frameworkVersions: result.graph.frameworkVersions ?? [],
            edges: (result.graph.edges ?? []).map(e => ({
              id: e.id, source: e.source, target: e.target, type: e.type,
              tainted: e.tainted, validated: e.validated,
            })),
          } : undefined;
          const uploadResult = {
            ...result,
            findings: result.findings.slice(0, MAX_UPLOAD_FINDINGS),
            graph: lightGraph as any, // Lightweight graph subset for platform architecture page
          };
          const response = await uploadResults({
            type: 'scan',
            project: collectProjectMeta(resolvedPath),
            machine: collectMachineMeta(),
            ci: detectCIMeta(),
            result: uploadResult,
          });
          if (response && !options.quiet) {
            console.log(`\n  Uploaded to: ${response.url}`);
          }
        } catch (err) {
          if (!options.quiet) {
            console.error(`  Upload failed: ${err instanceof Error ? err.message : err}`);
          }
        }
      }
      // OpenClaw live hardening probe
      if (options.openclawHardening !== undefined) {
        const hardeningUrl = typeof options.openclawHardening === 'string'
          ? options.openclawHardening
          : 'http://localhost:8080';
        const hardeningSpinner = options.quiet ? null : createSpinner(`Probing OpenClaw instance at ${hardeningUrl}...`);
        hardeningSpinner?.start();
        try {
          const { probeOpenClawInstance } = await import('../../mcp/openclaw-hardening.js');
          const hardeningResult = await probeOpenClawInstance(hardeningUrl);
          hardeningSpinner?.stop();

          if (options.json) {
            console.log(JSON.stringify(hardeningResult, null, 2));
          } else {
            const { reportOpenClawHardeningTerminal } = await import('../../reporters/openclaw-hardening-terminal.js');
            reportOpenClawHardeningTerminal(hardeningResult);
          }

          if (hardeningResult.summary.overallStatus === 'critical') {
            process.exit(1);
          }
        } catch (err) {
          hardeningSpinner?.stop();
          if (!options.quiet) {
            console.error(`  OpenClaw hardening probe failed: ${err instanceof Error ? err.message : err}`);
          }
        }
      }
    } catch (error) {
      spinner?.stop();
      console.error('Scan failed:', error instanceof Error ? error.message : error);
      process.exit(1);
    } finally {
      cleanup?.();
    }
  });
