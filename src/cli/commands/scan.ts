import * as path from 'node:path';
import * as fs from 'node:fs';
import { Command } from 'commander';
import { runScan } from '../../pipeline.js';
import { reportTerminal } from '../../reporters/terminal.js';
import { reportJson } from '../../reporters/json.js';
import { reportHtml } from '../../reporters/html.js';
import { reportSarif } from '../../reporters/sarif.js';
import { reportComplianceHtml, SUPPORTED_STANDARDS } from '../../reporters/compliance-html.js';
import { reportComplianceMarkdown } from '../../reporters/compliance-markdown.js';
import { loadConfig } from '../../config/loader.js';
import { createSpinner } from '../ui.js';
import { isRemoteUrl, parseTarget, cloneRepo } from '../../remote/clone.js';
import type { Severity } from '../../types/common.js';
import type { PresetName } from '../../types/config.js';

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
  .option('--markdown [file]', 'Output compliance report as Markdown (use with --report)')
  .option('--upload', 'Upload results to Guard0 platform')
  .option('--include-tests', 'Include test files in agent graph (normally excluded)')
  .option('--show-all', 'Show all findings including suppressed utility-code ones')
  .option('--ruleset <tier>', 'Rule pack tier: recommended (~200 high-signal), extended (~800), or all (default)')
  .option('--preset <name>', 'Scan policy preset: strict, balanced, or permissive')
  .option('--rules-dir <path>', 'Directory of custom YAML rules')
  .option('--ai-consensus <n>', 'Run AI FP detection N times and use majority vote', parseInt)
  .option('--openclaw-hardening [url]', 'Live hardening audit against OpenClaw instance (default: http://localhost:8080)')
  .option('--openclaw-audit [path]', 'Deployment audit of OpenClaw host (default: /data/.openclaw/agents)')
  .option('--fix', 'Auto-fix failed deployment audit checks (use with --openclaw-audit)')
  .option('--ci', 'CI/CD gate mode — evaluate against .g0-policy.yaml and exit with policy-based exit code')
  .option('--host-audit', 'Run OS-level host hardening audit (firewall, encryption, SSH, etc.)')
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
    markdown?: string | boolean;
    upload?: boolean;
    includeTests?: boolean;
    showAll?: boolean;
    ruleset?: string;
    openclawHardening?: string | boolean;
    openclawAudit?: string | boolean;
    fix?: boolean;
    ci?: boolean;
    hostAudit?: boolean;
    banner?: boolean;
    preset?: string;
    aiConsensus?: number;
    rulesDir?: string;
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
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`Clone failed: ${msg}`);
        if (msg.includes('not found') || msg.includes('404')) {
          console.error(`Hint: Check that the repository exists and is accessible. Private repos require authentication via \`gh auth login\` or a git credential helper.`);
        } else if (msg.includes('timeout') || msg.includes('ETIMEDOUT') || msg.includes('ENOTFOUND')) {
          console.error(`Hint: Check your network connection and try again. If behind a proxy, configure git: \`git config --global http.proxy <url>\`.`);
        } else if (msg.includes('Authentication') || msg.includes('403') || msg.includes('401')) {
          console.error(`Hint: Authentication failed. For private repos, ensure you have access and run \`gh auth login\` or configure SSH keys.`);
        }
        process.exit(1);
      }
    } else {
      resolvedPath = path.resolve(targetPath);
      if (!fs.existsSync(resolvedPath)) {
        console.error(`Error: Path does not exist: ${resolvedPath}`);
        console.error(`Hint: Run \`g0 scan .\` to scan the current directory, or provide a valid path.`);
        if (/^(github\.com|gitlab\.com)\//.test(targetPath)) {
          console.error(`Hint: To scan a remote repository, use the full URL: \`g0 scan https://${targetPath}\``);
        }
        process.exit(1);
      }
    }

    // Load config
    let config;
    try {
      config = loadConfig(resolvedPath, options.config) ?? undefined;
    } catch (err) {
      const configMsg = err instanceof Error ? err.message : String(err);
      console.error(`Config error: ${configMsg}`);
      if (configMsg.includes('YAML') || configMsg.includes('parse')) {
        console.error(`Hint: Check your .g0.yaml for syntax errors. Use a YAML validator to identify the issue.`);
      }
      process.exit(1);
    }

    // CLI --preset overrides config file preset
    if (options.preset) {
      const validPresets = ['strict', 'balanced', 'permissive', 'openclaw'];
      if (!validPresets.includes(options.preset)) {
        console.error(`Invalid preset: ${options.preset}. Available: ${validPresets.join(', ')}`);
        process.exit(1);
      }
      if (!config) config = {};
      config.preset = options.preset as PresetName;
      // Re-load with preset applied
      const { resolvePreset } = await import('../../config/presets/index.js');
      const { deepMergeConfig } = await import('../../config/merge.js');
      const preset = resolvePreset(options.preset as PresetName);
      config = deepMergeConfig(preset, config);
    }

    // CLI --rules-dir overrides config file
    if (options.rulesDir) {
      if (!config) config = {};
      config.rules_dir = options.rulesDir;
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

      // Apply risk acceptance from config
      let acceptedCount = 0;
      if (config?.risk_accepted?.length) {
        const { applyRiskAcceptance } = await import('../../config/risk-acceptance.js');
        const acceptance = applyRiskAcceptance(result.findings, config.risk_accepted);
        acceptedCount = acceptance.acceptedCount;
      }

      // Record evidence for governance
      try {
        const { createEvidenceRecord } = await import('../../governance/evidence-collector.js');
        const scanGrade = result.score.grade;
        const scanStandards = [...new Set(result.findings.flatMap(f => {
          const s = f.standards;
          return [
            ...(s.owaspAgentic ?? []),
            ...(s.nistAiRmf ?? []),
            ...(s.iso42001 ?? []),
          ];
        }))];
        createEvidenceRecord('scan', 'g0 scan', `Scan of ${resolvedPath}: grade ${scanGrade}, ${result.findings.length} findings`, {
          grade: scanGrade,
          totalFindings: result.findings.length,
          criticalCount: result.findings.filter(f => f.severity === 'critical').length,
          highCount: result.findings.filter(f => f.severity === 'high').length,
          domains: [...new Set(result.findings.map(f => f.domain))],
          acceptedCount,
        }, scanStandards);
      } catch (err) {
        // Evidence collection is non-critical but log for debugging
        if (process.env.G0_DEBUG) {
          console.error(`Evidence collection failed: ${err instanceof Error ? err.message : err}`);
        }
      }

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
        if (options.markdown != null) {
          const mdPath = typeof options.markdown === 'string'
            ? options.markdown
            : path.join(resolvedPath, `g0-${options.report}-report.md`);
          try {
            reportComplianceMarkdown(result, options.report, mdPath);
            if (!options.quiet) {
              console.log(`\n  Compliance report (${options.report}) written to: ${mdPath}`);
            }
          } catch (err) {
            console.error(`  Report generation failed: ${err instanceof Error ? err.message : err}`);
          }
        } else {
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
            graph: lightGraph as unknown as typeof result.graph, // Lightweight subset for upload
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
      // CI gate evaluation
      if (options.ci) {
        try {
          const { runCIGate, formatCIOutput, formatGitHubAnnotations } = await import('../../ci/gate.js');
          const ciResult = runCIGate({
            scanContext: {
              grade: result.score.grade,
              criticalCount: result.findings.filter(f => f.severity === 'critical').length,
              highCount: result.findings.filter(f => f.severity === 'high').length,
              standards: [...new Set(result.findings.flatMap(f => [
                ...(f.standards.owaspAgentic ?? []),
                ...(f.standards.nistAiRmf ?? []),
                ...(f.standards.iso42001 ?? []),
              ]))],
              domains: [...new Set(result.findings.map(f => f.domain))],
            },
            searchPath: resolvedPath,
          });

          // Print GitHub Actions annotations if in CI
          if (process.env.GITHUB_ACTIONS) {
            const annotations = formatGitHubAnnotations(ciResult);
            if (annotations) console.log(annotations);
          }

          if (!options.quiet) {
            console.log(formatCIOutput(ciResult));
          }

          if (ciResult.exitCode > 0) {
            process.exit(ciResult.exitCode);
          }
        } catch (err) {
          if (!options.quiet) {
            console.error(`  CI gate evaluation failed: ${err instanceof Error ? err.message : err}`);
          }
        }
      }

      // Host hardening audit
      if (options.hostAudit) {
        const hostSpinner = options.quiet ? null : createSpinner('Running host hardening audit...');
        hostSpinner?.start();
        try {
          const { auditHostHardening } = await import('../../endpoint/host-hardening.js');
          const hostResult = await auditHostHardening();
          hostSpinner?.stop();

          if (options.json) {
            console.log(JSON.stringify(hostResult, null, 2));
          } else {
            const chalk = (await import('chalk')).default;
            const passed = hostResult.checks.filter(c => c.status === 'pass').length;
            const failed = hostResult.checks.filter(c => c.status === 'fail').length;
            const skipped = hostResult.checks.filter(c => c.status === 'skip').length;
            console.log('');
            console.log(chalk.bold(`  Host Hardening Audit (${hostResult.platform})`));
            console.log(chalk.dim('  ' + '\u2500'.repeat(74)));
            console.log(`  ${chalk.green(`${passed} passed`)}  ${chalk.red(`${failed} failed`)}  ${chalk.dim(`${skipped} skipped`)}`);
            console.log('');
            for (const check of hostResult.checks) {
              const icon = check.status === 'pass' ? chalk.green('\u2713') :
                           check.status === 'fail' ? chalk.red('\u2717') : chalk.dim('\u2013');
              const sev = check.severity === 'critical' ? chalk.red(`[${check.severity}]`) :
                          check.severity === 'high' ? chalk.yellow(`[${check.severity}]`) :
                          chalk.dim(`[${check.severity}]`);
              console.log(`  ${icon} ${check.id} ${check.name} ${sev}`);
              if (check.status === 'fail' && check.detail) {
                console.log(`    ${chalk.dim(check.detail)}`);
              }
            }
          }

          if (hostResult.checks.some(c => c.status === 'fail' && c.severity === 'critical')) {
            process.exit(1);
          }
        } catch (err) {
          hostSpinner?.stop();
          if (!options.quiet) {
            console.error(`  Host audit failed: ${err instanceof Error ? err.message : err}`);
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
      // OpenClaw deployment audit (host-level checks)
      if (options.openclawAudit !== undefined) {
        const agentDataPath = typeof options.openclawAudit === 'string'
          ? options.openclawAudit
          : '/data/.openclaw/agents';
        const auditSpinner = options.quiet ? null : createSpinner(`Running OpenClaw deployment audit on ${agentDataPath}...`);
        auditSpinner?.start();
        try {
          const { auditOpenClawDeployment } = await import('../../mcp/openclaw-deployment.js');
          const auditResult = await auditOpenClawDeployment({ agentDataPath });
          auditSpinner?.stop();

          if (options.json) {
            console.log(JSON.stringify(auditResult, null, 2));
          } else {
            const { reportDeploymentAuditTerminal } = await import('../../reporters/openclaw-deployment-terminal.js');
            reportDeploymentAuditTerminal(auditResult, config?.risk_accepted);

            // Generate remediation configs for failed checks
            const failedIds = new Set(auditResult.checks.filter(c => c.status === 'fail').map(c => c.id));
            const chalk = (await import('chalk')).default;

            // Egress iptables rules (C1)
            if (auditResult.egressResult && auditResult.egressResult.violations.length > 0) {
              const { generateIptablesRules, formatRulesAsScript } = await import('../../endpoint/egress-rules.js');
              const ruleSet = await generateIptablesRules(
                auditResult.egressResult.connections
                  .filter(c => c.remoteHost)
                  .map(c => c.remoteHost!)
                  .filter((v, i, a) => a.indexOf(v) === i),
              );
              console.log('');
              console.log(chalk.bold('  Generated: Egress iptables Rules (C1)'));
              console.log(chalk.dim('  ' + '\u2500'.repeat(74)));
              console.log(chalk.dim('  Apply: sudo bash egress-rules.sh'));
              console.log('');
              const script = formatRulesAsScript(ruleSet);
              for (const line of script.split('\n').slice(0, 30)) {
                console.log(`  ${chalk.dim(line)}`);
              }
              if (ruleSet.unresolved.length > 0) {
                console.log(chalk.yellow(`  ${ruleSet.unresolved.length} entries could not be resolved to IPs`));
              }
            }

            // auditd rules (C5)
            if (failedIds.has('OC-H-032') || failedIds.has('OC-H-033') || failedIds.has('OC-H-031')) {
              const { generateAuditdRules, formatAuditdRulesFile } = await import('../../endpoint/auditd-rules.js');
              const auditdRules = generateAuditdRules({ agentDataPath });
              const ruleCount = auditdRules.sections.reduce((n, s) => n + s.rules.length, 0);
              console.log('');
              console.log(chalk.bold('  Generated: auditd Rules (C5)'));
              console.log(chalk.dim('  ' + '\u2500'.repeat(74)));
              console.log(chalk.dim(`  ${ruleCount} rules across ${auditdRules.sections.length} categories`));
              console.log(chalk.dim(`  Install: sudo cp <rules-file> ${auditdRules.rulesFilePath} && sudo augenrules --load`));
              console.log('');
              for (const section of auditdRules.sections) {
                console.log(`  ${chalk.cyan(section.title)} (${section.rules.length} rules)`);
                for (const rule of section.rules.slice(0, 3)) {
                  console.log(`    ${chalk.dim(rule)}`);
                }
                if (section.rules.length > 3) {
                  console.log(chalk.dim(`    ... and ${section.rules.length - 3} more`));
                }
              }
            }

            // Falco rules (C1/C4/C5/H1)
            if (failedIds.size > 0) {
              const { generateFalcoRules } = await import('../../endpoint/falco-rules.js');
              const falcoRules = generateFalcoRules({
                agentDataPath,
                egressAllowlist: auditResult.egressResult?.connections
                  .filter(c => c.remoteHost)
                  .map(c => c.remoteHost!)
                  .filter((v, i, a) => a.indexOf(v) === i),
              });
              console.log('');
              console.log(chalk.bold('  Generated: Falco Rules (C1/C4/C5/H1)'));
              console.log(chalk.dim('  ' + '\u2500'.repeat(74)));
              console.log(chalk.dim(`  ${falcoRules.ruleCount} rules, ${falcoRules.macros.length} macros, ${falcoRules.lists.length} lists`));
              console.log(chalk.dim('  Install: cp g0-openclaw-falco.yaml /etc/falco/rules.d/'));
              console.log(chalk.dim('  Falco uses eBPF for kernel-level monitoring — no g0 kernel dependency'));
              console.log('');
              // Show rule names from the YAML
              const ruleNames = falcoRules.yaml.match(/^- rule: (.+)$/gm);
              if (ruleNames) {
                for (const name of ruleNames) {
                  console.log(`  ${chalk.dim(name.replace('- rule: ', ''))}`);
                }
              }
            }
          }

          // Auto-fix failed checks
          if (options.fix) {
            const chalk = (await import('chalk')).default;
            const { fixDeploymentFindings } = await import('../../mcp/openclaw-deployment.js');
            const fixes = await fixDeploymentFindings(auditResult, {
              agentDataPath,
              dryRun: false,
            });

            if (fixes.length > 0) {
              console.log('');
              console.log(chalk.bold('  Auto-Fix Results'));
              console.log(chalk.dim('  ' + '\u2500'.repeat(74)));
              for (const fix of fixes) {
                const icon = fix.applied ? chalk.green('\u2713') : chalk.yellow('\u2192');
                console.log(`  ${icon} ${fix.checkId}: ${fix.description}`);
                if (fix.backupPath) {
                  console.log(`    ${chalk.dim(`Backup: ${fix.backupPath}`)}`);
                }
                if (fix.error) {
                  console.log(`    ${chalk.red(fix.error)}`);
                }
              }
              const applied = fixes.filter(f => f.applied).length;
              if (applied > 0) {
                console.log('');
                console.log(chalk.yellow('  Note: Docker daemon.json changes require `systemctl restart docker`'));
              }
            }
          }

          // AI-powered attack chain analysis
          if (options.ai) {
            try {
              const { getAIProvider } = await import('../../ai/provider.js');
              const aiProvider = getAIProvider({ model: options.model });
              if (aiProvider) {
                const aiSpinner = options.quiet ? null : createSpinner('Running AI attack chain analysis...');
                aiSpinner?.start();
                const { analyzeAuditWithAI } = await import('../../mcp/openclaw-deployment.js');
                const insights = await analyzeAuditWithAI(auditResult, aiProvider);
                aiSpinner?.stop();
                const { formatAIInsights } = await import('../../reporters/openclaw-deployment-terminal.js');
                formatAIInsights(insights);
              }
            } catch (err) {
              if (!options.quiet) {
                console.error(`  AI analysis failed: ${err instanceof Error ? err.message : err}`);
              }
            }
          }

          if (auditResult.summary.overallStatus === 'critical') {
            process.exit(1);
          }
        } catch (err) {
          auditSpinner?.stop();
          if (!options.quiet) {
            console.error(`  OpenClaw deployment audit failed: ${err instanceof Error ? err.message : err}`);
          }
        }
      }
    } catch (error) {
      spinner?.stop();
      const scanMsg = error instanceof Error ? error.message : String(error);
      console.error(`Scan failed: ${scanMsg}`);
      if (scanMsg.includes('ENOMEM') || scanMsg.includes('heap')) {
        console.error(`Hint: The project may be too large for available memory. Try excluding paths: \`g0 scan . --exclude-paths node_modules,dist\``);
      } else if (scanMsg.includes('EACCES') || scanMsg.includes('permission')) {
        console.error(`Hint: Permission denied reading files. Check directory permissions or run from an accessible location.`);
      }
      process.exit(1);
    } finally {
      cleanup?.();
    }
  });
