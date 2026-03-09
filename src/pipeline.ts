import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ScanResult, AIAnalysisResult, AnalyzabilityScore } from './types/score.js';
import type { G0Config } from './types/config.js';
import type { Severity, FileInventory } from './types/common.js';
import type { AgentGraph } from './types/agent-graph.js';
import type { Finding } from './types/finding.js';
import { walkDirectory } from './discovery/walker.js';
import { detectFrameworks, type DetectionSummary } from './discovery/detector.js';
import { buildAgentGraph } from './discovery/graph.js';
import { runAnalysis } from './analyzers/engine.js';
import { calculateScore } from './scoring/engine.js';
import { clearASTCache } from './analyzers/ast/index.js';
import { ASTStore } from './analyzers/ast/store.js';
import { extractFrameworkVersions } from './analyzers/parsers/versions.js';
import { detectVectorDBs } from './analyzers/parsers/vectordb.js';
import { buildControlRegistry } from './analyzers/control-registry.js';
import { enrichAgentGraph } from './analyzers/enrichment.js';
import { buildGraphEdges } from './discovery/edges.js';
import { computeAnalyzability, generateAnalyzabilityFindings } from './analyzers/analyzability.js';
import { detectPipelineTaint, convertTaintToFindings } from './analyzers/pipeline-taint.js';
import { detectDangerousToolCombinations, convertToolComboToFindings } from './analyzers/cross-tool-correlation.js';
import { detectCrossFileExfil } from './analyzers/cross-file-exfil.js';

export interface ScanOptions {
  targetPath: string;
  config?: G0Config;
  severity?: Severity;
  rules?: string[];
  excludeRules?: string[];
  frameworks?: string[];
  aiAnalysis?: boolean;
  aiModel?: string;
  includeTests?: boolean;
  showAll?: boolean;
  ruleset?: 'recommended' | 'extended' | 'all';
  preset?: string;
  aiConsensus?: number;
}

export interface DiscoveryResult {
  files: FileInventory;
  detection: DetectionSummary;
  astStore?: ASTStore;
}

/**
 * Step 1+2: Discover files and detect frameworks.
 */
export async function runDiscovery(
  rootPath: string,
  excludePaths?: string[],
): Promise<DiscoveryResult> {
  clearASTCache();
  const files = await walkDirectory(rootPath, excludePaths ?? []);

  // Create ASTStore once and share with detection + graph building
  const astStore = new ASTStore();
  astStore.parseAll(files.all);

  const detection = detectFrameworks(files, astStore);
  return { files, detection, astStore };
}

/**
 * Step 3: Build the agent graph from discovered files.
 */
export function runGraphBuild(
  rootPath: string,
  discovery: DiscoveryResult,
  includeTests = false,
): AgentGraph {
  const graph = buildAgentGraph(rootPath, discovery.files, discovery.detection, includeTests, discovery.astStore);

  // Enrich with framework versions and vector DB detection
  graph.frameworkVersions = extractFrameworkVersions(discovery.files);
  detectVectorDBs(graph, discovery.files);

  // Post-parser enrichment: extract security-relevant metadata
  enrichAgentGraph(graph, discovery.files);

  // Build typed edges from discovered data
  buildGraphEdges(graph);

  return graph;
}

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const startTime = Date.now();
  const rootPath = path.resolve(options.targetPath);
  const config = options.config;
  const analyzersConfig = config?.analyzers;

  // Merge config exclude_rules with CLI excludeRules
  const excludeRules = new Set<string>([
    ...(config?.exclude_rules ?? []),
    ...(options.excludeRules ?? []),
  ]);

  const excludePaths = config?.exclude_paths ?? [];

  // Steps 1-3: Discovery and graph building
  const discovery = await runDiscovery(rootPath, excludePaths);
  const graph = runGraphBuild(rootPath, discovery, options.includeTests);

  // Step 2.5: Compute analyzability (if enabled)
  let analyzability: AnalyzabilityScore | undefined;
  if (analyzersConfig?.analyzability !== false) {
    analyzability = computeAnalyzability(discovery.files);
  }

  // Step 3.5: Build security control registry (two-pass analysis)
  const controlRegistry = buildControlRegistry(graph);

  // Step 4: Run analysis rules
  let findings = runAnalysis(graph, {
    excludeRules: excludeRules.size > 0 ? [...excludeRules] : undefined,
    onlyRules: options.rules,
    severity: options.severity,
    frameworks: options.frameworks,
    rulesDir: config?.rules_dir,
    controlRegistry,
    showAll: options.showAll,
    ruleset: options.ruleset,
    thresholds: config?.thresholds,
    severityOverrides: config?.severity_overrides,
  });

  // Step 4.1: Add analyzability findings
  if (analyzability) {
    findings.push(...generateAnalyzabilityFindings(analyzability));
  }

  // Step 4.2: Pipeline taint tracking (if enabled)
  if (analyzersConfig?.pipeline_taint !== false) {
    const taintFindings = runPipelineTaintAnalysis(discovery.files, rootPath);
    findings.push(...taintFindings);
  }

  // Step 4.3: Cross-tool correlation
  if (analyzersConfig?.cross_file !== false) {
    const toolComboRisks = detectDangerousToolCombinations(graph);
    findings.push(...convertToolComboToFindings(toolComboRisks));

    // Cross-file exfiltration detection
    const crossFileFindings = detectCrossFileExfil(graph);
    findings.push(...crossFileFindings);
  }

  // Step 4.4: Apply severity overrides from config
  if (config?.severity_overrides) {
    for (const f of findings) {
      const override = config.severity_overrides[f.ruleId];
      if (override) {
        f.severity = override;
      }
    }
  }

  // Step 4.5: Suppress utility-code + unlikely findings (unless --show-all)
  // Only suppress when the graph has detected agents/tools — otherwise the
  // reachability index is uninformative and everything defaults to utility-code
  let suppressedCount = 0;
  const hasEntryPoints = graph.agents.length > 0 || graph.tools.length > 0;
  if (!options.showAll && hasEntryPoints) {
    const before = findings.length;
    findings = findings.filter(f =>
      !(f.reachability === 'utility-code' && f.exploitability === 'unlikely'));
    suppressedCount = before - findings.length;
  }

  // Step 5: Calculate score
  let score = calculateScore(findings, graph.moduleGraph, config?.thresholds, config?.domain_weights);

  // Step 6: AI analysis (optional)
  let aiAnalysis: AIAnalysisResult | undefined;
  if (options.aiAnalysis) {
    try {
      const { runAIAnalysis } = await import('./ai/analyzer.js');
      const { getAIProvider } = await import('./ai/provider.js');
      const provider = getAIProvider({ model: options.aiModel });
      if (provider) {
        aiAnalysis = await runAIAnalysis(findings, graph, provider, analyzability);

        // Step 6.5: Meta-analysis pass (optional 4th AI pass)
        try {
          const { runMetaAnalysis } = await import('./ai/meta-analyzer.js');
          const metaResult = await runMetaAnalysis(findings, graph, analyzability, aiAnalysis.enrichments, provider);

          // Apply meta-analysis adjustments
          for (const [id, adj] of metaResult.adjustments) {
            const enrichment = aiAnalysis.enrichments.get(id);
            if (adj.override === 'fp' && enrichment) {
              enrichment.falsePositive = true;
              enrichment.falsePositiveReason = `Meta-analysis: ${adj.reason}`;
            } else if (adj.override === 'tp' && enrichment) {
              enrichment.falsePositive = false;
              enrichment.falsePositiveReason = undefined;
            }
          }
        } catch {
          // Meta-analysis is optional
        }
      } else {
        console.error('  Warning: --ai flag set but no API key found (ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY)');
      }
    } catch {
      // AI analysis is purely additive; failures don't affect base results
    }
  }

  // Filter out AI-flagged false positives
  if (aiAnalysis) {
    const originalCount = findings.length;
    findings = findings.filter(f => {
      const enrichment = aiAnalysis!.enrichments.get(f.id);
      return !enrichment?.falsePositive;
    });
    aiAnalysis.excludedCount = originalCount - findings.length;
    if (aiAnalysis.excludedCount > 0) {
      score = calculateScore(findings, graph.moduleGraph, config?.thresholds, config?.domain_weights);
    }
  }

  const duration = Date.now() - startTime;

  return {
    score,
    findings,
    graph,
    duration,
    timestamp: new Date().toISOString(),
    aiAnalysis,
    suppressedCount,
    analyzability,
    activePreset: config?.preset,
  };
}

/**
 * Run pipeline taint analysis on source files.
 */
function runPipelineTaintAnalysis(files: FileInventory, rootPath: string): Finding[] {
  const sourceFiles = [
    ...files.python,
    ...files.typescript,
    ...files.javascript,
    ...files.go,
  ];

  const allPipelines: ReturnType<typeof detectPipelineTaint> = [];

  for (const file of sourceFiles) {
    try {
      const content = fs.readFileSync(file.path, 'utf-8');
      const pipelines = detectPipelineTaint(content, file.relativePath);
      allPipelines.push(...pipelines);
    } catch {
      // Skip unreadable files
    }
  }

  return convertTaintToFindings(allPipelines);
}
