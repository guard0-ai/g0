import * as path from 'node:path';
import type { ScanResult, AIAnalysisResult } from './types/score.js';
import type { G0Config } from './types/config.js';
import type { Severity, FileInventory } from './types/common.js';
import type { AgentGraph } from './types/agent-graph.js';
import { walkDirectory } from './discovery/walker.js';
import { detectFrameworks, type DetectionSummary } from './discovery/detector.js';
import { buildAgentGraph } from './discovery/graph.js';
import { runAnalysis } from './analyzers/engine.js';
import { calculateScore } from './scoring/engine.js';
import { clearASTCache } from './analyzers/ast/index.js';
import { extractFrameworkVersions } from './analyzers/parsers/versions.js';
import { detectVectorDBs } from './analyzers/parsers/vectordb.js';

export interface ScanOptions {
  targetPath: string;
  config?: G0Config;
  severity?: Severity;
  rules?: string[];
  excludeRules?: string[];
  frameworks?: string[];
  aiAnalysis?: boolean;
  aiModel?: string;
}

export interface DiscoveryResult {
  files: FileInventory;
  detection: DetectionSummary;
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
  const detection = detectFrameworks(files);
  return { files, detection };
}

/**
 * Step 3: Build the agent graph from discovered files.
 */
export function runGraphBuild(
  rootPath: string,
  discovery: DiscoveryResult,
): AgentGraph {
  const graph = buildAgentGraph(rootPath, discovery.files, discovery.detection);

  // Enrich with framework versions and vector DB detection
  graph.frameworkVersions = extractFrameworkVersions(discovery.files);
  detectVectorDBs(graph, discovery.files);

  return graph;
}

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const startTime = Date.now();
  const rootPath = path.resolve(options.targetPath);

  // Merge config exclude_rules with CLI excludeRules
  const excludeRules = new Set<string>([
    ...(options.config?.exclude_rules ?? []),
    ...(options.excludeRules ?? []),
  ]);

  const excludePaths = options.config?.exclude_paths ?? [];

  // Steps 1-3: Discovery and graph building
  const discovery = await runDiscovery(rootPath, excludePaths);
  const graph = runGraphBuild(rootPath, discovery);

  // Step 4: Run analysis rules
  const findings = runAnalysis(graph, {
    excludeRules: excludeRules.size > 0 ? [...excludeRules] : undefined,
    onlyRules: options.rules,
    severity: options.severity,
    frameworks: options.frameworks,
    rulesDir: options.config?.rules_dir,
  });

  // Step 5: Calculate score
  const score = calculateScore(findings);

  // Step 6: AI analysis (optional)
  let aiAnalysis: AIAnalysisResult | undefined;
  if (options.aiAnalysis) {
    try {
      const { runAIAnalysis } = await import('./ai/analyzer.js');
      const { getAIProvider } = await import('./ai/provider.js');
      const provider = getAIProvider({ model: options.aiModel });
      if (provider) {
        aiAnalysis = await runAIAnalysis(findings, graph, provider);
      } else {
        console.error('  Warning: --ai flag set but no API key found (ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY)');
      }
    } catch {
      // AI analysis is purely additive; failures don't affect base results
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
  };
}
