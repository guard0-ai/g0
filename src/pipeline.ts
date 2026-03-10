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
import { loadIOCDatabase, checkAgainstIOCs, type IOCMatch } from './intelligence/ioc-database.js';
import { fetchCVEFeed, checkVersionVulnerable, type CVEEntry } from './intelligence/cve-feed.js';

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

  // Step 4.4: Intelligence enrichment — check IOCs and CVEs
  if (analyzersConfig?.intelligence !== false) {
    try {
      const intelligenceFindings = await runIntelligenceChecks(graph);
      findings.push(...intelligenceFindings);
    } catch {
      // Intelligence checks are purely additive; failures don't break the scan
    }
  }

  // Step 4.5: Apply severity overrides from config
  if (config?.severity_overrides) {
    for (const f of findings) {
      const override = config.severity_overrides[f.ruleId];
      if (override) {
        f.severity = override;
      }
    }
  }

  // Step 4.6: Suppress utility-code + unlikely findings (unless --show-all)
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
 * Run intelligence checks against the agent graph.
 * Checks tool URLs/endpoints against IOC database and framework versions against CVE feed.
 */
async function runIntelligenceChecks(graph: AgentGraph): Promise<Finding[]> {
  const findings: Finding[] = [];
  let findingIndex = 0;

  // ── IOC checks ────────────────────────────────────────────────────────
  try {
    const iocDb = loadIOCDatabase();

    // Check tool descriptions and names for IOC domains
    for (const tool of graph.tools) {
      // Check tool name against typosquat patterns
      const nameMatches = checkAgainstIOCs(tool.name, 'name', iocDb);
      for (const match of nameMatches) {
        findings.push(iocMatchToFinding(match, tool.file, tool.line, `Tool "${tool.name}"`, findingIndex++));
      }

      // Check tool description for malicious domains
      if (tool.description) {
        for (const entry of iocDb.maliciousDomains) {
          if (tool.description.includes(entry.domain)) {
            findings.push(iocMatchToFinding(
              { type: 'domain', indicator: entry.domain, matched: entry.domain, description: entry.description, severity: 'high' },
              tool.file, tool.line, `Tool "${tool.name}" description references`, findingIndex++,
            ));
          }
        }
      }
    }

    // Check API endpoints and external calls against IOC domains and IPs
    for (const endpoint of graph.apiEndpoints) {
      if (!endpoint.url) continue;
      const domainMatches = checkAgainstIOCs(endpoint.url, 'domain', iocDb);
      for (const match of domainMatches) {
        findings.push(iocMatchToFinding(match, endpoint.file, endpoint.line, 'API endpoint', findingIndex++));
      }
      // Extract IP from URL and check
      const ipMatch = endpoint.url.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
      if (ipMatch) {
        const ipMatches = checkAgainstIOCs(ipMatch[1], 'ip', iocDb);
        for (const match of ipMatches) {
          findings.push(iocMatchToFinding(match, endpoint.file, endpoint.line, 'API endpoint IP', findingIndex++));
        }
      }
    }

    // Check API call nodes (Phase 2 graph)
    for (const apiCall of graph.apiCalls) {
      if (!apiCall.url) continue;
      const domainMatches = checkAgainstIOCs(apiCall.url, 'domain', iocDb);
      for (const match of domainMatches) {
        findings.push(iocMatchToFinding(match, apiCall.file, apiCall.line, 'External API call', findingIndex++));
      }
    }

    // Check agent names against typosquat patterns
    for (const agent of graph.agents) {
      const nameMatches = checkAgainstIOCs(agent.name, 'name', iocDb);
      for (const match of nameMatches) {
        findings.push(iocMatchToFinding(match, agent.file, agent.line, `Agent "${agent.name}"`, findingIndex++));
      }
    }
  } catch {
    // IOC check failure is non-fatal
  }

  // ── CVE checks ────────────────────────────────────────────────────────
  try {
    const cves = await fetchCVEFeed();

    for (const fw of graph.frameworkVersions) {
      if (!fw.version) continue;
      const vulnerable = checkVersionVulnerable(fw.version, cves);
      for (const cve of vulnerable) {
        findings.push(cveToFinding(cve, fw, findingIndex++));
      }
    }
  } catch {
    // CVE check failure is non-fatal
  }

  return findings;
}

/**
 * Convert an IOC match into a Finding.
 */
function iocMatchToFinding(match: IOCMatch, file: string, line: number, context: string, index: number): Finding {
  const severityMap: Record<IOCMatch['severity'], Severity> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
  };

  return {
    id: `intel-ioc-${index}`,
    ruleId: 'INTEL-IOC-001',
    title: `IOC match: ${context} references known ${match.type} indicator`,
    description: `${context} matches known indicator of compromise: ${match.description}. Matched value: "${match.matched}" against indicator "${match.indicator}".`,
    severity: severityMap[match.severity],
    confidence: match.type === 'hash' || match.type === 'ip' ? 'high' : 'medium',
    domain: 'supply-chain',
    location: { file, line },
    remediation: match.type === 'domain'
      ? `Remove or replace the reference to ${match.indicator}. If this is intentional (e.g., security testing), add a g0-ignore comment or accept the risk in .g0.yaml.`
      : match.type === 'name'
        ? `Verify the tool/agent name is legitimate and not a typosquat. Check the source and publisher.`
        : `Investigate the matched indicator "${match.matched}" and remove if not intentional.`,
    standards: {
      owaspAgentic: ['ASI06'],
      mitreAtlas: ['AML.T0010'],
    },
    checkType: 'ioc_match',
  };
}

/**
 * Convert a CVE match into a Finding.
 */
function cveToFinding(cve: CVEEntry, fw: { name: string; version?: string; file: string }, index: number): Finding {
  const severityMap: Record<CVEEntry['severity'], Severity> = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
  };

  return {
    id: `intel-cve-${index}`,
    ruleId: 'INTEL-CVE-001',
    title: `${cve.id}: ${fw.name} ${fw.version} is vulnerable`,
    description: `${cve.description} (CVSS ${cve.cvss}). Affects ${fw.name} version ${fw.version}. Status: ${cve.status}.${cve.fixedIn ? ` Fixed in ${cve.fixedIn}.` : ''}`,
    severity: severityMap[cve.severity],
    confidence: cve.status === 'confirmed' ? 'high' : 'medium',
    domain: 'supply-chain',
    location: { file: fw.file, line: 1 },
    remediation: cve.fixedIn
      ? `Upgrade ${fw.name} to version ${cve.fixedIn} or later.`
      : `Review ${cve.references[0] ?? cve.id} for mitigation guidance.`,
    standards: {
      owaspAgentic: ['ASI06'],
      mitreAtlas: ['AML.T0010'],
    },
    checkType: 'cve_match',
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
