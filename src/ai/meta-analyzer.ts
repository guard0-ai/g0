import type { Finding } from '../types/finding.js';
import type { AgentGraph } from '../types/agent-graph.js';
import type { AnalyzabilityScore, AIFindingEnrichment } from '../types/score.js';
import type { AIProvider } from './provider.js';

export interface MetaAnalysisResult {
  adjustments: Map<string, { override: 'fp' | 'tp' | 'none'; reason: string }>;
  globalInsights: string[];
}

const META_PROMPT = `You are a senior security meta-analyst reviewing the complete set of findings from an AI agent security scan. Your role is to provide holistic judgment by looking at ALL findings together.

Authority hierarchy (highest to lowest):
1. Meta-analysis (you) — holistic, cross-finding judgment
2. LLM false-positive pass — per-finding code review
3. Cross-file correlation — structural analysis
4. Taint tracking — data flow analysis
5. AST matching — syntax-level detection
6. Regex matching — pattern-level detection

Your responsibilities:
1. Identify findings that CONTRADICT each other (e.g., "no auth" + "auth bypass" in same flow)
2. Identify FALSE POSITIVES that individual passes missed (e.g., finding in dead code, finding negated by another control)
3. REINSTATE findings wrongly marked as FP when the holistic view shows they matter
4. Flag CORRELATED findings that together form a worse-than-sum attack path

Respond ONLY with valid JSON:
{
  "adjustments": [
    { "findingId": "<id>", "override": "fp|tp|none", "reason": "<explanation>" }
  ],
  "insights": ["<global insight>"]
}

Be conservative. Only adjust when the holistic view clearly changes the assessment.`;

export async function runMetaAnalysis(
  findings: Finding[],
  graph: AgentGraph,
  analyzability: AnalyzabilityScore | undefined,
  enrichments: Map<string, AIFindingEnrichment>,
  provider: AIProvider,
): Promise<MetaAnalysisResult> {
  const result: MetaAnalysisResult = {
    adjustments: new Map(),
    globalInsights: [],
  };

  if (findings.length === 0) return result;

  // Build summary for meta-analysis
  const summaryParts: string[] = [];

  summaryParts.push(`Total findings: ${findings.length}`);
  if (analyzability) {
    summaryParts.push(`Analyzability: ${analyzability.score}% (${analyzability.opaqueFiles.length} opaque files)`);
  }

  // Group by domain
  const byDomain = new Map<string, number>();
  for (const f of findings) {
    byDomain.set(f.domain, (byDomain.get(f.domain) ?? 0) + 1);
  }
  summaryParts.push(`Domains: ${[...byDomain.entries()].map(([d, c]) => `${d}=${c}`).join(', ')}`);

  // Include findings with their FP status
  const findingSummaries = findings.slice(0, 50).map(f => {
    const enrichment = enrichments.get(f.id);
    return {
      id: f.id,
      ruleId: f.ruleId,
      title: f.title,
      severity: f.severity,
      domain: f.domain,
      file: f.location.file,
      line: f.location.line,
      markedFP: enrichment?.falsePositive ?? false,
      fpReason: enrichment?.falsePositiveReason,
      hasTaintFlow: !!f.taintFlow,
      hasRelatedLocations: !!f.relatedLocations?.length,
    };
  });

  const context = JSON.stringify({ summary: summaryParts.join('\n'), findings: findingSummaries });

  try {
    const response = await provider.analyze(META_PROMPT, context.slice(0, 12000));
    const cleaned = response.trim();
    const jsonStart = cleaned.indexOf('{');
    const jsonEnd = cleaned.lastIndexOf('}');
    if (jsonStart >= 0 && jsonEnd > jsonStart) {
      const parsed = JSON.parse(cleaned.substring(jsonStart, jsonEnd + 1)) as {
        adjustments?: Array<{ findingId: string; override: string; reason: string }>;
        insights?: string[];
      };

      for (const adj of parsed.adjustments ?? []) {
        if (adj.override === 'fp' || adj.override === 'tp' || adj.override === 'none') {
          result.adjustments.set(adj.findingId, {
            override: adj.override,
            reason: adj.reason,
          });
        }
      }

      result.globalInsights = parsed.insights ?? [];
    }
  } catch {
    // Meta-analysis is optional; failures don't affect base results
  }

  return result;
}
