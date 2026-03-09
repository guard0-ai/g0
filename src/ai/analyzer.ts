import * as fs from 'node:fs';
import type { Finding } from '../types/finding.js';
import type { AgentGraph } from '../types/agent-graph.js';
import type { AIAnalysisResult, AIFindingEnrichment, AIComplexFinding, AnalyzabilityScore } from '../types/score.js';
import type { AIProvider } from './provider.js';
import { EXPLANATION_PROMPT, FALSE_POSITIVE_PROMPT, COMPLEX_PATTERN_PROMPT } from './prompts.js';

const BATCH_SIZE = 5;
const MAX_CONTEXT_CHARS = 8000;
const CODE_CONTEXT_LINES_BEFORE = 15;
const CODE_CONTEXT_LINES_AFTER = 15;

export async function runAIAnalysis(
  findings: Finding[],
  graph: AgentGraph,
  provider: AIProvider,
  analyzability?: AnalyzabilityScore,
): Promise<AIAnalysisResult> {
  const startTime = Date.now();
  const enrichments = new Map<string, AIFindingEnrichment>();
  const complexFindings: AIComplexFinding[] = [];

  // Process all medium+ confidence findings, not just top 20
  const reviewableFindings = prioritizeFindings(findings).filter(
    f => f.confidence !== 'low',
  );

  if (reviewableFindings.length > 0) {
    // Batch findings in groups of BATCH_SIZE for better context per finding
    const batches = chunkArray(reviewableFindings, BATCH_SIZE);

    // Pass 1: Explanation enrichment (batched)
    for (const batch of batches) {
      try {
        const explanations = await runExplanationPass(batch, graph, provider);
        for (const [id, enrichment] of explanations) {
          enrichments.set(id, enrichment);
        }
      } catch {
        // Non-fatal: continue without explanations for this batch
      }
    }

    // Pass 2: False positive detection (batched)
    for (const batch of batches) {
      try {
        const fpResults = await runFalsePositivePass(batch, graph, provider);
        for (const [id, fp] of fpResults) {
          const existing = enrichments.get(id);
          if (existing) {
            existing.falsePositive = fp.falsePositive;
            existing.falsePositiveReason = fp.reason;
          } else {
            enrichments.set(id, {
              explanation: '',
              remediation: '',
              falsePositive: fp.falsePositive,
              falsePositiveReason: fp.reason,
            });
          }
        }
      } catch {
        // Non-fatal
      }
    }
  }

  // Pass 3: Complex pattern detection
  try {
    const complex = await runComplexPatternPass(graph, provider);
    complexFindings.push(...complex);
  } catch {
    // Non-fatal
  }

  return {
    enrichments,
    complexFindings,
    provider: provider.name,
    duration: Date.now() - startTime,
  };
}

function chunkArray<T>(arr: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}

function prioritizeFindings(findings: Finding[]): Finding[] {
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return [...findings].sort((a, b) => order[a.severity] - order[b.severity]);
}

/**
 * Strip markdown code fences from LLM response before JSON parsing.
 * Handles ```json ... ```, ``` ... ```, and leading/trailing whitespace.
 */
function extractJSON(response: string): string {
  let cleaned = response.trim();
  // Strip ```json ... ``` or ``` ... ```
  const fenceMatch = cleaned.match(/^```(?:json)?\s*\n?([\s\S]*?)\n?\s*```$/);
  if (fenceMatch) {
    cleaned = fenceMatch[1].trim();
  }
  // Also handle case where response starts with text before JSON
  const jsonStart = cleaned.indexOf('{');
  const jsonEnd = cleaned.lastIndexOf('}');
  if (jsonStart >= 0 && jsonEnd > jsonStart) {
    cleaned = cleaned.substring(jsonStart, jsonEnd + 1);
  }
  return cleaned;
}

function buildFindingContext(finding: Finding, graph: AgentGraph): string {
  let context = `Finding: ${finding.title}\nRule: ${finding.ruleId}\nSeverity: ${finding.severity}\nConfidence: ${finding.confidence}\nDomain: ${finding.domain}\n`;
  if (finding.checkType) {
    context += `Detection method: ${finding.checkType}\n`;
  }
  // Include taint flow context if available
  if (finding.taintFlow) {
    context += `Taint flow (${finding.taintFlow.flowType}): ${finding.taintFlow.stages.map(s => s.command).join(' → ')}\n`;
  }
  // Include related locations for cross-file findings
  if (finding.relatedLocations?.length) {
    context += `Related: ${finding.relatedLocations.map(r => `${r.file}:${r.line} (${r.message})`).join(', ')}\n`;
  }
  context += `File: ${finding.location.file}:${finding.location.line}\n`;
  if (finding.location.snippet) {
    context += `Snippet: ${finding.location.snippet}\n`;
  }

  // Include wider surrounding code context (±15 lines)
  try {
    const fullPath = `${graph.rootPath}/${finding.location.file}`;
    const content = fs.readFileSync(fullPath, 'utf-8');
    const lines = content.split('\n');
    const start = Math.max(0, finding.location.line - CODE_CONTEXT_LINES_BEFORE - 1);
    const end = Math.min(lines.length, finding.location.line + CODE_CONTEXT_LINES_AFTER);
    const numberedLines = lines.slice(start, end).map((l, idx) => {
      const num = start + idx + 1;
      const marker = num === finding.location.line ? '>>>' : '   ';
      return `${marker} ${num}: ${l}`;
    });
    context += `\nCode context:\n${numberedLines.join('\n')}\n`;
  } catch {
    // File may not be readable
  }

  return context;
}

async function runExplanationPass(
  findings: Finding[],
  graph: AgentGraph,
  provider: AIProvider,
): Promise<Map<string, AIFindingEnrichment>> {
  const result = new Map<string, AIFindingEnrichment>();
  const contexts = findings.map(f => ({
    id: f.id,
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    domain: f.domain,
    checkType: f.checkType,
    context: buildFindingContext(f, graph),
  }));

  const contextStr = JSON.stringify(contexts).slice(0, MAX_CONTEXT_CHARS);
  const response = await provider.analyze(EXPLANATION_PROMPT, contextStr);

  try {
    const parsed = JSON.parse(extractJSON(response)) as {
      findings: Array<{ id: string; explanation: string; remediation: string }>;
    };
    for (const item of parsed.findings ?? []) {
      result.set(item.id, {
        explanation: item.explanation,
        remediation: item.remediation,
        falsePositive: false,
      });
    }
  } catch {
    // Response wasn't valid JSON; skip
  }

  return result;
}

async function runFalsePositivePass(
  findings: Finding[],
  graph: AgentGraph,
  provider: AIProvider,
): Promise<Map<string, { falsePositive: boolean; reason?: string }>> {
  const result = new Map<string, { falsePositive: boolean; reason?: string }>();
  const contexts = findings.map(f => ({
    id: f.id,
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    domain: f.domain,
    checkType: f.checkType,
    context: buildFindingContext(f, graph),
  }));

  const contextStr = JSON.stringify(contexts).slice(0, MAX_CONTEXT_CHARS);
  const response = await provider.analyze(FALSE_POSITIVE_PROMPT, contextStr);

  try {
    const parsed = JSON.parse(extractJSON(response)) as {
      assessments: Array<{ id: string; falsePositive: boolean; reason?: string }>;
    };
    for (const item of parsed.assessments ?? []) {
      result.set(item.id, {
        falsePositive: item.falsePositive,
        reason: item.reason,
      });
    }
  } catch {
    // Response wasn't valid JSON; skip
  }

  return result;
}

async function runComplexPatternPass(
  graph: AgentGraph,
  provider: AIProvider,
): Promise<AIComplexFinding[]> {
  const summary = buildGraphSummary(graph);
  const response = await provider.analyze(COMPLEX_PATTERN_PROMPT, summary);

  try {
    const parsed = JSON.parse(extractJSON(response)) as {
      findings: AIComplexFinding[];
    };
    return parsed.findings ?? [];
  } catch {
    return [];
  }
}

function buildGraphSummary(graph: AgentGraph): string {
  const parts: string[] = [];
  parts.push(`Framework: ${graph.primaryFramework}`);
  parts.push(`Agents (${graph.agents.length}):`);
  for (const agent of graph.agents) {
    parts.push(`  - ${agent.name} (${agent.framework}, tools: ${agent.tools.length}, prompt: ${agent.systemPrompt ? 'yes' : 'no'})`);
  }
  parts.push(`Tools (${graph.tools.length}):`);
  for (const tool of graph.tools) {
    parts.push(`  - ${tool.name}: ${tool.capabilities.join(', ')} (side-effects: ${tool.hasSideEffects})`);
  }
  parts.push(`Prompts (${graph.prompts.length}):`);
  for (const prompt of graph.prompts) {
    parts.push(`  - ${prompt.type} in ${prompt.file} (guarded: ${prompt.hasInstructionGuarding}, scope: ${prompt.scopeClarity})`);
    if (prompt.content) {
      parts.push(`    "${prompt.content.substring(0, 200)}..."`);
    }
  }
  if (graph.interAgentLinks.length > 0) {
    parts.push(`Inter-agent links (${graph.interAgentLinks.length}):`);
    for (const link of graph.interAgentLinks) {
      parts.push(`  - ${link.fromAgent} -> ${link.toAgent} (${link.communicationType}, auth: ${link.hasAuthentication})`);
    }
  }
  return parts.join('\n').slice(0, MAX_CONTEXT_CHARS);
}
