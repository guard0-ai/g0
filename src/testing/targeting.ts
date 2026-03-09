import type { AgentGraph } from '../types/agent-graph.js';
import type { Finding } from '../types/finding.js';
import type { StaticContext, RichTestContext, AttackPayload, AttackCategory } from '../types/test.js';
import { getAllPayloads, getPayloadsByCategories } from './payloads/index.js';
import type { ToolCombinationRisk } from '../analyzers/cross-tool-correlation.js';
import type { TaintedPipeline } from '../analyzers/pipeline-taint.js';
import type { AlignmentResult } from '../mcp/description-alignment.js';

/**
 * Build basic StaticContext (backwards compatible).
 */
export function buildStaticContext(graph: AgentGraph, findings: Finding[]): StaticContext {
  const ctx: StaticContext = {
    tools: graph.tools.map(t => ({
      name: t.name,
      capabilities: [...t.capabilities],
      hasValidation: t.hasInputValidation,
    })),
    models: graph.models.map(m => ({
      name: m.name,
      provider: m.provider,
    })),
    prompts: graph.prompts.map(p => ({
      type: p.type,
      hasGuarding: p.hasInstructionGuarding,
      scopeClarity: p.scopeClarity,
    })),
    findings: findings.map(f => ({
      ruleId: f.ruleId,
      domain: f.domain,
      severity: f.severity,
    })),
  };

  if (graph.primaryFramework && graph.primaryFramework !== 'generic') {
    ctx.framework = {
      id: graph.primaryFramework,
      secondaryFrameworks: graph.secondaryFrameworks.length > 0 ? graph.secondaryFrameworks : undefined,
    };
  }

  return ctx;
}

/**
 * Build RichTestContext — preserves full AgentGraph data for targeted testing.
 * This is a superset of StaticContext that keeps tool parameters, prompt text,
 * database accesses, API endpoints, auth flows, and inter-agent links.
 */
export function buildRichTestContext(graph: AgentGraph, findings: Finding[]): RichTestContext {
  const base = buildStaticContext(graph, findings);

  return {
    ...base,
    richTools: graph.tools.map(t => ({
      name: t.name,
      description: t.description,
      capabilities: [...t.capabilities],
      hasValidation: t.hasInputValidation,
      hasSandboxing: t.hasSandboxing,
      hasSideEffects: t.hasSideEffects,
      parameters: t.parameters?.map(p => ({
        name: p.name,
        type: p.type,
        required: p.required,
      })),
      file: t.file,
    })),
    systemPrompts: graph.prompts
      .filter(p => p.type === 'system')
      .map(p => ({
        text: p.content,
        type: p.type,
        hasGuarding: p.hasInstructionGuarding,
        scopeClarity: p.scopeClarity,
        file: p.file,
      })),
    databaseAccesses: graph.databaseAccesses.map(d => ({
      type: d.type,
      queryMethod: d.operation,
      file: d.file,
    })),
    apiEndpoints: graph.apiEndpoints.map(e => ({
      url: e.url,
      method: e.method,
      file: e.file,
    })),
    authFlows: graph.authFlows.map(a => ({
      type: a.type,
      file: a.file,
    })),
    interAgentLinks: graph.interAgentLinks.map(l => ({
      from: l.fromAgent,
      to: l.toAgent,
      method: l.communicationType,
    })),
    agentToolBindings: graph.agents.map(a => ({
      agentName: a.name,
      tools: a.tools ?? [],
    })),
    // Extended context for enhanced payloads (populated externally)
    crossToolRisks: [],
    taintedPipelines: [],
    descriptionMismatches: [],
    analyzabilityScore: 100,
  };
}

/**
 * Enrich RichTestContext with Phase 3/4/6 signals.
 */
export function enrichTestContext(
  ctx: RichTestContext,
  options: {
    crossToolRisks?: ToolCombinationRisk[];
    taintedPipelines?: TaintedPipeline[];
    descriptionMismatches?: AlignmentResult[];
    analyzabilityScore?: number;
  },
): RichTestContext {
  return {
    ...ctx,
    crossToolRisks: options.crossToolRisks ?? ctx.crossToolRisks ?? [],
    taintedPipelines: options.taintedPipelines ?? ctx.taintedPipelines ?? [],
    descriptionMismatches: options.descriptionMismatches ?? ctx.descriptionMismatches ?? [],
    analyzabilityScore: options.analyzabilityScore ?? ctx.analyzabilityScore ?? 100,
  };
}

interface ScoredPayload {
  payload: AttackPayload;
  score: number;
}

export function selectPayloads(
  context: StaticContext,
  categories?: AttackCategory[],
): AttackPayload[] {
  const pool = categories ? getPayloadsByCategories(categories) : getAllPayloads();
  const toolCapabilities = new Set(context.tools.flatMap(t => t.capabilities));
  const toolNames = new Set(context.tools.map(t => t.name.toLowerCase()));

  // Filter out payloads requiring tools the target doesn't have
  const eligible = pool.filter(p => {
    if (!p.requiresTools?.length) return true;
    return p.requiresTools.some(req =>
      toolCapabilities.has(req) || toolNames.has(req.toLowerCase())
    );
  });

  // Score each payload based on static context
  const scored: ScoredPayload[] = eligible.map(payload => {
    let score = 1; // Base score

    switch (payload.category) {
      case 'prompt-injection':
        if (context.prompts.some(p => !p.hasGuarding)) score += 3;
        if (context.prompts.some(p => p.scopeClarity === 'vague' || p.scopeClarity === 'missing')) score += 2;
        break;

      case 'data-exfiltration':
        if (context.findings.some(f => f.domain === 'data-leakage')) score += 3;
        if (context.findings.some(f => f.severity === 'critical' && f.domain === 'data-leakage')) score += 2;
        break;

      case 'tool-abuse':
        if (context.tools.some(t => !t.hasValidation)) score += 3;
        const dangerousCaps = ['shell', 'code-execution', 'database', 'filesystem'];
        const hasDangerous = context.tools.some(t =>
          t.capabilities.some(c => dangerousCaps.includes(c))
        );
        if (hasDangerous) score += 2;
        break;

      case 'jailbreak':
        if (context.prompts.some(p => !p.hasGuarding)) score += 2;
        if (context.findings.some(f => f.domain === 'goal-integrity')) score += 1;
        break;

      case 'goal-hijacking':
        if (context.findings.some(f => f.domain === 'goal-integrity')) score += 3;
        if (context.prompts.some(p => p.scopeClarity === 'missing')) score += 2;
        break;

      case 'authorization':
        if (context.findings.some(f => f.domain === 'identity-access')) score += 3;
        if (context.tools.some(t => t.capabilities.some(c => c === 'database' || c === 'user-management'))) score += 2;
        if (context.findings.some(f => f.severity === 'critical' && f.domain === 'identity-access')) score += 2;
        break;

      case 'indirect-injection':
        if (context.tools.some(t => t.capabilities.some(c =>
          ['http', 'fetch', 'web', 'rag', 'retrieval', 'search'].includes(c)
        ))) score += 3;
        if (context.prompts.some(p => !p.hasGuarding)) score += 2;
        if (context.findings.some(f => f.domain === 'tool-safety')) score += 1;
        break;

      case 'encoding-bypass':
        if (context.findings.some(f => f.domain === 'goal-integrity')) score += 3;
        if (context.prompts.some(p => !p.hasGuarding)) score += 2;
        break;
    }

    // Rich context boosters: use tool params and DB access when available
    const rich = context as RichTestContext;
    if (rich.richTools) {
      // Boost tool-abuse payloads when tools have dangerous params without validation
      if (payload.category === 'tool-abuse' && rich.richTools.some(t =>
        !t.hasValidation && t.parameters && t.parameters.length > 0
      )) {
        score += 1;
      }

      // Boost data-exfil when DB access exists
      if (payload.category === 'data-exfiltration' && rich.databaseAccesses?.length > 0) {
        score += 2;
      }

      // Boost auth payloads when auth flows exist
      if (payload.category === 'authorization' && rich.authFlows?.length > 0) {
        score += 1;
      }

      // Boost multi-agent payloads when inter-agent links exist
      if (payload.category === 'multi-agent' && rich.interAgentLinks?.length > 0) {
        score += 3;
      }
    }

    // Enhanced context boosters (Phase 8D)
    const richCtx = context as RichTestContext;
    if ((richCtx.crossToolRisks?.length ?? 0) > 0 && payload.category === 'cross-tool-chain') {
      score += 4;
    }
    if ((richCtx.taintedPipelines?.length ?? 0) > 0 && payload.category === 'taint-exploit') {
      score += 4;
    }
    if ((richCtx.descriptionMismatches?.length ?? 0) > 0 && payload.category === 'description-mismatch') {
      score += 3;
    }
    if (payload.category === 'tool-output-injection' && richCtx.agentToolBindings?.some(b => b.tools.length >= 2)) {
      score += 3;
    }
    // Low analyzability = can't trust static analysis, test harder
    if (richCtx.analyzabilityScore !== undefined && richCtx.analyzabilityScore < 70) {
      score += 1;
    }

    // Severity boost
    if (payload.severity === 'critical') score += 1;

    return { payload, score };
  });

  // Sort by score descending, then by severity
  scored.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return severityRank(b.payload.severity) - severityRank(a.payload.severity);
  });

  return scored.map(s => s.payload);
}

function severityRank(severity: string): number {
  switch (severity) {
    case 'critical': return 4;
    case 'high': return 3;
    case 'medium': return 2;
    case 'low': return 1;
    default: return 0;
  }
}
