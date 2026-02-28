import type { Severity, Confidence, FrameworkId } from './common.js';

export type AttackCategory =
  | 'prompt-injection'
  | 'data-exfiltration'
  | 'tool-abuse'
  | 'jailbreak'
  | 'goal-hijacking'
  | 'authorization'
  | 'indirect-injection'
  | 'encoding-bypass'
  | 'harmful-content'
  | 'mcp-attack'
  | 'rag-poisoning'
  | 'multi-agent'
  | 'compliance'
  | 'domain-specific'
  | 'content-safety'
  | 'bias-detection'
  | 'pii-probing'
  | 'agentic-attacks'
  | 'jailbreak-advanced'
  | 'hallucination';

export type Verdict = 'vulnerable' | 'resistant' | 'inconclusive' | 'error';
export type JudgeLevel = 'deterministic' | 'heuristic' | 'slm' | 'llm';
export type TargetType = 'http' | 'mcp-stdio' | 'direct-model' | 'a2a';

export interface ConversationMessage {
  role: 'user' | 'system';
  content: string;
  delayMs?: number;
}

export interface CanaryToken {
  type: 'api-key' | 'ssn' | 'email' | 'credit-card' | 'uuid';
  value: string;
  label?: string;
}

export interface JudgeCriteria {
  vulnerablePatterns?: string[];
  resistantPatterns?: string[];
  complianceIndicators?: string[];
  refusalIndicators?: string[];
  heuristicId?: string;
  llmJudgePrompt?: string;
  harmSubcategory?: string;
  canaryTokens?: CanaryToken[];
}

export interface AttackPayload {
  id: string;
  category: AttackCategory;
  name: string;
  description: string;
  severity: Severity;
  messages: ConversationMessage[];
  judgeCriteria: JudgeCriteria;
  tags: string[];
  requiresTools?: string[];
  harmSubcategory?: string;
}

export interface TestTarget {
  type: TargetType;
  endpoint: string;
  args?: string[];
  headers?: Record<string, string>;
  messageField?: string;
  responseField?: string;
  name?: string;
  openai?: boolean;
  model?: string;
  systemPrompt?: string;
  timeout?: number;
  provider?: 'openai' | 'anthropic' | 'google';
}

export type VerbosePhase = 'send' | 'receive' | 'judge';
export type VerboseCallback = (payloadId: string, phase: VerbosePhase, detail: string) => void;

export interface TestCaseResult {
  payloadId: string;
  payloadName: string;
  category: AttackCategory;
  severity: Severity;
  verdict: Verdict;
  judgeLevel: JudgeLevel;
  confidence: Confidence;
  messagesSent: ConversationMessage[];
  responsesReceived: string[];
  evidence: string;
  durationMs: number;
  error?: string;
  /** StrongREJECT-inspired: how specific/detailed is the attack response (1-5) */
  specificity?: number;
  /** StrongREJECT-inspired: how convincing/actionable is the response (1-5) */
  convincingness?: number;
  /** Combined quality score: (specificity + convincingness) / 10 */
  qualityScore?: number;
}

export interface TestRunSummary {
  total: number;
  vulnerable: number;
  resistant: number;
  inconclusive: number;
  errors: number;
  byCategory: Record<AttackCategory, { total: number; vulnerable: number; resistant: number }>;
  overallStatus: 'pass' | 'warn' | 'fail';
}

export interface StaticContext {
  tools: Array<{ name: string; capabilities: string[]; hasValidation: boolean }>;
  models: Array<{ name: string; provider: string }>;
  prompts: Array<{ type: string; hasGuarding: boolean; scopeClarity: string }>;
  findings: Array<{ ruleId: string; domain: string; severity: string }>;
  framework?: { id: FrameworkId; secondaryFrameworks?: FrameworkId[] };
}

/**
 * Rich test context — preserves full AgentGraph data for targeted payload generation.
 * Superset of StaticContext with tool params, prompt text, DB access, API endpoints, etc.
 */
export interface RichTestContext extends StaticContext {
  /** Full tool details: descriptions, parameters, file locations */
  richTools: Array<{
    name: string;
    description?: string;
    capabilities: string[];
    hasValidation: boolean;
    hasSandboxing: boolean;
    hasSideEffects: boolean;
    parameters?: Array<{ name: string; type?: string; required?: boolean }>;
    file?: string;
  }>;
  /** System prompt text for prompt-aware payloads */
  systemPrompts: Array<{
    text: string;
    type: string;
    hasGuarding: boolean;
    scopeClarity: string;
    file?: string;
  }>;
  /** Database access patterns for SQLi/data payloads */
  databaseAccesses: Array<{
    type: string;
    queryMethod?: string;
    file?: string;
  }>;
  /** API endpoints the agent calls or exposes */
  apiEndpoints: Array<{
    url?: string;
    method?: string;
    file?: string;
  }>;
  /** Auth flows for privilege escalation payloads */
  authFlows: Array<{
    type: string;
    file?: string;
  }>;
  /** Inter-agent links for multi-agent attack chains */
  interAgentLinks: Array<{
    from: string;
    to: string;
    method?: string;
  }>;
  /** Agent names and their associated tools */
  agentToolBindings: Array<{
    agentName: string;
    tools: string[];
  }>;
}

export interface TestRunResult {
  target: TestTarget;
  results: TestCaseResult[];
  adaptiveResults?: AdaptiveTestCaseResult[];
  summary: TestRunSummary;
  staticContext?: StaticContext;
  timestamp: string;
  durationMs: number;
}

export interface TestProvider {
  name: string;
  type: TargetType;
  send(message: string): Promise<string>;
  sendConversation(messages: ConversationMessage[]): Promise<string[]>;
  close(): Promise<void>;
}

export interface JudgeResult {
  verdict: Verdict;
  confidence: Confidence;
  evidence: string;
  judgeLevel: JudgeLevel;
  /** StrongREJECT-inspired: how specific/detailed is the attack response (1-5) */
  specificity?: number;
  /** StrongREJECT-inspired: how convincing/actionable is the response (1-5) */
  convincingness?: number;
  /** Combined quality score: (specificity + convincingness) / 10 */
  qualityScore?: number;
}

// Adaptive adversarial testing types

export type AdaptiveStrategyId = 'goat' | 'crescendo' | 'recon-probe' | 'hydra' | 'simba';

export interface AttackState {
  conversationHistory: ConversationMessage[];
  responsesReceived: string[];
  observations: string[];
  failedTactics: string[];
  promisingTactics: string[];
  phase: string;
  turnCount: number;
  meta: Record<string, unknown>;
}

export interface TurnDecision {
  message: string;
  shouldContinue: boolean;
  observations: string[];
  reasoning: string;
}

export interface AdaptiveAttackConfig {
  strategy: AdaptiveStrategyId;
  maxTurns: number;
  objective: string;
  category: AttackCategory;
  severity: Severity;
  frameworkId?: FrameworkId;
  priorIntelligence?: string;
}

export interface AdaptiveTestCaseResult extends TestCaseResult {
  strategyId: AdaptiveStrategyId;
  turnsExecuted: number;
  finalState: AttackState;
  cvssScore?: number;
  cvssVector?: string;
  remediation?: string;
  remediationCode?: string;
}
