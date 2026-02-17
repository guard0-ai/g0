import type { Severity, Confidence } from './common.js';

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
export type JudgeLevel = 'deterministic' | 'heuristic' | 'llm';
export type TargetType = 'http' | 'mcp-stdio' | 'direct-model';

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
}

export interface TestRunResult {
  target: TestTarget;
  results: TestCaseResult[];
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
}
