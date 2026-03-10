// ── OpenClaw Plugin SDK Types ────────────────────────────────────────────────
// Based on the real OpenClaw plugin API (https://openclaw.ai/docs/plugins)

// ── Hook Event Types ────────────────────────────────────────────────────────

export interface BeforeAgentStartEvent {
  agentId: string;
  sessionId: string;
  model?: string;
  systemPrompt?: string;
}

export interface BeforeAgentStartResult {
  prependContext?: string;
}

export interface BeforeToolCallEvent {
  toolName: string;
  arguments: Record<string, unknown>;
  agentId?: string;
  sessionId?: string;
}

export interface BeforeToolCallResult {
  block?: boolean;
  blockReason?: string;
}

export interface ToolResultEvent {
  toolName: string;
  message: string;
  durationMs: number;
  agentId?: string;
  sessionId?: string;
}

export interface ToolResultPersistResult {
  message?: string;
}

export interface MessageReceivedEvent {
  role: string;
  content: string;
  agentId?: string;
  sessionId?: string;
}

// ── Hook Handler Types ──────────────────────────────────────────────────────

export interface HookOptions {
  priority?: number;
}

export type BeforeAgentStartHandler = (event: BeforeAgentStartEvent) => BeforeAgentStartResult | void;
export type BeforeToolCallHandler = (event: BeforeToolCallEvent) => BeforeToolCallResult | void;
export type ToolResultPersistHandler = (event: ToolResultEvent) => ToolResultPersistResult | void;
export type MessageReceivedHandler = (event: MessageReceivedEvent) => void;

// ── Tool Definition ─────────────────────────────────────────────────────────

export interface ToolParameter {
  type: string;
  description?: string;
  required?: boolean;
  enum?: string[];
}

export interface ToolResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

export interface ToolDefinition {
  name: string;
  label: string;
  description: string;
  parameters: Record<string, ToolParameter>;
  execute: (args: Record<string, unknown>) => ToolResult | Promise<ToolResult>;
}

// ── Plugin Logger ───────────────────────────────────────────────────────────

export interface PluginLogger {
  info(message: string, data?: Record<string, unknown>): void;
  warn(message: string, data?: Record<string, unknown>): void;
  error(message: string, data?: Record<string, unknown>): void;
}

// ── Plugin API ──────────────────────────────────────────────────────────────

export interface OpenClawPluginApi {
  on(event: 'before_agent_start', handler: BeforeAgentStartHandler, opts?: HookOptions): void;
  on(event: 'before_tool_call', handler: BeforeToolCallHandler, opts?: HookOptions): void;
  on(event: 'tool_result_persist', handler: ToolResultPersistHandler, opts?: HookOptions): void;
  on(event: 'message_received', handler: MessageReceivedHandler, opts?: HookOptions): void;
  registerTool(definition: ToolDefinition): void;
  registerService(name: string, fn: () => void | Promise<void>): void;
  logger: PluginLogger;
  pluginConfig?: Record<string, unknown>;
}

// ── Plugin Export Shape ─────────────────────────────────────────────────────

export interface OpenClawPlugin {
  id: string;
  name: string;
  version: string;
  description: string;
  register(api: OpenClawPluginApi): void;
}

// ── g0 Plugin Config ────────────────────────────────────────────────────────

export interface G0PluginConfig {
  /** g0 daemon webhook URL (default: http://localhost:6040/events) */
  webhookUrl?: string;
  /** Enable tool call logging (default: true) */
  logToolCalls?: boolean;
  /** Enable injection detection in prompts (default: true) */
  detectInjection?: boolean;
  /** Enable PII scanning in tool outputs (default: true) */
  scanPii?: boolean;
  /** Blocked tool names (execution denied) */
  blockedTools?: string[];
  /** High-risk tools that trigger extra logging */
  highRiskTools?: string[];
  /** Max tool argument size before truncation in logs (bytes, default: 10000) */
  maxArgSize?: number;
  /** Suppress webhook errors in logs (default: false) */
  quietWebhook?: boolean;
  /** Inject security policy into agent context on start (default: true) */
  injectPolicy?: boolean;
  /** Register g0_security_check tool in agent (default: true) */
  registerGateTool?: boolean;
  /** Auth token for webhook requests */
  authToken?: string;
}

// ── Webhook Event Types ─────────────────────────────────────────────────────

export type EventType =
  | 'tool.executed'
  | 'tool.blocked'
  | 'injection.detected'
  | 'pii.detected'
  | 'pii.redacted'
  | 'security.gate'
  | 'error'
  | 'request'
  | 'response';

export interface WebhookEvent {
  type: EventType;
  timestamp: string;
  agentId?: string;
  sessionId?: string;
  data: Record<string, unknown>;
}
