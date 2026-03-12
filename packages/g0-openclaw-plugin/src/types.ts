// ── OpenClaw Plugin SDK Types ────────────────────────────────────────────────
// Aligned with real OpenClaw plugin API (v2026.3.x)
// Verified against /opt/homebrew/lib/node_modules/openclaw/dist/plugin-sdk/plugins/types.d.ts

// ── Agent Message Type ─────────────────────────────────────────────────────

export interface AgentMessageContentBlock {
  type: string;
  text?: string;
  [key: string]: unknown;
}

/** Message object as stored in OpenClaw session JSONL (from pi-agent-core) */
export interface AgentMessage {
  role: string;
  content: string | AgentMessageContentBlock[];
  [key: string]: unknown;
}

// ── Hook Context Types (2nd argument to all hook handlers) ─────────────────

export interface ToolHookContext {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  runId?: string;
  toolName: string;
  toolCallId?: string;
}

/** Context for tool_result_persist — no sessionId, no runId */
export interface ToolResultPersistContext {
  agentId?: string;
  sessionKey?: string;
  toolName?: string;
  toolCallId?: string;
}

export interface MessageHookContext {
  channelId: string;
  accountId?: string;
  conversationId?: string;
}

export interface AgentHookContext {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  workspaceDir?: string;
  messageProvider?: string;
  trigger?: string;
  channelId?: string;
}

export interface SessionHookContext {
  agentId?: string;
  sessionId: string;
  sessionKey?: string;
}

/** Context for before_message_write */
export interface MessageWriteContext {
  agentId?: string;
  sessionKey?: string;
}

/** Context for subagent hooks */
export interface SubagentHookContext {
  runId?: string;
  childSessionKey?: string;
  requesterSessionKey?: string;
}

/** Context for gateway hooks */
export interface GatewayHookContext {
  port?: number;
}

// ── Hook Event Types ────────────────────────────────────────────────────────

// Modifying hook — legacy, prefer before_prompt_build for context injection
export interface BeforeAgentStartEvent {
  prompt: string;
  messages?: unknown[];
}

// Real result = PluginHookBeforePromptBuildResult & PluginHookBeforeModelResolveResult
export interface BeforeAgentStartResult {
  systemPrompt?: string;
  prependContext?: string;
  modelOverride?: string;
  providerOverride?: string;
}

// Modifying hook — tool execution gating
export interface BeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
}

export interface BeforeToolCallResult {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
}

// Synchronous hook — tool result transformation before persistence
// WARNING: Async handlers are IGNORED by OpenClaw runtime with a warning.
export interface ToolResultPersistEvent {
  toolName?: string;
  toolCallId?: string;
  message: AgentMessage;
  isSynthetic?: boolean;
}

export interface ToolResultPersistResult {
  message?: AgentMessage;
}

// Void hook — inbound message observation (parallel, no return)
export interface MessageReceivedEvent {
  from: string;
  content: string;
  timestamp?: number;
  metadata?: Record<string, unknown>;
}

// Void hook — post-execution telemetry
export interface AfterToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
  result?: unknown;
  error?: string;
  durationMs?: number;
}

// Void hook — assembled prompt before model call
export interface LlmInputEvent {
  runId: string;
  sessionId: string;
  provider: string;
  model: string;
  systemPrompt?: string;
  prompt: string;
  historyMessages: unknown[];
  imagesCount: number;
}

// Void hook — model output
export interface LlmOutputEvent {
  runId: string;
  sessionId: string;
  provider: string;
  model: string;
  assistantTexts: string[];
  lastAssistant?: unknown;
  usage?: {
    input?: number;
    output?: number;
    cacheRead?: number;
    cacheWrite?: number;
    total?: number;
  };
}

// Modifying hook — can modify or cancel outbound messages
export interface MessageSendingEvent {
  to: string;
  content: string;
  metadata?: Record<string, unknown>;
}

export interface MessageSendingResult {
  content?: string;
  cancel?: boolean;
}

// Synchronous hook — can transform or block message before write to session
export interface BeforeMessageWriteEvent {
  message: AgentMessage;
  sessionKey?: string;
  agentId?: string;
}

export interface BeforeMessageWriteResult {
  message?: AgentMessage;
  block?: boolean;
}

// Void hook — session lifecycle
export interface SessionStartEvent {
  sessionId: string;
  sessionKey?: string;
  resumedFrom?: string;
}

export interface SessionEndEvent {
  sessionId: string;
  sessionKey?: string;
  messageCount: number;
  durationMs?: number;
}

// Void hook — agent run end
export interface AgentEndEvent {
  messages: unknown[];
  success: boolean;
  error?: string;
  durationMs?: number;
}

// ── Subagent Hooks (critical for sandbox/multi-agent architectures) ────────

/** Requester channel info for subagent hooks */
export interface SubagentRequester {
  channel?: string;
  accountId?: string;
  to?: string;
  threadId?: string | number;
}

// Modifying hook (sequential) — fires before subagent starts, can block
export interface SubagentSpawningEvent {
  childSessionKey: string;
  agentId: string;
  label?: string;
  mode: 'run' | 'session';
  requester?: SubagentRequester;
  threadRequested: boolean;
}

// Discriminated union result
export type SubagentSpawningResult =
  | { status: 'ok'; threadBindingReady?: boolean }
  | { status: 'error'; error: string };

// Void hook — subagent is now running
export interface SubagentSpawnedEvent {
  childSessionKey: string;
  agentId: string;
  label?: string;
  mode: 'run' | 'session';
  runId: string;
  requester?: SubagentRequester;
}

// Void hook — subagent finished
export type SubagentTargetKind = 'subagent' | 'acp';

export interface SubagentEndedEvent {
  targetSessionKey: string;
  targetKind: SubagentTargetKind;
  reason: string;
  sendFarewell?: boolean;
  accountId?: string;
  runId?: string;
  endedAt?: number;
  outcome?: 'ok' | 'error' | 'timeout' | 'killed' | 'reset' | 'deleted';
  error?: string;
}

// Modifying hook (sequential) — resolve where subagent results are delivered
export interface SubagentDeliveryTargetEvent {
  childSessionKey: string;
  requesterSessionKey: string;
  requesterOrigin?: SubagentRequester;
  childRunId?: string;
  spawnMode?: 'run' | 'session';
  expectsCompletionMessage: boolean;
}

export interface SubagentDeliveryTargetResult {
  origin?: SubagentRequester;
}

// Void hooks — gateway lifecycle
export interface GatewayStartEvent {
  port: number;
}

export interface GatewayStopEvent {
  reason?: string;
}

// ── Hook Handler Types ──────────────────────────────────────────────────────

export interface HookOptions {
  priority?: number;
}

// Modifying hooks — can return Promise in real SDK
export type BeforeAgentStartHandler = (event: BeforeAgentStartEvent, ctx: AgentHookContext) => Promise<BeforeAgentStartResult | void> | BeforeAgentStartResult | void;
export type BeforeToolCallHandler = (event: BeforeToolCallEvent, ctx: ToolHookContext) => Promise<BeforeToolCallResult | void> | BeforeToolCallResult | void;
export type MessageSendingHandler = (event: MessageSendingEvent, ctx: MessageHookContext) => Promise<MessageSendingResult | void> | MessageSendingResult | void;
export type SubagentSpawningHandler = (event: SubagentSpawningEvent, ctx: SubagentHookContext) => Promise<SubagentSpawningResult | void> | SubagentSpawningResult | void;
export type SubagentDeliveryTargetHandler = (event: SubagentDeliveryTargetEvent, ctx: SubagentHookContext) => Promise<SubagentDeliveryTargetResult | void> | SubagentDeliveryTargetResult | void;

// MUST be synchronous — OpenClaw ignores Promise returns with a warning
export type ToolResultPersistHandler = (event: ToolResultPersistEvent, ctx: ToolResultPersistContext) => ToolResultPersistResult | void;
export type BeforeMessageWriteHandler = (event: BeforeMessageWriteEvent, ctx: MessageWriteContext) => BeforeMessageWriteResult | void;

// Void hooks — can return Promise<void> | void
export type MessageReceivedHandler = (event: MessageReceivedEvent, ctx: MessageHookContext) => void;
export type AfterToolCallHandler = (event: AfterToolCallEvent, ctx: ToolHookContext) => void;
export type LlmInputHandler = (event: LlmInputEvent, ctx: AgentHookContext) => void;
export type LlmOutputHandler = (event: LlmOutputEvent, ctx: AgentHookContext) => void;
export type SessionStartHandler = (event: SessionStartEvent, ctx: SessionHookContext) => void;
export type SessionEndHandler = (event: SessionEndEvent, ctx: SessionHookContext) => void;
export type AgentEndHandler = (event: AgentEndEvent, ctx: AgentHookContext) => void;
export type SubagentSpawnedHandler = (event: SubagentSpawnedEvent, ctx: SubagentHookContext) => void;
export type SubagentEndedHandler = (event: SubagentEndedEvent, ctx: SubagentHookContext) => void;
export type GatewayStartHandler = (event: GatewayStartEvent, ctx: GatewayHookContext) => void;
export type GatewayStopHandler = (event: GatewayStopEvent, ctx: GatewayHookContext) => void;

// ── Tool Definition ─────────────────────────────────────────────────────────
// Real API uses AnyAgentTool from pi-agent-core with TypeBox schemas.
// We define a compatible subset using JSON Schema objects for parameters.

/** JSON Schema property definition (compatible with TypeBox output) */
export interface JsonSchemaProperty {
  type: string;
  description?: string;
  enum?: string[];
  default?: unknown;
  [key: string]: unknown;
}

/** JSON Schema object for tool parameters (compatible with TypeBox Type.Object output) */
export interface ToolParametersSchema {
  type: 'object';
  properties: Record<string, JsonSchemaProperty>;
  required?: string[];
  [key: string]: unknown;
}

export interface AgentToolResult {
  content: Array<{ type: string; text?: string; [key: string]: unknown }>;
  isError?: boolean;
  details?: Record<string, unknown>;
}

/**
 * Tool definition compatible with OpenClaw's AnyAgentTool.
 * Real execute: (toolCallId, params, signal?, onUpdate?) => Promise<AgentToolResult>
 */
export interface ToolDefinition {
  name: string;
  label: string;
  description: string;
  parameters: ToolParametersSchema;
  execute: (toolCallId: string, params: Record<string, unknown>, signal?: AbortSignal) => AgentToolResult | Promise<AgentToolResult>;
}

// ── Plugin Logger ───────────────────────────────────────────────────────────
// Real logger only accepts a single string argument (no structured data param)

export interface PluginLogger {
  debug?(message: string): void;
  info(message: string): void;
  warn(message: string): void;
  error(message: string): void;
}

// ── Plugin Service ──────────────────────────────────────────────────────────

export interface PluginServiceContext {
  config?: Record<string, unknown>;
  workspaceDir?: string;
  stateDir: string;
  logger: PluginLogger;
}

export interface PluginService {
  id: string;
  start: (ctx: PluginServiceContext) => void | Promise<void>;
  stop?: (ctx: PluginServiceContext) => void | Promise<void>;
}

// ── Plugin API ──────────────────────────────────────────────────────────────

export interface OpenClawPluginApi {
  // Plugin identity (read-only, populated by OpenClaw)
  readonly id: string;
  readonly name: string;
  readonly version?: string;
  readonly description?: string;
  readonly source: string;

  // Modifying hooks (sequential, priority-ordered)
  on(event: 'before_agent_start', handler: BeforeAgentStartHandler, opts?: HookOptions): void;
  on(event: 'before_tool_call', handler: BeforeToolCallHandler, opts?: HookOptions): void;
  on(event: 'message_sending', handler: MessageSendingHandler, opts?: HookOptions): void;
  on(event: 'subagent_spawning', handler: SubagentSpawningHandler, opts?: HookOptions): void;
  on(event: 'subagent_delivery_target', handler: SubagentDeliveryTargetHandler, opts?: HookOptions): void;

  // Synchronous hooks (SYNC ONLY — promises detected and IGNORED)
  on(event: 'tool_result_persist', handler: ToolResultPersistHandler, opts?: HookOptions): void;
  on(event: 'before_message_write', handler: BeforeMessageWriteHandler, opts?: HookOptions): void;

  // Void hooks (parallel via Promise.all, fire-and-forget)
  on(event: 'message_received', handler: MessageReceivedHandler, opts?: HookOptions): void;
  on(event: 'after_tool_call', handler: AfterToolCallHandler, opts?: HookOptions): void;
  on(event: 'llm_input', handler: LlmInputHandler, opts?: HookOptions): void;
  on(event: 'llm_output', handler: LlmOutputHandler, opts?: HookOptions): void;
  on(event: 'session_start', handler: SessionStartHandler, opts?: HookOptions): void;
  on(event: 'session_end', handler: SessionEndHandler, opts?: HookOptions): void;
  on(event: 'agent_end', handler: AgentEndHandler, opts?: HookOptions): void;
  on(event: 'subagent_spawned', handler: SubagentSpawnedHandler, opts?: HookOptions): void;
  on(event: 'subagent_ended', handler: SubagentEndedHandler, opts?: HookOptions): void;
  on(event: 'gateway_start', handler: GatewayStartHandler, opts?: HookOptions): void;
  on(event: 'gateway_stop', handler: GatewayStopHandler, opts?: HookOptions): void;

  registerTool(tool: ToolDefinition): void;
  registerService(service: PluginService): void;
  logger: PluginLogger;
  pluginConfig?: Record<string, unknown>;
}

// ── Plugin Export Shape ─────────────────────────────────────────────────────

export interface OpenClawPlugin {
  id?: string;
  name?: string;
  version?: string;
  description?: string;
  register?: (api: OpenClawPluginApi) => void | Promise<void>;
  activate?: (api: OpenClawPluginApi) => void | Promise<void>;
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
  /** Enable outbound message PII blocking (default: true) */
  blockOutboundPii?: boolean;
  /** Enable LLM I/O monitoring (default: true) */
  monitorLlm?: boolean;
  /** Enable session lifecycle tracking (default: true) */
  trackSessions?: boolean;
}

// ── Webhook Event Types ─────────────────────────────────────────────────────

export type EventType =
  | 'tool.executed'
  | 'tool.blocked'
  | 'tool.result'
  | 'injection.detected'
  | 'pii.detected'
  | 'pii.redacted'
  | 'pii.blocked_outbound'
  | 'security.gate'
  | 'llm.input'
  | 'llm.output'
  | 'session.start'
  | 'session.end'
  | 'agent.end'
  | 'message.blocked'
  | 'subagent.spawning'
  | 'subagent.spawned'
  | 'subagent.ended'
  | 'subagent.blocked'
  | 'gateway.start'
  | 'gateway.stop'
  | 'error'
  | 'request'
  | 'response';

export interface WebhookEvent {
  type: EventType;
  timestamp: string;
  agentId?: string;
  sessionId?: string;
  sessionKey?: string;
  data: Record<string, unknown>;
}
