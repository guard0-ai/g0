// g0 Public SDK API
export { runScan, runDiscovery, runGraphBuild } from './pipeline.js';
export type { ScanOptions, DiscoveryResult } from './pipeline.js';
export type { ScanResult, ScanScore, DomainScore } from './types/score.js';
export type { Finding, FindingSummary } from './types/finding.js';
export type { AgentGraph, AgentNode, ToolNode, PromptNode, ModelNode, VectorDBNode, FrameworkInfo } from './types/agent-graph.js';
export type { Severity, Confidence, FrameworkId, Grade, SecurityDomain } from './types/common.js';
export type { Rule } from './types/control.js';
export { getAllRules, getRuleById, getRulesByDomain } from './analyzers/rules/index.js';
export { calculateScore } from './scoring/engine.js';
export { reportJson } from './reporters/json.js';
export { reportHtml } from './reporters/html.js';

// Endpoint types
export type {
  EndpointScanResult,
  EndpointScanOptions,
  EndpointScore,
  EndpointGrade,
  NetworkScanResult,
  ListeningService,
  AIServiceType,
  ArtifactScanResult,
  CredentialExposure,
  DataStoreExposure,
  CrossReferenceFinding,
  DriftResult,
  DriftEvent,
  EndpointStatusResult,
  ForensicsScanResult,
  ConversationStore,
  BrowserScanResult,
  AIBrowsingEntry,
  RemediationResult,
  RemediationStep,
  RemediationAction,
} from './types/endpoint.js';

// Platform types (for guard0-platform to import)
export type {
  ScanUploadPayload,
  InventoryUploadPayload,
  MCPUploadPayload,
  TestUploadPayload,
  EndpointUploadPayload,
  UploadPayload,
  UploadResponse,
  ProjectMeta,
  GitMeta,
  MachineMeta,
  CIMeta,
  EndpointRegisterPayload,
  EndpointRegisterResponse,
  HeartbeatPayload,
  HeartbeatResponse,
  PlatformConfig,
} from './platform/types.js';
