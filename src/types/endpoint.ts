import type { MCPScanResult, MCPServerInfo, MCPFindingSeverity } from './mcp-scan.js';

// ─── Layer 1: Config Discovery (existing) ────────────────────────────────────

export interface AITool {
  name: string;
  configPath: string;
  installed: boolean;
  running: boolean;
  mcpServerCount: number;
  servers: MCPServerInfo[];
}

// ─── Layer 3: Network Discovery ──────────────────────────────────────────────

export type AIServiceType =
  | 'mcp-sse'
  | 'mcp-streamable'
  | 'openai-compatible'
  | 'a2a'
  | 'ollama'
  | 'lm-studio'
  | 'vllm'
  | 'llama-cpp'
  | 'jan'
  | 'unknown-http'
  | 'non-http';

export interface ListeningService {
  port: number;
  pid: number;
  process: string;
  bindAddress: string;
  type: AIServiceType;
  authenticated: boolean | null;
  declaredInConfig: boolean;
  tlsEnabled: boolean;
  corsWildcard: boolean | null;
}

export interface NetworkFinding {
  severity: MCPFindingSeverity;
  type: string;
  title: string;
  description: string;
  port?: number;
  service?: string;
}

export interface NetworkScanResult {
  services: ListeningService[];
  findings: NetworkFinding[];
  summary: {
    totalListening: number;
    aiServices: number;
    shadowServices: number;
    unauthenticated: number;
    exposedToNetwork: number;
  };
}

// ─── Layer 4: Artifact Scanning ──────────────────────────────────────────────

export type KeyType = 'anthropic' | 'openai' | 'google' | 'aws' | 'github' | 'azure' | 'huggingface' | 'other';

export type CredentialIssue = 'plaintext' | 'bad-permissions' | 'env-leak' | 'config-embedded';

export interface CredentialExposure {
  tool: string;
  keyType: KeyType;
  location: string;
  redactedValue: string;
  issue: CredentialIssue;
  severity: MCPFindingSeverity;
  filePermissions?: string;
}

export type DataStoreType = 'sqlite' | 'json' | 'model-cache' | 'log';

export interface DataStoreExposure {
  tool: string;
  storeType: DataStoreType;
  path: string;
  sizeBytes: number;
  encrypted: boolean;
  permissions: string;
  lastModified: string;
}

export interface ArtifactScanResult {
  credentials: CredentialExposure[];
  dataStores: DataStoreExposure[];
  findings: ArtifactFinding[];
  summary: {
    totalCredentials: number;
    totalDataStores: number;
    totalDataSizeBytes: number;
    totalFindings: number;
  };
}

export interface ArtifactFinding {
  severity: MCPFindingSeverity;
  type: string;
  title: string;
  description: string;
  location?: string;
}

// ─── Layer 5: Forensics (opt-in) ────────────────────────────────────────────

export interface ConversationStore {
  tool: string;
  path: string;
  storeType: 'sqlite' | 'json' | 'leveldb';
  conversationCount: number;
  messageCount: number;
  oldestDate: string | null;
  newestDate: string | null;
  sizeBytes: number;
  encrypted: boolean;
}

export interface ForensicsScanResult {
  stores: ConversationStore[];
  summary: {
    totalStores: number;
    totalConversations: number;
    totalMessages: number;
    oldestActivity: string | null;
    newestActivity: string | null;
    totalSizeBytes: number;
  };
}

// ─── Layer 6: Browser History (opt-in) ──────────────────────────────────────

export interface AIBrowsingEntry {
  browser: string;
  url: string;
  title: string;
  visitCount: number;
  lastVisit: string;
  service: string; // 'chatgpt' | 'claude' | 'gemini' | 'copilot' | 'perplexity' | etc.
}

export interface BrowserScanResult {
  entries: AIBrowsingEntry[];
  summary: {
    totalEntries: number;
    browsers: string[];
    services: Record<string, number>;
    dateRange: { oldest: string | null; newest: string | null };
  };
}

// ─── Remediation (opt-in) ───────────────────────────────────────────────────

export type RemediationAction =
  | 'fix-permissions'
  | 'add-gitignore'
  | 'rotate-key'
  | 'bind-localhost'
  | 'enable-auth'
  | 'enable-tls';

export interface RemediationStep {
  action: RemediationAction;
  target: string;
  description: string;
  command?: string;
  applied: boolean;
  error?: string;
}

export interface RemediationResult {
  steps: RemediationStep[];
  summary: {
    totalSteps: number;
    applied: number;
    skipped: number;
    failed: number;
  };
}

// ─── Cross-Reference ─────────────────────────────────────────────────────────

export type CrossReferenceStatus =
  | 'fully-tracked'        // config + process + network all agree
  | 'stdio-expected'       // config + process, no port (expected for stdio)
  | 'configured-inactive'  // in config, not running
  | 'shadow-service'       // on network, not in any config
  | 'config-mismatch'      // config vs reality divergence
  | 'orphaned-config';     // in config, process gone, port gone

export interface CrossReferenceFinding {
  severity: MCPFindingSeverity;
  type: string;
  title: string;
  description: string;
  status: CrossReferenceStatus;
  port?: number;
  service?: string;
  configRef?: string;
}

// ─── Endpoint Score ──────────────────────────────────────────────────────────

export type EndpointGrade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface CategoryScore {
  score: number;
  max: number;
  deductions: Array<{
    finding: string;
    severity: MCPFindingSeverity;
    points: number;
  }>;
}

export interface EndpointScore {
  total: number;
  grade: EndpointGrade;
  categories: {
    configuration: CategoryScore;
    credentials: CategoryScore;
    network: CategoryScore;
    discovery: CategoryScore;
  };
}

// ─── Scan Options ────────────────────────────────────────────────────────────

export interface EndpointScanOptions {
  network?: boolean;
  artifacts?: boolean;
  forensics?: boolean;
  browser?: boolean;
  fix?: boolean;
  json?: boolean;
}

// ─── Full Endpoint Scan Result ───────────────────────────────────────────────

export interface EndpointScanResult {
  machineId: string;
  hostname: string;
  timestamp: string;

  // Layer 1+2: Config + process discovery (existing)
  tools: AITool[];

  // MCP security scan (existing)
  mcp: MCPScanResult;

  // Layer 3: Network discovery
  network: NetworkScanResult;

  // Layer 4: Artifact scanning
  artifacts: ArtifactScanResult;

  // Cross-reference findings
  crossReference: CrossReferenceFinding[];

  // Composite score
  score: EndpointScore;

  // Layer 5: Forensics (opt-in)
  forensics?: ForensicsScanResult;

  // Layer 6: Browser history (opt-in)
  browser?: BrowserScanResult;

  // Remediation (opt-in)
  remediation?: RemediationResult;

  // Summary
  summary: {
    totalTools: number;
    runningTools: number;
    totalServers: number;
    totalFindings: number;
    findingsBySeverity: Record<string, number>;
    networkServices: number;
    shadowServices: number;
    credentialExposures: number;
    dataStores: number;
    overallStatus: 'ok' | 'warn' | 'critical';
  };

  // Metadata
  duration: number;
  layersRun: Array<'config' | 'process' | 'mcp' | 'network' | 'artifacts' | 'forensics' | 'browser'>;
}

// ─── Endpoint Status (existing, extended) ────────────────────────────────────

export interface EndpointStatusResult {
  machineId: string;
  hostname: string;
  platform: string;
  arch: string;
  nodeVersion: string;
  daemon: { running: boolean; pid?: number };
  auth: { authenticated: boolean };
  watchPaths: string[];
  mcpServers: number;
  daemonConfig: {
    intervalMinutes: number;
    upload: boolean;
    mcpScan: boolean;
    networkScan: boolean;
    artifactScan: boolean;
  };
  lastScore?: number;
  lastGrade?: EndpointGrade;
}

// ─── Drift Detection ─────────────────────────────────────────────────────────

export type DriftEventType =
  | 'new-shadow-service'
  | 'new-credential-exposure'
  | 'score-drop'
  | 'new-tool-installed'
  | 'finding-resolved'
  | 'service-secured';

export interface DriftEvent {
  type: DriftEventType;
  severity: MCPFindingSeverity;
  title: string;
  description: string;
  timestamp: string;
}

export interface DriftResult {
  events: DriftEvent[];
  scoreDelta: number;
  previousScore: number;
  currentScore: number;
}
