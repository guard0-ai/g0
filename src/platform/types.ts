import type { Grade, Severity, SecurityDomain } from '../types/common.js';
import type { FindingSummary } from '../types/finding.js';
import type { ScanResult } from '../types/score.js';
import type { InventoryResult } from '../types/inventory.js';
import type { MCPScanResult } from '../types/mcp-scan.js';
import type { TestRunResult } from '../types/test.js';

// ─── Auth ────────────────────────────────────────────────────────────────────

export interface AuthTokens {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number; // Unix timestamp ms
  email?: string;
  userId?: string;
  orgId?: string;
}

export interface DeviceCodeResponse {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  expiresIn: number;
  interval: number;
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
}

// ─── API Key ─────────────────────────────────────────────────────────────────

export interface APIKeyInfo {
  id: string;
  name: string;
  prefix: string; // First 8 chars for display
  createdAt: string;
  lastUsedAt?: string;
}

// ─── Upload Payloads ─────────────────────────────────────────────────────────

export interface ScanUploadPayload {
  type: 'scan';
  project: ProjectMeta;
  machine: MachineMeta;
  ci?: CIMeta;
  result: ScanResult;
}

export interface InventoryUploadPayload {
  type: 'inventory';
  project: ProjectMeta;
  machine: MachineMeta;
  ci?: CIMeta;
  result: InventoryResult;
}

export interface MCPUploadPayload {
  type: 'mcp';
  project?: ProjectMeta;
  machine: MachineMeta;
  ci?: CIMeta;
  result: MCPScanResult;
}

export interface TestUploadPayload {
  type: 'test';
  project: ProjectMeta;
  machine: MachineMeta;
  ci?: CIMeta;
  result: TestRunResult;
}

export type UploadPayload =
  | ScanUploadPayload
  | InventoryUploadPayload
  | MCPUploadPayload
  | TestUploadPayload;

export interface UploadResponse {
  id: string;
  url: string;
  message: string;
}

// ─── Metadata ────────────────────────────────────────────────────────────────

export interface ProjectMeta {
  name: string;
  path: string;
  git?: GitMeta;
}

export interface GitMeta {
  remote?: string;
  branch?: string;
  commit?: string;
  dirty?: boolean;
}

export interface MachineMeta {
  machineId: string;
  hostname: string;
  platform: string;
  arch: string;
  nodeVersion: string;
  g0Version: string;
}

export interface CIMeta {
  provider: string; // 'github-actions' | 'gitlab-ci' | 'jenkins' | 'circleci' | etc.
  buildId?: string;
  buildUrl?: string;
  pipelineId?: string;
}

// ─── Endpoint / Daemon ───────────────────────────────────────────────────────

export interface EndpointRegisterPayload {
  machineId: string;
  hostname: string;
  platform: string;
  arch: string;
  g0Version: string;
  watchPaths: string[];
}

export interface EndpointRegisterResponse {
  endpointId: string;
  message: string;
}

export interface HeartbeatPayload {
  endpointId: string;
  machineId: string;
  timestamp: string;
  status: 'healthy' | 'degraded' | 'error';
  lastScanAt?: string;
  issues?: string[];
}

export interface HeartbeatResponse {
  ack: boolean;
  nextInterval?: number; // Server may adjust interval
}

// ─── Platform Client Config ──────────────────────────────────────────────────

export interface PlatformConfig {
  baseUrl: string;
  apiVersion: string;
}

export const DEFAULT_PLATFORM_CONFIG: PlatformConfig = {
  baseUrl: 'https://app.guard0.ai',
  apiVersion: 'v1',
};
