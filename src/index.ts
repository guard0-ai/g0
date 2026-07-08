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
export { reportSarif } from './reporters/sarif.js';
// v2: reportHtml removed — available via Guard0 Platform

// v2: Inventory + signed CycloneDX AI-BOM
export { buildInventory } from './inventory/builder.js';
export { toCycloneDX, computeBomHash } from './inventory/cyclonedx.js';
export type { CycloneDXBom, BomMeta } from './inventory/cyclonedx.js';
export { generateKeyPair, signBomHash, verifyBomSignature, loadPrivateKey } from './inventory/sign.js';
export type { BomSignature } from './inventory/sign.js';

// v2: Attestation & evidence
export { buildAttestationPack, buildStandardsCoverage, computeAttestationHash } from './governance/attestation.js';
export type { AttestationPack, StandardCoverage } from './governance/attestation.js';

// v2: Multi-ecosystem threat feed
export { fetchThreatFeed, fetchCVEFeed, checkVersionVulnerable, checkPackageVulnerable, resolveFeedSources, getCVESummary } from './intelligence/cve-feed.js';
export type { CVEEntry, Ecosystem, FeedSource } from './intelligence/cve-feed.js';

// v2: Diff-based gate baseline
export { buildBaseline, diffAgainstBaseline, fingerprintFinding, loadBaseline, writeBaseline } from './ci/baseline.js';
export type { BaselineFile, BaselineDiff } from './ci/baseline.js';

// v2: Fleet control plane
export { buildSnapshot, writeSnapshot, computeFleetSummary, computeDrift, listAssetIds, latestSnapshot, getSnapshots } from './platform/fleet.js';
export type { FleetSnapshot, FleetSummary, FleetDrift } from './platform/fleet.js';

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
