/**
 * Zod schemas for all CLI → Platform upload payloads.
 *
 * These are the single source of truth for the upload API contract.
 * Both the CLI (for construction) and the platform (for validation)
 * should use these schemas.
 */
import { z } from 'zod';

// ─── Shared Enums ─────────────────────────────────────────────────────────────

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export const ConfidenceSchema = z.enum(['high', 'medium', 'low']);
export const GradeSchema = z.enum(['A', 'B', 'C', 'D', 'F']);
export const StatusSchema = z.enum(['healthy', 'degraded', 'error', 'offline']);

// ─── Metadata ─────────────────────────────────────────────────────────────────

export const GitMetaSchema = z.object({
  remote: z.string().optional(),
  branch: z.string().optional(),
  commit: z.string().optional(),
  dirty: z.boolean().optional(),
});

export const ProjectMetaSchema = z.object({
  name: z.string().min(1),
  path: z.string(),
  git: GitMetaSchema.optional(),
});

export const MachineMetaSchema = z.object({
  machineId: z.string().min(1),
  hostname: z.string().optional(),
  platform: z.string().optional(),
  arch: z.string().optional(),
  nodeVersion: z.string().optional(),
  g0Version: z.string().optional(),
});

export const CIMetaSchema = z.object({
  provider: z.string().min(1),
  buildId: z.string().optional(),
  buildUrl: z.string().optional(),
  pipelineId: z.string().optional(),
});

// ─── Finding ──────────────────────────────────────────────────────────────────

export const FindingLocationSchema = z.object({
  file: z.string(),
  line: z.number().int().min(0),
  snippet: z.string().optional(),
});

export const FindingSchema = z.object({
  id: z.string(),
  ruleId: z.string(),
  title: z.string(),
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  domain: z.string(),
  location: FindingLocationSchema,
  description: z.string().optional(),
  remediation: z.string().optional(),
  category: z.enum(['vulnerability', 'hardening', 'informational']).optional(),
  reachability: z.string().optional(),
  exploitability: z.string().optional(),
  standards: z.record(z.array(z.string())).optional(),
});

// ─── Score ────────────────────────────────────────────────────────────────────

export const DomainScoreSchema = z.object({
  domain: z.string(),
  label: z.string(),
  score: z.number().min(0).max(100),
  findings: z.number().int().min(0),
  critical: z.number().int().min(0),
  high: z.number().int().min(0),
  medium: z.number().int().min(0),
  low: z.number().int().min(0),
});

export const ScanScoreSchema = z.object({
  overall: z.number().min(0).max(100),
  grade: GradeSchema,
  securityScore: z.number().min(0).max(100).optional(),
  hardeningScore: z.number().min(0).max(100).optional(),
  domains: z.array(DomainScoreSchema),
  correlations: z.unknown().optional(),
});

// ─── Upload Payloads ──────────────────────────────────────────────────────────

export const ScanUploadSchema = z.object({
  type: z.literal('scan'),
  project: ProjectMetaSchema,
  machine: MachineMetaSchema,
  ci: CIMetaSchema.optional(),
  result: z.object({
    score: ScanScoreSchema,
    findings: z.array(FindingSchema),
    duration: z.number(),
    timestamp: z.string(),
    graph: z.unknown().optional(),
    analyzability: z.unknown().optional(),
  }).passthrough(),
});

export const InventoryUploadSchema = z.object({
  type: z.literal('inventory'),
  project: ProjectMetaSchema,
  machine: MachineMetaSchema,
  ci: CIMetaSchema.optional(),
  result: z.object({
    summary: z.object({
      totalModels: z.number().int().min(0),
      totalFrameworks: z.number().int().min(0),
      totalTools: z.number().int().min(0),
      totalAgents: z.number().int().min(0),
      totalMCPServers: z.number().int().min(0),
    }),
  }).passthrough(),
});

export const MCPUploadSchema = z.object({
  type: z.literal('mcp'),
  project: ProjectMetaSchema.optional(),
  machine: MachineMetaSchema,
  ci: CIMetaSchema.optional(),
  result: z.object({
    servers: z.array(z.object({ name: z.string(), command: z.string(), status: z.string() }).passthrough()),
    tools: z.array(z.object({ name: z.string() }).passthrough()),
    findings: z.array(z.object({ severity: SeveritySchema }).passthrough()),
    summary: z.object({
      totalServers: z.number().int(),
      totalTools: z.number().int(),
      totalFindings: z.number().int(),
    }),
  }).passthrough(),
});

export const TestUploadSchema = z.object({
  type: z.literal('test'),
  project: ProjectMetaSchema,
  machine: MachineMetaSchema,
  ci: CIMetaSchema.optional(),
  result: z.object({
    target: z.object({ type: z.string(), endpoint: z.string() }),
    summary: z.object({
      total: z.number().int(),
      vulnerable: z.number().int(),
      resistant: z.number().int(),
      inconclusive: z.number().int(),
      overallStatus: z.string(),
    }),
  }).passthrough(),
});

export const FlowsUploadSchema = z.object({
  type: z.literal('flows'),
  project: ProjectMetaSchema,
  machine: MachineMetaSchema,
  ci: CIMetaSchema.optional(),
  result: z.object({
    nodes: z.array(z.object({ id: z.string(), label: z.string(), type: z.string() })),
    edges: z.array(z.object({ from: z.string(), to: z.string(), label: z.string().optional() })),
    paths: z.array(z.object({ nodes: z.array(z.string()), riskScore: z.number(), description: z.string() })),
    toxicFlows: z.array(z.object({
      severity: SeveritySchema,
      title: z.string(),
      description: z.string(),
      path: z.array(z.string()),
      riskScore: z.number(),
    })),
    summary: z.object({
      totalNodes: z.number().int(),
      totalEdges: z.number().int(),
      totalPaths: z.number().int(),
      toxicFlowCount: z.number().int(),
      maxRiskScore: z.number(),
      riskLevel: z.string(),
    }),
  }).passthrough(),
});

export const EndpointUploadSchema = z.object({
  type: z.literal('endpoint'),
  machine: MachineMetaSchema,
  result: z.object({
    machineId: z.string(),
    hostname: z.string(),
    timestamp: z.string(),
    tools: z.array(z.object({
      name: z.string(),
      installed: z.boolean(),
      running: z.boolean(),
      mcpServerCount: z.number().int(),
    }).passthrough()),
    summary: z.object({
      totalTools: z.number().int(),
      runningTools: z.number().int(),
      totalServers: z.number().int(),
      totalFindings: z.number().int(),
      overallStatus: z.string(),
    }).passthrough(),
    score: z.object({
      total: z.number().min(0).max(100),
      grade: GradeSchema,
    }).passthrough(),
    duration: z.number(),
  }).passthrough(),
});

export const HostHardeningUploadSchema = z.object({
  type: z.literal('host-hardening'),
  machine: MachineMetaSchema,
  result: z.object({
    checks: z.array(z.object({
      id: z.string(),
      name: z.string(),
      severity: SeveritySchema,
      status: z.string(),
      detail: z.string(),
    })),
    platform: z.string(),
    summary: z.object({
      total: z.number().int(),
      passed: z.number().int(),
      failed: z.number().int(),
      skipped: z.number().int(),
      errors: z.number().int(),
    }),
  }),
});

export const OpenClawAuditUploadSchema = z.object({
  type: z.literal('openclaw-audit'),
  machine: MachineMetaSchema,
  result: z.object({
    checks: z.array(z.object({
      id: z.string(),
      name: z.string(),
      severity: SeveritySchema,
      status: z.string(),
      detail: z.string(),
    })),
    summary: z.object({
      total: z.number().int(),
      pass: z.number().int(),
      fail: z.number().int(),
      warn: z.number().int(),
      skip: z.number().int(),
      error: z.number().int(),
    }),
    timestamp: z.string(),
    duration: z.number(),
  }),
});

// ─── Discriminated Union ──────────────────────────────────────────────────────

export const UploadPayloadSchema = z.discriminatedUnion('type', [
  ScanUploadSchema,
  InventoryUploadSchema,
  MCPUploadSchema,
  TestUploadSchema,
  FlowsUploadSchema,
  EndpointUploadSchema,
  HostHardeningUploadSchema,
  OpenClawAuditUploadSchema,
]);

export type ValidatedUploadPayload = z.infer<typeof UploadPayloadSchema>;

// ─── Endpoint API Schemas ─────────────────────────────────────────────────────

export const EndpointRegisterSchema = z.object({
  machineId: z.string().min(1),
  hostname: z.string(),
  platform: z.string(),
  arch: z.string(),
  g0Version: z.string(),
  watchPaths: z.array(z.string()),
});

export const HeartbeatSchema = z.object({
  endpointId: z.string().min(1),
  machineId: z.string().min(1),
  timestamp: z.string(),
  status: StatusSchema,
  lastScanAt: z.string().optional(),
  score: z.number().min(0).max(100).optional(),
  scoreDelta: z.number().optional(),
  issues: z.array(z.string()).optional(),
  openclawStatus: z.enum(['secure', 'warn', 'critical']).optional(),
  openclawFailedChecks: z.number().int().optional(),
  openclawDriftEvents: z.number().int().optional(),
});
