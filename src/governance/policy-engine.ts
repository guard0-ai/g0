import * as fs from 'node:fs';
import * as path from 'node:path';

// ── Types ──────────────────────────────────────────────────────────────────

export interface SecurityPolicy {
  apiVersion: string;
  kind: string;
  metadata?: {
    name?: string;
    description?: string;
  };
  spec: PolicySpec;
}

export interface PolicySpec {
  scan?: {
    minGrade?: string; // A, B, C, D, F
    maxCritical?: number;
    maxHigh?: number;
    requiredStandards?: string[];
    blockedDomains?: string[];
  };
  runtime?: {
    killSwitch?: 'required' | 'optional';
    injectionResponse?: 'block' | 'alert' | 'log';
    piiResponse?: 'redact' | 'alert' | 'log';
    costLimitUsd?: number;
  };
  host?: {
    firewall?: 'required' | 'optional';
    diskEncryption?: 'required' | 'optional';
    sshHardening?: 'required' | 'optional';
  };
  agents?: {
    sandboxMode?: string;
    gatewayBind?: string;
    authMode?: string;
    blockedTools?: string[];
  };
  compliance?: {
    frameworks?: string[];
    evidenceRetentionDays?: number;
  };
  enforcement?: {
    ciGate?: boolean;
    driftAlert?: boolean;
    autoFix?: boolean;
  };
}

export interface PolicyViolation {
  rule: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  actual: unknown;
  expected: unknown;
}

export interface PolicyEvaluation {
  policy: SecurityPolicy;
  violations: PolicyViolation[];
  passed: boolean;
  grade: string;
}

// ── Grade Definitions ──────────────────────────────────────────────────────

const GRADE_ORDER: Record<string, number> = { A: 0, B: 1, C: 2, D: 3, F: 4 };

function meetsMinGrade(actual: string, required: string): boolean {
  return (GRADE_ORDER[actual.toUpperCase()] ?? 4) <= (GRADE_ORDER[required.toUpperCase()] ?? 0);
}

// ── Policy Loading ─────────────────────────────────────────────────────────

/**
 * Load a security policy from a YAML file.
 * Supports simplified YAML parsing (key: value format).
 */
export function loadPolicy(policyPath: string): SecurityPolicy | null {
  try {
    if (!fs.existsSync(policyPath)) return null;
    const raw = fs.readFileSync(policyPath, 'utf-8');
    return parseSimpleYaml(raw);
  } catch {
    return null;
  }
}

/**
 * Find and load policy from standard locations
 */
export function findPolicy(searchPath?: string): SecurityPolicy | null {
  const candidates = [
    searchPath ? path.join(searchPath, '.g0-policy.yaml') : null,
    searchPath ? path.join(searchPath, '.g0-policy.yml') : null,
    '.g0-policy.yaml',
    '.g0-policy.yml',
    path.join(process.env.HOME ?? '', '.g0', 'policy.yaml'),
  ].filter(Boolean) as string[];

  for (const candidate of candidates) {
    const policy = loadPolicy(candidate);
    if (policy) return policy;
  }

  return null;
}

// ── Policy Evaluation ──────────────────────────────────────────────────────

export interface ScanContext {
  grade?: string;
  criticalCount?: number;
  highCount?: number;
  standards?: string[];
  domains?: string[];
}

export interface RuntimeContext {
  killSwitchAvailable?: boolean;
  injectionBlocking?: boolean;
  piiRedaction?: boolean;
}

export interface HostContext {
  firewallEnabled?: boolean;
  diskEncrypted?: boolean;
  sshHardened?: boolean;
}

/**
 * Evaluate scan results against a security policy
 */
export function evaluateScanPolicy(
  policy: SecurityPolicy,
  ctx: ScanContext,
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  const spec = policy.spec.scan;
  if (!spec) return violations;

  if (spec.minGrade && ctx.grade && !meetsMinGrade(ctx.grade, spec.minGrade)) {
    violations.push({
      rule: 'scan.minGrade',
      severity: 'high',
      message: `Scan grade ${ctx.grade} does not meet minimum required grade ${spec.minGrade}`,
      actual: ctx.grade,
      expected: spec.minGrade,
    });
  }

  if (spec.maxCritical !== undefined && ctx.criticalCount !== undefined && ctx.criticalCount > spec.maxCritical) {
    violations.push({
      rule: 'scan.maxCritical',
      severity: 'critical',
      message: `${ctx.criticalCount} critical findings exceed maximum of ${spec.maxCritical}`,
      actual: ctx.criticalCount,
      expected: spec.maxCritical,
    });
  }

  if (spec.maxHigh !== undefined && ctx.highCount !== undefined && ctx.highCount > spec.maxHigh) {
    violations.push({
      rule: 'scan.maxHigh',
      severity: 'high',
      message: `${ctx.highCount} high findings exceed maximum of ${spec.maxHigh}`,
      actual: ctx.highCount,
      expected: spec.maxHigh,
    });
  }

  if (spec.requiredStandards && ctx.standards) {
    for (const required of spec.requiredStandards) {
      if (!ctx.standards.includes(required)) {
        violations.push({
          rule: 'scan.requiredStandards',
          severity: 'medium',
          message: `Required compliance standard "${required}" not present in scan`,
          actual: ctx.standards,
          expected: required,
        });
      }
    }
  }

  return violations;
}

/**
 * Evaluate runtime configuration against policy
 */
export function evaluateRuntimePolicy(
  policy: SecurityPolicy,
  ctx: RuntimeContext,
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  const spec = policy.spec.runtime;
  if (!spec) return violations;

  if (spec.killSwitch === 'required' && !ctx.killSwitchAvailable) {
    violations.push({
      rule: 'runtime.killSwitch',
      severity: 'high',
      message: 'Kill switch is required by policy but not configured',
      actual: false,
      expected: true,
    });
  }

  if (spec.injectionResponse === 'block' && !ctx.injectionBlocking) {
    violations.push({
      rule: 'runtime.injectionResponse',
      severity: 'high',
      message: 'Injection blocking is required by policy but not enabled',
      actual: 'alert',
      expected: 'block',
    });
  }

  if (spec.piiResponse === 'redact' && !ctx.piiRedaction) {
    violations.push({
      rule: 'runtime.piiResponse',
      severity: 'medium',
      message: 'PII redaction is required by policy but not enabled',
      actual: 'log',
      expected: 'redact',
    });
  }

  return violations;
}

/**
 * Evaluate host hardening against policy
 */
export function evaluateHostPolicy(
  policy: SecurityPolicy,
  ctx: HostContext,
): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  const spec = policy.spec.host;
  if (!spec) return violations;

  if (spec.firewall === 'required' && !ctx.firewallEnabled) {
    violations.push({
      rule: 'host.firewall',
      severity: 'high',
      message: 'Firewall is required by policy but not enabled',
      actual: false,
      expected: true,
    });
  }

  if (spec.diskEncryption === 'required' && !ctx.diskEncrypted) {
    violations.push({
      rule: 'host.diskEncryption',
      severity: 'critical',
      message: 'Disk encryption is required by policy but not enabled',
      actual: false,
      expected: true,
    });
  }

  if (spec.sshHardening === 'required' && !ctx.sshHardened) {
    violations.push({
      rule: 'host.sshHardening',
      severity: 'high',
      message: 'SSH hardening is required by policy but not configured',
      actual: false,
      expected: true,
    });
  }

  return violations;
}

/**
 * Full policy evaluation combining all contexts
 */
export function evaluatePolicy(
  policy: SecurityPolicy,
  scan?: ScanContext,
  runtime?: RuntimeContext,
  host?: HostContext,
): PolicyEvaluation {
  const violations: PolicyViolation[] = [];

  if (scan) violations.push(...evaluateScanPolicy(policy, scan));
  if (runtime) violations.push(...evaluateRuntimePolicy(policy, runtime));
  if (host) violations.push(...evaluateHostPolicy(policy, host));

  const hasCritical = violations.some(v => v.severity === 'critical');
  const hasHigh = violations.some(v => v.severity === 'high');
  const grade = hasCritical ? 'F' : hasHigh ? 'D' : violations.length > 0 ? 'C' : 'A';

  return {
    policy,
    violations,
    passed: violations.length === 0,
    grade,
  };
}

/**
 * Get CI exit code from policy evaluation
 * 0 = pass, 1 = fail (policy violation), 2 = warning
 */
export function getCIExitCode(evaluation: PolicyEvaluation): number {
  if (evaluation.passed) return 0;
  const hasCriticalOrHigh = evaluation.violations.some(
    v => v.severity === 'critical' || v.severity === 'high',
  );
  return hasCriticalOrHigh ? 1 : 2;
}

// ── Internal YAML Parser ──────────────────────────────────────────────────

function parseSimpleYaml(raw: string): SecurityPolicy {
  // Simple JSON fallback — if it's JSON, parse directly
  const trimmed = raw.trim();
  if (trimmed.startsWith('{')) {
    return JSON.parse(trimmed);
  }

  // Minimal YAML-like parser for flat nested structure
  const result: any = {};
  const lines = raw.split('\n');
  const stack: Array<{ obj: any; indent: number }> = [{ obj: result, indent: -1 }];

  for (const line of lines) {
    const stripped = line.replace(/#.*$/, ''); // Remove comments
    if (!stripped.trim()) continue;

    const indent = stripped.search(/\S/);
    const content = stripped.trim();

    // Pop stack until we find the right parent
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }
    const parent = stack[stack.length - 1].obj;

    const kvMatch = content.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.*)$/);
    if (kvMatch) {
      const [, key, value] = kvMatch;
      if (value.trim()) {
        // Has value — parse it
        parent[key] = parseYamlValue(value.trim());
      } else {
        // No value — nested object
        parent[key] = {};
        stack.push({ obj: parent[key], indent });
      }
    } else if (content.startsWith('- ')) {
      // Array item — find the parent key
      const parentKeys = Object.keys(parent);
      const lastKey = parentKeys[parentKeys.length - 1];
      if (lastKey && !Array.isArray(parent[lastKey])) {
        parent[lastKey] = [];
      }
      if (lastKey && Array.isArray(parent[lastKey])) {
        parent[lastKey].push(parseYamlValue(content.slice(2).trim()));
      }
    }
  }

  return result as SecurityPolicy;
}

function parseYamlValue(value: string): unknown {
  if (value === 'true') return true;
  if (value === 'false') return false;
  if (value === 'null') return null;
  if (/^\d+$/.test(value)) return parseInt(value, 10);
  if (/^\d+\.\d+$/.test(value)) return parseFloat(value);
  if (value.startsWith('[') && value.endsWith(']')) {
    return value.slice(1, -1).split(',').map(s => parseYamlValue(s.trim()));
  }
  // Strip quotes
  if ((value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}
