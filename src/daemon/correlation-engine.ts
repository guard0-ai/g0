import type { ReceivedEvent } from './event-receiver.js';
import type { CVEEntry } from '../intelligence/cve-feed.js';
import type { IOCMatch } from '../intelligence/ioc-database.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface StaticFinding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  domain: string;
  name: string;
}

export interface DynamicResult {
  category: string;
  passed: boolean;
  details?: string;
}

export interface CorrelatedThreat {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium';
  confidence: number; // 0-100
  sources: Array<{
    type: 'static' | 'dynamic' | 'runtime' | 'cve' | 'ioc';
    id: string;
    timestamp?: string;
  }>;
  attackChain: string[];
  narrative: string;
  remediation: string[];
}

// ── Correlation Rules ──────────────────────────────────────────────────────

interface CorrelationRule {
  id: string;
  name: string;
  severity: CorrelatedThreat['severity'];
  baseConfidence: number;
  match: (ctx: CorrelationContext) => CorrelatedThreat | null;
}

interface CorrelationContext {
  staticFindings: StaticFinding[];
  dynamicResults: DynamicResult[];
  runtimeEvents: ReceivedEvent[];
  cves: CVEEntry[];
  iocs: IOCMatch[];
}

const CORRELATION_RULES: CorrelationRule[] = [
  {
    id: 'CT-001',
    name: 'Confirmed Injection Vulnerability',
    severity: 'critical',
    baseConfidence: 90,
    match(ctx) {
      const hasStaticNoValidation = ctx.staticFindings.some(
        f => f.name.toLowerCase().includes('validation') || f.name.toLowerCase().includes('sanitiz'),
      );
      const hasRuntimeInjection = ctx.runtimeEvents.some(
        e => e.type.includes('injection'),
      );

      if (hasStaticNoValidation && hasRuntimeInjection) {
        return {
          id: 'CT-001',
          name: 'Confirmed Injection Vulnerability',
          severity: 'critical',
          confidence: 95,
          sources: [
            ...ctx.staticFindings
              .filter(f => f.name.toLowerCase().includes('validation'))
              .map(f => ({ type: 'static' as const, id: f.id })),
            ...ctx.runtimeEvents
              .filter(e => e.type.includes('injection'))
              .slice(0, 3)
              .map(e => ({ type: 'runtime' as const, id: e.type, timestamp: e.timestamp })),
          ],
          attackChain: ['Missing input validation', 'Injection pattern detected at runtime', 'Confirmed exploitable'],
          narrative: 'Static analysis found missing input validation AND runtime monitoring detected actual injection attempts. This confirms the vulnerability is exploitable in production.',
          remediation: [
            'Add input validation/sanitization to all tool handlers',
            'Enable injection blocking in the g0 OpenClaw plugin (before_tool_call hook)',
            'Review session transcripts for successful exploitation',
          ],
        };
      }
      return null;
    },
  },
  {
    id: 'CT-002',
    name: 'Known CVE with Exposed Gateway',
    severity: 'critical',
    baseConfidence: 85,
    match(ctx) {
      const hasCriticalCVE = ctx.cves.some(c => c.severity === 'critical');
      const hasGatewayExposure = ctx.staticFindings.some(
        f => f.name.toLowerCase().includes('gateway') || f.name.toLowerCase().includes('bind'),
      );

      if (hasCriticalCVE && hasGatewayExposure) {
        return {
          id: 'CT-002',
          name: 'Known CVE with Exposed Gateway',
          severity: 'critical',
          confidence: 90,
          sources: [
            ...ctx.cves.filter(c => c.severity === 'critical').map(c => ({ type: 'cve' as const, id: c.id })),
            ...ctx.staticFindings.filter(f => f.name.toLowerCase().includes('gateway')).map(f => ({ type: 'static' as const, id: f.id })),
          ],
          attackChain: ['Critical CVE exists', 'Gateway is network-exposed', 'Remote exploitation possible'],
          narrative: 'A critical CVE affects this OpenClaw version AND the gateway is exposed beyond loopback. Remote attackers can exploit the vulnerability.',
          remediation: [
            'Update OpenClaw to the patched version immediately',
            'Restrict gateway.bind to loopback until patched',
            'Enable gateway.auth.mode = "token"',
          ],
        };
      }
      return null;
    },
  },
  {
    id: 'CT-003',
    name: 'Active Compromise Indicators',
    severity: 'critical',
    baseConfidence: 80,
    match(ctx) {
      const hasAnomalousActivity = ctx.runtimeEvents.some(
        e => e.type.includes('anomaly') || e.type.includes('burst'),
      );
      const hasIOCMatch = ctx.iocs.some(m => m.type === 'ip' || m.type === 'domain');

      if (hasAnomalousActivity && hasIOCMatch) {
        return {
          id: 'CT-003',
          name: 'Active Compromise Indicators',
          severity: 'critical',
          confidence: 85,
          sources: [
            ...ctx.runtimeEvents
              .filter(e => e.type.includes('anomaly'))
              .slice(0, 3)
              .map(e => ({ type: 'runtime' as const, id: e.type, timestamp: e.timestamp })),
            ...ctx.iocs
              .filter(m => m.type === 'ip' || m.type === 'domain')
              .map(m => ({ type: 'ioc' as const, id: m.matched })),
          ],
          attackChain: ['Behavioral anomaly detected', 'Egress to known malicious endpoint', 'Possible active compromise'],
          narrative: 'Unusual agent behavior combined with network connections to known malicious endpoints suggests an active compromise.',
          remediation: [
            'Activate kill switch immediately: g0 daemon kill-switch on',
            'Review session transcripts for data exfiltration',
            'Rotate all credentials accessible to compromised agents',
            'Block egress to identified malicious endpoints',
          ],
        };
      }
      return null;
    },
  },
  {
    id: 'CT-004',
    name: 'Confirmed Exploitable — Dynamic Test',
    severity: 'high',
    baseConfidence: 85,
    match(ctx) {
      const hasTestSuccess = ctx.dynamicResults.some(r => !r.passed);
      const hasNoSandbox = ctx.staticFindings.some(
        f => f.name.toLowerCase().includes('sandbox') || f.name.toLowerCase().includes('isolation'),
      );

      if (hasTestSuccess && hasNoSandbox) {
        return {
          id: 'CT-004',
          name: 'Confirmed Exploitable — Dynamic Test',
          severity: 'high',
          confidence: 90,
          sources: [
            ...ctx.dynamicResults.filter(r => !r.passed).slice(0, 3).map(r => ({ type: 'dynamic' as const, id: r.category })),
            ...ctx.staticFindings.filter(f => f.name.toLowerCase().includes('sandbox')).map(f => ({ type: 'static' as const, id: f.id })),
          ],
          attackChain: ['Dynamic test bypassed security controls', 'No sandboxing in place', 'Exploit has direct host access'],
          narrative: 'Adversarial testing successfully bypassed security controls AND no sandboxing is configured. Exploits have direct access to host resources.',
          remediation: [
            'Enable sandbox mode: agents.defaults.sandbox.mode = "all"',
            'Fix the specific vulnerability exposed by the dynamic test',
            'Add tool-level input validation',
          ],
        };
      }
      return null;
    },
  },
  {
    id: 'CT-005',
    name: 'Cognitive Poisoning',
    severity: 'critical',
    baseConfidence: 75,
    match(ctx) {
      const hasCognitiveDrift = ctx.runtimeEvents.some(
        e => e.type.includes('cognitive') && e.type.includes('modif'),
      );
      const hasInjection = ctx.runtimeEvents.some(
        e => e.type.includes('injection'),
      );

      if (hasCognitiveDrift && hasInjection) {
        return {
          id: 'CT-005',
          name: 'Cognitive Poisoning',
          severity: 'critical',
          confidence: 80,
          sources: [
            ...ctx.runtimeEvents
              .filter(e => e.type.includes('cognitive'))
              .slice(0, 2)
              .map(e => ({ type: 'runtime' as const, id: e.type, timestamp: e.timestamp })),
            ...ctx.runtimeEvents
              .filter(e => e.type.includes('injection'))
              .slice(0, 2)
              .map(e => ({ type: 'runtime' as const, id: e.type, timestamp: e.timestamp })),
          ],
          attackChain: ['Cognitive file modified', 'Injection patterns detected in modification', 'Agent personality/memory poisoned'],
          narrative: 'Cognitive files (SOUL.md, MEMORY.md) were modified AND injection patterns were detected in the changes. This indicates an attempt to poison the agent\'s personality or memory.',
          remediation: [
            'Restore cognitive files from the last known-good baseline',
            'Review the modification diff for injected instructions',
            'Enable cognitive file integrity monitoring in the daemon',
            'Consider read-only mounts for cognitive files in production',
          ],
        };
      }
      return null;
    },
  },
  {
    id: 'CT-006',
    name: 'Cost Abuse Indicator',
    severity: 'high',
    baseConfidence: 70,
    match(ctx) {
      const hasCostSpike = ctx.runtimeEvents.some(
        e => e.type.includes('cost') && (e.type.includes('warning') || e.type.includes('tripped')),
      );
      const hasNewTools = ctx.runtimeEvents.some(
        e => e.type.includes('new-tool') || e.type.includes('first-seen'),
      );

      if (hasCostSpike && hasNewTools) {
        return {
          id: 'CT-006',
          name: 'Cost Abuse Indicator',
          severity: 'high',
          confidence: 75,
          sources: [
            ...ctx.runtimeEvents
              .filter(e => e.type.includes('cost'))
              .slice(0, 2)
              .map(e => ({ type: 'runtime' as const, id: e.type, timestamp: e.timestamp })),
            ...ctx.runtimeEvents
              .filter(e => e.type.includes('new-tool') || e.type.includes('first-seen'))
              .slice(0, 2)
              .map(e => ({ type: 'runtime' as const, id: e.type, timestamp: e.timestamp })),
          ],
          attackChain: ['New/unusual tool patterns detected', 'Cost spike observed', 'Possible abuse or compromise'],
          narrative: 'Unusual tool usage patterns combined with a cost spike suggest the agent may be under adversarial control or being abused for resource exhaustion.',
          remediation: [
            'Review recent tool call logs for suspicious activity',
            'Set cost limits: costMonitor.hourlyLimitUsd in daemon.json',
            'Enable circuit breaker to auto-activate kill switch on cost threshold',
          ],
        };
      }
      return null;
    },
  },
];

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Correlate events from multiple detection sources to identify attack chains.
 */
export function correlateEvents(
  staticFindings: StaticFinding[],
  dynamicResults: DynamicResult[],
  runtimeEvents: ReceivedEvent[],
  cves: CVEEntry[],
  iocs: IOCMatch[],
): CorrelatedThreat[] {
  const ctx: CorrelationContext = {
    staticFindings,
    dynamicResults,
    runtimeEvents,
    cves,
    iocs,
  };

  const threats: CorrelatedThreat[] = [];

  for (const rule of CORRELATION_RULES) {
    const threat = rule.match(ctx);
    if (threat) {
      threats.push(threat);
    }
  }

  // Sort by severity then confidence
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2 };
  threats.sort((a, b) => {
    const sevDiff = (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3);
    if (sevDiff !== 0) return sevDiff;
    return b.confidence - a.confidence;
  });

  return threats;
}

/**
 * Get all correlation rule definitions (for documentation/display)
 */
export function getCorrelationRules(): Array<{ id: string; name: string; severity: string }> {
  return CORRELATION_RULES.map(r => ({ id: r.id, name: r.name, severity: r.severity }));
}
