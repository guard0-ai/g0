import { execFileSync } from 'node:child_process';
import * as dns from 'node:dns';
import * as os from 'node:os';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface IptablesRuleSet {
  /** The generated iptables commands */
  rules: string[];
  /** Resolved hostname → IP mappings used */
  resolved: Record<string, string[]>;
  /** Entries that could not be resolved */
  unresolved: string[];
  /** Chain name used (default: DOCKER-USER) */
  chain: string;
  /** Whether a default-deny rule is included */
  defaultDeny: boolean;
}

export interface EgressRuleOptions {
  /** iptables chain to insert rules into (default: DOCKER-USER) */
  chain?: string;
  /** Append a default-deny rule at the end (default: true) */
  defaultDeny?: boolean;
  /** Interface for Docker bridge traffic (default: docker0) */
  dockerInterface?: string;
  /** Comment prefix for iptables rules (default: g0-egress) */
  commentPrefix?: string;
  /** Include a RELATED,ESTABLISHED rule at the top (default: true) */
  allowEstablished?: boolean;
  /** Also generate rules for OUTPUT chain (non-Docker host traffic) */
  includeOutputChain?: boolean;
}

// ─── DNS Resolution ──────────────────────────────────────────────────────────

const DNS_RESOLVE_TIMEOUT = 5000;

/** Resolve a hostname to IPv4 addresses */
async function resolveHostname(hostname: string): Promise<string[]> {
  try {
    const addresses = await Promise.race([
      dns.promises.resolve4(hostname),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('dns timeout')), DNS_RESOLVE_TIMEOUT),
      ),
    ]);
    return addresses;
  } catch {
    return [];
  }
}

// ─── Rule Generation ─────────────────────────────────────────────────────────

/**
 * Generate iptables rules from an egress allowlist.
 *
 * Supports the same allowlist formats as the egress monitor:
 *  - Exact hostname: "api.anthropic.com" → resolved to IPs
 *  - Wildcard hostname: "*.openai.com" → skipped with warning (DNS can't enumerate)
 *  - Exact IP: "142.250.80.46"
 *  - CIDR: "10.0.0.0/8"
 */
export async function generateIptablesRules(
  allowlist: string[],
  options: EgressRuleOptions = {},
): Promise<IptablesRuleSet> {
  const chain = options.chain ?? 'DOCKER-USER';
  const iface = options.dockerInterface ?? 'docker0';
  const comment = options.commentPrefix ?? 'g0-egress';
  const defaultDeny = options.defaultDeny ?? true;
  const allowEstablished = options.allowEstablished ?? true;
  const includeOutput = options.includeOutputChain ?? false;

  const rules: string[] = [];
  const resolved: Record<string, string[]> = {};
  const unresolved: string[] = [];

  // Header comment
  rules.push(`# g0 egress rules — generated ${new Date().toISOString()}`);
  rules.push(`# Chain: ${chain}, Interface: ${iface}`);
  rules.push('');

  // Flush existing g0-managed rules (by comment match)
  rules.push(`# Flush existing g0-egress rules`);
  rules.push(`iptables -S ${chain} | grep -- "--comment ${comment}" | sed 's/-A/-D/' | while read rule; do iptables $rule; done`);
  rules.push('');

  // Allow established/related connections (return traffic)
  if (allowEstablished) {
    rules.push(`# Allow return traffic for established connections`);
    rules.push(
      `iptables -I ${chain} -i ${iface} -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "${comment}-established" -j RETURN`,
    );
    rules.push('');
  }

  // Allow DNS (UDP 53) so container DNS resolution works
  rules.push(`# Allow DNS resolution`);
  rules.push(
    `iptables -I ${chain} -i ${iface} -p udp --dport 53 -m comment --comment "${comment}-dns" -j RETURN`,
  );
  rules.push('');

  // Process allowlist entries
  rules.push(`# Allowlist entries`);

  for (const entry of allowlist) {
    if (entry.startsWith('*.')) {
      // Wildcard hostnames cannot be resolved to a finite set of IPs
      unresolved.push(entry);
      rules.push(`# SKIP: wildcard "${entry}" — cannot resolve to specific IPs`);
      rules.push(`# Consider adding specific IPs or CIDRs for ${entry}`);
      continue;
    }

    if (entry.includes('/')) {
      // CIDR — use directly
      rules.push(
        `iptables -I ${chain} -i ${iface} -d ${entry} -m comment --comment "${comment}-cidr" -j RETURN`,
      );
      if (includeOutput) {
        rules.push(
          `iptables -I OUTPUT -d ${entry} -m comment --comment "${comment}-cidr" -j ACCEPT`,
        );
      }
      continue;
    }

    // Check if it's an IP address (simple check: starts with digit and has dots)
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(entry)) {
      rules.push(
        `iptables -I ${chain} -i ${iface} -d ${entry} -m comment --comment "${comment}-ip" -j RETURN`,
      );
      if (includeOutput) {
        rules.push(
          `iptables -I OUTPUT -d ${entry} -m comment --comment "${comment}-ip" -j ACCEPT`,
        );
      }
      continue;
    }

    // Hostname — resolve to IPs
    const ips = await resolveHostname(entry);
    if (ips.length === 0) {
      unresolved.push(entry);
      rules.push(`# UNRESOLVED: "${entry}" — DNS lookup returned no results`);
      continue;
    }

    resolved[entry] = ips;
    rules.push(`# ${entry} → ${ips.join(', ')}`);
    for (const ip of ips) {
      rules.push(
        `iptables -I ${chain} -i ${iface} -d ${ip} -m comment --comment "${comment}-${entry}" -j RETURN`,
      );
      if (includeOutput) {
        rules.push(
          `iptables -I OUTPUT -d ${ip} -m comment --comment "${comment}-${entry}" -j ACCEPT`,
        );
      }
    }
  }

  // Default deny at the end of the chain
  if (defaultDeny) {
    rules.push('');
    rules.push(`# Default deny — drop all other outbound from containers`);
    rules.push(
      `iptables -A ${chain} -i ${iface} -j DROP -m comment --comment "${comment}-deny"`,
    );
    if (includeOutput) {
      rules.push(
        `# Note: OUTPUT chain default deny not applied — too broad for host traffic`,
      );
    }
  }

  rules.push('');

  return {
    rules,
    resolved,
    unresolved,
    chain,
    defaultDeny,
  };
}

// ─── Rule Application ────────────────────────────────────────────────────────

export interface ApplyResult {
  applied: boolean;
  rulesApplied: number;
  errors: string[];
}

/**
 * Apply generated iptables rules to the running firewall.
 * Requires root/sudo. Linux-only.
 */
export function applyIptablesRules(
  ruleSet: IptablesRuleSet,
  logger?: { info: (msg: string) => void; warn: (msg: string) => void; error: (msg: string) => void },
): ApplyResult {
  if (os.platform() !== 'linux') {
    return {
      applied: false,
      rulesApplied: 0,
      errors: ['iptables rules can only be applied on Linux'],
    };
  }

  const errors: string[] = [];
  let applied = 0;

  for (const rule of ruleSet.rules) {
    // Skip comments and empty lines
    const trimmed = rule.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Handle the flush command (shell piped command) separately
    if (trimmed.includes('|') || trimmed.includes('while read')) {
      // This is the cleanup command — run via sh for pipe support
      try {
        execFileSync('/bin/sh', ['-c', trimmed], {
          encoding: 'utf-8',
          timeout: 10_000,
          stdio: ['pipe', 'pipe', 'pipe'],
        });
        logger?.info(`Egress rules: flushed existing g0 rules`);
      } catch {
        // Non-fatal — chain may not have existing rules
      }
      continue;
    }

    // Parse iptables command into args
    const parts = trimmed.split(/\s+/);
    if (parts[0] !== 'iptables') continue;

    const args = parts.slice(1);

    try {
      execFileSync('iptables', args, {
        encoding: 'utf-8',
        timeout: 5_000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      applied++;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      errors.push(`Failed: ${trimmed} — ${msg}`);
      logger?.error(`Egress rules: ${errors[errors.length - 1]}`);
    }
  }

  if (applied > 0) {
    logger?.info(`Egress rules: ${applied} iptables rules applied`);
  }

  return {
    applied: applied > 0,
    rulesApplied: applied,
    errors,
  };
}

/**
 * Format rules as a shell script string for manual review/application.
 */
export function formatRulesAsScript(ruleSet: IptablesRuleSet): string {
  const lines = [
    '#!/bin/bash',
    '# g0 egress firewall rules',
    '# Apply with: sudo bash egress-rules.sh',
    '# Review before applying!',
    '',
    'set -euo pipefail',
    '',
    ...ruleSet.rules,
  ];
  return lines.join('\n') + '\n';
}
