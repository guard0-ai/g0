import * as path from 'node:path';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface FalcoRuleSet {
  /** The generated Falco YAML rules */
  yaml: string;
  /** Individual rules generated */
  ruleCount: number;
  /** Macro names defined */
  macros: string[];
  /** List names defined */
  lists: string[];
}

export interface FalcoRuleOptions {
  /** OpenClaw agent data path */
  agentDataPath: string;
  /** Container name patterns for OpenClaw agents */
  containerPatterns?: string[];
  /** Docker image name pattern for OpenClaw (default: openclaw) */
  imagePattern?: string;
  /** Allowed outbound destinations */
  egressAllowlist?: string[];
  /** Gateway port (default: 18789) */
  gatewayPort?: number;
  /** Rule priority (default: WARNING) */
  defaultPriority?: 'EMERGENCY' | 'ALERT' | 'CRITICAL' | 'ERROR' | 'WARNING' | 'NOTICE' | 'INFO' | 'DEBUG';
}

// ─── Rule Generation ─────────────────────────────────────────────────────────

/**
 * Generate Falco rules for runtime monitoring of an OpenClaw deployment.
 *
 * Falco uses eBPF/kernel module under the hood but is deployed separately.
 * g0 generates the rules; the customer deploys Falco with these rules.
 *
 * Coverage:
 * - C1: Egress filtering violations (unexpected outbound connections)
 * - C4: Cross-agent data access (file reads across agent boundaries)
 * - C5: Tool call and file access auditing
 * - H1: Container running as root
 * - L1: Session transcript access
 */
export function generateFalcoRules(options: FalcoRuleOptions): FalcoRuleSet {
  const agentPath = options.agentDataPath;
  const imagePattern = options.imagePattern ?? 'openclaw';
  const containerPatterns = options.containerPatterns ?? ['openclaw-*', 'oc-agent-*'];
  const gatewayPort = options.gatewayPort ?? 18789;
  const priority = options.defaultPriority ?? 'WARNING';

  const macros: string[] = [];
  const lists: string[] = [];
  const sections: string[] = [];

  // ── Header ──────────────────────────────────────────────────────────
  sections.push(`# g0 OpenClaw Falco Rules`);
  sections.push(`# Generated: ${new Date().toISOString()}`);
  sections.push(`# Deploy: cp g0-openclaw-falco.yaml /etc/falco/rules.d/`);
  sections.push(`# Requires: Falco >= 0.35.0`);
  sections.push('');

  // ── Lists ───────────────────────────────────────────────────────────
  sections.push('# ── Lists ──────────────────────────────────────────────────');
  sections.push('');

  // OpenClaw container patterns
  const containerListItems = containerPatterns.map(p => `"${p}"`).join(', ');
  sections.push(`- list: g0_openclaw_containers`);
  sections.push(`  items: [${containerListItems}]`);
  sections.push('');
  lists.push('g0_openclaw_containers');

  // Allowed egress destinations
  if (options.egressAllowlist?.length) {
    const egressItems = options.egressAllowlist
      .filter(e => !e.startsWith('*')) // Skip wildcards (Falco doesn't support them in lists)
      .map(e => `"${e}"`)
      .join(', ');
    sections.push(`- list: g0_allowed_egress`);
    sections.push(`  items: [${egressItems}]`);
    sections.push('');
    lists.push('g0_allowed_egress');
  }

  // Sensitive binaries that agents shouldn't invoke
  sections.push(`- list: g0_sensitive_binaries`);
  sections.push(`  items: [curl, wget, nc, ncat, ssh, scp, rsync, ftp, telnet, socat]`);
  sections.push('');
  lists.push('g0_sensitive_binaries');

  // ── Macros ──────────────────────────────────────────────────────────
  sections.push('# ── Macros ─────────────────────────────────────────────────');
  sections.push('');

  sections.push(`- macro: g0_openclaw_container`);
  sections.push(`  condition: (container.image.repository contains "${imagePattern}")`);
  sections.push('');
  macros.push('g0_openclaw_container');

  sections.push(`- macro: g0_agent_data_path`);
  sections.push(`  condition: (fd.name startswith "${agentPath}")`);
  sections.push('');
  macros.push('g0_agent_data_path');

  // ── Rules ───────────────────────────────────────────────────────────
  sections.push('# ── Rules ──────────────────────────────────────────────────');
  sections.push('');

  let ruleCount = 0;

  // Rule 1: Unexpected outbound connection from OpenClaw container (C1)
  sections.push(`- rule: g0_openclaw_unexpected_egress`);
  sections.push(`  desc: OpenClaw container made outbound connection to non-allowlisted destination`);
  sections.push(`  condition: >`);
  sections.push(`    evt.type in (connect) and`);
  sections.push(`    evt.dir = < and`);
  sections.push(`    fd.typechar = 4 and`);
  sections.push(`    fd.ip != "0.0.0.0" and`);
  sections.push(`    fd.sip != "127.0.0.1" and`);
  sections.push(`    g0_openclaw_container`);
  if (options.egressAllowlist?.length) {
    sections.push(`    and not fd.sip in (g0_allowed_egress)`);
  }
  sections.push(`  output: >`);
  sections.push(`    OpenClaw egress violation:`);
  sections.push(`    container=%container.name image=%container.image.repository`);
  sections.push(`    connection=%fd.name pid=%proc.pid process=%proc.name`);
  sections.push(`    user=%user.name`);
  sections.push(`  priority: ${priority}`);
  sections.push(`  tags: [g0, openclaw, network, egress, C1]`);
  sections.push('');
  ruleCount++;

  // Rule 2: Cross-agent data access (C4)
  sections.push(`- rule: g0_openclaw_cross_agent_access`);
  sections.push(`  desc: OpenClaw agent container accessed another agent's data directory`);
  sections.push(`  condition: >`);
  sections.push(`    evt.type in (open, openat, openat2) and`);
  sections.push(`    evt.dir = < and`);
  sections.push(`    g0_agent_data_path and`);
  sections.push(`    g0_openclaw_container and`);
  sections.push(`    not fd.name startswith concat("${agentPath}/", container.name)`);
  sections.push(`  output: >`);
  sections.push(`    Cross-agent data access:`);
  sections.push(`    container=%container.name accessed file=%fd.name`);
  sections.push(`    process=%proc.name pid=%proc.pid user=%user.name`);
  sections.push(`  priority: CRITICAL`);
  sections.push(`  tags: [g0, openclaw, filesystem, privacy, C4]`);
  sections.push('');
  ruleCount++;

  // Rule 3: Credential file access (C4/C2)
  sections.push(`- rule: g0_openclaw_credential_access`);
  sections.push(`  desc: Process accessed OpenClaw agent credential files (.env)`);
  sections.push(`  condition: >`);
  sections.push(`    evt.type in (open, openat, openat2) and`);
  sections.push(`    evt.dir = < and`);
  sections.push(`    fd.name contains "/.env" and`);
  sections.push(`    g0_agent_data_path`);
  sections.push(`  output: >`);
  sections.push(`    Credential file access:`);
  sections.push(`    file=%fd.name container=%container.name`);
  sections.push(`    process=%proc.name pid=%proc.pid user=%user.name`);
  sections.push(`  priority: ${priority}`);
  sections.push(`  tags: [g0, openclaw, credential, C2, C4]`);
  sections.push('');
  ruleCount++;

  // Rule 4: Session transcript access (L1)
  sections.push(`- rule: g0_openclaw_session_access`);
  sections.push(`  desc: Process accessed OpenClaw session transcript files`);
  sections.push(`  condition: >`);
  sections.push(`    evt.type in (open, openat, openat2) and`);
  sections.push(`    evt.dir = < and`);
  sections.push(`    fd.name contains "/sessions/" and`);
  sections.push(`    fd.name endswith ".jsonl" and`);
  sections.push(`    g0_agent_data_path`);
  sections.push(`  output: >`);
  sections.push(`    Session transcript access:`);
  sections.push(`    file=%fd.name container=%container.name`);
  sections.push(`    process=%proc.name pid=%proc.pid user=%user.name`);
  sections.push(`  priority: NOTICE`);
  sections.push(`  tags: [g0, openclaw, session, privacy, L1]`);
  sections.push('');
  ruleCount++;

  // Rule 5: Container running as root (H1)
  sections.push(`- rule: g0_openclaw_root_container`);
  sections.push(`  desc: OpenClaw container process running as root`);
  sections.push(`  condition: >`);
  sections.push(`    spawned_process and`);
  sections.push(`    g0_openclaw_container and`);
  sections.push(`    user.uid = 0`);
  sections.push(`  output: >`);
  sections.push(`    Root process in OpenClaw container:`);
  sections.push(`    container=%container.name process=%proc.name pid=%proc.pid`);
  sections.push(`    parent=%proc.pname cmdline=%proc.cmdline`);
  sections.push(`  priority: ${priority}`);
  sections.push(`  tags: [g0, openclaw, container, privilege, H1]`);
  sections.push('');
  ruleCount++;

  // Rule 6: Sensitive binary execution in agent container
  sections.push(`- rule: g0_openclaw_sensitive_binary`);
  sections.push(`  desc: OpenClaw container executed a sensitive network/file transfer binary`);
  sections.push(`  condition: >`);
  sections.push(`    spawned_process and`);
  sections.push(`    g0_openclaw_container and`);
  sections.push(`    proc.name in (g0_sensitive_binaries)`);
  sections.push(`  output: >`);
  sections.push(`    Sensitive binary in OpenClaw container:`);
  sections.push(`    container=%container.name binary=%proc.name pid=%proc.pid`);
  sections.push(`    cmdline=%proc.cmdline parent=%proc.pname user=%user.name`);
  sections.push(`  priority: ${priority}`);
  sections.push(`  tags: [g0, openclaw, execution, suspicious]`);
  sections.push('');
  ruleCount++;

  // Rule 7: Docker socket mount access from agent container (C3)
  sections.push(`- rule: g0_openclaw_docker_socket_access`);
  sections.push(`  desc: OpenClaw container accessed Docker socket (container escape risk)`);
  sections.push(`  condition: >`);
  sections.push(`    evt.type in (open, openat, openat2, connect) and`);
  sections.push(`    evt.dir = < and`);
  sections.push(`    fd.name = "/var/run/docker.sock" and`);
  sections.push(`    g0_openclaw_container`);
  sections.push(`  output: >`);
  sections.push(`    Docker socket access from OpenClaw container:`);
  sections.push(`    container=%container.name process=%proc.name pid=%proc.pid`);
  sections.push(`    user=%user.name`);
  sections.push(`  priority: CRITICAL`);
  sections.push(`  tags: [g0, openclaw, docker, escape, C3]`);
  sections.push('');
  ruleCount++;

  // Rule 8: Gateway port exposure check
  sections.push(`- rule: g0_openclaw_gateway_external_bind`);
  sections.push(`  desc: OpenClaw gateway bound to 0.0.0.0 (externally accessible)`);
  sections.push(`  condition: >`);
  sections.push(`    evt.type = bind and`);
  sections.push(`    evt.dir = < and`);
  sections.push(`    fd.sport = ${gatewayPort} and`);
  sections.push(`    fd.sip = "0.0.0.0"`);
  sections.push(`  output: >`);
  sections.push(`    OpenClaw gateway bound to all interfaces:`);
  sections.push(`    port=${gatewayPort} process=%proc.name pid=%proc.pid`);
  sections.push(`    container=%container.name`);
  sections.push(`  priority: CRITICAL`);
  sections.push(`  tags: [g0, openclaw, network, exposure]`);
  sections.push('');
  ruleCount++;

  // Rule 9: Log file tampering
  sections.push(`- rule: g0_openclaw_log_tampering`);
  sections.push(`  desc: OpenClaw log or audit trail files were modified or deleted`);
  sections.push(`  condition: >`);
  sections.push(`    (evt.type in (unlink, unlinkat, rename, renameat, truncate, ftruncate)) and`);
  sections.push(`    g0_agent_data_path and`);
  sections.push(`    (fd.name contains "/logs/" or fd.name contains "tool-calls")`);
  sections.push(`  output: >`);
  sections.push(`    Log tampering detected:`);
  sections.push(`    file=%fd.name operation=%evt.type container=%container.name`);
  sections.push(`    process=%proc.name pid=%proc.pid user=%user.name`);
  sections.push(`  priority: CRITICAL`);
  sections.push(`  tags: [g0, openclaw, tampering, audit, C5]`);
  sections.push('');
  ruleCount++;

  return {
    yaml: sections.join('\n'),
    ruleCount,
    macros,
    lists,
  };
}

/** Format as a complete YAML file ready to deploy */
export function formatFalcoRulesFile(ruleSet: FalcoRuleSet): string {
  return ruleSet.yaml + '\n';
}
