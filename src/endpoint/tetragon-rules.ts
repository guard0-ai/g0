/**
 * Tetragon TracingPolicy Generator for OpenClaw deployments.
 *
 * Tetragon provides eBPF-based runtime enforcement — it can observe AND kill
 * processes at the kernel level. This differs from Falco (detection-only).
 *
 * Deployment: Tetragon runs as a DaemonSet (k8s) or privileged container (Docker).
 * Policies are applied as TracingPolicy CRDs or JSON files loaded at startup.
 *
 * g0 generates these policies; the customer deploys Tetragon with them.
 */

// ── Types ────────────────────────────────────────────────────────────────────

export interface TetragonPolicySet {
  /** Array of TracingPolicy objects (JSON-serializable) */
  policies: TracingPolicy[];
  /** Total policy count */
  policyCount: number;
  /** Combined YAML output for all policies */
  yaml: string;
  /** Docker Compose snippet for deploying Tetragon */
  dockerCompose: string;
}

export interface TetragonRuleOptions {
  /** OpenClaw agent data path */
  agentDataPath: string;
  /** Container name patterns for OpenClaw agents */
  containerPatterns?: string[];
  /** Docker image name pattern (default: openclaw) */
  imagePattern?: string;
  /** Allowed outbound destinations (IPs/CIDRs) */
  egressAllowlist?: string[];
  /** Gateway port (default: 18789) */
  gatewayPort?: number;
  /** Enable enforcement (SIGKILL on violation). Default: false (observe-only) */
  enforce?: boolean;
  /** g0 daemon webhook URL for event forwarding (default: http://localhost:6040/events) */
  webhookUrl?: string;
}

// ── TracingPolicy Schema (Tetragon CRD) ──────────────────────────────────────

interface TracingPolicy {
  apiVersion: string;
  kind: string;
  metadata: { name: string; labels?: Record<string, string> };
  spec: {
    kprobes?: KprobeSpec[];
    tracepoints?: TracepointSpec[];
  };
}

interface KprobeSpec {
  call: string;
  syscall: boolean;
  return?: boolean;
  args: ArgSpec[];
  selectors: SelectorSpec[];
  returnArg?: ArgSpec;
}

interface TracepointSpec {
  subsystem: string;
  event: string;
  args?: ArgSpec[];
  selectors: SelectorSpec[];
}

interface ArgSpec {
  index: number;
  type: string;
  label?: string;
}

interface SelectorSpec {
  matchArgs?: MatchArgSpec[];
  matchBinaries?: MatchBinarySpec[];
  matchNamespaces?: MatchNamespaceSpec[];
  matchActions?: MatchActionSpec[];
}

interface MatchArgSpec {
  index: number;
  operator: 'Equal' | 'NotEqual' | 'Prefix' | 'Postfix' | 'Mask' | 'In' | 'NotIn';
  values: string[];
}

interface MatchBinarySpec {
  operator: 'In' | 'NotIn';
  values: string[];
}

interface MatchNamespaceSpec {
  namespace: string;
  operator: 'In' | 'NotIn';
  values: string[];
}

interface MatchActionSpec {
  action: 'Sigkill' | 'Signal' | 'Override' | 'Post' | 'NoPost';
  argError?: number;
}

// ── Policy Generators ────────────────────────────────────────────────────────

function makePolicy(name: string, spec: TracingPolicy['spec']): TracingPolicy {
  return {
    apiVersion: 'cilium.io/v1alpha1',
    kind: 'TracingPolicy',
    metadata: {
      name,
      labels: {
        'app.kubernetes.io/managed-by': 'g0',
        'g0.guard0.dev/component': 'openclaw',
      },
    },
    spec,
  };
}

function enforceAction(enforce: boolean): MatchActionSpec[] {
  return enforce
    ? [{ action: 'Sigkill' }]
    : [{ action: 'Post' }]; // Post = observe & send event (no kill)
}

/**
 * Policy 1: Egress enforcement — block/observe unauthorized outbound connections.
 * Maps to customer finding C1 (Egress Filtering).
 */
function egressPolicy(options: TetragonRuleOptions): TracingPolicy {
  const enforce = options.enforce ?? false;

  // sys_connect kprobe: intercepts connect() syscall
  const kprobe: KprobeSpec = {
    call: 'sys_connect',
    syscall: true,
    args: [
      { index: 0, type: 'int' },                    // fd
      { index: 1, type: 'sockaddr' },               // address struct
    ],
    selectors: [
      {
        // Match TCP connections (AF_INET)
        matchArgs: [
          { index: 1, operator: 'NotEqual', values: ['127.0.0.1'] }, // exclude loopback
        ],
        matchActions: enforceAction(enforce),
      },
    ],
  };

  // If we have an allowlist, use NotIn to catch violations
  if (options.egressAllowlist?.length) {
    const allowedIps = options.egressAllowlist.filter(e =>
      /^\d+\.\d+\.\d+\.\d+/.test(e), // only IPs, not hostnames
    );
    if (allowedIps.length > 0) {
      kprobe.selectors = [
        {
          matchArgs: [
            { index: 1, operator: 'NotIn', values: ['127.0.0.1', ...allowedIps] },
          ],
          matchActions: enforceAction(enforce),
        },
      ];
    }
  }

  return makePolicy('g0-openclaw-egress', { kprobes: [kprobe] });
}

/**
 * Policy 2: Cross-agent file access — block/observe file opens across agent boundaries.
 * Maps to customer finding C4 (Data Privacy Boundaries).
 */
function crossAgentAccessPolicy(options: TetragonRuleOptions): TracingPolicy {
  const enforce = options.enforce ?? false;
  const agentPath = options.agentDataPath;

  return makePolicy('g0-openclaw-cross-agent', {
    kprobes: [
      {
        call: 'sys_openat',
        syscall: true,
        args: [
          { index: 0, type: 'int' },     // dirfd
          { index: 1, type: 'string' },   // pathname
          { index: 2, type: 'int' },      // flags
        ],
        selectors: [
          {
            matchArgs: [
              { index: 1, operator: 'Prefix', values: [agentPath] },
            ],
            matchActions: enforceAction(enforce),
          },
        ],
      },
    ],
  });
}

/**
 * Policy 3: Docker socket access — block/observe attempts to access docker.sock.
 * Maps to customer finding C3 (Docker Socket Mount).
 */
function dockerSocketPolicy(options: TetragonRuleOptions): TracingPolicy {
  const enforce = options.enforce ?? false;

  return makePolicy('g0-openclaw-docker-socket', {
    kprobes: [
      {
        call: 'sys_openat',
        syscall: true,
        args: [
          { index: 0, type: 'int' },
          { index: 1, type: 'string' },
          { index: 2, type: 'int' },
        ],
        selectors: [
          {
            matchArgs: [
              { index: 1, operator: 'Equal', values: ['/var/run/docker.sock'] },
            ],
            matchActions: enforceAction(enforce),
          },
        ],
      },
      // Also catch connect() to docker socket
      {
        call: 'sys_connect',
        syscall: true,
        args: [
          { index: 0, type: 'int' },
          { index: 1, type: 'sockaddr' },
        ],
        selectors: [
          {
            matchArgs: [
              { index: 1, operator: 'Equal', values: ['/var/run/docker.sock'] },
            ],
            matchActions: enforceAction(enforce),
          },
        ],
      },
    ],
  });
}

/**
 * Policy 4: Sensitive binary execution — block/observe curl, wget, nc, ssh etc.
 * Maps to customer finding C5 (Per-Agent Observability).
 */
function sensitiveBinaryPolicy(options: TetragonRuleOptions): TracingPolicy {
  const enforce = options.enforce ?? false;

  const sensitiveBinaries = [
    '/usr/bin/curl', '/usr/bin/wget', '/usr/bin/nc', '/usr/bin/ncat',
    '/usr/bin/ssh', '/usr/bin/scp', '/usr/bin/rsync', '/usr/bin/ftp',
    '/usr/bin/telnet', '/usr/bin/socat', '/usr/bin/nmap',
    '/bin/curl', '/bin/wget', '/bin/nc', '/bin/ssh',
  ];

  return makePolicy('g0-openclaw-sensitive-binary', {
    kprobes: [
      {
        call: 'sys_execve',
        syscall: true,
        args: [
          { index: 0, type: 'string' },  // filename
        ],
        selectors: [
          {
            matchArgs: [
              { index: 0, operator: 'In', values: sensitiveBinaries },
            ],
            matchActions: enforceAction(enforce),
          },
        ],
      },
    ],
  });
}

/**
 * Policy 5: Credential file protection — block/observe reads of .env files.
 * Maps to customer finding C2 (Secret Duplication).
 */
function credentialProtectionPolicy(options: TetragonRuleOptions): TracingPolicy {
  const enforce = options.enforce ?? false;
  const agentPath = options.agentDataPath;

  return makePolicy('g0-openclaw-credential-protection', {
    kprobes: [
      {
        call: 'sys_openat',
        syscall: true,
        args: [
          { index: 0, type: 'int' },
          { index: 1, type: 'string' },
          { index: 2, type: 'int' },
        ],
        selectors: [
          {
            matchArgs: [
              { index: 1, operator: 'Postfix', values: ['.env'] },
            ],
            matchActions: enforceAction(enforce),
          },
        ],
      },
    ],
  });
}

/**
 * Policy 6: Log tampering prevention — block/observe deletion or truncation of logs.
 * Maps to customer finding C5 (Observability) + audit integrity.
 */
function logTamperingPolicy(options: TetragonRuleOptions): TracingPolicy {
  const enforce = options.enforce ?? false;
  const agentPath = options.agentDataPath;

  return makePolicy('g0-openclaw-log-protection', {
    kprobes: [
      // Block unlink/unlinkat on log files
      {
        call: 'sys_unlinkat',
        syscall: true,
        args: [
          { index: 0, type: 'int' },
          { index: 1, type: 'string' },
          { index: 2, type: 'int' },
        ],
        selectors: [
          {
            matchArgs: [
              { index: 1, operator: 'Prefix', values: [`${agentPath}`] },
            ],
            matchActions: enforceAction(enforce),
          },
        ],
      },
      // Block truncate on log files
      {
        call: 'sys_truncate',
        syscall: true,
        args: [
          { index: 0, type: 'string' },
        ],
        selectors: [
          {
            matchArgs: [
              { index: 0, operator: 'Prefix', values: [`${agentPath}`] },
            ],
            matchActions: enforceAction(enforce),
          },
        ],
      },
    ],
  });
}

// ── Docker Compose Generator ─────────────────────────────────────────────────

function generateDockerCompose(options: TetragonRuleOptions): string {
  const webhookUrl = options.webhookUrl ?? 'http://host.docker.internal:6040/events';

  return `# g0 Tetragon deployment for OpenClaw
# Add this to your docker-compose.yml
# Generated: ${new Date().toISOString()}

  tetragon:
    image: quay.io/cilium/tetragon:v1.3
    container_name: g0-tetragon
    restart: unless-stopped
    pid: host
    privileged: true
    volumes:
      - /sys/kernel:/sys/kernel:ro
      - /proc:/procHost:ro
      - ./tetragon-policies:/etc/tetragon/tetragon.tp.d:ro
    environment:
      - TETRAGON_EXPORT_ALLOWLIST=
      - TETRAGON_EXPORT_FILENAME=/var/log/tetragon/events.log
    # Optional: forward events to g0 daemon via webhook
    # Use tetragon-events-exporter or a sidecar with:
    #   tetra getevents -o json | while read line; do
    #     curl -s -X POST ${webhookUrl} \\
    #       -H "Content-Type: application/json" \\
    #       -d "{\\"source\\":\\"tetragon\\",\\"type\\":\\"tetragon.event\\",\\"data\\":$line}";
    #   done
`;
}

// ── YAML Serializer ──────────────────────────────────────────────────────────

function policyToYaml(policy: TracingPolicy): string {
  // Simple YAML serialization for TracingPolicy CRDs
  const lines: string[] = [];
  lines.push('---');
  lines.push(`apiVersion: ${policy.apiVersion}`);
  lines.push(`kind: ${policy.kind}`);
  lines.push('metadata:');
  lines.push(`  name: ${policy.metadata.name}`);
  if (policy.metadata.labels) {
    lines.push('  labels:');
    for (const [k, v] of Object.entries(policy.metadata.labels)) {
      lines.push(`    ${k}: "${v}"`);
    }
  }
  lines.push('spec:');

  if (policy.spec.kprobes?.length) {
    lines.push('  kprobes:');
    for (const kprobe of policy.spec.kprobes) {
      lines.push(`    - call: "${kprobe.call}"`);
      lines.push(`      syscall: ${kprobe.syscall}`);
      if (kprobe.return) lines.push(`      return: ${kprobe.return}`);
      lines.push('      args:');
      for (const arg of kprobe.args) {
        lines.push(`        - index: ${arg.index}`);
        lines.push(`          type: "${arg.type}"`);
        if (arg.label) lines.push(`          label: "${arg.label}"`);
      }
      if (kprobe.returnArg) {
        lines.push('      returnArg:');
        lines.push(`        index: ${kprobe.returnArg.index}`);
        lines.push(`        type: "${kprobe.returnArg.type}"`);
      }
      lines.push('      selectors:');
      for (const selector of kprobe.selectors) {
        lines.push('        - matchArgs:');
        if (selector.matchArgs) {
          for (const ma of selector.matchArgs) {
            lines.push(`            - index: ${ma.index}`);
            lines.push(`              operator: "${ma.operator}"`);
            lines.push('              values:');
            for (const v of ma.values) {
              lines.push(`                - "${v}"`);
            }
          }
        }
        if (selector.matchBinaries) {
          lines.push('          matchBinaries:');
          for (const mb of selector.matchBinaries) {
            lines.push(`            - operator: "${mb.operator}"`);
            lines.push('              values:');
            for (const v of mb.values) {
              lines.push(`                - "${v}"`);
            }
          }
        }
        if (selector.matchActions) {
          lines.push('          matchActions:');
          for (const ma of selector.matchActions) {
            lines.push(`            - action: "${ma.action}"`);
            if (ma.argError !== undefined) {
              lines.push(`              argError: ${ma.argError}`);
            }
          }
        }
      }
    }
  }

  if (policy.spec.tracepoints?.length) {
    lines.push('  tracepoints:');
    for (const tp of policy.spec.tracepoints) {
      lines.push(`    - subsystem: "${tp.subsystem}"`);
      lines.push(`      event: "${tp.event}"`);
      if (tp.args?.length) {
        lines.push('      args:');
        for (const arg of tp.args) {
          lines.push(`        - index: ${arg.index}`);
          lines.push(`          type: "${arg.type}"`);
        }
      }
      lines.push('      selectors:');
      for (const selector of tp.selectors) {
        lines.push('        - matchActions:');
        if (selector.matchActions) {
          for (const ma of selector.matchActions) {
            lines.push(`            - action: "${ma.action}"`);
          }
        }
      }
    }
  }

  return lines.join('\n');
}

// ── Main Generator ───────────────────────────────────────────────────────────

/**
 * Generate Tetragon TracingPolicies for an OpenClaw deployment.
 *
 * Produces 6 policies covering:
 * - C1: Egress enforcement (sys_connect)
 * - C2: Credential protection (sys_openat on .env)
 * - C3: Docker socket access (sys_openat + sys_connect)
 * - C4: Cross-agent data access (sys_openat)
 * - C5: Sensitive binary execution (sys_execve) + log tampering (sys_unlinkat)
 */
export function generateTetragonRules(options: TetragonRuleOptions): TetragonPolicySet {
  const policies: TracingPolicy[] = [
    egressPolicy(options),
    crossAgentAccessPolicy(options),
    dockerSocketPolicy(options),
    sensitiveBinaryPolicy(options),
    credentialProtectionPolicy(options),
    logTamperingPolicy(options),
  ];

  const yamlParts = policies.map(p => policyToYaml(p));
  const yaml = [
    `# g0 Tetragon TracingPolicies for OpenClaw`,
    `# Generated: ${new Date().toISOString()}`,
    `# Mode: ${options.enforce ? 'ENFORCE (Sigkill on violation)' : 'OBSERVE (Post events only)'}`,
    `# Deploy: cp *.yaml /etc/tetragon/tetragon.tp.d/`,
    `# Requires: Tetragon >= 1.0`,
    '',
    ...yamlParts,
  ].join('\n');

  return {
    policies,
    policyCount: policies.length,
    yaml,
    dockerCompose: generateDockerCompose(options),
  };
}

/** Format a single policy as a standalone YAML file */
export function formatTetragonPolicyFile(policy: TracingPolicy): string {
  return policyToYaml(policy) + '\n';
}

/** Format the Docker Compose snippet */
export function formatTetragonDockerCompose(options: TetragonRuleOptions): string {
  return generateDockerCompose(options);
}
