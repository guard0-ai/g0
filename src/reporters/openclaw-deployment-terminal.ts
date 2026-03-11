import chalk from 'chalk';
import type { DeploymentAuditResult, AIAuditInsight } from '../mcp/openclaw-deployment.js';
import type { HardeningCheck } from '../mcp/openclaw-hardening.js';
import type { RiskAcceptance } from '../types/config.js';
import { isCheckAccepted } from '../config/risk-acceptance.js';

/** Map g0 check IDs to security audit categories for cross-referencing. */
const CHECK_TO_CATEGORY: Record<string, string> = {
  'OC-H-019': 'NET',   // Egress filtering (iptables)
  'OC-H-020': 'CRED',  // Secret duplication
  'OC-H-021': 'DOCK',  // Docker socket mount
  'OC-H-022': 'DATA',  // Data privacy boundaries
  'OC-H-023': 'O11Y',  // Per-agent observability (infra)
  'OC-H-031': 'O11Y',  // Per-agent observability (tool call logging)
  'OC-H-032': 'O11Y',  // Per-agent observability (file access auditing)
  'OC-H-033': 'O11Y',  // Per-agent observability (network connection logging)
  'OC-H-024': 'DATA',  // Backups
  'OC-H-025': 'DOCK',  // Container root user
  'OC-H-026': 'DOCK',  // Docker log rotation
  'OC-H-027': 'DOCK',  // Shared bridge network
  'OC-H-028': 'DATA',  // Session transcript encryption
  'OC-H-029': 'DOCK',  // Docker image scanning
  'OC-H-030': 'CRED',  // Overprivileged env injection
  'OC-H-034': 'DATA',  // Backup encryption & retention
  'OC-H-035': 'SYS',   // Kernel reboot pending
  'OC-H-036': 'NET',   // Tailscale account & ACL
  'OC-H-037': 'FORNS', // Session transcript forensics
  'OC-H-056': 'DOCK',  // Container cap_drop ALL
  'OC-H-057': 'DOCK',  // Container no-new-privileges
  'OC-H-058': 'DOCK',  // Read-only root filesystem
  'OC-H-059': 'DOCK',  // Container memory/CPU limits
  'OC-H-060': 'DOCK',  // Container not using host network
  'OC-H-061': 'DOCK',  // OPENCLAW_DISABLE_BONJOUR set
  'OC-H-062': 'DOCK',  // No sensitive volume mounts
  'OC-H-063': 'DOCK',  // Container image verification
  'OC-H-064': 'CRED',  // No secrets in container process args
};

type CheckStatus = HardeningCheck['status'];
type CheckSeverity = HardeningCheck['severity'];

function statusIcon(status: CheckStatus): string {
  switch (status) {
    case 'pass':  return chalk.green('PASS');
    case 'fail':  return chalk.red.bold('FAIL');
    case 'error': return chalk.dim('ERR ');
    case 'skip':  return chalk.dim('SKIP');
  }
}

function severityLabel(sev: CheckSeverity): string {
  switch (sev) {
    case 'critical': return chalk.red.bold('[CRITICAL]');
    case 'high':     return chalk.red('[HIGH]    ');
    case 'medium':   return chalk.yellow('[MEDIUM]  ');
    case 'low':      return chalk.dim('[LOW]     ');
  }
}

interface Remediation {
  category: string;
  title: string;
  steps: string[];
}

function getRemediationGuidance(failedChecks: HardeningCheck[]): Remediation[] {
  const remediations: Remediation[] = [];
  const seenCategories = new Set<string>();

  for (const check of failedChecks) {
    const category = CHECK_TO_CATEGORY[check.id];
    if (!category || seenCategories.has(category)) continue;
    seenCategories.add(category);

    switch (check.id) {
      case 'OC-H-019':
        remediations.push({
          category: 'NET', title: 'Egress Filtering',
          steps: [
            'Configure egressAllowlist in daemon.json with allowed destinations',
            'g0 generates iptables -I DOCKER-USER rules from your allowlist',
            'Enable enforcement.applyEgressRules to auto-apply on violations',
            'Fast egress loop (60s) catches violations between full audits',
          ],
        });
        break;
      case 'OC-H-020':
        remediations.push({
          category: 'CRED', title: 'Secret Duplication',
          steps: [
            'Issue unique API keys per agent (rotate shared credentials)',
            'Use a secret manager (Vault, AWS SSM) instead of .env files',
          ],
        });
        break;
      case 'OC-H-021':
        remediations.push({
          category: 'DOCK', title: 'Docker Socket Mount',
          steps: [
            'Remove docker.sock mount from agent containers',
            'If Docker API is needed, use a socket proxy with read-only access',
          ],
        });
        break;
      case 'OC-H-022':
        remediations.push({
          category: 'DATA', title: 'Data Privacy Boundaries',
          steps: [
            'Set file permissions: chmod 600 on all .env files',
            'Use separate Docker volumes per agent (no shared mounts)',
          ],
        });
        break;
      case 'OC-H-023':
      case 'OC-H-031':
      case 'OC-H-032':
      case 'OC-H-033':
        if (!seenCategories.has('O11Y-done')) {
          seenCategories.add('O11Y-done');
          remediations.push({
            category: 'O11Y', title: 'Per-Agent Observability',
            steps: [
              'g0 generates auditd rules for your agent paths (file + network + exec)',
              'g0 generates Falco rules for runtime container monitoring (eBPF)',
              'Install: sudo cp g0-openclaw.rules /etc/audit/rules.d/ && augenrules --load',
              'Install: cp g0-openclaw-falco.yaml /etc/falco/rules.d/',
              'Set openclaw.json: { "logging": { "toolCalls": true, "level": "verbose" } }',
            ],
          });
        }
        break;
      case 'OC-H-024':
        remediations.push({
          category: 'DATA', title: 'Backups',
          steps: [
            'Configure automated backups with cron or systemd timer',
            'Back up agent data, session transcripts, and configuration',
          ],
        });
        break;
      case 'OC-H-025':
        remediations.push({
          category: 'DOCK', title: 'Container Root User',
          steps: [
            'Add USER directive in Dockerfile (e.g., USER 1000:1000)',
            'Set user in docker-compose: user: "1000:1000"',
          ],
        });
        break;
      case 'OC-H-026':
        remediations.push({
          category: 'DOCK', title: 'Docker Log Rotation',
          steps: [
            'Add to /etc/docker/daemon.json: { "log-driver": "json-file", "log-opts": { "max-size": "10m", "max-file": "3" } }',
          ],
        });
        break;
      case 'OC-H-027':
        remediations.push({
          category: 'DOCK', title: 'Shared Bridge Network',
          steps: [
            'Create isolated Docker networks per agent: docker network create oc-agent-X',
            'Assign each container to its own network in docker-compose',
          ],
        });
        break;
      case 'OC-H-028':
        remediations.push({
          category: 'DATA', title: 'Session Transcript Encryption',
          steps: [
            'Enable encryption-at-rest for session .jsonl files',
            'Use LUKS/dm-crypt for the volume or application-level AES-256-GCM',
          ],
        });
        break;
      case 'OC-H-029':
        remediations.push({
          category: 'DOCK', title: 'Docker Image Scanning',
          steps: [
            'Add Trivy/Grype to CI: trivy image openclaw:latest',
            'Block deploys on critical CVEs',
          ],
        });
        break;
      case 'OC-H-030':
        remediations.push({
          category: 'CRED', title: 'Overprivileged Env Injection',
          steps: [
            'Audit env vars per agent — remove unused keys',
            'Use env_file with minimal scoped credentials',
          ],
        });
        break;
      case 'OC-H-034':
        remediations.push({
          category: 'DATA', title: 'Backup Encryption & Retention',
          steps: [
            'Enable encryption: restic uses encryption by default; borg: use --encryption=repokey-blake2',
            'Add retention policy: --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune',
            'Install GPG or age for backup encryption key management',
          ],
        });
        break;
      case 'OC-H-035':
        if (!seenCategories.has('SYS')) {
          seenCategories.add('SYS');
          remediations.push({
            category: 'SYS', title: 'Kernel Reboot Pending',
            steps: [
              'Schedule a maintenance window and reboot to apply kernel security patches',
              'Enable automatic security updates: apt install unattended-upgrades (Debian/Ubuntu)',
              'Add reboot check to CI/CD pipeline: test ! -f /var/run/reboot-required',
            ],
          });
        }
        break;
      case 'OC-H-036':
        remediations.push({
          category: 'NET', title: 'Tailscale Account & ACL',
          steps: [
            'Use an organization Tailscale account (not personal email) for production deployments',
            'Configure ACLs to restrict which devices can access the OpenClaw gateway',
            'Enable MagicDNS with a custom domain for service discovery',
          ],
        });
        break;
      case 'OC-H-064':
        remediations.push({
          category: 'CRED', title: 'Secrets Exposed in Process Arguments',
          steps: [
            'Never pass secrets via docker run -e FLAG=value — they are visible to all users via ps aux',
            'Use Docker secrets: echo "secret" | docker secret create my_secret - ; then reference in compose',
            'Or use --env-file with restricted permissions: docker run --env-file .env (chmod 600 .env)',
            'For Kubernetes: use Secrets objects mounted as files, not env vars',
          ],
        });
        break;
      case 'OC-H-037':
        remediations.push({
          category: 'FORNS', title: 'Session Transcript Forensics',
          steps: [
            'Review flagged session transcripts for data exfiltration, reverse shells, or privilege escalation',
            'Rotate any credentials exposed in session outputs',
            'Enable real-time monitoring with g0 daemon for continuous session scanning',
          ],
        });
        break;
    }
  }

  return remediations;
}

export function reportDeploymentAuditTerminal(
  result: DeploymentAuditResult,
  riskAccepted?: RiskAcceptance[],
): void {
  console.log('');
  console.log(chalk.bold('  OpenClaw Deployment Audit'));
  console.log(chalk.dim('  ' + '\u2500'.repeat(74)));

  const colW = { category: 5, id: 10, name: 36, sev: 12, status: 6 };
  let acceptedCount = 0;

  for (const check of result.checks) {
    const categoryTag = CHECK_TO_CATEGORY[check.id] ?? '  ';
    const acceptance = riskAccepted ? isCheckAccepted(check.id, riskAccepted) : null;

    if (acceptance && check.status === 'fail') {
      // Show as accepted instead of failed
      const row = [
        chalk.cyan(categoryTag.padEnd(colW.category)),
        check.id.padEnd(colW.id),
        chalk.dim(check.name.padEnd(colW.name).substring(0, colW.name)),
        severityLabel(check.severity),
        chalk.bgGreen.black('ACCEPTED'),
      ].join('  ');
      console.log(`  ${row}`);
      console.log(`          ${chalk.dim(acceptance.reason)}`);
      acceptedCount++;
      continue;
    }

    const row = [
      chalk.cyan(categoryTag.padEnd(colW.category)),
      check.id.padEnd(colW.id),
      check.name.padEnd(colW.name).substring(0, colW.name),
      severityLabel(check.severity),
      statusIcon(check.status),
    ].join('  ');
    console.log(`  ${row}`);
    if (check.status === 'fail') {
      console.log(`          ${chalk.dim(check.detail)}`);
    }
  }

  // Agent config summary
  if (result.agentConfigResult) {
    const ac = result.agentConfigResult;
    console.log('');
    console.log(chalk.bold('  Agent Credentials'));
    console.log(chalk.dim('  ' + '\u2500'.repeat(74)));
    console.log(`  Agents scanned: ${ac.agentsScanned}  |  Credentials: ${ac.totalCredentials}  |  Duplicate groups: ${ac.duplicateGroups.length}  |  Overprivileged: ${ac.overprivileged.length}`);
    if (ac.duplicateGroups.length > 0) {
      for (const dup of ac.duplicateGroups.slice(0, 5)) {
        console.log(`    ${chalk.red('\u25cf')} ${chalk.bold(dup.key)} shared by ${dup.agents.join(', ')}`);
      }
      if (ac.duplicateGroups.length > 5) {
        console.log(chalk.dim(`    ... and ${ac.duplicateGroups.length - 5} more`));
      }
    }
  }

  // Egress summary
  if (result.egressResult) {
    const eg = result.egressResult;
    console.log('');
    console.log(chalk.bold('  Egress Monitor'));
    console.log(chalk.dim('  ' + '\u2500'.repeat(74)));
    console.log(`  Total connections: ${eg.totalConnections}  |  Allowed: ${eg.allowedConnections}  |  Violations: ${eg.violations.length}`);
    if (eg.violations.length > 0) {
      for (const v of eg.violations.slice(0, 5)) {
        const dest = v.connection.remoteHost || v.connection.remote;
        const container = v.connection.container ? ` (${v.connection.container})` : '';
        console.log(`    ${chalk.red('\u25cf')} ${dest}${container} \u2014 ${v.reason}`);
      }
      if (eg.violations.length > 5) {
        console.log(chalk.dim(`    ... and ${eg.violations.length - 5} more`));
      }
    }
  }

  // Session forensics summary
  if (result.forensicsResults && result.forensicsResults.length > 0) {
    const totalFindings = result.forensicsResults.reduce((s, r) => s + r.findings.length, 0);
    console.log('');
    console.log(chalk.bold('  Session Forensics'));
    console.log(chalk.dim('  ' + '\u2500'.repeat(74)));
    console.log(`  ${chalk.red(`${totalFindings} suspicious findings`)} across ${result.forensicsResults.length} agent session(s)`);
    for (const r of result.forensicsResults.slice(0, 5)) {
      for (const f of r.findings.slice(0, 3)) {
        const sevColor = f.severity === 'critical' ? chalk.red.bold : f.severity === 'high' ? chalk.red : chalk.yellow;
        console.log(`    ${sevColor('\u25cf')} [${f.severity}] ${f.type}: ${chalk.dim(f.content.slice(0, 80))}`);
      }
      if (r.findings.length > 3) {
        console.log(chalk.dim(`    ... and ${r.findings.length - 3} more in ${r.agentId}`));
      }
    }
  }

  // Remediation guidance for failed checks (exclude accepted)
  const acceptedIds = new Set(
    (riskAccepted ?? []).filter(a => {
      try { return !a.expires || new Date(a.expires) > new Date(); } catch { return true; }
    }).map(a => a.rule),
  );
  const failedChecks = result.checks.filter(c => c.status === 'fail' && !acceptedIds.has(c.id));
  if (failedChecks.length > 0) {
    const remediations = getRemediationGuidance(failedChecks);
    if (remediations.length > 0) {
      console.log('');
      console.log(chalk.bold('  Remediation'));
      console.log(chalk.dim('  ' + '\u2500'.repeat(74)));
      for (const r of remediations) {
        console.log(`  ${chalk.cyan(r.category)}  ${r.title}`);
        for (const step of r.steps) {
          console.log(`    ${chalk.dim('\u2192')} ${chalk.dim(step)}`);
        }
      }
      console.log('');
      console.log(chalk.dim('  Run with --json to get machine-readable output including generated rules.'));
      console.log(chalk.dim('  Egress rules: g0 generates iptables rules from your egressAllowlist config.'));
      console.log(chalk.dim('  Observability: g0 generates auditd + Falco rules for your agent paths.'));
    }
  }

  // Overall summary
  const s = result.summary;
  const overallColor = s.overallStatus === 'secure' ? chalk.green
    : s.overallStatus === 'warn' ? chalk.yellow
    : chalk.red.bold;

  console.log('');
  console.log(chalk.bold('  Summary'));
  console.log(chalk.dim('  ' + '\u2500'.repeat(74)));
  const effectiveFailed = s.failed - acceptedCount;
  const effectiveStatus = acceptedCount > 0 && effectiveFailed === 0 && s.overallStatus === 'critical'
    ? 'warn' : s.overallStatus;
  const effectiveColor = effectiveStatus === 'secure' ? chalk.green
    : effectiveStatus === 'warn' ? chalk.yellow
    : chalk.red.bold;

  console.log(`  Overall: ${effectiveColor(effectiveStatus.toUpperCase())}  (${s.total} checks)`);
  const parts = [
    chalk.green(`Passed: ${s.passed}`),
    chalk.red(`Failed: ${effectiveFailed}`),
  ];
  if (acceptedCount > 0) parts.push(chalk.green(`Accepted: ${acceptedCount}`));
  parts.push(chalk.dim(`Errors: ${s.errors}`));
  parts.push(chalk.dim(`Skipped: ${s.skipped}`));
  console.log(`  ${parts.join('  ')}`);
  console.log('');
}

export function formatAIInsights(insights: AIAuditInsight): void {
  if (insights.attackChains.length === 0 && insights.prioritizedRemediation.length === 0) {
    return;
  }

  // Attack chains
  if (insights.attackChains.length > 0) {
    console.log('');
    console.log(chalk.bold('  AI Attack Chain Analysis'));
    console.log(chalk.dim('  ' + '\u2500'.repeat(74)));

    for (const chain of insights.attackChains) {
      const sevColor = chain.severity === 'critical' ? chalk.red.bold
        : chain.severity === 'high' ? chalk.red
        : chalk.yellow;
      console.log(`  ${sevColor(`[${chain.severity.toUpperCase()}]`)} ${chalk.bold(chain.name)}`);
      console.log(`    Checks: ${chain.failedChecks.join(' + ')}`);
      console.log(`    ${chalk.dim(chain.narrative)}`);
      console.log('');
    }
  }

  // Prioritized remediation
  if (insights.prioritizedRemediation.length > 0) {
    console.log(chalk.bold('  Prioritized Remediation'));
    console.log(chalk.dim('  ' + '\u2500'.repeat(74)));

    for (const item of insights.prioritizedRemediation) {
      const blocks = item.blocksChains.length > 0
        ? chalk.dim(` (blocks: ${item.blocksChains.join(', ')})`)
        : '';
      console.log(`  ${chalk.cyan(`${item.order}.`)} ${item.checkId} — ${item.reason}${blocks}`);
    }
    console.log('');
  }

  // Overall risk narrative
  if (insights.overallRiskNarrative) {
    console.log(chalk.bold('  Risk Assessment'));
    console.log(chalk.dim('  ' + '\u2500'.repeat(74)));
    console.log(`  ${chalk.dim(insights.overallRiskNarrative)}`);
    console.log('');
  }
}
