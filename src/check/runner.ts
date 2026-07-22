import { auditSkillsFromDirectory } from '../mcp/clawhub-auditor.js';
import type { BulkAuditResult } from '../mcp/clawhub-auditor.js';
import { scanInfostealerArtifacts } from '../intelligence/ioc-database.js';
import type { IOCMatch } from '../intelligence/ioc-database.js';
import { scanClaudeEstate } from '../endpoint/claude-estate-scanner.js';
import type { ClaudeEstateResult } from '../endpoint/claude-estate-scanner.js';
import { scanEndpoint } from '../endpoint/scanner.js';
import { planQuarantine } from '../endpoint/quarantine.js';
import type { QuarantineCandidate } from '../endpoint/quarantine.js';
import { computeGrade, SEVERITY_DEDUCTIONS } from '../endpoint/scoring.js';
import type { EndpointGrade, EndpointScanResult, EndpointScore } from '../types/endpoint.js';

// ─── Verdict ─────────────────────────────────────────────────────────────────

export interface CheckVerdictInput {
  endpointScore?: EndpointScore;
  skills: BulkAuditResult;
  infostealerIOCs: IOCMatch[];
  maliciousServers: QuarantineCandidate[];
  claudeEstate: ClaudeEstateResult;
}

export interface CheckVerdict {
  score: number;
  grade: EndpointGrade;
  capped: boolean;
  headline: string;
}

// A known-malicious component must never grade above F, no matter how clean
// the rest of the estate looks (D starts at 40).
const CAPPED_SCORE = 35;

function plural(n: number, word: string): string {
  return n === 1 ? word : `${word}s`;
}

function buildHeadline(input: CheckVerdictInput): string {
  const skillsMal = input.skills.summary.malicious;
  const serversMal = input.maliciousServers.length;
  const skillsTotal = input.skills.summary.total;

  if (skillsMal > 0 && serversMal > 0) {
    return `${skillsMal} known-malicious ${plural(skillsMal, 'skill')} and ${serversMal} known-malicious MCP ${plural(serversMal, 'server')} installed`;
  }
  if (skillsMal > 0) {
    return `${skillsMal} of ${skillsTotal} installed skills ${skillsMal === 1 ? 'is' : 'are'} known-malicious`;
  }
  if (serversMal > 0) {
    return `${serversMal} known-malicious MCP ${plural(serversMal, 'server')} in your IDE configs`;
  }
  if (input.infostealerIOCs.length > 0) {
    const n = input.infostealerIOCs.length;
    return `${n} infostealer ${plural(n, 'artifact')} detected on this machine`;
  }
  if (input.claudeEstate.summary.critical > 0) {
    const n = input.claudeEstate.summary.critical;
    return `${n} critical ${plural(n, 'finding')} in your Claude skills/plugins/hooks`;
  }
  if (skillsTotal > 0) {
    return `No known-malicious components across ${skillsTotal} installed ${plural(skillsTotal, 'skill')}`;
  }
  return 'No known-malicious components found';
}

export function computeCheckVerdict(input: CheckVerdictInput): CheckVerdict {
  const { endpointScore, skills, infostealerIOCs, maliciousServers } = input;

  let score: number;
  if (endpointScore) {
    score = endpointScore.total;
  } else {
    const bySeverity = skills.summary.findingsBySeverity;
    const deducted =
      bySeverity.critical * SEVERITY_DEDUCTIONS.critical +
      bySeverity.high * SEVERITY_DEDUCTIONS.high +
      bySeverity.medium * SEVERITY_DEDUCTIONS.medium +
      bySeverity.low * SEVERITY_DEDUCTIONS.low;
    score = Math.max(0, 100 - deducted);
  }

  const capped =
    skills.summary.malicious > 0 ||
    maliciousServers.length > 0 ||
    infostealerIOCs.length > 0 ||
    input.claudeEstate.summary.critical > 0;
  if (capped) {
    score = Math.min(score, CAPPED_SCORE);
  }

  return { score, grade: computeGrade(score), capped, headline: buildHeadline(input) };
}

// ─── Runner ──────────────────────────────────────────────────────────────────

export interface CheckOptions {
  rootPath?: string;
  /** Run the full endpoint (machine) scan, including the IDE-config server audit (default true). */
  endpoint?: boolean;
  /** Home directory for the Claude estate scan (test injection; default os.homedir()). */
  homeDir?: string;
}

export interface CheckResult {
  endpoint?: EndpointScanResult;
  skills: BulkAuditResult;
  infostealerIOCs: IOCMatch[];
  /** MCP servers in IDE configs matching the known-malicious IOC database. */
  maliciousServers: QuarantineCandidate[];
  /** The Claude-native supply chain: skills, plugins, agents, hooks, Desktop extensions. */
  claudeEstate: ClaudeEstateResult;
  verdict: CheckVerdict;
}

export async function runCheck(options: CheckOptions = {}): Promise<CheckResult> {
  const rootPath = options.rootPath ?? process.cwd();
  const runEndpoint = options.endpoint !== false;

  const [endpoint, skills] = await Promise.all([
    runEndpoint ? scanEndpoint({}) : Promise.resolve(undefined),
    auditSkillsFromDirectory(rootPath),
  ]);
  const infostealerIOCs = runEndpoint ? scanInfostealerArtifacts() : [];
  const maliciousServers = runEndpoint ? planQuarantine().candidates : [];
  const claudeEstate = scanClaudeEstate({ homeDir: options.homeDir });

  const verdict = computeCheckVerdict({
    endpointScore: endpoint?.score,
    skills,
    infostealerIOCs,
    maliciousServers,
    claudeEstate,
  });

  return { endpoint, skills, infostealerIOCs, maliciousServers, claudeEstate, verdict };
}
