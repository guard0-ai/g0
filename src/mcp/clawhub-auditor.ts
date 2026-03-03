import * as fs from 'node:fs';
import * as path from 'node:path';
import { scanOpenClawFiles } from './openclaw-scanner.js';
import type { MCPFinding, MCPFindingSeverity } from '../types/mcp-scan.js';

export type TrustLevel = 'trusted' | 'caution' | 'untrusted' | 'malicious';

export interface SkillRegistryInfo {
  name: string;
  publisher?: string;
  verified: boolean;
  downloads?: number;
  ageInDays?: number;
  registry: string;
  found: boolean;
}

export interface SkillAuditResult {
  skillName: string;
  filePath?: string;
  registryInfo?: SkillRegistryInfo;
  staticFindings: MCPFinding[];
  trustScore: number;
  trustLevel: TrustLevel;
  risks: string[];
}

export interface BulkAuditResult {
  skills: SkillAuditResult[];
  summary: {
    total: number;
    trusted: number;
    caution: number;
    untrusted: number;
    malicious: number;
    totalFindings: number;
    findingsBySeverity: Record<MCPFindingSeverity, number>;
  };
}

const CLAWHUB_REGISTRY = 'https://registry.clawhub.io';
const CLAWHAVOC_IOC_PATTERN = /clawback\d+\.onion|\.claw_update\s*\(/i;

function computeTrustScore(
  registryInfo: SkillRegistryInfo | undefined,
  staticFindings: MCPFinding[],
): { score: number; risks: string[] } {
  const risks: string[] = [];
  let score = 100;

  // Check for ClawHavoc IOCs first — immediate override to 0
  const hasMaliciousIOC = staticFindings.some(
    f => f.type === 'openclaw-clawhavoc-c2-ioc' || f.type === 'openclaw-clawhavoc-hook',
  );
  if (hasMaliciousIOC) {
    risks.push('ClawHavoc malware IOC detected — skill is malicious');
    return { score: 0, risks };
  }

  if (registryInfo) {
    if (!registryInfo.verified) {
      score -= 20;
      risks.push('Unverified publisher');
    }
    if (registryInfo.downloads !== undefined && registryInfo.downloads < 100) {
      score -= 15;
      risks.push(`Low download count (${registryInfo.downloads})`);
    }
    if (registryInfo.ageInDays !== undefined && registryInfo.ageInDays < 30) {
      score -= 20;
      risks.push(`Recently published (${registryInfo.ageInDays} days old)`);
    }
    if (registryInfo.registry !== CLAWHUB_REGISTRY) {
      score -= 15;
      risks.push(`Community (non-official) registry: ${registryInfo.registry}`);
    }
    if (!registryInfo.found) {
      score -= 25;
      risks.push('Skill not found in official registry');
    }
  } else {
    score -= 20;
    risks.push('Registry information unavailable');
  }

  // Static finding deductions
  for (const finding of staticFindings) {
    if (finding.severity === 'critical') {
      score -= 50;
      risks.push(`Critical finding: ${finding.title}`);
    } else if (finding.severity === 'high') {
      score -= 25;
      risks.push(`High finding: ${finding.title}`);
    } else if (finding.severity === 'medium') {
      score -= 10;
      risks.push(`Medium finding: ${finding.title}`);
    }
  }

  return { score: Math.max(0, score), risks };
}

function scoreToLevel(score: number): TrustLevel {
  if (score >= 80) return 'trusted';
  if (score >= 50) return 'caution';
  if (score >= 20) return 'untrusted';
  return 'malicious';
}

async function fetchSkillRegistryInfo(skillName: string): Promise<SkillRegistryInfo> {
  const url = `${CLAWHUB_REGISTRY}/v1/skills/${encodeURIComponent(skillName)}`;
  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(8000),
      headers: { 'User-Agent': 'g0-security-scanner/1.0' },
    });

    if (!response.ok) {
      return { name: skillName, verified: false, registry: CLAWHUB_REGISTRY, found: false };
    }

    const data = await response.json() as {
      publisher?: string;
      verified?: boolean;
      downloads?: number;
      publishedAt?: string;
    };

    const ageInDays = data.publishedAt
      ? Math.floor((Date.now() - new Date(data.publishedAt).getTime()) / (1000 * 60 * 60 * 24))
      : undefined;

    return {
      name: skillName,
      publisher: data.publisher,
      verified: data.verified ?? false,
      downloads: data.downloads,
      ageInDays,
      registry: CLAWHUB_REGISTRY,
      found: true,
    };
  } catch {
    return { name: skillName, verified: false, registry: CLAWHUB_REGISTRY, found: false };
  }
}

export async function auditSkill(skillName: string, content?: string): Promise<SkillAuditResult> {
  const registryInfo = await fetchSkillRegistryInfo(skillName);

  let staticFindings: MCPFinding[] = [];
  if (content) {
    // Scan provided content directly by writing to temp and scanning, or inline scan
    const hasMaliciousIOC = CLAWHAVOC_IOC_PATTERN.test(content);
    if (hasMaliciousIOC) {
      staticFindings.push({
        severity: 'critical',
        type: 'openclaw-clawhavoc-c2-ioc',
        title: 'ClawHavoc C2 IOC in skill content',
        description: 'Skill content contains a ClawHavoc malware campaign indicator.',
        file: skillName,
      });
    }
  }

  const { score, risks } = computeTrustScore(registryInfo, staticFindings);
  return {
    skillName,
    registryInfo,
    staticFindings,
    trustScore: score,
    trustLevel: scoreToLevel(score),
    risks,
  };
}

export async function auditSkillsFromDirectory(rootPath: string): Promise<BulkAuditResult> {
  const resolvedRoot = path.resolve(rootPath);
  const openClawFiles = scanOpenClawFiles(resolvedRoot);
  const results: SkillAuditResult[] = [];

  for (const fileInfo of openClawFiles) {
    if (fileInfo.fileType !== 'SKILL.md') continue;

    const skillName = path.basename(path.dirname(fileInfo.path)) + '/' + path.basename(fileInfo.path, '.md');
    const { score, risks } = computeTrustScore(undefined, fileInfo.findings);

    results.push({
      skillName,
      filePath: fileInfo.path,
      staticFindings: fileInfo.findings,
      trustScore: score,
      trustLevel: scoreToLevel(score),
      risks,
    });
  }

  // Also check openclaw.json for registry-level issues
  const configFiles = openClawFiles.filter(f => f.fileType === 'openclaw.json');
  for (const cf of configFiles) {
    if (cf.findings.length > 0) {
      const { score, risks } = computeTrustScore(undefined, cf.findings);
      results.push({
        skillName: 'openclaw.json',
        filePath: cf.path,
        staticFindings: cf.findings,
        trustScore: score,
        trustLevel: scoreToLevel(score),
        risks,
      });
    }
  }

  return buildBulkResult(results);
}

export async function auditSkillsFromList(skills: string[]): Promise<BulkAuditResult> {
  const results = await Promise.all(skills.map(s => auditSkill(s)));
  return buildBulkResult(results);
}

function buildBulkResult(skills: SkillAuditResult[]): BulkAuditResult {
  const allFindings = skills.flatMap(s => s.staticFindings);
  const findingsBySeverity: Record<MCPFindingSeverity, number> = {
    critical: allFindings.filter(f => f.severity === 'critical').length,
    high: allFindings.filter(f => f.severity === 'high').length,
    medium: allFindings.filter(f => f.severity === 'medium').length,
    low: allFindings.filter(f => f.severity === 'low').length,
  };

  return {
    skills,
    summary: {
      total: skills.length,
      trusted: skills.filter(s => s.trustLevel === 'trusted').length,
      caution: skills.filter(s => s.trustLevel === 'caution').length,
      untrusted: skills.filter(s => s.trustLevel === 'untrusted').length,
      malicious: skills.filter(s => s.trustLevel === 'malicious').length,
      totalFindings: allFindings.length,
      findingsBySeverity,
    },
  };
}
