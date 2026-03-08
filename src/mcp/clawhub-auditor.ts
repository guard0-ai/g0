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

const DEFAULT_REGISTRY = 'https://clawhub.ai';
const CLAWHAVOC_IOC_PATTERN = /clawback\d+\.onion|\.claw_(?:update|install|exec|payload|hook)\s*\(/i;

// Simple in-memory cache for registry lookups to avoid duplicate queries
const registryCache = new Map<string, { info: SkillRegistryInfo; ts: number }>();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function computeTrustScore(
  registryInfo: SkillRegistryInfo | undefined,
  staticFindings: MCPFinding[],
  registryUrl = DEFAULT_REGISTRY,
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
    if (registryInfo.registry !== registryUrl) {
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

async function fetchSkillRegistryInfo(skillName: string, registryUrl = DEFAULT_REGISTRY): Promise<SkillRegistryInfo> {
  const cacheKey = `${registryUrl}:${skillName}`;
  const cached = registryCache.get(cacheKey);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    return cached.info;
  }

  const url = `${registryUrl}/v1/skills/${encodeURIComponent(skillName)}`;
  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(8000),
      headers: { 'User-Agent': 'g0-security-scanner/1.0' },
    });

    if (!response.ok) {
      const info: SkillRegistryInfo = { name: skillName, verified: false, registry: registryUrl, found: false };
      registryCache.set(cacheKey, { info, ts: Date.now() });
      return info;
    }

    const data = await response.json() as Record<string, unknown>;

    // Validate response fields — don't trust arbitrary JSON shapes
    const publisher = typeof data.publisher === 'string' ? data.publisher : undefined;
    const verified = typeof data.verified === 'boolean' ? data.verified : false;
    const downloads = typeof data.downloads === 'number' && data.downloads >= 0 ? data.downloads : undefined;
    const publishedAt = typeof data.publishedAt === 'string' ? data.publishedAt : undefined;

    let ageInDays: number | undefined;
    if (publishedAt) {
      const pubDate = new Date(publishedAt);
      // Validate the date is valid and not in the future
      if (!isNaN(pubDate.getTime()) && pubDate.getTime() <= Date.now()) {
        ageInDays = Math.floor((Date.now() - pubDate.getTime()) / (86_400_000));
      }
    }

    const info: SkillRegistryInfo = {
      name: skillName,
      publisher,
      verified,
      downloads,
      ageInDays,
      registry: registryUrl,
      found: true,
    };
    registryCache.set(cacheKey, { info, ts: Date.now() });
    return info;
  } catch {
    const info: SkillRegistryInfo = { name: skillName, verified: false, registry: registryUrl, found: false };
    registryCache.set(cacheKey, { info, ts: Date.now() });
    return info;
  }
}

export async function auditSkill(
  skillName: string,
  content?: string,
  options?: { registryUrl?: string },
): Promise<SkillAuditResult> {
  const registryUrl = options?.registryUrl ?? DEFAULT_REGISTRY;
  const registryInfo = await fetchSkillRegistryInfo(skillName, registryUrl);

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

  const { score, risks } = computeTrustScore(registryInfo, staticFindings, registryUrl);
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

    // Derive skill name from directory — use parent dir name (e.g., "skills/web-search/SKILL.md" → "web-search/SKILL")
    const parentDir = path.basename(path.dirname(fileInfo.path));
    const baseName = path.basename(fileInfo.path, '.md');
    const skillName = parentDir === '.' ? baseName : `${parentDir}/${baseName}`;
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

export async function auditSkillsFromList(
  skills: string[],
  options?: { registryUrl?: string },
): Promise<BulkAuditResult> {
  // Deduplicate skill names before querying
  const uniqueSkills = [...new Set(skills)];
  const results = await Promise.all(uniqueSkills.map(s => auditSkill(s, undefined, options)));
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
