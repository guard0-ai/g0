/**
 * Attestation packs — signed, standards-mapped evidence of an assessment.
 *
 * Scanners find issues; auditors need evidence. This turns a scan result into a
 * portable attestation: the score, the finding severity profile, and a
 * per-standard control-coverage matrix (which controls the findings touch),
 * bound by a content hash and an optional ed25519 signature.
 */
import * as crypto from 'node:crypto';
import type { Finding, StandardsMapping } from '../types/finding.js';
import type { ScanScore } from '../types/score.js';
import { STANDARDS_INFO } from '../standards/mapping.js';
import type { BomSignature } from '../inventory/sign.js';

export const ATTESTATION_SCHEMA = 'g0-attestation/1';

/** Keys on a finding's StandardsMapping, in stable display order. */
const STANDARD_KEYS: Array<keyof StandardsMapping> = [
  'owaspAgentic', 'owaspAgenticTop10', 'owaspLlmTop10', 'owaspAivss',
  'nistAiRmf', 'iso42001', 'iso23894', 'euAiAct', 'aiuc1', 'mitreAtlas',
];

export interface ControlCoverage {
  control: string;
  findingCount: number;
  severities: Record<string, number>;
}

export interface StandardCoverage {
  key: string;
  name: string;
  url: string;
  findingCount: number;
  controls: ControlCoverage[];
}

export interface AttestationPack {
  schema: string;
  project: string;
  generatedAt: string;
  tool: string;
  hostname: string;
  scan: {
    score: number;
    grade: string;
    capReason?: string;
    totalFindings: number;
    bySeverity: Record<string, number>;
  };
  standards: StandardCoverage[];
  evidence?: { id: string; sha256: string };
  contentHash: string;
  signature?: BomSignature;
}

/** Build per-standard control coverage from a set of findings. */
export function buildStandardsCoverage(findings: Finding[]): StandardCoverage[] {
  const result: StandardCoverage[] = [];

  for (const key of STANDARD_KEYS) {
    // control id -> { count, severities }
    const controls = new Map<string, ControlCoverage>();
    let findingCount = 0;

    for (const f of findings) {
      const ids = (f.standards?.[key] ?? []) as string[];
      if (!ids || ids.length === 0) continue;
      findingCount++;
      for (const id of ids) {
        let entry = controls.get(id);
        if (!entry) {
          entry = { control: id, findingCount: 0, severities: {} };
          controls.set(id, entry);
        }
        entry.findingCount++;
        entry.severities[f.severity] = (entry.severities[f.severity] ?? 0) + 1;
      }
    }

    if (findingCount === 0) continue;

    const info = STANDARDS_INFO[key] ?? { name: String(key), url: '' };
    result.push({
      key: String(key),
      name: info.name,
      url: info.url,
      findingCount,
      controls: [...controls.values()].sort((a, b) => a.control.localeCompare(b.control)),
    });
  }

  return result;
}

function severityProfile(findings: Finding[]): Record<string, number> {
  const by: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) by[f.severity] = (by[f.severity] ?? 0) + 1;
  return by;
}

/** Canonical content hash of a pack, excluding volatile/self fields. */
export function computeAttestationHash(pack: Omit<AttestationPack, 'contentHash' | 'signature'>): string {
  const canonical = {
    schema: pack.schema,
    project: pack.project,
    tool: pack.tool,
    scan: pack.scan,
    standards: pack.standards,
    evidence: pack.evidence ?? null,
  };
  return crypto.createHash('sha256').update(JSON.stringify(canonical)).digest('hex');
}

/** Assemble an attestation pack from a scan score + findings. */
export function buildAttestationPack(params: {
  project: string;
  score: ScanScore;
  findings: Finding[];
  toolVersion: string;
  hostname: string;
  generatedAt: string;
  evidence?: { id: string; sha256: string };
}): AttestationPack {
  const { project, score, findings, toolVersion, hostname, generatedAt, evidence } = params;

  const base: Omit<AttestationPack, 'contentHash' | 'signature'> = {
    schema: ATTESTATION_SCHEMA,
    project,
    generatedAt,
    tool: `g0@${toolVersion}`,
    hostname,
    scan: {
      score: score.overall,
      grade: score.grade,
      ...(score.capReason ? { capReason: score.capReason } : {}),
      totalFindings: findings.length,
      bySeverity: severityProfile(findings),
    },
    standards: buildStandardsCoverage(findings),
    ...(evidence ? { evidence } : {}),
  };

  return { ...base, contentHash: computeAttestationHash(base) };
}
