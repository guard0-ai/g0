import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { version: g0Version } = require('../../package.json');

const G0_DIR = path.join(os.homedir(), '.g0');
const EVIDENCE_DIR = path.join(G0_DIR, 'evidence');

export type EvidenceType = 'scan' | 'test' | 'audit' | 'runtime' | 'policy';

export interface EvidenceRecord {
  id: string;
  type: EvidenceType;
  timestamp: string;
  source: string;
  summary: string;
  data: Record<string, unknown>;
  standards?: string[];
  sha256: string;
  hostname: string;
  version: string;
}

export interface ComplianceReport {
  standard: string;
  generatedAt: string;
  evidenceCount: number;
  records: EvidenceRecord[];
  coveragePercentage: number;
}

const STANDARD_REQUIRED_TYPES: Record<string, EvidenceType[]> = {
  'owasp-asi': ['scan', 'test', 'runtime'],
  'nist-ai-rmf': ['scan', 'audit', 'policy'],
  'eu-ai-act': ['scan', 'test', 'audit', 'policy', 'runtime'],
};

/** Overridable base directory for testing. */
let evidenceBaseDir = EVIDENCE_DIR;

export function setEvidenceDir(dir: string): void {
  evidenceBaseDir = dir;
}

export function resetEvidenceDir(): void {
  evidenceBaseDir = EVIDENCE_DIR;
}

function hashData(data: Record<string, unknown>): string {
  return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

function monthDir(timestamp: string): string {
  const d = new Date(timestamp);
  const yyyy = d.getUTCFullYear();
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  return `${yyyy}-${mm}`;
}

export function createEvidenceRecord(
  type: EvidenceType,
  source: string,
  summary: string,
  data: Record<string, unknown>,
  standards?: string[],
): EvidenceRecord {
  const id = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const sha256 = hashData(data);

  const record: EvidenceRecord = {
    id,
    type,
    timestamp,
    source,
    summary,
    data,
    ...(standards ? { standards } : {}),
    sha256,
    hostname: os.hostname(),
    version: g0Version,
  };

  const dir = path.join(evidenceBaseDir, monthDir(timestamp));
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(record, null, 2));

  return record;
}

export function listEvidence(options?: {
  type?: EvidenceType;
  since?: string;
  standard?: string;
}): EvidenceRecord[] {
  if (!fs.existsSync(evidenceBaseDir)) return [];

  const records: EvidenceRecord[] = [];
  const monthDirs = fs.readdirSync(evidenceBaseDir).filter((d) => {
    const full = path.join(evidenceBaseDir, d);
    return fs.statSync(full).isDirectory();
  });

  for (const md of monthDirs) {
    const dirPath = path.join(evidenceBaseDir, md);
    const files = fs.readdirSync(dirPath).filter((f) => f.endsWith('.json'));
    for (const file of files) {
      try {
        const content = fs.readFileSync(path.join(dirPath, file), 'utf-8');
        const record: EvidenceRecord = JSON.parse(content);
        records.push(record);
      } catch {
        // skip malformed files
      }
    }
  }

  let filtered = records;

  if (options?.type) {
    filtered = filtered.filter((r) => r.type === options.type);
  }

  if (options?.since) {
    const sinceDate = new Date(options.since).getTime();
    filtered = filtered.filter((r) => new Date(r.timestamp).getTime() >= sinceDate);
  }

  if (options?.standard) {
    filtered = filtered.filter((r) => r.standards?.includes(options.standard!));
  }

  return filtered;
}

export function generateComplianceReport(standard: string, since?: string): ComplianceReport {
  const records = listEvidence({ standard, since });

  const requiredTypes = STANDARD_REQUIRED_TYPES[standard] ?? ['scan'];
  const presentTypes = new Set(records.map((r) => r.type));
  const coveredCount = requiredTypes.filter((t) => presentTypes.has(t)).length;
  const coveragePercentage = Math.round((coveredCount / requiredTypes.length) * 100);

  return {
    standard,
    generatedAt: new Date().toISOString(),
    evidenceCount: records.length,
    records,
    coveragePercentage,
  };
}

export function pruneEvidence(olderThanDays: number): number {
  if (!fs.existsSync(evidenceBaseDir)) return 0;

  const cutoff = Date.now() - olderThanDays * 86_400_000;
  let deletedCount = 0;

  const monthDirs = fs.readdirSync(evidenceBaseDir).filter((d) => {
    const full = path.join(evidenceBaseDir, d);
    return fs.statSync(full).isDirectory();
  });

  for (const md of monthDirs) {
    const dirPath = path.join(evidenceBaseDir, md);
    const files = fs.readdirSync(dirPath).filter((f) => f.endsWith('.json'));

    for (const file of files) {
      const filePath = path.join(dirPath, file);
      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const record: EvidenceRecord = JSON.parse(content);
        if (new Date(record.timestamp).getTime() < cutoff) {
          fs.unlinkSync(filePath);
          deletedCount++;
        }
      } catch {
        // skip malformed files
      }
    }

    // remove empty month directories
    const remaining = fs.readdirSync(dirPath);
    if (remaining.length === 0) {
      fs.rmdirSync(dirPath);
    }
  }

  return deletedCount;
}
