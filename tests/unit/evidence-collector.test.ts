import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import {
  createEvidenceRecord,
  listEvidence,
  generateComplianceReport,
  pruneEvidence,
  setEvidenceDir,
  resetEvidenceDir,
} from '../../src/governance/evidence-collector.js';
import type { EvidenceRecord } from '../../src/governance/evidence-collector.js';

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-evidence-test-'));
  setEvidenceDir(tmpDir);
});

afterEach(() => {
  resetEvidenceDir();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('evidence-collector', () => {
  describe('createEvidenceRecord', () => {
    it('produces a valid record with correct SHA-256', () => {
      const data = { findings: 5, severity: 'high' };
      const record = createEvidenceRecord('scan', 'g0 scan', 'Scan of project X', data, ['owasp-asi']);

      expect(record.id).toMatch(/^[0-9a-f-]{36}$/);
      expect(record.type).toBe('scan');
      expect(record.source).toBe('g0 scan');
      expect(record.summary).toBe('Scan of project X');
      expect(record.data).toEqual(data);
      expect(record.standards).toEqual(['owasp-asi']);
      expect(record.hostname).toBe(os.hostname());
      expect(record.version).toBe('1.5.1');

      const expectedHash = crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
      expect(record.sha256).toBe(expectedHash);
    });

    it('omits standards field when not provided', () => {
      const record = createEvidenceRecord('test', 'g0 test', 'Test run', { passed: true });
      expect(record.standards).toBeUndefined();
    });

    it('saves record to disk and is readable', () => {
      const record = createEvidenceRecord('audit', 'openclaw-audit', 'Gateway audit', { probes: 18 });

      const d = new Date(record.timestamp);
      const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
      const monthFolder = `${d.getUTCFullYear()}-${mm}`;
      const filePath = path.join(tmpDir, monthFolder, `${record.id}.json`);

      expect(fs.existsSync(filePath)).toBe(true);

      const loaded: EvidenceRecord = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      expect(loaded.id).toBe(record.id);
      expect(loaded.sha256).toBe(record.sha256);
      expect(loaded.data).toEqual({ probes: 18 });
    });
  });

  describe('listEvidence', () => {
    it('returns all records when no filters', () => {
      createEvidenceRecord('scan', 'g0 scan', 'S1', { a: 1 });
      createEvidenceRecord('test', 'g0 test', 'T1', { b: 2 });

      const all = listEvidence();
      expect(all).toHaveLength(2);
    });

    it('filters by type', () => {
      createEvidenceRecord('scan', 'g0 scan', 'S1', { a: 1 });
      createEvidenceRecord('test', 'g0 test', 'T1', { b: 2 });
      createEvidenceRecord('scan', 'g0 scan', 'S2', { c: 3 });

      const scans = listEvidence({ type: 'scan' });
      expect(scans).toHaveLength(2);
      expect(scans.every((r) => r.type === 'scan')).toBe(true);
    });

    it('filters by standard', () => {
      createEvidenceRecord('scan', 'g0 scan', 'S1', { a: 1 }, ['owasp-asi']);
      createEvidenceRecord('test', 'g0 test', 'T1', { b: 2 }, ['nist-ai-rmf']);
      createEvidenceRecord('audit', 'g0 audit', 'A1', { c: 3 }, ['owasp-asi', 'eu-ai-act']);

      const owasp = listEvidence({ standard: 'owasp-asi' });
      expect(owasp).toHaveLength(2);
    });

    it('returns empty array when evidence dir does not exist', () => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
      expect(listEvidence()).toEqual([]);
    });
  });

  describe('generateComplianceReport', () => {
    it('calculates coverage for owasp-asi (scan+test+runtime)', () => {
      createEvidenceRecord('scan', 'g0 scan', 'S', { x: 1 }, ['owasp-asi']);
      createEvidenceRecord('test', 'g0 test', 'T', { x: 2 }, ['owasp-asi']);
      // missing runtime → 67%

      const report = generateComplianceReport('owasp-asi');
      expect(report.standard).toBe('owasp-asi');
      expect(report.evidenceCount).toBe(2);
      expect(report.coveragePercentage).toBe(67);
      expect(report.records).toHaveLength(2);
    });

    it('returns 100% when all required types present', () => {
      createEvidenceRecord('scan', 'g0 scan', 'S', { x: 1 }, ['nist-ai-rmf']);
      createEvidenceRecord('audit', 'g0 audit', 'A', { x: 2 }, ['nist-ai-rmf']);
      createEvidenceRecord('policy', 'g0 policy', 'P', { x: 3 }, ['nist-ai-rmf']);

      const report = generateComplianceReport('nist-ai-rmf');
      expect(report.coveragePercentage).toBe(100);
    });

    it('returns 0% when no matching evidence', () => {
      const report = generateComplianceReport('eu-ai-act');
      expect(report.coveragePercentage).toBe(0);
      expect(report.evidenceCount).toBe(0);
    });
  });

  describe('pruneEvidence', () => {
    it('deletes records older than N days and returns count', () => {
      // Create a record, then backdate its file
      const record = createEvidenceRecord('scan', 'g0 scan', 'Old scan', { old: true });

      const d = new Date(record.timestamp);
      const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
      const monthFolder = `${d.getUTCFullYear()}-${mm}`;
      const filePath = path.join(tmpDir, monthFolder, `${record.id}.json`);

      // Backdate the record's timestamp to 100 days ago
      const oldRecord = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      oldRecord.timestamp = new Date(Date.now() - 100 * 86_400_000).toISOString();
      fs.writeFileSync(filePath, JSON.stringify(oldRecord, null, 2));

      // Create a fresh record that should survive
      createEvidenceRecord('test', 'g0 test', 'Recent test', { recent: true });

      const deleted = pruneEvidence(30);
      expect(deleted).toBe(1);

      const remaining = listEvidence();
      expect(remaining).toHaveLength(1);
      expect(remaining[0].type).toBe('test');
    });
  });
});
