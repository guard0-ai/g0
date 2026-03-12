import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { validateConfigContent, validateFile } from '../../src/cli/commands/config.js';

describe('config validate', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-cfg-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('validateConfigContent', () => {
    it('accepts a valid minimal config', () => {
      const result = validateConfigContent({ preset: 'strict', min_score: 70 }, 'test.yaml');
      expect(result.errors).toHaveLength(0);
    });

    it('accepts a full valid config', () => {
      const result = validateConfigContent({
        preset: 'balanced',
        min_score: 80,
        min_grade: 'B',
        fail_on: 'high',
        exclude_rules: ['AA-DL-001'],
        exclude_paths: ['tests/'],
        rules_dir: './rules',
        severity_overrides: { 'AA-DL-001': 'low' },
        thresholds: { max_findings_per_rule: 5 },
        analyzers: { taint_flow: true, cross_file: false },
        domain_weights: { 'goal-integrity': 2.0 },
        risk_accepted: [{ rule: 'OC-H-003', reason: 'Accepted risk' }],
      }, 'test.yaml');
      expect(result.errors).toHaveLength(0);
    });

    it('reports unknown top-level keys', () => {
      const result = validateConfigContent({ presett: 'strict' }, 'test.yaml');
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toContain('Unknown key "presett"');
      expect(result.errors[0]).toContain('did you mean "preset"');
    });

    it('reports invalid preset with suggestion', () => {
      const result = validateConfigContent({ preset: 'strickt' }, 'test.yaml');
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toContain('Unknown preset "strickt"');
      expect(result.errors[0]).toContain('did you mean "strict"');
    });

    it('reports invalid min_score type', () => {
      const result = validateConfigContent({ min_score: 'high' }, 'test.yaml');
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toContain('"min_score" must be a number');
    });

    it('warns on out-of-range min_score', () => {
      const result = validateConfigContent({ min_score: 150 }, 'test.yaml');
      expect(result.errors).toHaveLength(0);
      expect(result.warnings).toHaveLength(1);
      expect(result.warnings[0]).toContain('outside 0-100');
    });

    it('reports invalid fail_on value', () => {
      const result = validateConfigContent({ fail_on: 'extreme' }, 'test.yaml');
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toContain('must be one of');
    });

    it('reports invalid severity_overrides values', () => {
      const result = validateConfigContent({ severity_overrides: { 'RULE-1': 'extreme' } }, 'test.yaml');
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toContain('severity must be one of');
    });

    it('reports invalid analyzer keys', () => {
      const result = validateConfigContent({ analyzers: { unknown_analyzer: true } }, 'test.yaml');
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toContain('Unknown analyzer key');
    });

    it('reports non-boolean analyzer values', () => {
      const result = validateConfigContent({ analyzers: { taint_flow: 'yes' } }, 'test.yaml');
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toContain('must be a boolean');
    });

    it('reports missing rule/reason in risk_accepted', () => {
      const result = validateConfigContent({ risk_accepted: [{ rule: 'X' }] }, 'test.yaml');
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toContain('reason is required');
    });

    it('handles empty/null config as warning', () => {
      const result = validateConfigContent(null, 'test.yaml');
      expect(result.errors).toHaveLength(0);
      expect(result.warnings).toHaveLength(1);
      expect(result.warnings[0]).toContain('empty');
    });

    it('rejects non-object config', () => {
      const result = validateConfigContent('just a string', 'test.yaml');
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toContain('must be a YAML mapping');
    });

    it('reports exclude_rules must be array', () => {
      const result = validateConfigContent({ exclude_rules: 'not-array' }, 'test.yaml');
      expect(result.errors).toHaveLength(1);
    });
  });

  describe('validateFile', () => {
    it('validates a valid YAML file', () => {
      const filePath = path.join(tmpDir, '.g0.yaml');
      fs.writeFileSync(filePath, 'preset: strict\nmin_score: 70\n');
      const result = validateFile(filePath);
      expect(result.errors).toHaveLength(0);
    });

    it('reports file not found', () => {
      const result = validateFile('/nonexistent/.g0.yaml');
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toContain('File not found');
    });

    it('reports YAML parse errors', () => {
      const filePath = path.join(tmpDir, '.g0.yaml');
      fs.writeFileSync(filePath, ':\n  - [\ninvalid yaml {{{\n');
      const result = validateFile(filePath);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toContain('YAML parse error');
    });

    it('validates a file with errors', () => {
      const filePath = path.join(tmpDir, '.g0.yaml');
      fs.writeFileSync(filePath, 'preset: strickt\nunknown_key: value\n');
      const result = validateFile(filePath);
      expect(result.errors.length).toBeGreaterThanOrEqual(2);
    });
  });
});
