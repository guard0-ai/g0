import { describe, it, expect } from 'vitest';
import { deepMergeConfig } from '../../src/config/merge.js';
import { resolvePreset, PRESETS } from '../../src/config/presets/index.js';
import type { G0Config } from '../../src/types/config.js';

describe('Scan Policy System', () => {
  describe('Presets', () => {
    it('resolves strict preset', () => {
      const preset = resolvePreset('strict');
      expect(preset.fail_on).toBe('medium');
      expect(preset.min_score).toBe(80);
      expect(preset.thresholds?.max_findings_per_rule).toBe(30);
      expect(preset.analyzers?.pipeline_taint).toBe(true);
    });

    it('resolves balanced preset', () => {
      const preset = resolvePreset('balanced');
      expect(preset.thresholds?.max_findings_per_rule).toBe(50);
      expect(preset.analyzers?.pipeline_taint).toBe(true);
    });

    it('resolves permissive preset', () => {
      const preset = resolvePreset('permissive');
      expect(preset.fail_on).toBe('critical');
      expect(preset.thresholds?.max_findings_per_rule).toBe(100);
      expect(preset.analyzers?.pipeline_taint).toBe(false);
    });

    it('throws on unknown preset', () => {
      expect(() => resolvePreset('nonexistent' as any)).toThrow('Unknown preset');
    });

    it('has all presets', () => {
      expect(Object.keys(PRESETS)).toEqual(['strict', 'balanced', 'permissive', 'openclaw']);
    });

    it('resolves openclaw preset', () => {
      const preset = resolvePreset('openclaw');
      expect(preset.fail_on).toBe('medium');
      expect(preset.min_score).toBe(85);
      expect(preset.analyzers?.taint_flow).toBe(true);
      expect(preset.analyzers?.pipeline_taint).toBe(true);
      expect(preset.domain_weights?.['code-execution']).toBe(1.5);
      expect(preset.domain_weights?.['data-leakage']).toBe(1.5);
    });
  });

  describe('Deep Merge', () => {
    it('merges scalar values with override priority', () => {
      const base: G0Config = { min_score: 70, fail_on: 'high' };
      const override: G0Config = { min_score: 90 };
      const result = deepMergeConfig(base, override);
      expect(result.min_score).toBe(90);
      expect(result.fail_on).toBe('high');
    });

    it('replaces arrays entirely', () => {
      const base: G0Config = { exclude_rules: ['A', 'B'] };
      const override: G0Config = { exclude_rules: ['C'] };
      const result = deepMergeConfig(base, override);
      expect(result.exclude_rules).toEqual(['C']);
    });

    it('deep merges objects', () => {
      const base: G0Config = {
        thresholds: { max_findings_per_rule: 50, low_severity_cap: 10 },
      };
      const override: G0Config = {
        thresholds: { max_findings_per_rule: 30 },
      };
      const result = deepMergeConfig(base, override);
      expect(result.thresholds?.max_findings_per_rule).toBe(30);
      expect(result.thresholds?.low_severity_cap).toBe(10);
    });

    it('preserves base when override is empty', () => {
      const base: G0Config = { min_score: 80, fail_on: 'high' };
      const result = deepMergeConfig(base, {});
      expect(result.min_score).toBe(80);
      expect(result.fail_on).toBe('high');
    });

    it('handles undefined override values', () => {
      const base: G0Config = { min_score: 80 };
      const override: G0Config = { min_score: undefined };
      const result = deepMergeConfig(base, override);
      expect(result.min_score).toBe(80);
    });
  });

  describe('Severity Overrides', () => {
    it('override applied via config type', () => {
      const config: G0Config = {
        severity_overrides: {
          'AA-GI-001': 'low',
          'AA-TS-007': 'critical',
        },
      };
      expect(config.severity_overrides?.['AA-GI-001']).toBe('low');
      expect(config.severity_overrides?.['AA-TS-007']).toBe('critical');
    });
  });

  describe('Backward Compatibility', () => {
    it('existing config shape still works', () => {
      const config: G0Config = {
        min_score: 70,
        min_grade: 'C',
        fail_on: 'high',
        exclude_rules: ['AA-GI-001'],
        exclude_paths: ['vendor/'],
        include_beta: true,
        rules_dir: './custom-rules',
      };
      // All original fields should be preserved
      expect(config.min_score).toBe(70);
      expect(config.min_grade).toBe('C');
      expect(config.fail_on).toBe('high');
      expect(config.exclude_rules).toEqual(['AA-GI-001']);
      expect(config.exclude_paths).toEqual(['vendor/']);
      expect(config.include_beta).toBe(true);
      expect(config.rules_dir).toBe('./custom-rules');
    });

    it('new fields are optional', () => {
      const config: G0Config = {};
      expect(config.preset).toBeUndefined();
      expect(config.severity_overrides).toBeUndefined();
      expect(config.thresholds).toBeUndefined();
      expect(config.analyzers).toBeUndefined();
      expect(config.domain_weights).toBeUndefined();
    });
  });

  describe('Preset + Override integration', () => {
    it('user overrides take priority over preset', () => {
      const preset = resolvePreset('strict');
      const userOverrides: G0Config = {
        fail_on: 'critical',
        thresholds: { max_findings_per_rule: 100 },
      };
      const merged = deepMergeConfig(preset, userOverrides);
      expect(merged.fail_on).toBe('critical'); // overridden
      expect(merged.min_score).toBe(80); // from strict preset
      expect(merged.thresholds?.max_findings_per_rule).toBe(100); // overridden
      expect(merged.thresholds?.low_severity_cap).toBe(5); // from strict preset
    });
  });
});
