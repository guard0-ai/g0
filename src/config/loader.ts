import * as fs from 'node:fs';
import * as path from 'node:path';
import YAML from 'yaml';
import type { G0Config, PresetName, RiskAcceptance } from '../types/config.js';
import { resolvePreset } from './presets/index.js';
import { deepMergeConfig } from './merge.js';

const CONFIG_FILENAMES = ['.g0.yaml', '.g0.yml', 'g0.yaml', 'g0.yml'];
const VALID_PRESETS: PresetName[] = ['strict', 'balanced', 'permissive', 'openclaw'];

export function loadConfig(rootPath: string, configPath?: string): G0Config | null {
  if (configPath) {
    const resolved = path.resolve(configPath);
    if (!fs.existsSync(resolved)) {
      throw new Error(`Config file not found: ${resolved}`);
    }
    return parseConfigFile(resolved);
  }

  for (const name of CONFIG_FILENAMES) {
    const filePath = path.join(rootPath, name);
    if (fs.existsSync(filePath)) {
      return parseConfigFile(filePath);
    }
  }

  return null;
}

function parseConfigFile(filePath: string): G0Config {
  const content = fs.readFileSync(filePath, 'utf-8');
  const raw = YAML.parse(content);

  if (!raw || typeof raw !== 'object') {
    return {};
  }

  // If preset is specified, start with preset defaults then merge user overrides
  let config: G0Config = {};
  if (typeof raw.preset === 'string' && VALID_PRESETS.includes(raw.preset as PresetName)) {
    config = resolvePreset(raw.preset as PresetName);
  }

  const userConfig: G0Config = {};

  if (typeof raw.min_score === 'number') {
    userConfig.min_score = Math.max(0, Math.min(100, raw.min_score));
  }
  if (typeof raw.min_grade === 'string' && ['A', 'B', 'C', 'D', 'F'].includes(raw.min_grade.toUpperCase())) {
    userConfig.min_grade = raw.min_grade.toUpperCase() as G0Config['min_grade'];
  }
  if (typeof raw.fail_on === 'string' && ['critical', 'high', 'medium', 'low', 'info'].includes(raw.fail_on)) {
    userConfig.fail_on = raw.fail_on as G0Config['fail_on'];
  }
  if (Array.isArray(raw.exclude_rules)) {
    userConfig.exclude_rules = raw.exclude_rules.filter((r: unknown) => typeof r === 'string');
  }
  if (Array.isArray(raw.exclude_paths)) {
    userConfig.exclude_paths = raw.exclude_paths.filter((p: unknown) => typeof p === 'string');
  }
  if (typeof raw.rules_dir === 'string') {
    userConfig.rules_dir = raw.rules_dir;
  }
  if (typeof raw.preset === 'string' && VALID_PRESETS.includes(raw.preset as PresetName)) {
    userConfig.preset = raw.preset as PresetName;
  }

  // Parse severity_overrides
  if (raw.severity_overrides && typeof raw.severity_overrides === 'object') {
    const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
    const overrides: Record<string, any> = {};
    for (const [ruleId, sev] of Object.entries(raw.severity_overrides)) {
      if (typeof sev === 'string' && validSeverities.includes(sev)) {
        overrides[ruleId] = sev;
      }
    }
    if (Object.keys(overrides).length > 0) {
      userConfig.severity_overrides = overrides;
    }
  }

  // Parse thresholds
  if (raw.thresholds && typeof raw.thresholds === 'object') {
    userConfig.thresholds = {};
    if (typeof raw.thresholds.max_findings_per_rule === 'number') {
      userConfig.thresholds.max_findings_per_rule = raw.thresholds.max_findings_per_rule;
    }
    if (typeof raw.thresholds.low_severity_cap === 'number') {
      userConfig.thresholds.low_severity_cap = raw.thresholds.low_severity_cap;
    }
    if (typeof raw.thresholds.medium_severity_cap === 'number') {
      userConfig.thresholds.medium_severity_cap = raw.thresholds.medium_severity_cap;
    }
  }

  // Parse analyzers
  if (raw.analyzers && typeof raw.analyzers === 'object') {
    userConfig.analyzers = {};
    for (const key of ['taint_flow', 'cross_file', 'pipeline_taint', 'analyzability'] as const) {
      if (typeof raw.analyzers[key] === 'boolean') {
        userConfig.analyzers[key] = raw.analyzers[key];
      }
    }
  }

  // Parse domain_weights
  if (raw.domain_weights && typeof raw.domain_weights === 'object') {
    userConfig.domain_weights = {};
    for (const [domain, weight] of Object.entries(raw.domain_weights)) {
      if (typeof weight === 'number') {
        (userConfig.domain_weights as Record<string, number>)[domain] = weight;
      }
    }
  }

  // Parse risk_accepted
  if (Array.isArray(raw.risk_accepted)) {
    const accepted: RiskAcceptance[] = [];
    for (const entry of raw.risk_accepted) {
      if (entry && typeof entry === 'object' && typeof entry.rule === 'string' && typeof entry.reason === 'string') {
        const ra: RiskAcceptance = { rule: entry.rule, reason: entry.reason };
        if (typeof entry.expires === 'string') {
          ra.expires = entry.expires;
        }
        accepted.push(ra);
      }
    }
    if (accepted.length > 0) {
      userConfig.risk_accepted = accepted;
    }
  }

  // Merge: preset base + user overrides
  return deepMergeConfig(config, userConfig);
}
