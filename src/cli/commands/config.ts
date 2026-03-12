import * as fs from 'node:fs';
import * as path from 'node:path';
import { Command } from 'commander';
import chalk from 'chalk';
import YAML from 'yaml';
import type { G0Config, PresetName } from '../../types/config.js';
import type { Severity, Grade } from '../../types/common.js';

const CONFIG_FILENAMES = ['.g0.yaml', '.g0.yml', 'g0.yaml', 'g0.yml'];
const VALID_PRESETS: readonly string[] = ['strict', 'balanced', 'permissive', 'openclaw'];
const VALID_SEVERITIES: readonly string[] = ['critical', 'high', 'medium', 'low', 'info'];
const VALID_GRADES: readonly string[] = ['A', 'B', 'C', 'D', 'F'];
const VALID_FAIL_ON: readonly string[] = ['critical', 'high', 'medium', 'low', 'info'];
const VALID_ANALYZER_KEYS: readonly string[] = ['taint_flow', 'cross_file', 'pipeline_taint', 'analyzability', 'intelligence'];

const KNOWN_TOP_LEVEL_KEYS: readonly string[] = [
  'preset',
  'min_score',
  'min_grade',
  'fail_on',
  'exclude_rules',
  'exclude_paths',
  'rules_dir',
  'severity_overrides',
  'thresholds',
  'analyzers',
  'domain_weights',
  'risk_accepted',
];

const KNOWN_THRESHOLD_KEYS: readonly string[] = [
  'max_findings_per_rule',
  'low_severity_cap',
  'medium_severity_cap',
];

export interface ValidationResult {
  file: string;
  errors: string[];
  warnings: string[];
}

function findSimilar(value: string, valid: readonly string[]): string | null {
  for (const v of valid) {
    if (Math.abs(v.length - value.length) <= 2) {
      let diff = 0;
      const maxLen = Math.max(v.length, value.length);
      for (let i = 0; i < maxLen; i++) {
        if (v[i] !== value[i]) diff++;
      }
      if (diff <= 2) return v;
    }
  }
  return null;
}

export function validateConfigContent(raw: unknown, filePath: string): ValidationResult {
  const result: ValidationResult = { file: filePath, errors: [], warnings: [] };

  if (raw === null || raw === undefined) {
    result.warnings.push('File is empty — no configuration defined');
    return result;
  }

  if (typeof raw !== 'object' || Array.isArray(raw)) {
    result.errors.push('Config must be a YAML mapping (object), not a scalar or array');
    return result;
  }

  const obj = raw as Record<string, unknown>;

  // Check for unknown top-level keys
  for (const key of Object.keys(obj)) {
    if (!KNOWN_TOP_LEVEL_KEYS.includes(key)) {
      const suggestion = findSimilar(key, KNOWN_TOP_LEVEL_KEYS);
      const hint = suggestion ? ` (did you mean "${suggestion}"?)` : '';
      result.errors.push(`Unknown key "${key}"${hint}`);
    }
  }

  // preset
  if (obj.preset !== undefined) {
    if (typeof obj.preset !== 'string') {
      result.errors.push(`"preset" must be a string`);
    } else if (!VALID_PRESETS.includes(obj.preset)) {
      const suggestion = findSimilar(obj.preset, VALID_PRESETS);
      const hint = suggestion ? ` (did you mean "${suggestion}"?)` : '';
      result.errors.push(`Unknown preset "${obj.preset}"${hint}`);
    }
  }

  // min_score
  if (obj.min_score !== undefined) {
    if (typeof obj.min_score !== 'number') {
      result.errors.push(`"min_score" must be a number`);
    } else if (obj.min_score < 0 || obj.min_score > 100) {
      result.warnings.push(`"min_score" ${obj.min_score} is outside 0-100 range — will be clamped`);
    }
  }

  // min_grade
  if (obj.min_grade !== undefined) {
    if (typeof obj.min_grade !== 'string') {
      result.errors.push(`"min_grade" must be a string`);
    } else if (!VALID_GRADES.includes(obj.min_grade.toUpperCase())) {
      result.errors.push(`"min_grade" must be one of: ${VALID_GRADES.join(', ')}`);
    }
  }

  // fail_on
  if (obj.fail_on !== undefined) {
    if (typeof obj.fail_on !== 'string') {
      result.errors.push(`"fail_on" must be a string`);
    } else if (!VALID_FAIL_ON.includes(obj.fail_on)) {
      result.errors.push(`"fail_on" must be one of: ${VALID_FAIL_ON.join(', ')}`);
    }
  }

  // exclude_rules
  if (obj.exclude_rules !== undefined) {
    if (!Array.isArray(obj.exclude_rules)) {
      result.errors.push(`"exclude_rules" must be an array`);
    } else {
      for (let i = 0; i < obj.exclude_rules.length; i++) {
        if (typeof obj.exclude_rules[i] !== 'string') {
          result.errors.push(`"exclude_rules[${i}]" must be a string`);
        }
      }
    }
  }

  // exclude_paths
  if (obj.exclude_paths !== undefined) {
    if (!Array.isArray(obj.exclude_paths)) {
      result.errors.push(`"exclude_paths" must be an array`);
    } else {
      for (let i = 0; i < obj.exclude_paths.length; i++) {
        if (typeof obj.exclude_paths[i] !== 'string') {
          result.errors.push(`"exclude_paths[${i}]" must be a string`);
        }
      }
    }
  }

  // rules_dir
  if (obj.rules_dir !== undefined && typeof obj.rules_dir !== 'string') {
    result.errors.push(`"rules_dir" must be a string`);
  }

  // severity_overrides
  if (obj.severity_overrides !== undefined) {
    if (typeof obj.severity_overrides !== 'object' || obj.severity_overrides === null || Array.isArray(obj.severity_overrides)) {
      result.errors.push(`"severity_overrides" must be a mapping`);
    } else {
      for (const [ruleId, sev] of Object.entries(obj.severity_overrides as Record<string, unknown>)) {
        if (typeof sev !== 'string' || !VALID_SEVERITIES.includes(sev)) {
          result.errors.push(`severity_overrides.${ruleId}: severity must be one of: ${VALID_SEVERITIES.join(', ')}`);
        }
      }
    }
  }

  // thresholds
  if (obj.thresholds !== undefined) {
    if (typeof obj.thresholds !== 'object' || obj.thresholds === null || Array.isArray(obj.thresholds)) {
      result.errors.push(`"thresholds" must be a mapping`);
    } else {
      const th = obj.thresholds as Record<string, unknown>;
      for (const key of Object.keys(th)) {
        if (!KNOWN_THRESHOLD_KEYS.includes(key)) {
          result.errors.push(`Unknown threshold key "${key}"`);
        } else if (typeof th[key] !== 'number') {
          result.errors.push(`thresholds.${key} must be a number`);
        }
      }
    }
  }

  // analyzers
  if (obj.analyzers !== undefined) {
    if (typeof obj.analyzers !== 'object' || obj.analyzers === null || Array.isArray(obj.analyzers)) {
      result.errors.push(`"analyzers" must be a mapping`);
    } else {
      const an = obj.analyzers as Record<string, unknown>;
      for (const key of Object.keys(an)) {
        if (!VALID_ANALYZER_KEYS.includes(key)) {
          result.errors.push(`Unknown analyzer key "${key}"`);
        } else if (typeof an[key] !== 'boolean') {
          result.errors.push(`analyzers.${key} must be a boolean`);
        }
      }
    }
  }

  // domain_weights
  if (obj.domain_weights !== undefined) {
    if (typeof obj.domain_weights !== 'object' || obj.domain_weights === null || Array.isArray(obj.domain_weights)) {
      result.errors.push(`"domain_weights" must be a mapping`);
    } else {
      for (const [domain, weight] of Object.entries(obj.domain_weights as Record<string, unknown>)) {
        if (typeof weight !== 'number') {
          result.errors.push(`domain_weights.${domain} must be a number`);
        }
      }
    }
  }

  // risk_accepted
  if (obj.risk_accepted !== undefined) {
    if (!Array.isArray(obj.risk_accepted)) {
      result.errors.push(`"risk_accepted" must be an array`);
    } else {
      for (let i = 0; i < obj.risk_accepted.length; i++) {
        const entry = obj.risk_accepted[i];
        if (!entry || typeof entry !== 'object') {
          result.errors.push(`risk_accepted[${i}] must be an object`);
          continue;
        }
        if (typeof entry.rule !== 'string') {
          result.errors.push(`risk_accepted[${i}].rule is required and must be a string`);
        }
        if (typeof entry.reason !== 'string') {
          result.errors.push(`risk_accepted[${i}].reason is required and must be a string`);
        }
        if (entry.expires !== undefined && typeof entry.expires !== 'string') {
          result.errors.push(`risk_accepted[${i}].expires must be a string (ISO 8601 date)`);
        }
      }
    }
  }

  return result;
}

export function validateFile(filePath: string): ValidationResult {
  const resolved = path.resolve(filePath);

  if (!fs.existsSync(resolved)) {
    return { file: filePath, errors: [`File not found: ${resolved}`], warnings: [] };
  }

  let content: string;
  try {
    content = fs.readFileSync(resolved, 'utf-8');
  } catch (err) {
    return { file: filePath, errors: [`Cannot read file: ${(err as Error).message}`], warnings: [] };
  }

  let raw: unknown;
  try {
    raw = YAML.parse(content);
  } catch (err) {
    return { file: filePath, errors: [`YAML parse error: ${(err as Error).message}`], warnings: [] };
  }

  return validateConfigContent(raw, filePath);
}

function findConfigFiles(rootPath: string): string[] {
  const found: string[] = [];
  for (const name of CONFIG_FILENAMES) {
    const fp = path.join(rootPath, name);
    if (fs.existsSync(fp)) {
      found.push(fp);
    }
  }
  return found;
}

function printResult(result: ValidationResult): void {
  if (result.errors.length === 0 && result.warnings.length === 0) {
    console.log(chalk.green(`✓ ${result.file} is valid`));
    return;
  }

  for (const warning of result.warnings) {
    console.log(chalk.yellow(`⚠ ${result.file} — ${warning}`));
  }

  for (const error of result.errors) {
    console.log(chalk.red(`✗ ${result.file} — ${error}`));
  }
}

export const configCommand = new Command('config')
  .description('Configuration management commands');

configCommand
  .command('validate')
  .description('Validate g0 configuration files')
  .argument('[path]', 'Path to config file or directory')
  .action((configPath?: string) => {
    let results: ValidationResult[];

    if (configPath) {
      const resolved = path.resolve(configPath);
      if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
        const files = findConfigFiles(resolved);
        if (files.length === 0) {
          console.log(chalk.yellow('No g0 config files found in ' + resolved));
          process.exit(1);
        }
        results = files.map(f => validateFile(f));
      } else {
        results = [validateFile(resolved)];
      }
    } else {
      const files = findConfigFiles(process.cwd());
      if (files.length === 0) {
        console.log(chalk.yellow('No g0 config files found in current directory'));
        console.log(chalk.dim('Run `g0 init` to create one'));
        process.exit(1);
      }
      results = files.map(f => validateFile(f));
    }

    for (const result of results) {
      printResult(result);
    }

    const hasErrors = results.some(r => r.errors.length > 0);
    if (hasErrors) {
      process.exit(1);
    }
  });
