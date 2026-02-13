import * as fs from 'node:fs';
import * as path from 'node:path';
import YAML from 'yaml';
import type { Rule } from '../types/control.js';
import { yamlRuleSchema } from './yaml-schema.js';
import { compileYamlRule } from './yaml-compiler.js';

export interface YamlLoadResult {
  rules: Rule[];
  errors: YamlLoadError[];
}

export interface YamlLoadError {
  file: string;
  message: string;
}

/**
 * Loads and compiles all YAML rule files from a directory.
 */
export function loadYamlRules(rulesDir: string): YamlLoadResult {
  const result: YamlLoadResult = { rules: [], errors: [] };

  if (!fs.existsSync(rulesDir)) {
    return result;
  }

  const stat = fs.statSync(rulesDir);
  if (!stat.isDirectory()) {
    result.errors.push({ file: rulesDir, message: 'Not a directory' });
    return result;
  }

  const entries = fs.readdirSync(rulesDir, { recursive: true }) as string[];
  const files = entries.filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));

  for (const file of files) {
    const filePath = path.join(rulesDir, file);
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const docs = YAML.parseAllDocuments(content);

      for (const doc of docs) {
        if (doc.errors.length > 0) {
          result.errors.push({
            file: filePath,
            message: `YAML parse error: ${doc.errors[0].message}`,
          });
          continue;
        }

        const raw = doc.toJSON();
        if (!raw) continue;

        // Support both single rule and array of rules in one file
        const ruleObjects = Array.isArray(raw) ? raw : [raw];

        for (const ruleObj of ruleObjects) {
          const parsed = yamlRuleSchema.safeParse(ruleObj);
          if (!parsed.success) {
            result.errors.push({
              file: filePath,
              message: `Validation error for ${ruleObj?.id ?? 'unknown'}: ${parsed.error.issues[0]?.message ?? 'Invalid rule'}`,
            });
            continue;
          }

          try {
            const compiled = compileYamlRule(parsed.data);
            result.rules.push(compiled);
          } catch (err) {
            result.errors.push({
              file: filePath,
              message: `Compile error for ${parsed.data.id}: ${err instanceof Error ? err.message : String(err)}`,
            });
          }
        }
      }
    } catch (err) {
      result.errors.push({
        file: filePath,
        message: `Read error: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  return result;
}

/**
 * Merges YAML rules with hardcoded rules. YAML rules override hardcoded rules with the same ID.
 */
export function mergeRules(hardcoded: Rule[], yaml: Rule[]): Rule[] {
  const yamlIds = new Set(yaml.map(r => r.id));
  const filtered = hardcoded.filter(r => !yamlIds.has(r.id));
  return [...filtered, ...yaml];
}
