/**
 * Phase 6A: SARIF output for `g0 test` results.
 *
 * Maps dynamic test results to SARIF findings, enabling
 * GitHub code scanning integration for red-team results.
 */

import * as fs from 'node:fs';
import type { TestRunResult, TestCaseResult, AttackCategory } from '../types/test.js';

interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: string };
  properties: { tags: string[]; 'security-severity': string };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: string;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
    };
  }>;
  properties?: Record<string, unknown>;
}

const SEVERITY_MAP: Record<string, string> = {
  critical: '9.0',
  high: '7.0',
  medium: '4.0',
  low: '1.0',
};

const SARIF_LEVEL: Record<string, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
};

function categoryToRuleId(category: AttackCategory): string {
  return `g0-test-${category}`;
}

function categoryToRuleName(category: AttackCategory): string {
  return category.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
}

export function reportTestSarif(result: TestRunResult, outputPath?: string): string {
  // Collect unique categories as rules
  const categorySet = new Set<AttackCategory>();
  for (const r of result.results) {
    if (r.verdict === 'vulnerable') categorySet.add(r.category);
  }
  // Also include adaptive results
  if (result.adaptiveResults) {
    for (const r of result.adaptiveResults) {
      if (r.verdict === 'vulnerable') categorySet.add(r.category);
    }
  }

  const categories = [...categorySet];
  const ruleIndex = new Map<string, number>();
  const rules: SarifRule[] = categories.map((cat, i) => {
    const ruleId = categoryToRuleId(cat);
    ruleIndex.set(ruleId, i);
    return {
      id: ruleId,
      name: categoryToRuleName(cat),
      shortDescription: { text: `Dynamic test vulnerability: ${categoryToRuleName(cat)}` },
      defaultConfiguration: { level: 'warning' },
      properties: {
        tags: ['security', 'dynamic-test', cat],
        'security-severity': '7.0',
      },
    };
  });

  const results: SarifResult[] = [];

  // Map vulnerable test results to SARIF findings
  const vulnerableResults = result.results.filter(r => r.verdict === 'vulnerable');
  for (const testResult of vulnerableResults) {
    const ruleId = categoryToRuleId(testResult.category);
    const idx = ruleIndex.get(ruleId);
    if (idx === undefined) continue;

    results.push({
      ruleId,
      ruleIndex: idx,
      level: SARIF_LEVEL[testResult.severity] ?? 'warning',
      message: {
        text: `${testResult.payloadName}: ${testResult.evidence}`,
      },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: result.target.endpoint },
        },
      }],
      properties: {
        payloadId: testResult.payloadId,
        judgeLevel: testResult.judgeLevel,
        confidence: testResult.confidence,
        severity: testResult.severity,
        qualityScore: testResult.qualityScore,
        specificity: testResult.specificity,
        convincingness: testResult.convincingness,
      },
    });
  }

  // Map adaptive vulnerable results
  if (result.adaptiveResults) {
    for (const adaptiveResult of result.adaptiveResults.filter(r => r.verdict === 'vulnerable')) {
      const ruleId = categoryToRuleId(adaptiveResult.category);
      const idx = ruleIndex.get(ruleId);
      if (idx === undefined) continue;

      results.push({
        ruleId,
        ruleIndex: idx,
        level: SARIF_LEVEL[adaptiveResult.severity] ?? 'warning',
        message: {
          text: `[Adaptive ${adaptiveResult.strategyId}] ${adaptiveResult.payloadName}: ${adaptiveResult.evidence}`,
        },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: result.target.endpoint },
          },
        }],
        properties: {
          payloadId: adaptiveResult.payloadId,
          strategyId: adaptiveResult.strategyId,
          turnsExecuted: adaptiveResult.turnsExecuted,
          cvssScore: adaptiveResult.cvssScore,
          cvssVector: adaptiveResult.cvssVector,
        },
      });
    }
  }

  const sarif: SarifLog = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'g0-test',
          version: '0.1.0',
          informationUri: 'https://guard0.ai',
          rules,
        },
      },
      results,
    }],
  };

  const json = JSON.stringify(sarif, null, 2);

  if (outputPath) {
    fs.writeFileSync(outputPath, json, 'utf-8');
  }

  return json;
}
