import * as fs from 'node:fs';
import { createHash } from 'node:crypto';
import type { ScanResult } from '../types/score.js';
import type { Finding } from '../types/finding.js';
import type { Severity } from '../types/common.js';
import { getAllRules } from '../analyzers/rules/index.js';

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
  invocations: SarifInvocation[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  defaultConfiguration: { level: string };
  properties: {
    tags: string[];
    security_severity: string;
    standards?: Record<string, string[]>;
  };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: string;
  message: { text: string };
  locations: SarifLocation[];
  relatedLocations?: SarifRelatedLocation[];
  partialFingerprints?: Record<string, string>;
  properties?: Record<string, unknown>;
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region: { startLine: number; startColumn?: number; snippet?: { text: string } };
  };
}

interface SarifRelatedLocation {
  id: number;
  message: { text: string };
  physicalLocation: {
    artifactLocation: { uri: string };
    region: { startLine: number };
  };
}

interface SarifInvocation {
  executionSuccessful: boolean;
  endTimeUtc: string;
  properties: Record<string, unknown>;
}

const OWASP_ASI_URLS: Record<string, string> = {
  ASI01: 'https://genai.owasp.org/threats/prompt-injection/',
  ASI02: 'https://genai.owasp.org/threats/tool-misuse/',
  ASI03: 'https://genai.owasp.org/threats/excessive-agency/',
  ASI04: 'https://genai.owasp.org/threats/supply-chain/',
  ASI05: 'https://genai.owasp.org/threats/insecure-output-handling/',
  ASI06: 'https://genai.owasp.org/threats/model-denial-of-service/',
  ASI07: 'https://genai.owasp.org/threats/sensitive-information-disclosure/',
  ASI08: 'https://genai.owasp.org/threats/overreliance/',
  ASI09: 'https://genai.owasp.org/threats/training-data-poisoning/',
  ASI10: 'https://genai.owasp.org/threats/model-theft/',
};

function severityToLevel(severity: Severity): string {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
  }
}

function severityToScore(severity: Severity): string {
  switch (severity) {
    case 'critical': return '9.0';
    case 'high': return '7.0';
    case 'medium': return '4.0';
    case 'low': return '2.0';
    case 'info': return '1.0';
  }
}

function computeFingerprint(ruleId: string, file: string, snippet?: string): string {
  const content = `${ruleId}:${file}:${snippet ?? ''}`;
  return createHash('sha256').update(content).digest('hex');
}

function resolveHelpUri(owaspCodes: string[]): string | undefined {
  for (const code of owaspCodes) {
    if (OWASP_ASI_URLS[code]) return OWASP_ASI_URLS[code];
  }
  return undefined;
}

export function reportSarif(result: ScanResult, outputPath?: string): string {
  const allRules = getAllRules();
  const ruleIndexMap = new Map<string, number>();
  const sarifRules: SarifRule[] = allRules.map((rule, i) => {
    ruleIndexMap.set(rule.id, i);
    const helpUri = resolveHelpUri(rule.owaspAgentic);
    const ruleEntry: SarifRule = {
      id: rule.id,
      name: rule.name.replace(/\s+/g, ''),
      shortDescription: { text: rule.name },
      fullDescription: { text: rule.description },
      defaultConfiguration: { level: severityToLevel(rule.severity) },
      properties: {
        tags: ['security', rule.domain, ...rule.owaspAgentic],
        security_severity: severityToScore(rule.severity),
      },
    };
    if (helpUri) {
      ruleEntry.helpUri = helpUri;
    }
    if (rule.standards) {
      ruleEntry.properties.standards = {};
      for (const [key, val] of Object.entries(rule.standards)) {
        if (val && Array.isArray(val) && val.length > 0) {
          ruleEntry.properties.standards[key] = val;
        }
      }
    }
    return ruleEntry;
  });

  const sarifResults: SarifResult[] = result.findings.map((finding: Finding) => {
    const ruleIndex = ruleIndexMap.get(finding.ruleId) ?? 0;
    const sarifResult: SarifResult = {
      ruleId: finding.ruleId,
      ruleIndex,
      level: severityToLevel(finding.severity),
      message: { text: finding.remediation
        ? `${finding.title}: ${finding.description}\n\nRemediation: ${finding.remediation}`
        : `${finding.title}: ${finding.description}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: finding.location.file },
            region: {
              startLine: finding.location.line,
              ...(finding.location.column ? { startColumn: finding.location.column } : {}),
              ...(finding.location.snippet ? { snippet: { text: finding.location.snippet } } : {}),
            },
          },
        },
      ],
      partialFingerprints: {
        primaryLocationLineHash: computeFingerprint(
          finding.ruleId,
          finding.location.file,
          finding.location.snippet,
        ),
      },
    };

    if (finding.standards) {
      sarifResult.properties = {
        standards: finding.standards,
        ...(finding.reachability && { reachability: finding.reachability }),
        ...(finding.exploitability && { exploitability: finding.exploitability }),
      };
    }

    return sarifResult;
  });

  const sarifLog: SarifLog = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'g0',
            version: '1.0.0',
            informationUri: 'https://github.com/guard0-ai/g0',
            rules: sarifRules,
          },
        },
        results: sarifResults,
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: result.timestamp,
            properties: {
              score: result.score.overall,
              grade: result.score.grade,
              duration: result.duration,
              target: result.graph.rootPath,
              framework: result.graph.primaryFramework,
            },
          },
        ],
      },
    ],
  };

  const json = JSON.stringify(sarifLog, null, 2);

  if (outputPath) {
    fs.writeFileSync(outputPath, json, 'utf-8');
  }

  return json;
}
