import * as fs from 'node:fs';
import type { ScanResult } from '../types/score.js';

export interface JsonReport {
  version: string;
  timestamp: string;
  target: string;
  framework: string;
  duration: number;
  score: {
    overall: number;
    grade: string;
    domains: Array<{
      domain: string;
      label: string;
      score: number;
      findings: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
    }>;
  };
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings: Array<{
    id: string;
    ruleId: string;
    title: string;
    description: string;
    severity: string;
    confidence: string;
    domain: string;
    file: string;
    line: number;
    remediation: string;
    standards: { owaspAgentic: string[]; aiuc1?: string[]; iso42001?: string[]; nistAiRmf?: string[] };
    snippet?: string;
    reachability?: string;
    exploitability?: string;
  }>;
  graph: {
    agents: number;
    tools: number;
    prompts: number;
    files: number;
  };
  analyzability?: {
    score: number;
    totalFiles: number;
    analyzableFiles: number;
    opaqueFileCount: number;
  };
  activePreset?: string;
  taintFlows?: Array<{
    file: string;
    line: number;
    flowType: string;
    stages: Array<{ command: string; taintTypes: string[] }>;
  }>;
}

export function reportJson(result: ScanResult, outputPath?: string): string {
  const report: JsonReport = {
    version: '1.0.0',
    timestamp: result.timestamp,
    target: result.graph.rootPath,
    framework: result.graph.primaryFramework,
    duration: result.duration,
    score: {
      overall: result.score.overall,
      grade: result.score.grade,
      domains: result.score.domains.map(d => ({
        domain: d.domain,
        label: d.label,
        score: d.score,
        findings: d.findings,
        critical: d.critical,
        high: d.high,
        medium: d.medium,
        low: d.low,
      })),
      ...(result.score.correlations ? { correlations: result.score.correlations } : {}),
    },
    summary: {
      total: result.findings.length,
      critical: result.findings.filter(f => f.severity === 'critical').length,
      high: result.findings.filter(f => f.severity === 'high').length,
      medium: result.findings.filter(f => f.severity === 'medium').length,
      low: result.findings.filter(f => f.severity === 'low').length,
      info: result.findings.filter(f => f.severity === 'info').length,
    },
    findings: result.findings.map(f => ({
      id: f.id,
      ruleId: f.ruleId,
      title: f.title,
      description: f.description,
      severity: f.severity,
      confidence: f.confidence,
      domain: f.domain,
      file: f.location.file,
      line: f.location.line,
      remediation: f.remediation,
      snippet: f.location.snippet || undefined,
      standards: f.standards,
      reachability: f.reachability,
      exploitability: f.exploitability,
    })),
    graph: {
      agents: result.graph.agents.length,
      tools: result.graph.tools.length,
      prompts: result.graph.prompts.length,
      files: result.graph.files.all.length,
    },
    ...(result.analyzability && {
      analyzability: {
        score: result.analyzability.score,
        totalFiles: result.analyzability.totalFiles,
        analyzableFiles: result.analyzability.analyzableFiles,
        opaqueFileCount: result.analyzability.opaqueFiles.length,
      },
    }),
    ...(result.activePreset && { activePreset: result.activePreset }),
    ...(result.findings.some(f => f.taintFlow) && {
      taintFlows: result.findings
        .filter(f => f.taintFlow)
        .map(f => ({
          file: f.location.file,
          line: f.location.line,
          flowType: f.taintFlow!.flowType,
          stages: f.taintFlow!.stages.map(s => ({ command: s.command, taintTypes: s.taintTypes })),
        })),
    }),
  };

  const json = JSON.stringify(report, null, 2);

  if (outputPath) {
    fs.writeFileSync(outputPath, json, 'utf-8');
  }

  return json;
}
