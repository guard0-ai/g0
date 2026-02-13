import * as fs from 'node:fs';
import type { Rule } from '../types/control.js';
import type { Finding, StandardsMapping } from '../types/finding.js';
import type { AgentGraph } from '../types/agent-graph.js';
import type { YamlRule } from './yaml-schema.js';

/**
 * Compiles a parsed YAML rule into a Rule with a check() function.
 */
export function compileYamlRule(yaml: YamlRule): Rule {
  const standards = mapStandards(yaml.info.standards);
  const frameworks = yaml.info.frameworks.includes('all')
    ? ['langchain', 'crewai', 'mcp', 'openai', 'vercel-ai', 'bedrock', 'autogen', 'generic']
    : yaml.info.frameworks;

  // Sync info-level owasp_agentic into standards.owaspAgentic if not already set
  if ((!standards.owaspAgentic || standards.owaspAgentic.length === 0) && yaml.info.owasp_agentic.length > 0) {
    standards.owaspAgentic = yaml.info.owasp_agentic;
  }

  return {
    id: yaml.id,
    name: yaml.info.name,
    domain: yaml.info.domain,
    severity: yaml.info.severity,
    confidence: yaml.info.confidence,
    description: yaml.info.description,
    frameworks,
    owaspAgentic: yaml.info.owasp_agentic,
    standards,
    check: buildCheckFunction(yaml),
  };
}

function mapStandards(yamlStandards?: {
  owasp_agentic?: string[];
  nist_ai_rmf?: string[];
  iso42001?: string[];
  iso23894?: string[];
  owasp_aivss?: string[];
  a2as_basic?: string[];
  aiuc1?: string[];
}): StandardsMapping {
  if (!yamlStandards) return { owaspAgentic: [] };
  return {
    owaspAgentic: yamlStandards.owasp_agentic ?? [],
    nistAiRmf: yamlStandards.nist_ai_rmf,
    iso42001: yamlStandards.iso42001,
    iso23894: yamlStandards.iso23894,
    owaspAivss: yamlStandards.owasp_aivss,
    a2asBasic: yamlStandards.a2as_basic,
    aiuc1: yamlStandards.aiuc1,
  };
}

function buildCheckFunction(yaml: YamlRule): (graph: AgentGraph) => Finding[] {
  const { check } = yaml;
  const ruleId = yaml.id;
  const domain = yaml.info.domain;
  const severity = yaml.info.severity;
  const confidence = yaml.info.confidence;
  const standards = mapStandards(yaml.info.standards);

  switch (check.type) {
    case 'prompt_contains':
      return (graph) => {
        const findings: Finding[] = [];
        const regex = new RegExp(check.pattern, 'i');
        for (const prompt of graph.prompts) {
          if (check.prompt_type !== 'any' && prompt.type !== check.prompt_type) continue;
          if (regex.test(prompt.content)) {
            findings.push(makeFinding(ruleId, check.message, domain, severity, confidence, standards, {
              file: prompt.file,
              line: prompt.line,
              snippet: prompt.content.substring(0, 100),
            }));
          }
        }
        return findings;
      };

    case 'prompt_missing':
      return (graph) => {
        const findings: Finding[] = [];
        const regex = new RegExp(check.pattern, 'i');
        for (const prompt of graph.prompts) {
          if (check.prompt_type !== 'any' && prompt.type !== check.prompt_type) continue;
          if (!regex.test(prompt.content) && prompt.content.length > 20) {
            findings.push(makeFinding(ruleId, check.message, domain, severity, confidence, standards, {
              file: prompt.file,
              line: prompt.line,
              snippet: prompt.content.substring(0, 100),
            }));
          }
        }
        return findings;
      };

    case 'tool_has_capability':
      return (graph) => {
        const findings: Finding[] = [];
        for (const tool of graph.tools) {
          if (tool.capabilities.includes(check.capability as any)) {
            findings.push(makeFinding(ruleId, check.message, domain, severity, confidence, standards, {
              file: tool.file,
              line: tool.line,
              snippet: `Tool "${tool.name}" has capability: ${check.capability}`,
            }));
          }
        }
        return findings;
      };

    case 'tool_missing_property':
      return (graph) => {
        const findings: Finding[] = [];
        for (const tool of graph.tools) {
          const actual = tool[check.property as keyof typeof tool];
          const expected = check.expected;
          if (actual !== expected) {
            findings.push(makeFinding(ruleId, check.message, domain, severity, confidence, standards, {
              file: tool.file,
              line: tool.line,
              snippet: `Tool "${tool.name}": ${check.property} = ${actual}`,
            }));
          }
        }
        return findings;
      };

    case 'config_matches':
      return (graph) => {
        const findings: Finding[] = [];
        const regex = new RegExp(check.pattern, 'i');
        for (const config of graph.configs) {
          // Read file content for pattern matching
          try {
            const content = fs.readFileSync(config.file, 'utf-8');
            if (regex.test(content)) {
              findings.push(makeFinding(ruleId, check.message, domain, severity, confidence, standards, {
                file: config.file,
                line: 1,
                snippet: config.type,
              }));
            }
          } catch {
            // File not readable, skip
          }
        }
        return findings;
      };

    case 'code_matches':
      return (graph) => {
        const findings: Finding[] = [];
        const regex = new RegExp(check.pattern, 'gm');
        const fileList = getFilesForLanguage(graph, check.language);
        for (const fileInfo of fileList) {
          try {
            const content = fs.readFileSync(fileInfo.path, 'utf-8');
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
              if (regex.test(lines[i])) {
                findings.push(makeFinding(ruleId, check.message, domain, severity, confidence, standards, {
                  file: fileInfo.path,
                  line: i + 1,
                  snippet: lines[i].trim().substring(0, 100),
                }));
              }
              regex.lastIndex = 0;
            }
          } catch {
            // File not readable, skip
          }
        }
        return findings;
      };

    case 'agent_property':
      return (graph) => {
        const findings: Finding[] = [];
        for (const agent of graph.agents) {
          const value = (agent as any)[check.property];
          let match = false;
          if (check.condition === 'missing') match = value === undefined || value === null;
          else if (check.condition === 'exists') match = value !== undefined && value !== null;
          else if (check.condition === 'equals') match = value === check.value;

          if (match) {
            findings.push(makeFinding(ruleId, check.message, domain, severity, confidence, standards, {
              file: agent.file,
              line: agent.line,
              snippet: `Agent "${agent.name}": ${check.property} ${check.condition}`,
            }));
          }
        }
        return findings;
      };

    case 'model_property':
      return (graph) => {
        const findings: Finding[] = [];
        for (const model of graph.models) {
          const value = (model as any)[check.property];
          let match = false;
          if (check.condition === 'missing') match = value === undefined || value === null;
          else if (check.condition === 'exists') match = value !== undefined && value !== null;
          else if (check.condition === 'equals') match = value === check.value;
          else if (check.condition === 'matches') match = typeof value === 'string' && new RegExp(String(check.value)).test(value);

          if (match) {
            findings.push(makeFinding(ruleId, check.message, domain, severity, confidence, standards, {
              file: model.file,
              line: model.line,
              snippet: `Model "${model.name}": ${check.property} ${check.condition}`,
            }));
          }
        }
        return findings;
      };

    case 'no_check':
      return () => [];
  }
}

function getFilesForLanguage(graph: AgentGraph, language: string) {
  switch (language) {
    case 'python': return graph.files.python;
    case 'typescript': return graph.files.typescript;
    case 'javascript': return graph.files.javascript;
    case 'yaml': return graph.files.yaml;
    case 'json': return graph.files.json;
    case 'any': return graph.files.all;
    default: return graph.files.all;
  }
}

function makeFinding(
  ruleId: string,
  message: string,
  domain: string,
  severity: string,
  confidence: string,
  standards: StandardsMapping,
  location: { file: string; line: number; snippet?: string },
): Finding {
  return {
    id: `${ruleId}-0`,
    ruleId,
    title: message,
    description: message,
    severity: severity as Finding['severity'],
    confidence: confidence as Finding['confidence'],
    domain: domain as Finding['domain'],
    location,
    remediation: `Address ${ruleId}: ${message}`,
    standards,
  };
}
