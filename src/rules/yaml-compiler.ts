import * as fs from 'node:fs';
import type { Rule } from '../types/control.js';
import type { Finding, StandardsMapping } from '../types/finding.js';
import type { AgentGraph } from '../types/agent-graph.js';
import type { YamlRule } from './yaml-schema.js';
import type { SecurityDomain } from '../types/common.js';
import { isCommentLine } from '../analyzers/ast/queries.js';
import { getFileTree } from '../analyzers/ast/cache.js';
import { isMatchInExcludedContext } from '../analyzers/ast/context.js';
import { findPatternMatches, canFlowWithinScope, checkProximityFlow, crossFileTaint as crossFileTaintCheck } from '../analyzers/ast/taint.js';
import { applyDomainDefaults } from '../standards/mapping.js';
import type { SecurityControlType } from '../analyzers/control-registry.js';

/**
 * Compiles a parsed YAML rule into a Rule with a check() function.
 */
export function compileYamlRule(yaml: YamlRule): Rule {
  const standards = mapStandards(yaml.info.standards);
  const frameworks = yaml.info.frameworks.includes('all')
    ? ['langchain', 'crewai', 'mcp', 'openai', 'vercel-ai', 'bedrock', 'autogen', 'langchain4j', 'spring-ai', 'golang-ai', 'generic']
    : yaml.info.frameworks;

  // Sync info-level owasp_agentic into standards.owaspAgentic if not already set
  if ((!standards.owaspAgentic || standards.owaspAgentic.length === 0) && yaml.info.owasp_agentic.length > 0) {
    standards.owaspAgentic = yaml.info.owasp_agentic;
  }

  // Auto-populate missing standards from domain defaults
  const enrichedStandards = applyDomainDefaults(standards, yaml.info.domain as SecurityDomain);

  const rule: Rule & { suppressedBy?: SecurityControlType[]; requiresControl?: SecurityControlType } = {
    id: yaml.id,
    name: yaml.info.name,
    domain: yaml.info.domain,
    severity: yaml.info.severity,
    confidence: yaml.info.confidence,
    description: yaml.info.description,
    frameworks,
    owaspAgentic: enrichedStandards.owaspAgentic,
    standards: enrichedStandards,
    check: buildCheckFunction(yaml),
  };

  // Attach suppressed_by metadata for engine-level filtering
  if (yaml.suppressed_by && yaml.suppressed_by.length > 0) {
    rule.suppressedBy = yaml.suppressed_by as SecurityControlType[];
  }

  // For project_missing checks, attach the required control type
  if (yaml.check.type === 'project_missing') {
    rule.requiresControl = yaml.check.control as SecurityControlType;
  }

  return rule;
}

function mapStandards(yamlStandards?: {
  owasp_agentic?: string[];
  nist_ai_rmf?: string[];
  iso42001?: string[];
  iso23894?: string[];
  owasp_aivss?: string[];
  a2as_basic?: string[];
  aiuc1?: string[];
  eu_ai_act?: string[];
  mitre_atlas?: string[];
  owasp_llm_top10?: string[];
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
    euAiAct: yamlStandards.eu_ai_act,
    mitreAtlas: yamlStandards.mitre_atlas,
    owaspLlmTop10: yamlStandards.owasp_llm_top10,
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
            }, 'prompt_contains'));
          }
        }
        return findings;
      };

    case 'prompt_missing':
      return (graph) => {
        const findings: Finding[] = [];
        // Inter-agent rules only apply when multiple agents exist
        if (domain === 'inter-agent' && graph.agents.length < 2) return findings;
        const regex = new RegExp(check.pattern, 'i');
        // Cap confidence at medium for prompt_missing rules (high FP rate)
        const cappedConfidence = confidence === 'high' ? 'medium' : confidence;
        // Downgrade severity for prompt_missing (absence of keyword is weak signal)
        const cappedSeverity = severity === 'critical' ? 'medium' : severity === 'high' ? 'low' : severity;
        // Cap prompt_missing findings at 3 per rule per scan to reduce noise
        const MAX_PROMPT_MISSING_FINDINGS = 3;
        for (const prompt of graph.prompts) {
          if (findings.length >= MAX_PROMPT_MISSING_FINDINGS) break;
          if (check.prompt_type !== 'any' && prompt.type !== check.prompt_type) continue;
          if (!regex.test(prompt.content) && prompt.content.length > 50) {
            findings.push(makeFinding(ruleId, check.message, domain, cappedSeverity, cappedConfidence, standards, {
              file: prompt.file,
              line: prompt.line,
              snippet: prompt.content.substring(0, 100),
            }, 'prompt_missing'));
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
            }, 'tool_has_capability'));
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
            }, 'tool_missing_property'));
          }
        }
        return findings;
      };

    case 'config_matches':
      return (graph) => {
        const findings: Finding[] = [];
        const regex = new RegExp(check.pattern, 'i');
        for (const config of graph.configs) {
          try {
            const content = fs.readFileSync(config.file, 'utf-8');
            if (regex.test(content)) {
              findings.push(makeFinding(ruleId, check.message, domain, severity, confidence, standards, {
                file: config.file,
                line: 1,
                snippet: config.type,
              }, 'config_matches'));
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
        // Inter-agent rules only apply when multiple agents exist
        if (domain === 'inter-agent' && graph.agents.length < 2) return findings;
        const regex = new RegExp(check.pattern, 'gm');
        const fileList = getFilesForLanguage(graph, check.language);
        for (const fileInfo of fileList) {
          try {
            const content = graph.astStore?.getContent(fileInfo.path) ?? fs.readFileSync(fileInfo.path, 'utf-8');
            // Skip very large files (likely generated/bundled — 500KB threshold)
            if (content.length > 500_000) continue;
            const lines = content.split('\n');
            let fileMatchCount = 0;

            // Try to get AST for AST-based context filtering (prefer ASTStore)
            const tree = graph.astStore?.getTree(fileInfo.path) ?? getFileTree(fileInfo.path, content);

            for (let i = 0; i < lines.length; i++) {
              if (regex.test(lines[i])) {
                // AST-based context filtering: skip matches inside comments, strings, imports, type annotations
                if (tree) {
                  if (isMatchInExcludedContext(tree, i, 0)) {
                    regex.lastIndex = 0;
                    continue;
                  }
                } else {
                  // Fallback: skip comment lines (text-based FP reduction)
                  const matchIdx = content.indexOf(lines[i]);
                  if (matchIdx !== -1 && isCommentLine(content, matchIdx, fileInfo.language ?? 'javascript')) {
                    regex.lastIndex = 0;
                    continue;
                  }
                }
                findings.push(makeFinding(ruleId, check.message, domain, severity, confidence, standards, {
                  file: fileInfo.path,
                  line: i + 1,
                  snippet: lines[i].trim().substring(0, 100),
                }, 'code_matches'));
                fileMatchCount++;
                // Cap at 10 findings per file per rule (inline, before dedup)
                if (fileMatchCount >= 10) { regex.lastIndex = 0; break; }
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
        // Inter-agent rules only apply when multiple agents exist
        if (domain === 'inter-agent' && graph.agents.length < 2) return findings;
        // Cap agent_property findings at 3 per rule per scan to reduce noise.
        // These fire per-agent for missing properties that no framework defines,
        // so hundreds of agents = thousands of identical findings without a cap.
        const MAX_AGENT_PROPERTY_FINDINGS = 3;
        for (const agent of graph.agents) {
          if (findings.length >= MAX_AGENT_PROPERTY_FINDINGS) break;
          const value = (agent as any)[check.property];
          let match = false;
          if (check.condition === 'missing') match = value === undefined || value === null;
          else if (check.condition === 'exists') match = value !== undefined && value !== null;
          else if (check.condition === 'equals') match = value === check.value;

          if (match) {
            // Downgrade severity for 'missing' checks on non-standard properties.
            // Properties like principalValidation, outputFilter, toolAllowlist,
            // systemPromptReserve are g0-recommended but not defined in any framework SDK.
            const effectiveSeverity = check.condition === 'missing' && severity !== 'info'
              ? (severity === 'critical' ? 'medium' : severity === 'high' ? 'low' : 'low')
              : severity;
            findings.push(makeFinding(ruleId, check.message, domain, effectiveSeverity, confidence, standards, {
              file: agent.file,
              line: agent.line,
              snippet: `Agent "${agent.name}": ${check.property} ${check.condition}`,
            }, 'agent_property'));
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
            }, 'model_property'));
          }
        }
        return findings;
      };

    case 'project_missing':
      // Always emit a finding — the engine will suppress it if the
      // control registry shows the project HAS this control.
      // This inverts the detection: flag absence, not presence.
      return (graph) => {
        // Only emit if there's at least one agent (i.e., this is an agent project)
        if (graph.agents.length === 0 && graph.tools.length === 0) return [];
        return [makeFinding(ruleId, check.message, domain, severity, confidence, standards, {
          file: graph.rootPath,
          line: 0,
          snippet: `Project missing security control: ${check.control}`,
        }, 'project_missing')];
      };

    case 'taint_flow':
      return (graph) => {
        const findings: Finding[] = [];
        const sourcePatterns = check.sources.map((s: { pattern: string }) => new RegExp(s.pattern, 'gm'));
        const sinkPatterns = check.sinks.map((s: { pattern: string }) => new RegExp(s.pattern, 'gm'));
        const sanitizerPatterns = (check.sanitizers ?? []).map((s: { pattern: string }) => new RegExp(s.pattern, 'gm'));

        const fileList = getFilesForLanguage(graph, check.language);
        for (const fileInfo of fileList) {
          try {
            const content = graph.astStore?.getContent(fileInfo.path) ?? fs.readFileSync(fileInfo.path, 'utf-8');
            if (content.length > 500_000) continue;

            const tree = graph.astStore?.getTree(fileInfo.path) ?? getFileTree(fileInfo.path, content);
            if (tree) {
              // AST-based taint tracking (precise)
              const sources = findPatternMatches(content, sourcePatterns, tree);
              const sinks = findPatternMatches(content, sinkPatterns, tree);
              const sanitizers = findPatternMatches(content, sanitizerPatterns, tree);

              let fileFlowCount = 0;
              for (const source of sources) {
                for (const sink of sinks) {
                  if (canFlowWithinScope(tree, source, sink, sanitizers)) {
                    findings.push(makeFinding(ruleId, check.message, domain, severity, confidence, standards, {
                      file: fileInfo.path,
                      line: sink.line + 1,
                      snippet: `${source.text} \u2192 ${sink.text}`,
                    }, 'taint_flow'));
                    fileFlowCount++;
                    if (fileFlowCount >= 5) break;
                  }
                }
                if (fileFlowCount >= 5) break;
              }
            } else {
              // Regex fallback: proximity heuristic
              const lines = content.split('\n');
              const flows = checkProximityFlow(lines, sourcePatterns, sinkPatterns, sanitizerPatterns);
              let fileFlowCount = 0;
              for (const flow of flows) {
                findings.push(makeFinding(ruleId, check.message, domain, severity, 'low', standards, {
                  file: fileInfo.path,
                  line: flow.sinkLine + 1,
                  snippet: `${flow.sourceText} \u2192 ${flow.sinkText}`,
                }, 'taint_flow'));
                fileFlowCount++;
                if (fileFlowCount >= 5) break;
              }
            }
          } catch {
            // File not readable, skip
          }
        }
        return findings;
      };

    case 'cross_file_taint':
      return (graph) => {
        const findings: Finding[] = [];
        if (!graph.astStore || !graph.moduleGraph) return findings;

        const sourceRe = new RegExp(check.source, 'i');
        const sinkRe = new RegExp(check.sink, 'i');

        const taintResults = crossFileTaintCheck(
          sourceRe,
          sinkRe,
          graph.astStore,
          graph.moduleGraph,
          check.max_depth ?? 3,
        );

        for (const result of taintResults) {
          findings.push(makeFinding(ruleId, check.message, domain, severity, confidence, standards, {
            file: result.sinkFile,
            line: result.sinkLine,
            snippet: `${result.sourceText} \u2192 ${result.sinkText} (cross-file: ${result.callChain.join(' \u2192 ')})`,
          }, 'cross_file_taint'));
        }

        return findings;
      };

    case 'ast_matches':
      return (graph) => {
        const findings: Finding[] = [];
        // Inter-agent rules only apply when multiple agents exist
        if (domain === 'inter-agent' && graph.agents.length < 2) return findings;
        const fileList = getFilesForLanguage(graph, check.language);
        const filters = check.filters ?? [];
        const excludeContexts = new Set(check.context?.not_in ?? ['comment', 'string_literal']);

        for (const fileInfo of fileList) {
          // Get tree from ASTStore (preferred) or parse on-demand
          const tree = graph.astStore?.getTree(fileInfo.path) ?? getFileTree(fileInfo.path);
          if (!tree) continue;

          // Find all nodes of the specified type
          const matchNodes = findNodesForAst(tree, check.node_type);
          let fileMatchCount = 0;

          for (const node of matchNodes) {
            // Context exclusion: skip if node is inside an excluded context
            if (isNodeInExcludedAstContext(node, excludeContexts)) continue;

            // Apply filters
            if (!applyAstFilters(node, filters)) continue;

            const line = node.startPosition.row + 1;
            findings.push(makeFinding(ruleId, check.message, domain, severity, confidence, standards, {
              file: fileInfo.path,
              line,
              snippet: node.text.substring(0, 100),
            }, 'ast_matches'));

            fileMatchCount++;
            if (fileMatchCount >= 10) break;
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
    case 'java': return graph.files.java;
    case 'go': return graph.files.go;
    case 'yaml': return graph.files.yaml;
    case 'json': return graph.files.json;
    case 'any': return graph.files.all;
    default: return graph.files.all;
  }
}

// ─── AST Matches helpers ─────────────────────────────────────────────

import { findNodes } from '../analyzers/ast/queries.js';
import type { SyntaxNode, Tree as ASTTree } from '../analyzers/ast/parser.js';

const AST_COMMENT_TYPES = new Set(['comment', 'line_comment', 'block_comment']);
const AST_STRING_TYPES = new Set(['string', 'string_literal', 'template_string', 'concatenated_string', 'string_content']);
const AST_IMPORT_TYPES = new Set(['import_statement', 'import_from_statement', 'import_declaration', 'export_statement']);
const AST_DECORATOR_TYPES = new Set(['decorator', 'annotation', 'marker_annotation', 'normal_annotation']);
const AST_TYPE_TYPES = new Set(['type_annotation', 'type_alias_declaration', 'interface_declaration', 'type_identifier']);

const CONTEXT_TYPE_MAP: Record<string, Set<string>> = {
  comment: AST_COMMENT_TYPES,
  string_literal: AST_STRING_TYPES,
  import: AST_IMPORT_TYPES,
  decorator: AST_DECORATOR_TYPES,
  type_annotation: AST_TYPE_TYPES,
};

function findNodesForAst(tree: ASTTree, nodeType: string): SyntaxNode[] {
  // Support pipe-separated node types: "call_expression|call"
  const types = nodeType.split('|').map(t => t.trim());
  return findNodes(tree, (node) => types.includes(node.type));
}

function isNodeInExcludedAstContext(node: SyntaxNode, excludeContexts: Set<string>): boolean {
  let current: SyntaxNode | null = node;
  while (current) {
    for (const ctx of excludeContexts) {
      const typeSet = CONTEXT_TYPE_MAP[ctx];
      if (typeSet) {
        if (typeSet.has(current.type)) return true;
      } else {
        // Treat as literal node type
        if (current.type === ctx) return true;
      }
    }
    current = current.parent;
  }
  return false;
}

interface AstFilter {
  field?: string;
  pattern?: string;
  contains_string_concat?: boolean;
  has_child_type?: string;
  ancestor_type?: string;
}

function applyAstFilters(node: SyntaxNode, filters: AstFilter[]): boolean {
  for (const filter of filters) {
    if (!applyOneAstFilter(node, filter)) return false;
  }
  return true;
}

function applyOneAstFilter(node: SyntaxNode, filter: AstFilter): boolean {
  // Field + pattern: check a named child field against regex
  if (filter.field && filter.pattern) {
    const regex = new RegExp(filter.pattern, 'i');
    const child = node.childForFieldName(filter.field);
    if (child) {
      // Named field found — test it
      if (!regex.test(child.text)) return false;
    } else {
      // Field not found — fall back to full node text match
      // This handles member_expression, identifier, and other node types
      // where the expected field name doesn't exist
      if (!regex.test(node.text)) return false;
    }
  }

  // contains_string_concat: check if subtree has string concatenation
  if (filter.contains_string_concat) {
    const fieldNode = filter.field ? node.childForFieldName(filter.field) : node;
    if (!fieldNode) return false;
    if (!hasStringConcat(fieldNode)) return false;
  }

  // has_child_type: check if a child of given type exists
  if (filter.has_child_type) {
    const types = filter.has_child_type.split('|').map(t => t.trim());
    const hasChild = node.namedChildren.some(c => types.includes(c.type));
    if (!hasChild) return false;
  }

  // ancestor_type: check if node has an ancestor of given type
  if (filter.ancestor_type) {
    const types = filter.ancestor_type.split('|').map(t => t.trim());
    let current: SyntaxNode | null = node.parent;
    let found = false;
    while (current) {
      if (types.includes(current.type)) { found = true; break; }
      current = current.parent;
    }
    if (!found) return false;
  }

  return true;
}

function hasStringConcat(node: SyntaxNode): boolean {
  if (node.type === 'binary_expression' || node.type === 'binary_operator') {
    const op = node.children.find(c => c.text === '+');
    if (op) return true;
  }
  if (node.type === 'template_substitution' || node.type === 'interpolation') return true;
  if (node.type === 'formatted_string' || node.type === 'f_string') return true;
  for (const child of node.children) {
    if (hasStringConcat(child)) return true;
  }
  return false;
}

function makeFinding(
  ruleId: string,
  message: string,
  domain: string,
  severity: string,
  confidence: string,
  standards: StandardsMapping,
  location: { file: string; line: number; snippet?: string },
  checkType?: string,
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
    checkType,
  };
}
