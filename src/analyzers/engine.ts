import * as fs from 'node:fs';
import type { AgentGraph } from '../types/agent-graph.js';
import type { Rule } from '../types/control.js';
import type { Finding } from '../types/finding.js';
import type { Confidence, Severity } from '../types/common.js';
import { getAllRules, getRulesByTier, type RulesetTier } from './rules/index.js';
import type { ControlRegistry, SecurityControlType } from './control-registry.js';
import { DOMAIN_CONTROL_MAP } from './control-registry.js';
import { buildReachabilityIndex } from './reachability.js';
import type { Tree } from './ast/parser.js';
import { getFileTree } from './ast/cache.js';
import { assessExploitability, getFunctionScopeKey } from './ast/taint.js';

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const COMPENSATING_PATTERNS = /\b(sanitize|validate|escape|allowlist|denylist|whitelist|blacklist|filter|encode|purify)\b/i;

const DEV_GUARD_PATTERNS = /\b(?:if\s*\(\s*(?:isDev|is_dev|isDebug|is_debug|isLocal|isDevelopment|process\.env\.NODE_ENV\s*[!=]==?\s*['"](?:development|test)['"]|settings\.DEBUG|os\.environ\.get\s*\(\s*['"](?:DEBUG|ENV|FLASK_ENV|DJANGO_SETTINGS_MODULE)['"]|app\.debug|DEBUG\s*==\s*True))\b/i;

const TEST_FILE_PATTERNS = [
  /\/tests?\//, /\/__tests__\//, /\/spec\//, /\/fixtures?\//,
  /_test\.\w+$/, /\.test\.\w+$/, /\.spec\.\w+$/, /\/conftest\.py$/,
  /\/examples?\//, /\/docs?\//, /\/tutorials?\//, /\/notebooks?\//,
  /\/demo\//, /\/samples?\//, /\/quickstart\//, /\/cookbook\//,
  /\/benchmarks?\//, /\/e2e\//, /\/integration_tests?\//,
];

const TEST_SEVERITY_DOWNGRADE: Record<string, Severity> = {
  critical: 'medium',
  high: 'low',
};

export function isTestFile(filePath: string): boolean {
  return TEST_FILE_PATTERNS.some(p => p.test(filePath));
}

export interface AnalysisOptions {
  excludeRules?: string[];
  onlyRules?: string[];
  severity?: Severity;
  frameworks?: string[];
  rulesDir?: string;
  controlRegistry?: ControlRegistry;
  showAll?: boolean;
  ruleset?: RulesetTier;
  thresholds?: {
    max_findings_per_rule?: number;
    low_severity_cap?: number;
    medium_severity_cap?: number;
  };
  severityOverrides?: Record<string, Severity>;
}

export function runAnalysis(graph: AgentGraph, options?: AnalysisOptions): Finding[] {
  // Use graph's ASTStore for tree lookups if available
  const astStore = graph.astStore;
  const getTree = (filePath: string) => astStore?.getTree(filePath) ?? getFileTree(filePath);

  let rules = getAllRules(options?.rulesDir);

  // Apply ruleset tier filter (recommended/extended/all)
  if (options?.ruleset && options.ruleset !== 'all') {
    rules = getRulesByTier(rules, options.ruleset);
  }

  // Filter by --rules (only run these)
  if (options?.onlyRules && options.onlyRules.length > 0) {
    const includeSet = new Set(options.onlyRules);
    rules = rules.filter(r => includeSet.has(r.id));
  }

  // Filter by --exclude-rules
  if (options?.excludeRules && options.excludeRules.length > 0) {
    const excludeSet = new Set(options.excludeRules);
    rules = rules.filter(r => !excludeSet.has(r.id));
  }

  // Filter by --frameworks
  if (options?.frameworks && options.frameworks.length > 0) {
    const fwSet = new Set(options.frameworks);
    rules = rules.filter(r =>
      r.frameworks.includes('all') || r.frameworks.some(f => fwSet.has(f)),
    );
  }

  const findings: Finding[] = [];
  const registry = options?.controlRegistry;

  for (const rule of rules) {
    // For project_missing rules, skip if the control registry shows the control exists
    const ruleRecord = rule as Rule & Record<string, unknown>;
    if (ruleRecord.requiresControl && registry) {
      if (registry.hasControl(ruleRecord.requiresControl as SecurityControlType)) continue;
    }

    // For rules with suppressed_by, skip if ALL listed controls are present
    if (ruleRecord.suppressedBy && registry) {
      const suppressors = ruleRecord.suppressedBy as string[];
      const allPresent = suppressors.every((s: string) => registry.hasControl(s as SecurityControlType));
      if (allPresent) continue;
    }

    const ruleFindings = rule.check(graph);
    findings.push(...ruleFindings);
  }

  let result = deduplicateFindings(findings);

  // Per-rule cap for blanket check types (agent_property, prompt_missing, model_property)
  // These fire per-agent/per-prompt and produce noise. Code-level rules are NOT capped
  // to avoid hiding true positives in different files.
  result = capBlanketRules(result, 5);

  // Global per-rule safety cap: prevents any single rule from flooding large repos
  // (e.g., lobe-chat 11k+ files). Configurable via thresholds.max_findings_per_rule.
  const maxPerRule = options?.thresholds?.max_findings_per_rule ?? 50;
  result = capPerRule(result, maxPerRule);

  // Cross-rule dedup: max 1 finding per domain per file:line
  result = deduplicateCrossRule(result);

  // Cap prompt_missing findings at 5 per prompt location
  result = capPromptMissing(result);

  // Function-scope dedup: collapse multiple hits of same rule within one function
  result = deduplicateByFunctionScope(result, getTree);

  // Filter inline suppressions (// g0-ignore or # g0-ignore)
  result = filterSuppressed(result);

  // Tag findings with reachability and exploitability
  const reachIndex = buildReachabilityIndex(graph);
  for (const f of result) {
    f.reachability = reachIndex.getReachability(f.location.file, f.location.line);

    // Assess exploitability for agent/tool-reachable findings
    if (f.reachability === 'agent-reachable' || f.reachability === 'tool-reachable') {
      const tree = getTree(f.location.file);
      f.exploitability = assessExploitability(
        tree,
        f.location.file,
        f.location.line,
        reachIndex.agentFiles,
        reachIndex.toolFiles,
      );
    } else {
      f.exploitability = f.reachability === 'utility-code' ? 'unlikely' : 'not-assessed';
    }
  }

  // Filter test-file findings: remove medium/low/info noise, keep critical/high downgraded
  if (options?.showAll) {
    // --show-all: just downgrade, don't filter
    for (const f of result) {
      if (isTestFile(f.location.file)) {
        const downgraded = TEST_SEVERITY_DOWNGRADE[f.severity];
        if (downgraded) f.severity = downgraded;
        f.confidence = 'low';
      }
    }
  } else {
    result = result.filter(f => {
      if (!isTestFile(f.location.file)) return true;
      // Remove medium/low/info test findings entirely
      if (f.severity !== 'critical' && f.severity !== 'high') return false;
      // Keep critical/high but downgrade them
      const downgraded = TEST_SEVERITY_DOWNGRADE[f.severity];
      if (downgraded) f.severity = downgraded;
      f.confidence = 'low';
      return true;
    });
  }

  // Detect compensating controls nearby and downgrade severity
  applyCompensatingControls(result);

  // Control-registry-aware confidence calibration
  if (options?.controlRegistry) {
    applyControlRegistryCalibration(result, options.controlRegistry);
  }

  // Filter by minimum severity
  if (options?.severity) {
    const minLevel = SEVERITY_ORDER[options.severity];
    result = result.filter(f => SEVERITY_ORDER[f.severity] <= minLevel);
  }

  return result;
}

/** Max findings per rule per file — prevents one broad regex from flooding results */
const MAX_FINDINGS_PER_RULE_PER_FILE = 10;

/** Non-code binary/media files that should never be scanned */
const BINARY_FILE_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.bmp', '.tiff',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.mp3', '.mp4', '.wav', '.ogg', '.webm', '.avi',
  '.pdf', '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
  '.svg', '.map', '.lock',
  '.min.js', '.min.css', '.bundle.js', '.chunk.js',
]);

/** JSON/YAML data files should be excluded unless they're config/secret scanning */
const CONFIG_SCAN_RULES = new Set([
  'AA-IA-001', 'AA-IA-002', 'AA-IA-003', 'AA-IA-004', // secret/key detection
  'AA-SC-061', // unpinned deps
]);

/** Vendor/generated directories that produce noise */
const VENDOR_DIR_PATTERNS = [
  /\/node_modules\//, /\/vendor\//, /\/dist\//, /\/build\//,
  /\/\.next\//, /\/\.nuxt\//, /\/\.output\//, /\/coverage\//,
  /\/\.git\//, /\/__pycache__\//, /\/\.tox\//, /\/\.mypy_cache\//,
  /\/\.pytest_cache\//, /\/site-packages\//,
  /\/cassettes\//, /\/snapshots\//, /\/__snapshots__\//,
];

function isBinaryFile(filePath: string): boolean {
  const lower = filePath.toLowerCase();
  for (const ext of BINARY_FILE_EXTENSIONS) {
    if (lower.endsWith(ext)) return true;
  }
  return false;
}

function isVendorPath(filePath: string): boolean {
  return VENDOR_DIR_PATTERNS.some(p => p.test(filePath));
}

function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const ruleFileCount = new Map<string, number>();

  return findings.filter(f => {
    // Exact line dedup
    const key = `${f.ruleId}:${f.location.file}:${f.location.line}`;
    if (seen.has(key)) return false;
    seen.add(key);

    // Skip binary files and vendor directories
    if (isBinaryFile(f.location.file) || isVendorPath(f.location.file)) return false;

    // JSON/YAML files only allowed for config/secret scanning rules
    const lower = f.location.file.toLowerCase();
    if ((lower.endsWith('.json') || lower.endsWith('.yaml') || lower.endsWith('.yml')) &&
        !CONFIG_SCAN_RULES.has(f.ruleId)) return false;

    // Per-rule-per-file cap (prevents one regex from flooding on a single file)
    const rfKey = `${f.ruleId}:${f.location.file}`;
    const rfCount = (ruleFileCount.get(rfKey) ?? 0) + 1;
    ruleFileCount.set(rfKey, rfCount);
    if (rfCount > MAX_FINDINGS_PER_RULE_PER_FILE) return false;

    return true;
  });
}

/** File content cache scoped to a single analysis run. */
const fileContentCache = new Map<string, string[] | null>();

function getFileLines(filePath: string): string[] | null {
  if (fileContentCache.has(filePath)) return fileContentCache.get(filePath)!;
  try {
    const lines = fs.readFileSync(filePath, 'utf-8').split('\n');
    fileContentCache.set(filePath, lines);
    return lines;
  } catch {
    fileContentCache.set(filePath, null);
    return null;
  }
}

/**
 * Filter out findings where the source line contains `// g0-ignore` or `# g0-ignore`.
 */
function filterSuppressed(findings: Finding[]): Finding[] {
  return findings.filter(f => {
    const lines = getFileLines(f.location.file);
    if (!lines) return true; // can't read → keep finding
    const line = lines[f.location.line - 1];
    if (!line) return true;
    return !(/\/\/\s*g0-ignore/.test(line) || /#\s*g0-ignore/.test(line));
  });
}

/**
 * Cap findings for blanket check types (agent_property, prompt_missing, model_property)
 * that fire per-agent/per-prompt without code-level specificity.
 * Code-level rules (code_matches, taint_flow, config_matches) are NOT capped here
 * to preserve true positives across different files.
 */
const BLANKET_CHECK_TYPES = new Set(['agent_property', 'prompt_missing', 'prompt_contains', 'model_property', 'tool_missing_property', 'tool_has_capability', 'project_missing']);

function capBlanketRules(findings: Finding[], maxPerRule: number): Finding[] {
  const ruleCount = new Map<string, number>();
  return findings.filter(f => {
    if (!f.checkType || !BLANKET_CHECK_TYPES.has(f.checkType)) return true;
    const count = (ruleCount.get(f.ruleId) ?? 0) + 1;
    ruleCount.set(f.ruleId, count);
    return count <= maxPerRule;
  });
}

/**
 * Global safety cap: max N findings per rule across the entire scan.
 * Prevents any single rule from flooding results in very large repos.
 */
function capPerRule(findings: Finding[], maxPerRule: number): Finding[] {
  const ruleCount = new Map<string, number>();
  return findings.filter(f => {
    const count = (ruleCount.get(f.ruleId) ?? 0) + 1;
    ruleCount.set(f.ruleId, count);
    return count <= maxPerRule;
  });
}

const SEVERITY_DOWNGRADE: Record<Severity, Severity> = {
  critical: 'high',
  high: 'medium',
  medium: 'low',
  low: 'info',
  info: 'info',
};

/**
 * Scan ±5 lines around each finding for compensating controls.
 * If found, downgrade severity by one level.
 */
function applyCompensatingControls(findings: Finding[]): void {
  for (const f of findings) {
    const lines = getFileLines(f.location.file);
    if (!lines) continue;
    const start = Math.max(0, f.location.line - 6); // -5 lines (0-indexed)
    const end = Math.min(lines.length, f.location.line + 5);
    const region = lines.slice(start, end).join('\n');
    if (COMPENSATING_PATTERNS.test(region)) {
      f.severity = SEVERITY_DOWNGRADE[f.severity];
    }
    // Downgrade findings inside development/debug guards
    if (DEV_GUARD_PATTERNS.test(region)) {
      f.severity = SEVERITY_DOWNGRADE[f.severity];
      f.confidence = 'low' as Confidence;
    }
  }
}

const CONFIDENCE_DOWNGRADE: Record<Confidence, Confidence> = {
  high: 'medium',
  medium: 'low',
  low: 'low',
};

/**
 * When the project has security controls relevant to a finding's domain,
 * downgrade the finding's confidence (not severity) since the project
 * is actively addressing that security concern.
 *
 * This prevents "detecting controls as vulnerabilities" — the #1 FP category.
 * If a project has rate-limiting, findings about missing rate-limiting
 * in other places get confidence-downgraded since the project clearly
 * knows about rate-limiting.
 */
function applyControlRegistryCalibration(findings: Finding[], registry: ControlRegistry): void {
  for (const f of findings) {
    const relevantControls = DOMAIN_CONTROL_MAP[f.domain];
    if (!relevantControls) continue;

    // Count how many relevant control types are present in the project
    let matchedControls = 0;
    for (const controlType of relevantControls) {
      if (registry.hasControl(controlType)) matchedControls++;
      // Extra credit: control exists in the SAME file as the finding
      if (registry.hasControlInFile(controlType, f.location.file)) {
        matchedControls++;
      }
    }

    // If 2+ relevant controls exist, downgrade confidence
    // If same-file control exists (matchedControls gets boosted), also downgrade severity
    if (matchedControls >= 3) {
      f.confidence = CONFIDENCE_DOWNGRADE[f.confidence];
      f.severity = SEVERITY_DOWNGRADE[f.severity];
    } else if (matchedControls >= 2) {
      f.confidence = CONFIDENCE_DOWNGRADE[f.confidence];
    }
  }
}

/**
 * Known semantic overlaps between rules from different domains.
 * When two rules from this set fire on the same file:line (or within ±3 lines),
 * only the higher-severity one is kept. This prevents duplicate findings
 * that describe the same underlying issue from different perspectives.
 */
const CROSS_DOMAIN_OVERLAPS: ReadonlySet<string> = new Set([
  // Agent capability boundaries ≈ missing human oversight (both flag unbounded agents)
  'AA-RA-011|AA-HO-005',
  'AA-HO-005|AA-RA-011',
  // Data leakage via retrieval ≈ identity/access missing tenant isolation
  'AA-DL-059|AA-IA-057',
  'AA-IA-057|AA-DL-059',
  // Data leakage via persistence ≈ memory persisted without encryption
  'AA-DL-058|AA-MP-008',
  'AA-MP-008|AA-DL-058',
  // Prompt injection ≈ user input in prompt (goal-integrity variants)
  'AA-GI-071|AA-GI-093',
  'AA-GI-093|AA-GI-071',
  // Missing rate limit ≈ missing retry budget (reliability overlap)
  'AA-RB-012|AA-RB-014',
  'AA-RB-014|AA-RB-012',
]);

/**
 * Cross-rule dedup: when multiple rules from the same domain fire on
 * the same file:line, keep only the highest-severity one per domain.
 * Also deduplicates known cross-domain overlaps at the same location.
 */
export function deduplicateCrossRule(findings: Finding[]): Finding[] {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = `${f.location.file}:${f.location.line}`;
    let group = groups.get(key);
    if (!group) { group = []; groups.set(key, group); }
    group.push(f);
  }
  const result: Finding[] = [];
  for (const group of groups.values()) {
    if (group.length === 1) { result.push(group[0]); continue; }
    // Keep max 1 per domain, highest severity wins
    const byDomain = new Map<string, Finding>();
    for (const f of group) {
      const existing = byDomain.get(f.domain);
      if (!existing || SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[existing.severity]) {
        byDomain.set(f.domain, f);
      }
    }
    result.push(...byDomain.values());
  }

  // Second pass: remove cross-domain semantic duplicates
  // Group by file with ±3 line proximity
  const byFile = new Map<string, Finding[]>();
  for (const f of result) {
    let group = byFile.get(f.location.file);
    if (!group) { group = []; byFile.set(f.location.file, group); }
    group.push(f);
  }

  const toRemove = new Set<Finding>();
  for (const fileFindings of byFile.values()) {
    if (fileFindings.length < 2) continue;
    // Sort by line for proximity check
    fileFindings.sort((a, b) => a.location.line - b.location.line);
    for (let i = 0; i < fileFindings.length; i++) {
      if (toRemove.has(fileFindings[i])) continue;
      for (let j = i + 1; j < fileFindings.length; j++) {
        if (toRemove.has(fileFindings[j])) continue;
        if (fileFindings[j].location.line - fileFindings[i].location.line > 3) break;
        const pairKey = `${fileFindings[i].ruleId}|${fileFindings[j].ruleId}`;
        if (CROSS_DOMAIN_OVERLAPS.has(pairKey)) {
          // Remove the lower-severity one
          const sevI = SEVERITY_ORDER[fileFindings[i].severity] ?? 99;
          const sevJ = SEVERITY_ORDER[fileFindings[j].severity] ?? 99;
          toRemove.add(sevI <= sevJ ? fileFindings[j] : fileFindings[i]);
        }
      }
    }
  }

  return result.filter(f => !toRemove.has(f));
}

/**
 * Cap prompt_missing findings at MAX per prompt location (file:line).
 * Keeps highest-severity findings first.
 */
const MAX_PROMPT_MISSING_PER_LOCATION = 5;

export function capPromptMissing(findings: Finding[]): Finding[] {
  // Sort by severity so we keep highest when filtering
  const sorted = [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const counts = new Map<string, number>();
  return sorted.filter(f => {
    if (f.checkType !== 'prompt_missing') return true;
    const key = `${f.location.file}:${f.location.line}`;
    const count = (counts.get(key) ?? 0) + 1;
    counts.set(key, count);
    return count <= MAX_PROMPT_MISSING_PER_LOCATION;
  });
}

/**
 * Function-scope dedup: within the same function, collapse multiple hits of the
 * same rule to a single finding (the one with the lowest line number).
 * This prevents "10 regex matches in one function" while preserving
 * "5 matches in 5 different functions" as genuinely separate issues.
 */
function deduplicateByFunctionScope(
  findings: Finding[],
  treeLookup: (filePath: string) => Tree | null = getFileTree,
): Finding[] {
  // Group by ruleId + function scope key
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const tree = treeLookup(f.location.file);
    const scopeKey = getFunctionScopeKey(tree, f.location.file, f.location.line);
    const key = `${f.ruleId}:${scopeKey}`;
    let group = groups.get(key);
    if (!group) { group = []; groups.set(key, group); }
    group.push(f);
  }

  const result: Finding[] = [];
  for (const group of groups.values()) {
    // Keep only the first finding (lowest line number) per group
    group.sort((a, b) => a.location.line - b.location.line);
    result.push(group[0]);
  }
  return result;
}
