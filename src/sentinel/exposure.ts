// Per-tool PII-exposure engine.
//
// For each discovered AI tool, answer two questions from LOCAL evidence only:
//   1. What can it reach?  (MCP servers it can call, network capability)
//   2. What did flow?      (PII classes + counts over the tool's local artifacts)
// Output carries classes + counts + file locators — never raw values.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { classifyText, mergeCounts, type PiiCounts } from './pii.js';

export type ToolCategory = 'coding-agent' | 'desktop-app' | 'browser' | 'mcp-client' | 'ai-tool';

export interface ToolReach {
  mcpServers: string[];
  network: boolean;
}

export interface ArtifactLocator {
  path: string;
  counts: PiiCounts;
}

export interface PiiScanResult {
  counts: PiiCounts;
  locators: ArtifactLocator[];
}

export interface ToolExposure {
  tool: string;
  category: ToolCategory;
  reach: ToolReach;
  evidenced: PiiCounts;
  locators: ArtifactLocator[];
  riskScore: number;
}

/** Minimal shape of a discovered tool this engine needs. */
export interface ExposureToolInput {
  name: string;
  mcpServerCount?: number;
  servers?: Array<{ name?: string }>;
}

const CATEGORY: Record<string, ToolCategory> = {
  'Claude Code': 'coding-agent',
  Codex: 'coding-agent',
  Cursor: 'coding-agent',
  Windsurf: 'coding-agent',
  Cline: 'coding-agent',
  Continue: 'coding-agent',
  Aider: 'coding-agent',
  Zed: 'coding-agent',
  'GitHub Copilot': 'coding-agent',
  'Claude Desktop': 'desktop-app',
  ChatGPT: 'desktop-app',
};

export function toolCategory(name: string): ToolCategory {
  return CATEGORY[name] ?? 'ai-tool';
}

/**
 * HOME-relative local artifact paths (session/history logs, config) a tool
 * produces or touches. Conservative: only well-known, tool-owned locations.
 * Directories are expanded to their files by scanArtifactsForPii.
 */
export function toolArtifactPaths(name: string, home: string): string[] {
  const j = (...p: string[]) => path.join(home, ...p);
  const byTool: Record<string, string[]> = {
    'Claude Code': [j('.claude'), j('.claude.json')],
    Codex: [j('.codex')],
    Cursor: [j('.cursor')],
    Windsurf: [j('.codeium', 'windsurf'), j('.windsurf')],
    Cline: [j('.cline')],
    'Claude Desktop': [j('Library', 'Application Support', 'Claude'), j('.config', 'claude')],
  };
  // Every tool: shared g0 MCP audit logs are evidence of what flowed through it.
  const shared = [j('.g0')];
  return [...(byTool[name] ?? []), ...shared];
}

const MAX_FILE_BYTES = 2 * 1024 * 1024; // skip large/binary blobs
const SCANNABLE = /\.(jsonl?|log|txt|md|ndjson|history)$/i;

function expandFiles(p: string, acc: string[], depth = 0): void {
  if (depth > 4 || acc.length > 500) return;
  let st: fs.Stats;
  try {
    st = fs.statSync(p);
  } catch {
    return;
  }
  if (st.isDirectory()) {
    let entries: string[] = [];
    try {
      entries = fs.readdirSync(p);
    } catch {
      return;
    }
    for (const e of entries) expandFiles(path.join(p, e), acc, depth + 1);
  } else if (st.isFile() && st.size <= MAX_FILE_BYTES) {
    // Scan known-text artifacts, plus extensionless history files.
    if (SCANNABLE.test(p) || /history$/i.test(p) || p.endsWith('.json')) acc.push(p);
  }
}

/** Read the given files/dirs, classify PII, return merged counts + per-file locators. */
export function scanArtifactsForPii(paths: string[]): PiiScanResult {
  const files: string[] = [];
  for (const p of paths) expandFiles(p, files);
  const locators: ArtifactLocator[] = [];
  const perFile: PiiCounts[] = [];
  const seen = new Set<string>();
  for (const f of files) {
    if (seen.has(f)) continue;
    seen.add(f);
    let text = '';
    try {
      text = fs.readFileSync(f, 'utf-8');
    } catch {
      continue;
    }
    const counts = classifyText(text);
    if (Object.keys(counts).length > 0) {
      locators.push({ path: f, counts });
      perFile.push(counts);
    }
  }
  return { counts: mergeCounts(perFile), locators };
}

// Weight of each PII class toward the risk score (secrets/identifiers heaviest).
const CLASS_WEIGHT: Record<string, number> = {
  private_key: 30,
  aws_access_key: 25,
  api_token: 20,
  jwt: 15,
  credit_card: 20,
  us_ssn: 20,
  email: 3,
  phone: 5,
  ipv4: 2,
};

/**
 * Reach × evidenced → 0–100 risk. Evidenced PII dominates; reach (callable MCP
 * servers + network) amplifies because it widens what the exposure can move.
 */
export function scoreExposure(reach: ToolReach, evidenced: PiiCounts): number {
  let evidenceScore = 0;
  for (const [k, n] of Object.entries(evidenced)) {
    evidenceScore += (CLASS_WEIGHT[k] ?? 5) * Math.min(n as number, 5);
  }
  const reachMultiplier = 1 + Math.min(reach.mcpServers.length, 5) * 0.1 + (reach.network ? 0.25 : 0);
  return Math.max(0, Math.min(100, Math.round(evidenceScore * reachMultiplier)));
}

/** Build an exposure record per tool over a given HOME. */
export function buildToolExposures(tools: ExposureToolInput[], home: string): ToolExposure[] {
  return tools.map((t) => {
    const scan = scanArtifactsForPii(toolArtifactPaths(t.name, home));
    const mcpServers = (t.servers ?? [])
      .map((s) => s.name)
      .filter((n): n is string => typeof n === 'string');
    const reach: ToolReach = { mcpServers, network: (t.mcpServerCount ?? 0) > 0 };
    return {
      tool: t.name,
      category: toolCategory(t.name),
      reach,
      evidenced: scan.counts,
      locators: scan.locators,
      riskScore: scoreExposure(reach, scan.counts),
    };
  });
}
