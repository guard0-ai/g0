/**
 * TOFU tool-list pinning (spec §6.3): pin what each proxied MCP server
 * CLAIMS to be — its tool names and descriptions — and surface drift.
 * A rug-pull (same server binary, new tool descriptions carrying injected
 * instructions) is exactly this drift.
 *
 * Matching is SEMANTIC — sorted tool names + per-description hashes — not
 * exact response strings, so reordering or whitespace never forces a
 * re-approval. Config pinning follows Trail of Bits' mcp-context-protector
 * prior art (July 2025); g0's differs by semantic matching and
 * policy/audit-path integration.
 *
 * All IO is never-throw: a pinning failure must never affect proxied
 * traffic.
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

export interface PinnedTool { name: string; descHash: string; }
export interface ToolsPin { v: 1; hash: string; tools: PinnedTool[]; approvedAt: string; }
export interface PinDrift { added: string[]; removed: string[]; changed: string[]; }

function sha256(text: string): string {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function sanitizeName(serverName: string): string {
  const safe = serverName.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '');
  return safe.length > 0 ? safe : 'unknown';
}

function pinsDir(dir?: string): string {
  return path.join(dir ?? path.join(os.homedir(), '.g0', 'proxy'), 'pins');
}

function pinPath(serverName: string, dir?: string): string {
  return path.join(pinsDir(dir), `${sanitizeName(serverName)}.json`);
}

function driftPath(serverName: string, dir?: string): string {
  return path.join(pinsDir(dir), `${sanitizeName(serverName)}.drift.json`);
}

/** Semantic pin of a `tools/list` result. Null when there is no tools array. */
export function computeToolsPin(toolsResult: unknown): ToolsPin | null {
  try {
    if (toolsResult === null || typeof toolsResult !== 'object') return null;
    const tools = (toolsResult as { tools?: unknown }).tools;
    if (!Array.isArray(tools)) return null;
    const pinned: PinnedTool[] = [];
    for (const tool of tools) {
      if (tool === null || typeof tool !== 'object') continue;
      const name = (tool as { name?: unknown }).name;
      if (typeof name !== 'string' || name.length === 0) continue;
      const description = (tool as { description?: unknown }).description;
      pinned.push({ name, descHash: sha256(typeof description === 'string' ? description : '') });
    }
    pinned.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    const hash = sha256(pinned.map((t) => `${t.name}:${t.descHash}`).join('\n'));
    return { v: 1, hash, tools: pinned, approvedAt: new Date().toISOString() };
  } catch {
    return null;
  }
}

/** Null = no drift. */
export function comparePins(approved: ToolsPin, current: ToolsPin): PinDrift | null {
  if (approved.hash === current.hash) return null;
  const approvedByName = new Map(approved.tools.map((t) => [t.name, t.descHash]));
  const currentByName = new Map(current.tools.map((t) => [t.name, t.descHash]));
  const added: string[] = [];
  const removed: string[] = [];
  const changed: string[] = [];
  for (const [name, descHash] of currentByName) {
    const approvedHash = approvedByName.get(name);
    if (approvedHash === undefined) added.push(name);
    else if (approvedHash !== descHash) changed.push(name);
  }
  for (const name of approvedByName.keys()) {
    if (!currentByName.has(name)) removed.push(name);
  }
  return { added: added.sort(), removed: removed.sort(), changed: changed.sort() };
}

function readPinFile(filePath: string): ToolsPin | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8')) as ToolsPin;
    return parsed && parsed.v === 1 && typeof parsed.hash === 'string' ? parsed : null;
  } catch {
    return null;
  }
}

function writePinFile(filePath: string, pin: ToolsPin): void {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(filePath, JSON.stringify(pin, null, 2), { mode: 0o600 });
  } catch {
    // never let pin IO affect traffic
  }
}

export function loadPin(serverName: string, dir?: string): ToolsPin | null {
  return readPinFile(pinPath(serverName, dir));
}

export function savePin(serverName: string, pin: ToolsPin, dir?: string): void {
  writePinFile(pinPath(serverName, dir), pin);
}

export function loadDrift(serverName: string, dir?: string): ToolsPin | null {
  return readPinFile(driftPath(serverName, dir));
}

export function saveDrift(serverName: string, pin: ToolsPin, dir?: string): void {
  writePinFile(driftPath(serverName, dir), pin);
}

export function clearDrift(serverName: string, dir?: string): void {
  try {
    fs.rmSync(driftPath(serverName, dir), { force: true });
  } catch {
    // best effort
  }
}

/** `g0 proxy review-server` core: inspect and optionally approve pending drift. */
export function reviewServer(
  serverName: string,
  opts: { policyDir?: string; approve?: boolean } = {},
): { status: 'clean' | 'pending' | 'approved'; drift?: PinDrift } {
  const pending = loadDrift(serverName, opts.policyDir);
  if (!pending) return { status: 'clean' };
  const approved = loadPin(serverName, opts.policyDir);
  const drift = approved ? (comparePins(approved, pending) ?? { added: [], removed: [], changed: [] }) : { added: pending.tools.map((t) => t.name), removed: [], changed: [] };
  if (!opts.approve) return { status: 'pending', drift };
  savePin(serverName, { ...pending, approvedAt: new Date().toISOString() }, opts.policyDir);
  clearDrift(serverName, opts.policyDir);
  return { status: 'approved', drift };
}
