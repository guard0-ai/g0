// Shared helpers for MCP tool handlers: result shaping and path confinement.
import * as fs from 'node:fs';
import * as path from 'node:path';

export interface ToolResult {
  // Index signature so this structurally satisfies the SDK's CallToolResult
  // (which is a loose zod object, `z.core.$loose`) without importing its type.
  [key: string]: unknown;
  content: Array<{ type: 'text'; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

/** Context injected by `index.ts` at server-startup time (not part of tool input). */
export interface ToolContext {
  /** When set, tools that accept a `path` argument confine it under this directory. */
  projectRoot?: string;
}

export function textResult(markdown: string, structuredContent?: Record<string, unknown>): ToolResult {
  return structuredContent !== undefined
    ? { content: [{ type: 'text', text: markdown }], structuredContent }
    : { content: [{ type: 'text', text: markdown }] };
}

export function errorResult(message: string): ToolResult {
  return { content: [{ type: 'text', text: `Error: ${message}` }], isError: true };
}

/**
 * Thrown by `resolveConfinedPath` when a path escapes `projectRoot`.
 * Distinguished from a generic Error so callers/tests can identify traversal
 * rejections specifically.
 */
export class PathEscapeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PathEscapeError';
  }
}

/**
 * Resolves `inputPath` to an absolute path. When `projectRoot` is provided,
 * rejects (throws `PathEscapeError`) any path that resolves outside of it —
 * this is the defense against a malicious/careless MCP client asking g0 to
 * scan or read files via `../../` traversal.
 *
 * When `projectRoot` is undefined, confinement is a no-op: the resolved path
 * is returned as-is (documented behavior — running `g0 mcp serve` without
 * `--project-root` grants tools the same filesystem reach as the OS user
 * running the process; pass `--project-root` to sandbox scans to one tree).
 */
export function resolveConfinedPath(inputPath: string, projectRoot?: string): string {
  const base = projectRoot ? path.resolve(projectRoot) : process.cwd();
  const resolved = path.resolve(base, inputPath);

  if (projectRoot) {
    const rootResolved = path.resolve(projectRoot);
    const rel = path.relative(rootResolved, resolved);
    const escapes = rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel);
    if (escapes) {
      throw new PathEscapeError(
        `Path "${inputPath}" resolves outside the confined project root (${rootResolved})`,
      );
    }
  }

  return resolved;
}

export function assertPathExists(resolvedPath: string): void {
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Path does not exist: ${resolvedPath}`);
  }
}

/** Result of `resolveToolPath`: either a usable absolute path, or a pre-built error `ToolResult` to return as-is. */
export type ToolPathResolution =
  | { ok: true; path: string }
  | { ok: false; result: ToolResult };

/**
 * Shared `resolveConfinedPath` + (optionally) `assertPathExists` + error
 * mapping, factored out of the near-identical try/catch block that appeared
 * at the top of every path-accepting tool handler (`scan_project`,
 * `scan_mcp_server`, `inventory`, `get_score`, and — with `requireExists:
 * false` — `explain_finding`). Callers do:
 *
 *   const resolution = resolveToolPath(args.path ?? '.', ctx);
 *   if (!resolution.ok) return resolution.result;
 *   const resolvedPath = resolution.path;
 */
export function resolveToolPath(
  inputPath: string,
  ctx: ToolContext,
  opts: { requireExists?: boolean } = {},
): ToolPathResolution {
  const requireExists = opts.requireExists ?? true;
  try {
    const resolved = resolveConfinedPath(inputPath, ctx.projectRoot);
    if (requireExists) assertPathExists(resolved);
    return { ok: true, path: resolved };
  } catch (err) {
    if (err instanceof PathEscapeError) return { ok: false, result: errorResult(err.message) };
    return { ok: false, result: errorResult(err instanceof Error ? err.message : String(err)) };
  }
}
