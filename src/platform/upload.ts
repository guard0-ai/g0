import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as childProcess from 'node:child_process';
import { PlatformClient } from './client.js';
import { getMachineId } from './machine-id.js';
import type {
  UploadPayload,
  UploadResponse,
  ProjectMeta,
  MachineMeta,
  GitMeta,
  CIMeta,
} from './types.js';

/**
 * Upload results to Guard0 platform.
 * Non-fatal: returns null on failure instead of throwing.
 */
export async function uploadResults(
  payload: UploadPayload,
): Promise<UploadResponse | null> {
  try {
    const client = new PlatformClient();
    return await client.upload(payload);
  } catch (err) {
    // Non-fatal: log warning but don't fail the scan
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`  Upload failed: ${msg}`);
    return null;
  }
}

// ─── Metadata Collection ─────────────────────────────────────────────────────

export function collectProjectMeta(projectPath: string): ProjectMeta {
  const name = detectProjectName(projectPath);
  const git = collectGitMeta(projectPath);

  return {
    name,
    path: projectPath,
    git: git ?? undefined,
  };
}

export function collectMachineMeta(): MachineMeta {
  return {
    machineId: getMachineId(),
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    nodeVersion: process.version,
    g0Version: '1.0.0',
  };
}

export function detectCIMeta(): CIMeta | undefined {
  // GitHub Actions
  if (process.env.GITHUB_ACTIONS) {
    return {
      provider: 'github-actions',
      buildId: process.env.GITHUB_RUN_ID,
      buildUrl: process.env.GITHUB_SERVER_URL && process.env.GITHUB_REPOSITORY && process.env.GITHUB_RUN_ID
        ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
        : undefined,
      pipelineId: process.env.GITHUB_WORKFLOW,
    };
  }

  // GitLab CI
  if (process.env.GITLAB_CI) {
    return {
      provider: 'gitlab-ci',
      buildId: process.env.CI_JOB_ID,
      buildUrl: process.env.CI_JOB_URL,
      pipelineId: process.env.CI_PIPELINE_ID,
    };
  }

  // Jenkins
  if (process.env.JENKINS_URL) {
    return {
      provider: 'jenkins',
      buildId: process.env.BUILD_NUMBER,
      buildUrl: process.env.BUILD_URL,
      pipelineId: process.env.JOB_NAME,
    };
  }

  // CircleCI
  if (process.env.CIRCLECI) {
    return {
      provider: 'circleci',
      buildId: process.env.CIRCLE_BUILD_NUM,
      buildUrl: process.env.CIRCLE_BUILD_URL,
      pipelineId: process.env.CIRCLE_PROJECT_REPONAME,
    };
  }

  // Generic CI detection
  if (process.env.CI) {
    return {
      provider: 'unknown',
      buildId: process.env.BUILD_ID ?? process.env.BUILD_NUMBER,
    };
  }

  return undefined;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function detectProjectName(projectPath: string): string {
  // Try package.json
  try {
    const pkgPath = path.join(projectPath, 'package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    if (pkg.name) return pkg.name;
  } catch { /* not a node project */ }

  // Try pyproject.toml (look for name = "...")
  try {
    const pyprojectPath = path.join(projectPath, 'pyproject.toml');
    const content = fs.readFileSync(pyprojectPath, 'utf-8');
    const match = content.match(/^name\s*=\s*"([^"]+)"/m);
    if (match) return match[1];
  } catch { /* not a python project */ }

  // Fall back to directory name
  return path.basename(path.resolve(projectPath));
}

function collectGitMeta(projectPath: string): GitMeta | null {
  try {
    const opts = { cwd: projectPath, encoding: 'utf-8' as const, timeout: 5000 };

    const remote = execGit(['config', '--get', 'remote.origin.url'], opts);
    const branch = execGit(['rev-parse', '--abbrev-ref', 'HEAD'], opts);
    const commit = execGit(['rev-parse', '--short', 'HEAD'], opts);
    const dirty = execGit(['status', '--porcelain'], opts) !== '';

    return {
      remote: remote || undefined,
      branch: branch || undefined,
      commit: commit || undefined,
      dirty,
    };
  } catch {
    return null;
  }
}

function execGit(args: string[], opts: { cwd: string; encoding: 'utf-8'; timeout: number }): string {
  try {
    return childProcess.execFileSync('git', args, {
      ...opts,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
  } catch {
    return '';
  }
}
