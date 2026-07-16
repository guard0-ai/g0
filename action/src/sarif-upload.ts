/**
 * Direct SARIF upload to GitHub Code Scanning (`POST
 * /repos/{owner}/{repo}/code-scanning/sarifs`) — gzip + base64 the SARIF
 * file and hand it to an injected octokit. Soft-fails (logs a warning,
 * returns false) rather than throwing: forks and PRs from forks commonly
 * lack the `security-events: write` permission needed for this endpoint, and
 * that must not fail the whole action run.
 */
import * as fs from 'node:fs/promises';
import * as zlib from 'node:zlib';

export interface SarifOctokitLike {
  rest: {
    codeScanning: {
      uploadSarif(params: {
        owner: string;
        repo: string;
        commit_sha: string;
        ref: string;
        sarif: string;
        tool_name?: string;
      }): Promise<unknown>;
    };
  };
}

export interface LoggerLike {
  info(message: string): void;
  warning(message: string): void;
}

const noopLogger: LoggerLike = { info() {}, warning() {} };

export interface UploadSarifOptions {
  octokit: SarifOctokitLike;
  owner: string;
  repo: string;
  commitSha: string;
  ref: string;
  sarifFilePath: string;
  logger?: LoggerLike;
}

export async function uploadSarifResults(opts: UploadSarifOptions): Promise<boolean> {
  const logger = opts.logger ?? noopLogger;
  try {
    const raw = await fs.readFile(opts.sarifFilePath);
    const gzipped = zlib.gzipSync(raw);
    const sarif = gzipped.toString('base64');

    await opts.octokit.rest.codeScanning.uploadSarif({
      owner: opts.owner,
      repo: opts.repo,
      commit_sha: opts.commitSha,
      ref: opts.ref,
      sarif,
      tool_name: 'g0',
    });

    logger.info('g0: uploaded SARIF results to GitHub Code Scanning');
    return true;
  } catch (err) {
    logger.warning(
      `g0: SARIF upload skipped (${err instanceof Error ? err.message : String(err)}) — ` +
        'ensure the "security-events: write" permission is granted (forked-repo PRs never have it)',
    );
    return false;
  }
}
