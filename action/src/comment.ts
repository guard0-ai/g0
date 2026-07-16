/**
 * Sticky PR comment posting.
 *
 * Takes an INJECTED octokit + context object (rather than importing
 * `@actions/github` directly and calling `getOctokit`/`context` at module
 * scope) so this module is fully unit-testable without a real GitHub Actions
 * environment or network access — tests pass in hand-rolled fakes that match
 * these narrow interfaces.
 */
import { REPORT_MARKER } from './render.js';

/** The subset of the octokit REST surface this module needs. */
export interface OctokitLike {
  rest: {
    issues: {
      listComments(params: {
        owner: string;
        repo: string;
        issue_number: number;
        per_page?: number;
        page?: number;
      }): Promise<{ data: Array<{ id: number; body?: string | null }> }>;
      updateComment(params: {
        owner: string;
        repo: string;
        comment_id: number;
        body: string;
      }): Promise<unknown>;
      createComment(params: {
        owner: string;
        repo: string;
        issue_number: number;
        body: string;
      }): Promise<{ data?: { id?: number } } | unknown>;
    };
  };
}

/** The subset of `@actions/github`'s `context` this module needs. */
export interface ActionContextLike {
  eventName: string;
  repo: { owner: string; repo: string };
  payload: {
    pull_request?: { number?: number };
  };
}

export interface LoggerLike {
  info(message: string): void;
  warning(message: string): void;
}

const noopLogger: LoggerLike = { info() {}, warning() {} };

export interface PostCommentOptions {
  octokit: OctokitLike;
  context: ActionContextLike;
  body: string;
  /** 'update' (default) finds and edits the existing marker comment, or creates one if none exists. Any other value always creates a new comment. */
  commentMode?: string;
  logger?: LoggerLike;
}

export type PostCommentResult =
  | { action: 'updated'; commentId: number }
  | { action: 'created'; commentId: number }
  | { action: 'skipped'; reason: 'not-pull-request' | 'no-pr-number' | 'error' };

/**
 * Posts (or updates) the g0 scan report as a PR comment. Never throws —
 * skips gracefully (logging via `logger`) when the event isn't a
 * pull_request, when the payload has no PR number, or when the GitHub API
 * call fails (e.g. the token lacks `pull-requests: write`, as happens on
 * fork PRs).
 */
export async function postStickyComment(opts: PostCommentOptions): Promise<PostCommentResult> {
  const { octokit, context, body } = opts;
  const logger = opts.logger ?? noopLogger;
  const mode = opts.commentMode ?? 'update';

  if (context.eventName !== 'pull_request' && context.eventName !== 'pull_request_target') {
    logger.info(`g0: event "${context.eventName}" is not a pull_request — skipping PR comment`);
    return { action: 'skipped', reason: 'not-pull-request' };
  }

  const prNumber = context.payload.pull_request?.number;
  if (!prNumber) {
    logger.info('g0: no pull_request number in the event payload — skipping PR comment');
    return { action: 'skipped', reason: 'no-pr-number' };
  }

  const { owner, repo } = context.repo;

  try {
    if (mode === 'update') {
      // PRs can accumulate more than one page of comments — list ALL pages
      // (stopping as soon as the marker is found) so the sticky comment is
      // always found and updated in place, never duplicated. Paginated
      // manually (rather than via `octokit.paginate`) because this module
      // takes an injected octokit for testability and the injected shape
      // only guarantees `listComments`, not the full paginate helper.
      const perPage = 100;
      let page = 1;
      let existing: { id: number; body?: string | null } | undefined;
      for (;;) {
        const { data } = await octokit.rest.issues.listComments({
          owner,
          repo,
          issue_number: prNumber,
          per_page: perPage,
          page,
        });
        existing = data.find(c => typeof c.body === 'string' && c.body.includes(REPORT_MARKER));
        if (existing || data.length < perPage) break;
        page += 1;
      }
      if (existing) {
        await octokit.rest.issues.updateComment({ owner, repo, comment_id: existing.id, body });
        return { action: 'updated', commentId: existing.id };
      }
    }

    const created = await octokit.rest.issues.createComment({ owner, repo, issue_number: prNumber, body });
    const commentId = (created as { data?: { id?: number } })?.data?.id ?? 0;
    return { action: 'created', commentId };
  } catch (err) {
    logger.warning(
      `g0: could not post PR comment (${err instanceof Error ? err.message : String(err)}) — ` +
        'check that the token has "pull-requests: write" permission',
    );
    return { action: 'skipped', reason: 'error' };
  }
}
