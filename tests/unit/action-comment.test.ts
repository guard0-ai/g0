import { describe, it, expect, vi } from 'vitest';
import { postStickyComment, type OctokitLike, type ActionContextLike } from '../../action/src/comment.js';
import { REPORT_MARKER } from '../../action/src/render.js';

function makeContext(overrides: Partial<ActionContextLike> = {}): ActionContextLike {
  return {
    eventName: 'pull_request',
    repo: { owner: 'guard0-ai', repo: 'g0' },
    payload: { pull_request: { number: 7 } },
    ...overrides,
  };
}

function makeOctokit(overrides: Partial<OctokitLike['rest']['issues']> = {}): OctokitLike {
  return {
    rest: {
      issues: {
        listComments: vi.fn().mockResolvedValue({ data: [] }),
        updateComment: vi.fn().mockResolvedValue({}),
        createComment: vi.fn().mockResolvedValue({ data: { id: 999 } }),
        ...overrides,
      },
    },
  };
}

describe('postStickyComment', () => {
  it('updates the existing marker comment in place when one is found', async () => {
    const octokit = makeOctokit({
      listComments: vi.fn().mockResolvedValue({
        data: [
          { id: 1, body: 'unrelated comment' },
          { id: 2, body: `${REPORT_MARKER}\nold report body` },
        ],
      }),
    });
    const result = await postStickyComment({
      octokit,
      context: makeContext(),
      body: `${REPORT_MARKER}\nnew report body`,
    });

    expect(result).toEqual({ action: 'updated', commentId: 2 });
    expect(octokit.rest.issues.updateComment).toHaveBeenCalledWith(
      expect.objectContaining({ comment_id: 2, body: `${REPORT_MARKER}\nnew report body` }),
    );
    expect(octokit.rest.issues.createComment).not.toHaveBeenCalled();
  });

  it('paginates past the first 100 comments to find and update the marker on the second page', async () => {
    const firstPage = Array.from({ length: 100 }, (_, i) => ({ id: i + 1, body: `comment ${i + 1}` }));
    const secondPage = [{ id: 500, body: `${REPORT_MARKER}\nold report body` }];
    const listComments = vi.fn().mockImplementation(async ({ page }: { page?: number }) => {
      if ((page ?? 1) === 1) return { data: firstPage };
      if ((page ?? 1) === 2) return { data: secondPage };
      return { data: [] };
    });
    const octokit = makeOctokit({ listComments });

    const result = await postStickyComment({
      octokit,
      context: makeContext(),
      body: `${REPORT_MARKER}\nnew report body`,
    });

    expect(result).toEqual({ action: 'updated', commentId: 500 });
    expect(octokit.rest.issues.updateComment).toHaveBeenCalledWith(
      expect.objectContaining({ comment_id: 500, body: `${REPORT_MARKER}\nnew report body` }),
    );
    expect(octokit.rest.issues.createComment).not.toHaveBeenCalled();
    expect(listComments).toHaveBeenCalledTimes(2);
    expect(listComments).toHaveBeenNthCalledWith(1, expect.objectContaining({ page: 1, per_page: 100 }));
    expect(listComments).toHaveBeenNthCalledWith(2, expect.objectContaining({ page: 2, per_page: 100 }));
  });

  it('creates a new comment when no marker comment exists yet', async () => {
    const octokit = makeOctokit({
      listComments: vi.fn().mockResolvedValue({ data: [{ id: 1, body: 'unrelated comment' }] }),
    });
    const result = await postStickyComment({
      octokit,
      context: makeContext(),
      body: `${REPORT_MARKER}\nfirst report`,
    });

    expect(result).toEqual({ action: 'created', commentId: 999 });
    expect(octokit.rest.issues.updateComment).not.toHaveBeenCalled();
    expect(octokit.rest.issues.createComment).toHaveBeenCalledWith(
      expect.objectContaining({ issue_number: 7, body: `${REPORT_MARKER}\nfirst report` }),
    );
  });

  it('no-ops when the event is not a pull_request', async () => {
    const octokit = makeOctokit();
    const result = await postStickyComment({
      octokit,
      context: makeContext({ eventName: 'push', payload: {} }),
      body: 'irrelevant',
    });

    expect(result).toEqual({ action: 'skipped', reason: 'not-pull-request' });
    expect(octokit.rest.issues.listComments).not.toHaveBeenCalled();
    expect(octokit.rest.issues.createComment).not.toHaveBeenCalled();
  });

  it('no-ops when the pull_request payload has no number', async () => {
    const octokit = makeOctokit();
    const result = await postStickyComment({
      octokit,
      context: makeContext({ payload: { pull_request: {} } }),
      body: 'irrelevant',
    });

    expect(result).toEqual({ action: 'skipped', reason: 'no-pr-number' });
    expect(octokit.rest.issues.listComments).not.toHaveBeenCalled();
  });

  it('always creates a new comment when commentMode is not "update"', async () => {
    const octokit = makeOctokit({
      listComments: vi.fn().mockResolvedValue({
        data: [{ id: 2, body: `${REPORT_MARKER}\nold report body` }],
      }),
    });
    const result = await postStickyComment({
      octokit,
      context: makeContext(),
      body: 'new report',
      commentMode: 'always-create',
    });

    expect(result).toEqual({ action: 'created', commentId: 999 });
    expect(octokit.rest.issues.listComments).not.toHaveBeenCalled();
    expect(octokit.rest.issues.createComment).toHaveBeenCalled();
  });

  it('skips gracefully (does not throw) when the API call fails', async () => {
    const octokit = makeOctokit({
      listComments: vi.fn().mockRejectedValue(new Error('Resource not accessible by integration')),
    });
    const logger = { info: vi.fn(), warning: vi.fn() };
    const result = await postStickyComment({ octokit, context: makeContext(), body: 'x', logger });

    expect(result).toEqual({ action: 'skipped', reason: 'error' });
    expect(logger.warning).toHaveBeenCalledTimes(1);
  });
});
