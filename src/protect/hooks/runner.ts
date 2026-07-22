/**
 * The `g0 hook` core: one Claude Code hook invocation end to end.
 *
 * Non-negotiable invariants (spec §10, mirroring proxy-core's discipline):
 *  - NOTHING thrown here escapes: the entire pipeline runs inside one
 *    guarded region. Default (`onError: open`) any failure allows; a
 *    `closed` policy expresses failure as a PreToolUse deny — never a
 *    non-zero exit, never broken stdout.
 *  - PostToolUse NEVER blocks — it tags provenance, audits, and returns.
 *  - Exit code is always 0; the decision travels in the JSON output.
 */

import * as path from 'node:path';
import { appendJsonlLine } from '../../enforcement/audit.js';
import { decide } from '../../enforcement/engine.js';
import { mapHookInput } from './mapping.js';
import { hookConfigDir } from './paths.js';
import { ensureDefaultHookPolicy, loadHookPolicy } from './policy.js';
import { loadSessionState } from './state.js';

export interface HookRunResult {
  stdout: string;
  exitCode: number;
}

export interface HookRunOptions {
  configDir?: string;
  stateDir?: string;
  /** Test seam: throw inside the guarded region to exercise onError paths. */
  _forceError?: boolean;
}

type HookEvent = 'pretooluse' | 'posttooluse';

function preToolUseOutput(decision: 'deny' | 'ask', reason: string): string {
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: decision,
      permissionDecisionReason: reason,
    },
  });
}

const ALLOW: HookRunResult = { stdout: '', exitCode: 0 };

export function runHook(eventName: HookEvent, stdinText: string, opts?: HookRunOptions): HookRunResult {
  const started = performance.now();
  const configDir = hookConfigDir(opts?.configDir);
  const auditPath = path.join(configDir, 'audit.jsonl');

  // Everything below is fail-open: `policy` may be unset when the failure
  // happened before/at policy load — treated as `onError: open`.
  let onErrorClosed = false;

  try {
    ensureDefaultHookPolicy(opts?.configDir);
    const policy = loadHookPolicy(opts?.configDir);
    onErrorClosed = policy.onError === 'closed';

    if (opts?._forceError) throw new Error('forced test error');

    const mapped = mapHookInput(safeParse(stdinText));
    if (!mapped) return ALLOW; // unmappable input is not an error — allow

    const state = loadSessionState(mapped.sessionId, opts);
    const ed = decide(mapped.event, policy, state.engineState);
    state.save();

    appendJsonlLine(auditPath, {
      ts: new Date().toISOString(),
      sessionId: mapped.sessionId,
      event: mapped.hookEventName,
      toolName: mapped.event.toolName,
      action: ed.decision.action,
      ruleId: ed.decision.ruleId,
      findings: ed.findingNames,
      signals: ed.auditExtras.signals,
      durationMs: Math.round((performance.now() - started) * 100) / 100,
    });

    if (mapped.hookEventName === 'PostToolUse') return ALLOW; // observe-only

    if (ed.decision.action === 'deny') {
      const reason = [ed.decision.message ?? 'Blocked by g0 policy', ...(ed.findingNames ?? [])].join('; ');
      return { stdout: preToolUseOutput('deny', reason), exitCode: 0 };
    }
    if (ed.decision.action === 'redact' || ed.decision.action === 'coach') {
      const label = ed.decision.action === 'redact' ? 'g0 would redact this' : 'g0 coach warning';
      const reason = [`${label}: ${ed.decision.message ?? 'policy finding'}`, ...(ed.findingNames ?? [])].join('; ');
      return { stdout: preToolUseOutput('ask', reason), exitCode: 0 };
    }
    return ALLOW; // allow / alert
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    appendJsonlLine(auditPath, {
      ts: new Date().toISOString(),
      event: eventName,
      action: 'error',
      error: message,
      durationMs: Math.round((performance.now() - started) * 100) / 100,
    });
    if (onErrorClosed && eventName === 'pretooluse') {
      return { stdout: preToolUseOutput('deny', `g0 hook internal error (fail-closed policy): ${message}`), exitCode: 0 };
    }
    return ALLOW;
  }
}

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
