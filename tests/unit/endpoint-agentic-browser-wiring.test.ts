import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { AgenticBrowserScanResult } from '../../src/types/endpoint.js';

// ─────────────────────────────────────────────────────────────────────────
// scanEndpoint() — wiring for the opt-in agentic-browser layer (Task E2).
//
// The detector itself (detectAgenticBrowsers) is already covered end-to-end
// against fixture trees in agentic-browser-scanner.test.ts. These tests
// verify the *orchestrator* wiring: the layer is zero-cost when off, scores
// are unaffected when off, results appear and the score deducts when on,
// and a throwing detector never crashes the scan (fail-open).
//
// `detectAgenticBrowsers` is mocked so behavior is deterministic and
// independent of whatever agentic browsers/extensions actually exist on the
// machine running the tests.
// ─────────────────────────────────────────────────────────────────────────

const detectAgenticBrowsersMock = vi.fn();

vi.mock('../../src/endpoint/agentic-browser-scanner.js', () => ({
  detectAgenticBrowsers: (...args: unknown[]) => detectAgenticBrowsersMock(...args),
}));

import { scanEndpoint } from '../../src/endpoint/scanner.js';

// network + artifacts disabled in every call below purely to keep these
// tests fast and deterministic (no real port scanning / disk sweeps) — not
// related to the feature under test.
const FAST_OPTIONS = { network: false, artifacts: false } as const;

describe('scanEndpoint — agentic browser layer wiring (opt-in)', () => {
  beforeEach(() => {
    detectAgenticBrowsersMock.mockReset();
  });

  it('does nothing when the option is off: layer does not run, no agenticBrowsers key, layersRun excludes it', async () => {
    const result = await scanEndpoint({ ...FAST_OPTIONS, agenticBrowser: false });

    expect(detectAgenticBrowsersMock).not.toHaveBeenCalled();
    expect(result.agenticBrowsers).toBeUndefined();
    expect(result.layersRun).not.toContain('agenticBrowser');
    // Backward-compatible JSON contract: the key is dropped entirely (not
    // emitted as `null`) when the layer didn't run, matching `browser`/`forensics`.
    expect(JSON.parse(JSON.stringify(result))).not.toHaveProperty('agenticBrowsers');
  });

  it('does nothing when the option is entirely absent (same as explicit false)', async () => {
    const result = await scanEndpoint({ ...FAST_OPTIONS });

    expect(detectAgenticBrowsersMock).not.toHaveBeenCalled();
    expect(result.agenticBrowsers).toBeUndefined();
    expect(result.layersRun).not.toContain('agenticBrowser');
  });

  it('produces an identical score whether the option is omitted or explicitly false', async () => {
    const baseline = await scanEndpoint({ ...FAST_OPTIONS });
    const explicitOff = await scanEndpoint({ ...FAST_OPTIONS, agenticBrowser: false });

    expect(detectAgenticBrowsersMock).not.toHaveBeenCalled();
    // The acceptance bar from the task brief: a scan without --agentic-browser
    // produces the exact same score as before this task existed.
    expect(explicitOff.score).toEqual(baseline.score);
  });

  it('runs the layer, surfaces detections, and deducts from the configuration score when on', async () => {
    const fixture: AgenticBrowserScanResult = {
      browsers: [
        {
          name: 'ChatGPT Atlas',
          installed: true,
          running: true,
          capability: 'full-agent',
          findings: [
            {
              severity: 'high',
              title: 'ChatGPT Atlas is running with autonomous agent capability',
              detail: 'test fixture',
            },
          ],
        },
      ],
      riskyExtensions: [
        {
          name: 'AI Autopilot',
          extensionId: 'riskyext01',
          browser: 'Chrome',
          path: '/fake/manifest.json',
          permissions: ['debugger', '<all_urls>'],
          aiSignals: ['name:"AI Autopilot"'],
          severity: 'critical',
        },
      ],
      summary: { installed: 1, running: 1, riskyExtensions: 1, findings: 1 },
    };
    detectAgenticBrowsersMock.mockReturnValue(fixture);

    const result = await scanEndpoint({ ...FAST_OPTIONS, agenticBrowser: true });

    expect(detectAgenticBrowsersMock).toHaveBeenCalledTimes(1);
    expect(result.agenticBrowsers).toEqual(fixture);
    expect(result.layersRun).toContain('agenticBrowser');

    const configDeductions = result.score.categories.configuration.deductions;
    expect(
      configDeductions.some(d => d.finding.includes('ChatGPT Atlas') && d.severity === 'high' && d.points === 10),
    ).toBe(true);
    expect(
      configDeductions.some(d => d.finding.includes('AI Autopilot') && d.severity === 'critical' && d.points === 15),
    ).toBe(true);
  });

  it('fails open: a throwing detector does not crash the scan and the layer is simply absent', async () => {
    detectAgenticBrowsersMock.mockImplementation(() => {
      throw new Error('boom: simulated detector crash');
    });

    const result = await scanEndpoint({ ...FAST_OPTIONS, agenticBrowser: true });

    expect(result.agenticBrowsers).toBeUndefined();
    // The layer was requested, so it's still recorded as attempted...
    expect(result.layersRun).toContain('agenticBrowser');
    // ...but the rest of the scan completed normally.
    expect(result.score).toBeDefined();
    expect(result.summary).toBeDefined();
  });
});
