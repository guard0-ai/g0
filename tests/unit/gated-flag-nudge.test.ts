import { describe, it, expect, vi, beforeEach } from 'vitest';

const maybeShowCtaMock = vi.fn();

vi.mock('../../src/platform/cta.js', () => ({
  maybeShowCta: (...args: unknown[]) => maybeShowCtaMock(...args),
}));

describe('nudgeGatedFlags', () => {
  beforeEach(() => {
    maybeShowCtaMock.mockClear();
  });

  it('does NOT call maybeShowCta when machineOutput is true, even with a gated flag set', async () => {
    const { nudgeGatedFlags } = await import('../../src/platform/gated-flag-nudge.js');
    nudgeGatedFlags({ html: true }, { machineOutput: true, showCta: maybeShowCtaMock });

    expect(maybeShowCtaMock).not.toHaveBeenCalled();
  });

  it('does NOT call maybeShowCta when machineOutput is true, using the default (non-injected) showCta', async () => {
    // Exercises the real wiring to src/platform/cta.js (mocked at module
    // level above) rather than an injected spy — proves the default param
    // path is also guarded.
    const { nudgeGatedFlags } = await import('../../src/platform/gated-flag-nudge.js');
    nudgeGatedFlags({ html: true, upload: true, report: 'soc2', adaptive: true }, { machineOutput: true });

    expect(maybeShowCtaMock).not.toHaveBeenCalled();
  });

  it('calls maybeShowCta with gated-flag-used and the right detail when machineOutput is false and --html is set', async () => {
    const { nudgeGatedFlags } = await import('../../src/platform/gated-flag-nudge.js');
    nudgeGatedFlags({ html: true }, { machineOutput: false, showCta: maybeShowCtaMock });

    expect(maybeShowCtaMock).toHaveBeenCalledTimes(1);
    expect(maybeShowCtaMock).toHaveBeenCalledWith('gated-flag-used', {
      detail: 'HTML reports',
      configCta: undefined,
    });
  });

  it('calls maybeShowCta with the right detail when --html is passed a file path (string, not boolean)', async () => {
    const { nudgeGatedFlags } = await import('../../src/platform/gated-flag-nudge.js');
    nudgeGatedFlags({ html: '/tmp/report.html' }, { machineOutput: false, showCta: maybeShowCtaMock });

    expect(maybeShowCtaMock).toHaveBeenCalledTimes(1);
    expect(maybeShowCtaMock).toHaveBeenCalledWith('gated-flag-used', {
      detail: 'HTML reports',
      configCta: undefined,
    });
  });

  it('calls maybeShowCta with "Cloud upload" when --upload is set', async () => {
    const { nudgeGatedFlags } = await import('../../src/platform/gated-flag-nudge.js');
    nudgeGatedFlags({ upload: true }, { machineOutput: false, showCta: maybeShowCtaMock });

    expect(maybeShowCtaMock).toHaveBeenCalledTimes(1);
    expect(maybeShowCtaMock).toHaveBeenCalledWith('gated-flag-used', {
      detail: 'Cloud upload',
      configCta: undefined,
    });
  });

  it('calls maybeShowCta with "Compliance reports" when --report is set', async () => {
    const { nudgeGatedFlags } = await import('../../src/platform/gated-flag-nudge.js');
    nudgeGatedFlags({ report: 'soc2' }, { machineOutput: false, showCta: maybeShowCtaMock });

    expect(maybeShowCtaMock).toHaveBeenCalledTimes(1);
    expect(maybeShowCtaMock).toHaveBeenCalledWith('gated-flag-used', {
      detail: 'Compliance reports',
      configCta: undefined,
    });
  });

  it('calls maybeShowCta with "Adaptive red teaming" when --adaptive is set', async () => {
    const { nudgeGatedFlags } = await import('../../src/platform/gated-flag-nudge.js');
    nudgeGatedFlags({ adaptive: true }, { machineOutput: false, showCta: maybeShowCtaMock });

    expect(maybeShowCtaMock).toHaveBeenCalledTimes(1);
    expect(maybeShowCtaMock).toHaveBeenCalledWith('gated-flag-used', {
      detail: 'Adaptive red teaming',
      configCta: undefined,
    });
  });

  it('forwards configCta:false through to maybeShowCta', async () => {
    const { nudgeGatedFlags } = await import('../../src/platform/gated-flag-nudge.js');
    nudgeGatedFlags({ upload: true }, { machineOutput: false, configCta: false, showCta: maybeShowCtaMock });

    expect(maybeShowCtaMock).toHaveBeenCalledWith('gated-flag-used', {
      detail: 'Cloud upload',
      configCta: false,
    });
  });

  it('forwards configCta:true through to maybeShowCta', async () => {
    const { nudgeGatedFlags } = await import('../../src/platform/gated-flag-nudge.js');
    nudgeGatedFlags({ report: 'iso42001' }, { machineOutput: false, configCta: true, showCta: maybeShowCtaMock });

    expect(maybeShowCtaMock).toHaveBeenCalledWith('gated-flag-used', {
      detail: 'Compliance reports',
      configCta: true,
    });
  });

  it('fires once per active gated flag when multiple are set', async () => {
    const { nudgeGatedFlags } = await import('../../src/platform/gated-flag-nudge.js');
    nudgeGatedFlags(
      { html: true, upload: true, report: 'soc2', adaptive: true },
      { machineOutput: false, showCta: maybeShowCtaMock },
    );

    expect(maybeShowCtaMock).toHaveBeenCalledTimes(4);
    expect(maybeShowCtaMock).toHaveBeenNthCalledWith(1, 'gated-flag-used', {
      detail: 'HTML reports',
      configCta: undefined,
    });
    expect(maybeShowCtaMock).toHaveBeenNthCalledWith(2, 'gated-flag-used', {
      detail: 'Cloud upload',
      configCta: undefined,
    });
    expect(maybeShowCtaMock).toHaveBeenNthCalledWith(3, 'gated-flag-used', {
      detail: 'Compliance reports',
      configCta: undefined,
    });
    expect(maybeShowCtaMock).toHaveBeenNthCalledWith(4, 'gated-flag-used', {
      detail: 'Adaptive red teaming',
      configCta: undefined,
    });
  });

  it('does not call maybeShowCta when machineOutput is false but no gated flag is set', async () => {
    const { nudgeGatedFlags } = await import('../../src/platform/gated-flag-nudge.js');
    nudgeGatedFlags({}, { machineOutput: false, showCta: maybeShowCtaMock });

    expect(maybeShowCtaMock).not.toHaveBeenCalled();
  });

  it('treats --upload / --adaptive as inactive when explicitly false or undefined', async () => {
    const { nudgeGatedFlags } = await import('../../src/platform/gated-flag-nudge.js');
    nudgeGatedFlags({ upload: false, adaptive: undefined }, { machineOutput: false, showCta: maybeShowCtaMock });

    expect(maybeShowCtaMock).not.toHaveBeenCalled();
  });
});
