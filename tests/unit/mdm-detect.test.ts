import { describe, it, expect } from 'vitest';
import type { MDMIOContext } from '../../src/endpoint/mdm-detect.js';
import { detectMDM, getMDMSummary } from '../../src/endpoint/mdm-detect.js';

// ─── Helper: build a mock IO context ────────────────────────────────────────

function mockIO(overrides: Partial<MDMIOContext> & { platform: MDMIOContext['platform'] }): MDMIOContext {
  return {
    platform: overrides.platform,
    pathExists: overrides.pathExists ?? (() => false),
    dirExists: overrides.dirExists ?? (() => false),
    tryExec: overrides.tryExec ?? (() => null),
  };
}

describe('mdm-detect', () => {
  // ── No MDM artifacts ────────────────────────────────────────────────────

  it('returns managed: false when no MDM artifacts found (darwin)', () => {
    const io = mockIO({ platform: () => 'darwin' });
    const result = detectMDM(io);

    expect(result.managed).toBe(false);
    expect(result.provider).toBeNull();
    expect(result.enrollmentStatus).toBe('unknown');
    expect(result.details.length).toBeGreaterThan(0);
    expect(result.details.every((d) => !d.found)).toBe(true);
  });

  it('returns managed: false when no MDM artifacts found (linux)', () => {
    const io = mockIO({ platform: () => 'linux' });
    const result = detectMDM(io);

    expect(result.managed).toBe(false);
    expect(result.provider).toBeNull();
    expect(result.enrollmentStatus).toBe('unknown');
    expect(result.details.every((d) => !d.found)).toBe(true);
  });

  // ── Jamf detection ─────────────────────────────────────────────────────

  it('detects Jamf on macOS', () => {
    const io = mockIO({
      platform: () => 'darwin',
      dirExists: (p) => p === '/Library/Application Support/JAMF/',
    });
    const result = detectMDM(io);

    expect(result.managed).toBe(true);
    expect(result.provider).toBe('jamf');
    const jamfDetail = result.details.find((d) => d.check === 'jamf-agent-directory');
    expect(jamfDetail?.found).toBe(true);
    expect(jamfDetail?.evidence).toContain('JAMF');
  });

  // ── Intune detection ───────────────────────────────────────────────────

  it('detects Intune on macOS via enrollment + directory', () => {
    const io = mockIO({
      platform: () => 'darwin',
      dirExists: (p) => p === '/Library/Intune/',
      tryExec: (cmd) => {
        if (cmd.includes('profiles status')) {
          return 'Enrolled to an MDM server: Yes';
        }
        return null;
      },
    });
    const result = detectMDM(io);

    expect(result.managed).toBe(true);
    expect(result.provider).toBe('intune');
    expect(result.enrollmentStatus).toBe('enrolled');
  });

  // ── Puppet on Linux ────────────────────────────────────────────────────

  it('detects Puppet on Linux', () => {
    const io = mockIO({
      platform: () => 'linux',
      pathExists: (p) => p === '/etc/puppetlabs/',
    });
    const result = detectMDM(io);

    expect(result.managed).toBe(true);
    expect(result.provider).toBe('puppet');
    expect(result.enrollmentStatus).toBe('enrolled');
    const puppetDetail = result.details.find((d) => d.check === 'puppet-agent');
    expect(puppetDetail?.found).toBe(true);
    expect(puppetDetail?.evidence).toContain('/etc/puppetlabs/');
  });

  // ── Unsupported platform ───────────────────────────────────────────────

  it('returns unmanaged for unsupported platforms', () => {
    const io = mockIO({ platform: () => 'win32' as NodeJS.Platform });
    const result = detectMDM(io);

    expect(result.managed).toBe(false);
    expect(result.provider).toBeNull();
    expect(result.details).toHaveLength(1);
    expect(result.details[0].check).toBe('unsupported-platform');
  });

  // ── Summary formatting ─────────────────────────────────────────────────

  it('formats summary for unmanaged host', () => {
    const summary = getMDMSummary({
      managed: false,
      provider: null,
      details: [],
      enrollmentStatus: 'unknown',
    });

    expect(summary).toBe('No MDM enrollment detected. Host appears unmanaged.');
  });

  it('formats summary for managed host with known provider', () => {
    const summary = getMDMSummary({
      managed: true,
      provider: 'jamf',
      details: [
        { check: 'jamf-agent-directory', found: true },
        { check: 'managed-preferences', found: false },
      ],
      enrollmentStatus: 'enrolled',
    });

    expect(summary).toBe('MDM detected: jamf (enrollment: enrolled, 1/2 checks matched).');
  });
});
