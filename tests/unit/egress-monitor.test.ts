import { describe, it, expect } from 'vitest';

describe('egress-monitor', () => {
  // ── parseLinuxSs ─────────────────────────────────────────────────────

  describe('parseLinuxSs', () => {
    it('parses standard ss output with process info', async () => {
      const { parseLinuxSs } = await import('../../src/endpoint/egress-monitor.js');

      const output = [
        'Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process',
        '0      0      10.0.0.5:42310      142.250.80.46:443  users:(("curl",pid=1234,fd=3))',
        '0      0      10.0.0.5:55000      52.23.1.100:8080   users:(("node",pid=5678,fd=7))',
      ].join('\n');

      const conns = parseLinuxSs(output);
      expect(conns).toHaveLength(2);
      expect(conns[0].remote).toBe('142.250.80.46:443');
      expect(conns[0].pid).toBe(1234);
      expect(conns[0].process).toBe('curl');
      expect(conns[1].remote).toBe('52.23.1.100:8080');
      expect(conns[1].pid).toBe(5678);
    });

    it('handles ss output with State column', async () => {
      const { parseLinuxSs } = await import('../../src/endpoint/egress-monitor.js');

      const output = [
        'State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process',
        'ESTAB  0      0      10.0.0.5:42310     142.250.80.46:443 users:(("curl",pid=1234,fd=3))',
      ].join('\n');

      const conns = parseLinuxSs(output);
      expect(conns).toHaveLength(1);
      expect(conns[0].remote).toBe('142.250.80.46:443');
    });

    it('returns empty for blank input', async () => {
      const { parseLinuxSs } = await import('../../src/endpoint/egress-monitor.js');
      expect(parseLinuxSs('')).toHaveLength(0);
    });
  });

  // ── parseMacOsLsof ──────────────────────────────────────────────────

  describe('parseMacOsLsof', () => {
    it('parses lsof -F pcn output', async () => {
      const { parseMacOsLsof } = await import('../../src/endpoint/egress-monitor.js');

      const output = [
        'p1234',
        'ccurl',
        'n10.0.0.5:42310->142.250.80.46:443',
        'p5678',
        'cnode',
        'n10.0.0.5:55000->52.23.1.100:8080',
      ].join('\n');

      const conns = parseMacOsLsof(output);
      expect(conns).toHaveLength(2);
      expect(conns[0].pid).toBe(1234);
      expect(conns[0].process).toBe('curl');
      expect(conns[0].local).toBe('10.0.0.5:42310');
      expect(conns[0].remote).toBe('142.250.80.46:443');
      expect(conns[1].pid).toBe(5678);
      expect(conns[1].process).toBe('node');
    });

    it('skips lines without arrow notation', async () => {
      const { parseMacOsLsof } = await import('../../src/endpoint/egress-monitor.js');
      const output = 'p1234\ncnode\nn*:8080';
      const conns = parseMacOsLsof(output);
      expect(conns).toHaveLength(0);
    });
  });

  // ── isAllowlisted ───────────────────────────────────────────────────

  describe('isAllowlisted', () => {
    it('matches exact IP', async () => {
      const { isAllowlisted } = await import('../../src/endpoint/egress-monitor.js');
      expect(isAllowlisted(undefined, '142.250.80.46', ['142.250.80.46'])).toBe(true);
    });

    it('matches exact hostname', async () => {
      const { isAllowlisted } = await import('../../src/endpoint/egress-monitor.js');
      expect(isAllowlisted('api.openai.com', '1.2.3.4', ['api.openai.com'])).toBe(true);
    });

    it('matches wildcard hostname', async () => {
      const { isAllowlisted } = await import('../../src/endpoint/egress-monitor.js');
      expect(isAllowlisted('api.openai.com', '1.2.3.4', ['*.openai.com'])).toBe(true);
      expect(isAllowlisted('openai.com', '1.2.3.4', ['*.openai.com'])).toBe(true);
    });

    it('does not match non-matching entries', async () => {
      const { isAllowlisted } = await import('../../src/endpoint/egress-monitor.js');
      expect(isAllowlisted('evil.com', '6.6.6.6', ['*.openai.com', '1.2.3.4'])).toBe(false);
    });

    it('matches CIDR /24', async () => {
      const { isAllowlisted } = await import('../../src/endpoint/egress-monitor.js');
      expect(isAllowlisted(undefined, '10.0.1.55', ['10.0.1.0/24'])).toBe(true);
      expect(isAllowlisted(undefined, '10.0.2.55', ['10.0.1.0/24'])).toBe(false);
    });

    it('matches CIDR /16', async () => {
      const { isAllowlisted } = await import('../../src/endpoint/egress-monitor.js');
      expect(isAllowlisted(undefined, '10.0.99.1', ['10.0.0.0/16'])).toBe(true);
      expect(isAllowlisted(undefined, '10.1.0.1', ['10.0.0.0/16'])).toBe(false);
    });
  });

  // ── matchCidr ───────────────────────────────────────────────────────

  describe('matchCidr', () => {
    it('matches /8 prefix', async () => {
      const { matchCidr } = await import('../../src/endpoint/egress-monitor.js');
      expect(matchCidr('10.99.88.77', '10.0.0.0/8')).toBe(true);
      expect(matchCidr('11.0.0.1', '10.0.0.0/8')).toBe(false);
    });

    it('matches /32 exactly', async () => {
      const { matchCidr } = await import('../../src/endpoint/egress-monitor.js');
      expect(matchCidr('1.2.3.4', '1.2.3.4/32')).toBe(true);
      expect(matchCidr('1.2.3.5', '1.2.3.4/32')).toBe(false);
    });

    it('returns false for invalid input', async () => {
      const { matchCidr } = await import('../../src/endpoint/egress-monitor.js');
      expect(matchCidr('not-an-ip', '10.0.0.0/8')).toBe(false);
      expect(matchCidr('10.0.0.1', 'bad/cidr')).toBe(false);
    });
  });

  // ── filterOutbound ──────────────────────────────────────────────────

  describe('filterOutbound', () => {
    it('removes loopback connections', async () => {
      const { filterOutbound } = await import('../../src/endpoint/egress-monitor.js');
      const conns = [
        { local: '127.0.0.1:8080', remote: '127.0.0.1:3000', state: 'ESTABLISHED' },
        { local: '10.0.0.5:42310', remote: '142.250.80.46:443', state: 'ESTABLISHED' },
      ];
      const filtered = filterOutbound(conns);
      expect(filtered).toHaveLength(1);
      expect(filtered[0].remote).toBe('142.250.80.46:443');
    });

    it('removes private non-Docker connections', async () => {
      const { filterOutbound } = await import('../../src/endpoint/egress-monitor.js');
      const conns = [
        { local: '10.0.0.5:1234', remote: '192.168.1.100:8080', state: 'ESTABLISHED' },
        { local: '10.0.0.5:1234', remote: '52.1.2.3:443', state: 'ESTABLISHED' },
      ];
      const filtered = filterOutbound(conns);
      expect(filtered).toHaveLength(1);
      expect(filtered[0].remote).toBe('52.1.2.3:443');
    });

    it('keeps Docker bridge connections for lateral movement', async () => {
      const { filterOutbound } = await import('../../src/endpoint/egress-monitor.js');
      const conns = [
        { local: '172.17.0.2:1234', remote: '172.17.0.3:8080', state: 'ESTABLISHED' },
      ];
      const filtered = filterOutbound(conns);
      expect(filtered).toHaveLength(1);
    });
  });

  // ── generateFindings ────────────────────────────────────────────────

  describe('generateFindings', () => {
    it('generates OC-EGRESS-003 when no allowlist', async () => {
      const { generateFindings } = await import('../../src/endpoint/egress-monitor.js');
      const findings = generateFindings([], [], { allowlist: [], perContainer: false });
      const f003 = findings.find(f => f.id === 'OC-EGRESS-003');
      expect(f003).toBeDefined();
      expect(f003!.severity).toBe('high');
    });

    it('generates OC-EGRESS-001 per violation', async () => {
      const { generateFindings } = await import('../../src/endpoint/egress-monitor.js');
      const violations = [
        {
          connection: { local: '10.0.0.5:1234', remote: '6.6.6.6:443', state: 'ESTABLISHED' },
          reason: 'Not in allowlist',
          severity: 'critical' as const,
        },
      ];
      const findings = generateFindings(violations, [], { allowlist: ['1.2.3.4'], perContainer: false });
      const f001 = findings.filter(f => f.id === 'OC-EGRESS-001');
      expect(f001).toHaveLength(1);
      expect(f001[0].severity).toBe('critical');
    });

    it('generates OC-EGRESS-002 for containers with 3+ violations', async () => {
      const { generateFindings } = await import('../../src/endpoint/egress-monitor.js');
      const violations = Array.from({ length: 3 }, (_, i) => ({
        connection: {
          local: `10.0.0.5:${1234 + i}`,
          remote: `6.6.6.${i}:443`,
          state: 'ESTABLISHED',
          container: 'evil-agent',
        },
        reason: 'Not in allowlist',
        severity: 'critical' as const,
      }));
      const findings = generateFindings(violations, [], { allowlist: ['1.2.3.4'], perContainer: true });
      const f002 = findings.find(f => f.id === 'OC-EGRESS-002');
      expect(f002).toBeDefined();
      expect(f002!.detail).toContain('evil-agent');
    });

    it('generates OC-EGRESS-004 for Docker bridge traffic', async () => {
      const { generateFindings } = await import('../../src/endpoint/egress-monitor.js');
      const conns = [
        { local: '172.17.0.2:1234', remote: '172.17.0.3:8080', process: 'python', pid: 100, state: 'ESTABLISHED' },
      ];
      const findings = generateFindings([], conns, { allowlist: ['1.2.3.4'], perContainer: false });
      const f004 = findings.find(f => f.id === 'OC-EGRESS-004');
      expect(f004).toBeDefined();
      expect(f004!.severity).toBe('high');
    });
  });

  // ── getContainerMap & mapPidToContainer ─────────────────────────────

  describe('mapPidToContainer', () => {
    it('returns direct match from container map', async () => {
      const { mapPidToContainer } = await import('../../src/endpoint/egress-monitor.js');
      const map = new Map<number, string>([[1234, 'my-container']]);
      expect(mapPidToContainer(1234, map)).toBe('my-container');
    });

    it('returns undefined for unknown PID', async () => {
      const { mapPidToContainer } = await import('../../src/endpoint/egress-monitor.js');
      const map = new Map<number, string>([[1234, 'my-container']]);
      expect(mapPidToContainer(9999, map)).toBeUndefined();
    });
  });
});
