import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('auditd-rules', () => {
  describe('generateAuditdRules', () => {
    it('generates rules with all sections', async () => {
      const { generateAuditdRules } = await import('../../src/endpoint/auditd-rules.js');

      const result = generateAuditdRules({
        agentDataPath: '/data/.openclaw/agents',
      });

      expect(result.sections.length).toBe(5);
      expect(result.sections.map(s => s.title)).toEqual([
        'File Access Monitoring',
        'Docker Socket & Config Monitoring',
        'Network Syscall Monitoring',
        'Process Execution Tracking',
        'Credential & Identity Monitoring',
      ]);
    });

    it('watches the agent data directory', async () => {
      const { generateAuditdRules } = await import('../../src/endpoint/auditd-rules.js');

      const result = generateAuditdRules({
        agentDataPath: '/data/.openclaw/agents',
      });

      const fileSection = result.sections.find(s => s.title === 'File Access Monitoring')!;
      expect(fileSection.rules.some(r => r.includes('/data/.openclaw/agents'))).toBe(true);
      expect(fileSection.rules.some(r => r.includes('-p rwxa'))).toBe(true);
    });

    it('uses custom key prefix', async () => {
      const { generateAuditdRules } = await import('../../src/endpoint/auditd-rules.js');

      const result = generateAuditdRules({
        agentDataPath: '/data/agents',
        keyPrefix: 'my-audit',
      });

      expect(result.rules.some(r => r.includes('-k my-audit-'))).toBe(true);
    });

    it('monitors docker socket by default', async () => {
      const { generateAuditdRules } = await import('../../src/endpoint/auditd-rules.js');

      const result = generateAuditdRules({
        agentDataPath: '/data/agents',
      });

      const dockerSection = result.sections.find(s => s.title.includes('Docker'))!;
      expect(dockerSection.rules.some(r => r.includes('/var/run/docker.sock'))).toBe(true);
    });

    it('includes network syscall rules by default', async () => {
      const { generateAuditdRules } = await import('../../src/endpoint/auditd-rules.js');

      const result = generateAuditdRules({
        agentDataPath: '/data/agents',
      });

      const netSection = result.sections.find(s => s.title === 'Network Syscall Monitoring')!;
      expect(netSection.rules.some(r => r.includes('-S connect'))).toBe(true);
      expect(netSection.rules.some(r => r.includes('-S sendto'))).toBe(true);
      expect(netSection.rules.some(r => r.includes('-S bind'))).toBe(true);
      expect(netSection.rules.some(r => r.includes('-S socket'))).toBe(true);
    });

    it('omits network syscalls when disabled', async () => {
      const { generateAuditdRules } = await import('../../src/endpoint/auditd-rules.js');

      const result = generateAuditdRules({
        agentDataPath: '/data/agents',
        networkSyscalls: false,
      });

      expect(result.sections.find(s => s.title === 'Network Syscall Monitoring')).toBeUndefined();
    });

    it('includes process execution tracking by default', async () => {
      const { generateAuditdRules } = await import('../../src/endpoint/auditd-rules.js');

      const result = generateAuditdRules({
        agentDataPath: '/data/agents',
      });

      const execSection = result.sections.find(s => s.title === 'Process Execution Tracking')!;
      expect(execSection.rules.some(r => r.includes('-S execve'))).toBe(true);
      expect(execSection.rules.some(r => r.includes('/usr/bin/curl'))).toBe(true);
      expect(execSection.rules.some(r => r.includes('/usr/bin/wget'))).toBe(true);
    });

    it('omits process execution when disabled', async () => {
      const { generateAuditdRules } = await import('../../src/endpoint/auditd-rules.js');

      const result = generateAuditdRules({
        agentDataPath: '/data/agents',
        processExecution: false,
      });

      expect(result.sections.find(s => s.title === 'Process Execution Tracking')).toBeUndefined();
    });

    it('watches additional custom paths', async () => {
      const { generateAuditdRules } = await import('../../src/endpoint/auditd-rules.js');

      const result = generateAuditdRules({
        agentDataPath: '/data/agents',
        additionalWatchPaths: ['/opt/custom-data', '/var/log/openclaw'],
      });

      const fileSection = result.sections.find(s => s.title === 'File Access Monitoring')!;
      expect(fileSection.rules.some(r => r.includes('/opt/custom-data'))).toBe(true);
      expect(fileSection.rules.some(r => r.includes('/var/log/openclaw'))).toBe(true);
    });

    it('includes identity/credential monitoring', async () => {
      const { generateAuditdRules } = await import('../../src/endpoint/auditd-rules.js');

      const result = generateAuditdRules({
        agentDataPath: '/data/agents',
      });

      const credSection = result.sections.find(s => s.title === 'Credential & Identity Monitoring')!;
      expect(credSection.rules.some(r => r.includes('/etc/passwd'))).toBe(true);
      expect(credSection.rules.some(r => r.includes('/etc/shadow'))).toBe(true);
      expect(credSection.rules.some(r => r.includes('/etc/sudoers'))).toBe(true);
    });

    it('watches per-agent .env files when agents exist', async () => {
      const { generateAuditdRules } = await import('../../src/endpoint/auditd-rules.js');

      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-auditd-'));
      const agentA = path.join(tmpDir, 'agent-a');
      fs.mkdirSync(agentA, { recursive: true });
      fs.writeFileSync(path.join(agentA, '.env'), 'KEY=val');

      try {
        const result = generateAuditdRules({ agentDataPath: tmpDir });
        const fileSection = result.sections.find(s => s.title === 'File Access Monitoring')!;
        expect(fileSection.rules.some(r => r.includes('agent-a/.env'))).toBe(true);
      } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    it('uses default output path', async () => {
      const { generateAuditdRules } = await import('../../src/endpoint/auditd-rules.js');

      const result = generateAuditdRules({
        agentDataPath: '/data/agents',
      });

      expect(result.rulesFilePath).toBe('/etc/audit/rules.d/g0-openclaw.rules');
    });
  });

  describe('formatAuditdRulesFile', () => {
    it('returns a string with all rules', async () => {
      const { generateAuditdRules, formatAuditdRulesFile } = await import('../../src/endpoint/auditd-rules.js');

      const ruleSet = generateAuditdRules({ agentDataPath: '/data/agents' });
      const content = formatAuditdRulesFile(ruleSet);

      expect(content).toContain('-w /data/agents');
      expect(content).toContain('-S connect');
      expect(content.endsWith('\n')).toBe(true);
    });
  });

  describe('formatAuditdReport', () => {
    it('returns human-readable report with sections', async () => {
      const { generateAuditdRules, formatAuditdReport } = await import('../../src/endpoint/auditd-rules.js');

      const ruleSet = generateAuditdRules({ agentDataPath: '/data/agents' });
      const report = formatAuditdReport(ruleSet);

      expect(report).toContain('File Access Monitoring');
      expect(report).toContain('Network Syscall Monitoring');
      expect(report).toContain('Installation');
      expect(report).toContain('augenrules');
    });
  });

  describe('applyAuditdRules', () => {
    it('returns not-applied on macOS', async () => {
      const { generateAuditdRules, applyAuditdRules } = await import('../../src/endpoint/auditd-rules.js');

      const ruleSet = generateAuditdRules({ agentDataPath: '/data/agents' });

      if (os.platform() === 'darwin') {
        const result = applyAuditdRules(ruleSet);
        expect(result.applied).toBe(false);
        expect(result.errors).toContain('auditd rules can only be applied on Linux');
      }
    });

    it('accepts a logger parameter', async () => {
      const { generateAuditdRules, applyAuditdRules } = await import('../../src/endpoint/auditd-rules.js');

      const ruleSet = generateAuditdRules({ agentDataPath: '/data/agents' });
      const mockLogger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };

      const result = applyAuditdRules(ruleSet, mockLogger);
      expect(result).toHaveProperty('applied');
      expect(result).toHaveProperty('rulesLoaded');
      expect(result).toHaveProperty('errors');
    });
  });
});
