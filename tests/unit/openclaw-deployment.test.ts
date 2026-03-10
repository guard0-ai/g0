import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('openclaw-deployment', () => {
  // ── DeploymentAuditResult interface shape ───────────────────────────

  describe('auditOpenClawDeployment', () => {
    it('returns valid result shape with all checks', async () => {
      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      const result = await auditOpenClawDeployment({
        agentDataPath: '/nonexistent/agents',
        skipDocker: true,
      });

      expect(result).toHaveProperty('checks');
      expect(result).toHaveProperty('summary');
      expect(result.summary).toHaveProperty('total');
      expect(result.summary).toHaveProperty('passed');
      expect(result.summary).toHaveProperty('failed');
      expect(result.summary).toHaveProperty('errors');
      expect(result.summary).toHaveProperty('skipped');
      expect(result.summary).toHaveProperty('overallStatus');
      expect(['secure', 'warn', 'critical']).toContain(result.summary.overallStatus);
    });

    it('includes all expected check IDs (OC-H-019 through OC-H-063)', async () => {
      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      const result = await auditOpenClawDeployment({
        agentDataPath: '/nonexistent/agents',
        skipDocker: true,
      });

      const checkIds = result.checks.map(c => c.id);
      const expectedIds = [
        'OC-H-019', 'OC-H-020', 'OC-H-021', 'OC-H-022', 'OC-H-023',
        'OC-H-024', 'OC-H-025', 'OC-H-026', 'OC-H-027', 'OC-H-028',
        'OC-H-029', 'OC-H-030', 'OC-H-031', 'OC-H-032', 'OC-H-033',
        'OC-H-034', 'OC-H-035', 'OC-H-036', 'OC-H-037',
        'OC-H-056', 'OC-H-057', 'OC-H-058', 'OC-H-059', 'OC-H-060', 'OC-H-061', 'OC-H-062', 'OC-H-063',
      ];

      for (const id of expectedIds) {
        expect(checkIds).toContain(id);
      }
    });

    it('checks have valid severity and status values', async () => {
      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      const result = await auditOpenClawDeployment({
        agentDataPath: '/nonexistent/agents',
        skipDocker: true,
      });

      const validSeverities = ['critical', 'high', 'medium', 'low'];
      const validStatuses = ['pass', 'fail', 'error', 'skip'];

      for (const check of result.checks) {
        expect(validSeverities).toContain(check.severity);
        expect(validStatuses).toContain(check.status);
        expect(check.name).toBeTruthy();
        expect(check.detail).toBeTruthy();
      }
    });

    it('summary counts match check statuses', async () => {
      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      const result = await auditOpenClawDeployment({
        agentDataPath: '/nonexistent/agents',
        skipDocker: true,
      });

      const passed = result.checks.filter(c => c.status === 'pass').length;
      const failed = result.checks.filter(c => c.status === 'fail').length;
      const errors = result.checks.filter(c => c.status === 'error').length;
      const skipped = result.checks.filter(c => c.status === 'skip').length;

      expect(result.summary.passed).toBe(passed);
      expect(result.summary.failed).toBe(failed);
      expect(result.summary.errors).toBe(errors);
      expect(result.summary.skipped).toBe(skipped);
      expect(result.summary.total).toBe(result.checks.length);
    });

    it('skips egress check (OC-H-019) on macOS', async () => {
      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      const result = await auditOpenClawDeployment({
        agentDataPath: '/nonexistent/agents',
        skipDocker: true,
      });

      if (os.platform() === 'darwin') {
        const egressCheck = result.checks.find(c => c.id === 'OC-H-019');
        expect(egressCheck).toBeDefined();
        expect(egressCheck!.status).toBe('skip');
      }
    });
  });

  // ── With real filesystem fixtures ──────────────────────────────────

  describe('with filesystem fixtures', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-deploy-'));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('detects secret duplication when agents share credentials', async () => {
      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      // Create agents with shared secrets
      const agent1 = path.join(tmpDir, 'agent-a');
      const agent2 = path.join(tmpDir, 'agent-b');
      fs.mkdirSync(agent1, { recursive: true });
      fs.mkdirSync(agent2, { recursive: true });

      fs.writeFileSync(path.join(agent1, '.env'), 'OPENAI_API_KEY=sk-shared123');
      fs.writeFileSync(path.join(agent2, '.env'), 'OPENAI_API_KEY=sk-shared123');

      const result = await auditOpenClawDeployment({
        agentDataPath: tmpDir,
        skipDocker: true,
      });

      const secretCheck = result.checks.find(c => c.id === 'OC-H-020');
      expect(secretCheck).toBeDefined();
      expect(secretCheck!.status).toBe('fail');
      expect(result.agentConfigResult).toBeDefined();
      expect(result.agentConfigResult!.duplicateGroups.length).toBeGreaterThanOrEqual(1);
    });

    it('passes OC-H-020 when agents have unique credentials', async () => {
      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      const agent1 = path.join(tmpDir, 'agent-a');
      const agent2 = path.join(tmpDir, 'agent-b');
      fs.mkdirSync(agent1, { recursive: true });
      fs.mkdirSync(agent2, { recursive: true });

      fs.writeFileSync(path.join(agent1, '.env'), 'OPENAI_API_KEY=sk-unique-a');
      fs.writeFileSync(path.join(agent2, '.env'), 'OPENAI_API_KEY=sk-unique-b');

      const result = await auditOpenClawDeployment({
        agentDataPath: tmpDir,
        skipDocker: true,
      });

      const secretCheck = result.checks.find(c => c.id === 'OC-H-020');
      expect(secretCheck).toBeDefined();
      expect(secretCheck!.status).toBe('pass');
    });

    it('detects world-readable credential files (OC-H-022)', async () => {
      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      const agentDir = path.join(tmpDir, 'agent-x');
      fs.mkdirSync(agentDir, { recursive: true });
      const envFile = path.join(agentDir, '.env');
      fs.writeFileSync(envFile, 'SECRET=abc');
      fs.chmodSync(envFile, 0o644);

      const result = await auditOpenClawDeployment({
        agentDataPath: tmpDir,
        skipDocker: true,
      });

      const privacyCheck = result.checks.find(c => c.id === 'OC-H-022');
      expect(privacyCheck).toBeDefined();
      expect(privacyCheck!.status).toBe('fail');
    });

    it('fails OC-H-031 when no tool call logs exist', async () => {
      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      // Create an agent directory with no tool call logs
      const agentDir = path.join(tmpDir, 'agent-nologs');
      fs.mkdirSync(agentDir, { recursive: true });
      fs.writeFileSync(path.join(agentDir, '.env'), 'KEY=val');

      const result = await auditOpenClawDeployment({
        agentDataPath: tmpDir,
        skipDocker: true,
      });

      const toolCallCheck = result.checks.find(c => c.id === 'OC-H-031');
      expect(toolCallCheck).toBeDefined();
      expect(toolCallCheck!.status).toBe('fail');
      expect(toolCallCheck!.detail).toContain('tool call logging');
    });

    it('passes OC-H-031 when tool-calls.jsonl exists in agent logs', async () => {
      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      const agentDir = path.join(tmpDir, 'agent-logged');
      const logsDir = path.join(agentDir, 'logs');
      fs.mkdirSync(logsDir, { recursive: true });
      fs.writeFileSync(path.join(logsDir, 'tool-calls.jsonl'), '{"tool":"email","args":{}}\n');

      const result = await auditOpenClawDeployment({
        agentDataPath: tmpDir,
        skipDocker: true,
      });

      const toolCallCheck = result.checks.find(c => c.id === 'OC-H-031');
      expect(toolCallCheck).toBeDefined();
      expect(toolCallCheck!.status).toBe('pass');
    });

    it('passes OC-H-031 when openclaw.json has logging config', async () => {
      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      // Create openclaw.json with logging enabled at parent of agentDataPath
      const configPath = path.join(tmpDir, '..', 'openclaw.json');
      fs.writeFileSync(configPath, JSON.stringify({ logging: { toolCalls: true, level: 'verbose' } }));

      // Need at least one agent dir for the probe to run
      const agentDir = path.join(tmpDir, 'agent-x');
      fs.mkdirSync(agentDir, { recursive: true });

      const result = await auditOpenClawDeployment({
        agentDataPath: tmpDir,
        skipDocker: true,
      });

      const toolCallCheck = result.checks.find(c => c.id === 'OC-H-031');
      expect(toolCallCheck).toBeDefined();
      expect(toolCallCheck!.status).toBe('pass');

      // Cleanup the config written outside tmpDir
      try { fs.unlinkSync(configPath); } catch { /* ok */ }
    });

    it('includes OC-H-032 and OC-H-033 in results', async () => {
      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      const result = await auditOpenClawDeployment({
        agentDataPath: tmpDir,
        skipDocker: true,
      });

      const fileAuditCheck = result.checks.find(c => c.id === 'OC-H-032');
      const netLogCheck = result.checks.find(c => c.id === 'OC-H-033');

      expect(fileAuditCheck).toBeDefined();
      expect(netLogCheck).toBeDefined();

      // On macOS both should be skipped
      if (os.platform() === 'darwin') {
        expect(fileAuditCheck!.status).toBe('skip');
        expect(netLogCheck!.status).toBe('skip');
      }
    });

    it('detects unencrypted session files (OC-H-028)', async () => {
      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      // Create agent with .jsonl transcript files in sessions/ subdirectory
      const sessionsDir = path.join(tmpDir, 'agent-sessions', 'sessions');
      fs.mkdirSync(sessionsDir, { recursive: true });
      fs.writeFileSync(path.join(sessionsDir, 'session-001.jsonl'), '{"role":"user","content":"hello"}');
      fs.writeFileSync(path.join(sessionsDir, 'session-002.jsonl'), '{"role":"assistant","content":"hi"}');

      const result = await auditOpenClawDeployment({
        agentDataPath: tmpDir,
        skipDocker: true,
      });

      const sessionCheck = result.checks.find(c => c.id === 'OC-H-028');
      expect(sessionCheck).toBeDefined();
      expect(sessionCheck!.status).toBe('fail');
    });
  });

  // ── Reporter ────────────────────────────────────────────────────────

  describe('reportDeploymentAuditTerminal', () => {
    it('does not throw on valid input', async () => {
      const { reportDeploymentAuditTerminal } = await import('../../src/reporters/openclaw-deployment-terminal.js');

      const mockResult = {
        checks: [
          { id: 'OC-H-019', name: 'Egress filtering', severity: 'critical' as const, status: 'skip' as const, detail: 'Skipped on macOS' },
          { id: 'OC-H-020', name: 'Secret duplication', severity: 'critical' as const, status: 'pass' as const, detail: 'No duplicates' },
        ],
        summary: {
          total: 2,
          passed: 1,
          failed: 0,
          errors: 0,
          skipped: 1,
          overallStatus: 'secure' as const,
        },
      };

      const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
      expect(() => reportDeploymentAuditTerminal(mockResult)).not.toThrow();
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });

    it('renders agent config summary when present', async () => {
      const { reportDeploymentAuditTerminal } = await import('../../src/reporters/openclaw-deployment-terminal.js');

      const mockResult = {
        checks: [],
        agentConfigResult: {
          agentsScanned: 5,
          totalCredentials: 12,
          duplicateGroups: [
            { key: 'OPENAI_API_KEY', valueHash: 'abc', agents: ['a', 'b'], files: ['f1', 'f2'], severity: 'critical' as const },
          ],
          overprivileged: [],
          permissionIssues: [],
          findings: [],
          duration: 100,
        },
        summary: {
          total: 0, passed: 0, failed: 0, errors: 0, skipped: 0,
          overallStatus: 'secure' as const,
        },
      };

      const logs: string[] = [];
      const spy = vi.spyOn(console, 'log').mockImplementation((...args) => {
        logs.push(args.join(' '));
      });

      reportDeploymentAuditTerminal(mockResult);

      const allOutput = logs.join('\n');
      expect(allOutput).toContain('Agent Credentials');
      expect(allOutput).toContain('5');
      spy.mockRestore();
    });
  });

  // ── New probes (OC-H-034, 035, 036) ────────────────────────────────

  describe('new probes', () => {
    it('OC-H-034 returns valid HardeningCheck shape', async () => {
      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      const result = await auditOpenClawDeployment({
        agentDataPath: '/nonexistent/agents',
        skipDocker: true,
      });

      const check = result.checks.find(c => c.id === 'OC-H-034');
      expect(check).toBeDefined();
      expect(check!.severity).toBe('high');
      expect(['pass', 'fail', 'error', 'skip']).toContain(check!.status);
      expect(check!.name).toBeTruthy();
      expect(check!.detail).toBeTruthy();
    });

    it('OC-H-035 returns valid HardeningCheck shape', async () => {
      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      const result = await auditOpenClawDeployment({
        agentDataPath: '/nonexistent/agents',
        skipDocker: true,
      });

      const check = result.checks.find(c => c.id === 'OC-H-035');
      expect(check).toBeDefined();
      expect(check!.severity).toBe('medium');
      expect(['pass', 'fail', 'error', 'skip']).toContain(check!.status);
    });

    it('OC-H-035 skips on macOS (no /var/run/reboot-required)', async () => {
      if (os.platform() !== 'darwin') return;

      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      const result = await auditOpenClawDeployment({
        agentDataPath: '/nonexistent/agents',
        skipDocker: true,
      });

      const check = result.checks.find(c => c.id === 'OC-H-035');
      expect(check).toBeDefined();
      // macOS uses softwareupdate — will either pass or have a result
      expect(['pass', 'fail', 'skip']).toContain(check!.status);
    });

    it('OC-H-036 returns valid HardeningCheck shape', async () => {
      const { auditOpenClawDeployment } = await import('../../src/mcp/openclaw-deployment.js');

      const result = await auditOpenClawDeployment({
        agentDataPath: '/nonexistent/agents',
        skipDocker: true,
      });

      const check = result.checks.find(c => c.id === 'OC-H-036');
      expect(check).toBeDefined();
      expect(check!.severity).toBe('medium');
      expect(['pass', 'fail', 'error', 'skip']).toContain(check!.status);
    });
  });

  // ── Fix functions ──────────────────────────────────────────────────

  describe('fixDeploymentFindings', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-fix-'));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('fixes credential permissions (OC-H-022)', async () => {
      const { fixDeploymentFindings } = await import('../../src/mcp/openclaw-deployment.js');

      // Create agent with insecure .env file
      const agentDir = path.join(tmpDir, 'agent-x');
      fs.mkdirSync(agentDir, { recursive: true });
      const envFile = path.join(agentDir, '.env');
      fs.writeFileSync(envFile, 'SECRET=abc');
      fs.chmodSync(envFile, 0o644);

      const mockResult = {
        checks: [
          { id: 'OC-H-022', name: 'test', severity: 'critical' as const, status: 'fail' as const, detail: 'test' },
        ],
        summary: { total: 1, passed: 0, failed: 1, errors: 0, skipped: 0, overallStatus: 'critical' as const },
      };

      const fixes = await fixDeploymentFindings(mockResult, { agentDataPath: tmpDir });

      const applied = fixes.filter(f => f.applied);
      expect(applied.length).toBeGreaterThanOrEqual(1);

      // Verify file is now 600
      const stat = fs.statSync(envFile);
      expect(stat.mode & 0o777).toBe(0o600);

      // Verify backup exists
      const backupFix = applied.find(f => f.backupPath);
      expect(backupFix).toBeDefined();
      expect(fs.existsSync(backupFix!.backupPath!)).toBe(true);
    });

    it('dryRun does not modify files', async () => {
      const { fixDeploymentFindings } = await import('../../src/mcp/openclaw-deployment.js');

      const agentDir = path.join(tmpDir, 'agent-x');
      fs.mkdirSync(agentDir, { recursive: true });
      const envFile = path.join(agentDir, '.env');
      fs.writeFileSync(envFile, 'SECRET=abc');
      fs.chmodSync(envFile, 0o644);

      const mockResult = {
        checks: [
          { id: 'OC-H-022', name: 'test', severity: 'critical' as const, status: 'fail' as const, detail: 'test' },
        ],
        summary: { total: 1, passed: 0, failed: 1, errors: 0, skipped: 0, overallStatus: 'critical' as const },
      };

      const fixes = await fixDeploymentFindings(mockResult, { agentDataPath: tmpDir, dryRun: true });

      expect(fixes.every(f => !f.applied)).toBe(true);

      // File should still be 644
      const stat = fs.statSync(envFile);
      expect(stat.mode & 0o777).toBe(0o644);
    });

    it('returns guidance for OC-H-028 (no auto-fix)', async () => {
      const { fixDeploymentFindings } = await import('../../src/mcp/openclaw-deployment.js');

      const mockResult = {
        checks: [
          { id: 'OC-H-028', name: 'test', severity: 'high' as const, status: 'fail' as const, detail: 'test' },
        ],
        summary: { total: 1, passed: 0, failed: 1, errors: 0, skipped: 0, overallStatus: 'warn' as const },
      };

      const fixes = await fixDeploymentFindings(mockResult);

      const sessionFix = fixes.find(f => f.checkId === 'OC-H-028');
      expect(sessionFix).toBeDefined();
      expect(sessionFix!.applied).toBe(false);
      expect(sessionFix!.description).toContain('encryption');
    });
  });

  // ── AI Audit Analyzer ─────────────────────────────────────────────

  describe('analyzeAuditWithAI', () => {
    it('returns valid insight structure with mock provider', async () => {
      const { analyzeAuditWithAI } = await import('../../src/mcp/openclaw-deployment.js');

      const mockProvider = {
        name: 'test',
        model: 'test-model',
        analyze: vi.fn().mockResolvedValue(JSON.stringify({
          attackChains: [{
            name: 'Credential exfil chain',
            severity: 'critical',
            failedChecks: ['OC-H-020', 'OC-H-022'],
            narrative: 'Shared credentials + weak permissions = lateral movement',
          }],
          prioritizedRemediation: [{
            order: 1,
            checkId: 'OC-H-022',
            reason: 'Blocks credential access',
            blocksChains: ['Credential exfil chain'],
          }],
          overallRiskNarrative: 'High risk deployment.',
        })),
      };

      const mockResult = {
        checks: [
          { id: 'OC-H-020', name: 'Secret dup', severity: 'critical' as const, status: 'fail' as const, detail: 'Shared creds' },
          { id: 'OC-H-022', name: 'Perms', severity: 'critical' as const, status: 'fail' as const, detail: 'Weak perms' },
        ],
        summary: { total: 2, passed: 0, failed: 2, errors: 0, skipped: 0, overallStatus: 'critical' as const },
      };

      const insights = await analyzeAuditWithAI(mockResult, mockProvider);

      expect(insights.attackChains).toHaveLength(1);
      expect(insights.attackChains[0].name).toBe('Credential exfil chain');
      expect(insights.prioritizedRemediation).toHaveLength(1);
      expect(insights.overallRiskNarrative).toBe('High risk deployment.');
    });

    it('gracefully handles malformed AI response', async () => {
      const { analyzeAuditWithAI } = await import('../../src/mcp/openclaw-deployment.js');

      const mockProvider = {
        name: 'test',
        model: 'test-model',
        analyze: vi.fn().mockResolvedValue('This is not valid JSON at all'),
      };

      const mockResult = {
        checks: [
          { id: 'OC-H-020', name: 'Test', severity: 'critical' as const, status: 'fail' as const, detail: 'test' },
        ],
        summary: { total: 1, passed: 0, failed: 1, errors: 0, skipped: 0, overallStatus: 'critical' as const },
      };

      const insights = await analyzeAuditWithAI(mockResult, mockProvider);

      // Should fallback gracefully
      expect(insights.attackChains).toEqual([]);
      expect(insights.prioritizedRemediation).toHaveLength(1);
      expect(insights.overallRiskNarrative).toContain('failed');
    });

    it('returns empty result when no checks failed', async () => {
      const { analyzeAuditWithAI } = await import('../../src/mcp/openclaw-deployment.js');

      const mockProvider = {
        name: 'test',
        model: 'test-model',
        analyze: vi.fn(),
      };

      const mockResult = {
        checks: [
          { id: 'OC-H-020', name: 'Test', severity: 'critical' as const, status: 'pass' as const, detail: 'ok' },
        ],
        summary: { total: 1, passed: 1, failed: 0, errors: 0, skipped: 0, overallStatus: 'secure' as const },
      };

      const insights = await analyzeAuditWithAI(mockResult, mockProvider);

      expect(insights.attackChains).toEqual([]);
      expect(insights.prioritizedRemediation).toEqual([]);
      expect(mockProvider.analyze).not.toHaveBeenCalled();
    });
  });
});
