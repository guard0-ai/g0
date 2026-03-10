import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('agent-config-scanner', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-acs-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // ── parseEnvFile ────────────────────────────────────────────────────────

  describe('parseEnvFile', () => {
    it('parses simple KEY=VALUE pairs', async () => {
      const { parseEnvFile } = await import('../../src/endpoint/agent-config-scanner.js');
      const result = parseEnvFile('OPENAI_API_KEY=sk-abc123\nSLACK_TOKEN=xoxb-456');
      expect(result.size).toBe(2);
      expect(result.get('OPENAI_API_KEY')).toBe('sk-abc123');
      expect(result.get('SLACK_TOKEN')).toBe('xoxb-456');
    });

    it('handles quoted values', async () => {
      const { parseEnvFile } = await import('../../src/endpoint/agent-config-scanner.js');
      const result = parseEnvFile('KEY="value with spaces"\nKEY2=\'single quoted\'');
      expect(result.get('KEY')).toBe('value with spaces');
      expect(result.get('KEY2')).toBe('single quoted');
    });

    it('strips export prefix', async () => {
      const { parseEnvFile } = await import('../../src/endpoint/agent-config-scanner.js');
      const result = parseEnvFile('export API_KEY=hello');
      expect(result.get('API_KEY')).toBe('hello');
    });

    it('skips comments and blank lines', async () => {
      const { parseEnvFile } = await import('../../src/endpoint/agent-config-scanner.js');
      const result = parseEnvFile('# comment\n\nKEY=val\n  # another comment');
      expect(result.size).toBe(1);
      expect(result.get('KEY')).toBe('val');
    });

    it('strips inline comments for unquoted values', async () => {
      const { parseEnvFile } = await import('../../src/endpoint/agent-config-scanner.js');
      const result = parseEnvFile('KEY=value # comment');
      expect(result.get('KEY')).toBe('value');
    });

    it('skips empty values', async () => {
      const { parseEnvFile } = await import('../../src/endpoint/agent-config-scanner.js');
      const result = parseEnvFile('EMPTY=\nFILLED=x');
      expect(result.size).toBe(1);
      expect(result.get('FILLED')).toBe('x');
    });
  });

  // ── detectProvider ──────────────────────────────────────────────────────

  describe('detectProvider', () => {
    it('detects OpenAI keys', async () => {
      const { detectProvider } = await import('../../src/endpoint/agent-config-scanner.js');
      expect(detectProvider('OPENAI_API_KEY')).toBe('openai');
    });

    it('detects Anthropic keys', async () => {
      const { detectProvider } = await import('../../src/endpoint/agent-config-scanner.js');
      expect(detectProvider('ANTHROPIC_API_KEY')).toBe('anthropic');
    });

    it('detects generic patterns', async () => {
      const { detectProvider } = await import('../../src/endpoint/agent-config-scanner.js');
      expect(detectProvider('CUSTOM_API_KEY')).toBe('generic');
      expect(detectProvider('MY_SECRET')).toBe('generic');
      expect(detectProvider('DB_PASSWORD')).toBe('generic');
    });

    it('returns undefined for non-credential keys', async () => {
      const { detectProvider } = await import('../../src/endpoint/agent-config-scanner.js');
      expect(detectProvider('LOG_LEVEL')).toBeUndefined();
      expect(detectProvider('PORT')).toBeUndefined();
    });
  });

  // ── hashValue ───────────────────────────────────────────────────────────

  describe('hashValue', () => {
    it('produces consistent SHA-256 hashes', async () => {
      const { hashValue } = await import('../../src/endpoint/agent-config-scanner.js');
      const h1 = hashValue('secret123');
      const h2 = hashValue('secret123');
      expect(h1).toBe(h2);
      expect(h1).toHaveLength(64);
    });

    it('produces different hashes for different values', async () => {
      const { hashValue } = await import('../../src/endpoint/agent-config-scanner.js');
      expect(hashValue('abc')).not.toBe(hashValue('def'));
    });
  });

  // ── checkFilePermissions ────────────────────────────────────────────────

  describe('checkFilePermissions', () => {
    it('returns null for mode 600', async () => {
      const { checkFilePermissions } = await import('../../src/endpoint/agent-config-scanner.js');
      const filePath = path.join(tmpDir, '.env');
      fs.writeFileSync(filePath, 'KEY=val');
      fs.chmodSync(filePath, 0o600);
      expect(checkFilePermissions(filePath, 'agent1')).toBeNull();
    });

    it('returns null for mode 400', async () => {
      const { checkFilePermissions } = await import('../../src/endpoint/agent-config-scanner.js');
      const filePath = path.join(tmpDir, '.env');
      fs.writeFileSync(filePath, 'KEY=val');
      fs.chmodSync(filePath, 0o400);
      expect(checkFilePermissions(filePath, 'agent1')).toBeNull();
    });

    it('flags world-readable files as critical', async () => {
      const { checkFilePermissions } = await import('../../src/endpoint/agent-config-scanner.js');
      const filePath = path.join(tmpDir, '.env');
      fs.writeFileSync(filePath, 'KEY=val');
      fs.chmodSync(filePath, 0o644);
      const result = checkFilePermissions(filePath, 'agent1');
      expect(result).not.toBeNull();
      expect(result!.severity).toBe('critical');
      expect(result!.currentMode).toBe('644');
    });

    it('flags group-readable files as high', async () => {
      const { checkFilePermissions } = await import('../../src/endpoint/agent-config-scanner.js');
      const filePath = path.join(tmpDir, '.env');
      fs.writeFileSync(filePath, 'KEY=val');
      fs.chmodSync(filePath, 0o640);
      const result = checkFilePermissions(filePath, 'agent1');
      expect(result).not.toBeNull();
      expect(result!.severity).toBe('high');
    });
  });

  // ── scanAgentConfigs (integration) ─────────────────────────────────────

  describe('scanAgentConfigs', () => {
    it('returns empty result for non-existent path', async () => {
      const { scanAgentConfigs } = await import('../../src/endpoint/agent-config-scanner.js');
      const result = await scanAgentConfigs({
        agentDataPath: '/nonexistent/path/agents',
      });
      expect(result.agentsScanned).toBe(0);
      expect(result.findings).toHaveLength(0);
    });

    it('returns empty result for empty agent directory', async () => {
      const { scanAgentConfigs } = await import('../../src/endpoint/agent-config-scanner.js');
      const result = await scanAgentConfigs({ agentDataPath: tmpDir });
      expect(result.agentsScanned).toBe(0);
    });

    it('detects credential duplication across agents', async () => {
      const { scanAgentConfigs } = await import('../../src/endpoint/agent-config-scanner.js');

      // Create two agents with the same secret
      const agent1Dir = path.join(tmpDir, 'agent-alpha');
      const agent2Dir = path.join(tmpDir, 'agent-beta');
      fs.mkdirSync(agent1Dir, { recursive: true });
      fs.mkdirSync(agent2Dir, { recursive: true });

      fs.writeFileSync(path.join(agent1Dir, '.env'), 'OPENAI_API_KEY=sk-shared-key-123');
      fs.writeFileSync(path.join(agent2Dir, '.env'), 'OPENAI_API_KEY=sk-shared-key-123');

      const result = await scanAgentConfigs({ agentDataPath: tmpDir });

      expect(result.agentsScanned).toBe(2);
      expect(result.totalCredentials).toBe(2);
      expect(result.duplicateGroups.length).toBeGreaterThanOrEqual(1);
      expect(result.duplicateGroups[0].agents).toContain('agent-alpha');
      expect(result.duplicateGroups[0].agents).toContain('agent-beta');

      const dupFindings = result.findings.filter(f => f.id === 'OC-AGENT-001');
      expect(dupFindings.length).toBeGreaterThanOrEqual(1);
    });

    it('detects overprivileged credential injection', async () => {
      const { scanAgentConfigs } = await import('../../src/endpoint/agent-config-scanner.js');

      const agentDir = path.join(tmpDir, 'email-agent');
      fs.mkdirSync(agentDir, { recursive: true });

      // Give it Slack creds but SKILL.md only mentions email
      fs.writeFileSync(path.join(agentDir, '.env'), 'SLACK_TOKEN=xoxb-abc\nOUTLOOK_TOKEN=abc');
      fs.writeFileSync(path.join(agentDir, 'SKILL.md'), '# Email Agent\nThis agent sends email via outlook.');

      const result = await scanAgentConfigs({ agentDataPath: tmpDir });

      expect(result.overprivileged.length).toBeGreaterThanOrEqual(1);
      const slackOverpriv = result.overprivileged.find(o => o.credential === 'SLACK_TOKEN');
      expect(slackOverpriv).toBeDefined();
      expect(slackOverpriv!.reason).toContain('SLACK_TOKEN');
    });

    it('generates OC-AGENT-003 findings for open file permissions', async () => {
      const { scanAgentConfigs } = await import('../../src/endpoint/agent-config-scanner.js');

      const agentDir = path.join(tmpDir, 'bad-perms-agent');
      fs.mkdirSync(agentDir, { recursive: true });
      const envFile = path.join(agentDir, '.env');
      fs.writeFileSync(envFile, 'SECRET_KEY=abc123');
      fs.chmodSync(envFile, 0o644);

      const result = await scanAgentConfigs({ agentDataPath: tmpDir });

      const permFindings = result.findings.filter(f => f.id === 'OC-AGENT-003');
      expect(permFindings.length).toBeGreaterThanOrEqual(1);
      expect(permFindings[0].severity).toBe('critical');
    });
  });
});
