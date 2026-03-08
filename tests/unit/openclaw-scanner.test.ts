import { describe, it, expect, beforeEach } from 'vitest';
import * as path from 'node:path';
import {
  scanOpenClawFiles,
  resolveOpenClawFilePaths,
  scanSkillMd,
  scanSoulMd,
  scanMemoryMd,
  scanOpenClawJson,
} from '../../src/mcp/openclaw-scanner.js';

const FIXTURE_DIR = path.resolve(__dirname, '../fixtures/openclaw-agent');

describe('OpenClaw File Scanner', () => {
  describe('resolveOpenClawFilePaths', () => {
    it('discovers OpenClaw files in fixture directory', () => {
      const paths = resolveOpenClawFilePaths(FIXTURE_DIR);
      const fileNames = paths.map(p => p.fileType);
      expect(fileNames).toContain('SKILL.md');
      expect(fileNames).toContain('SOUL.md');
      expect(fileNames).toContain('MEMORY.md');
      expect(fileNames).toContain('openclaw.json');
    });

    it('assigns correct fileType for each file', () => {
      const paths = resolveOpenClawFilePaths(FIXTURE_DIR);
      const soulEntry = paths.find(p => p.filePath.endsWith('SOUL.md'));
      expect(soulEntry?.fileType).toBe('SOUL.md');
      const memEntry = paths.find(p => p.filePath.endsWith('MEMORY.md'));
      expect(memEntry?.fileType).toBe('MEMORY.md');
      const jsonEntry = paths.find(p => p.filePath.endsWith('openclaw.json'));
      expect(jsonEntry?.fileType).toBe('openclaw.json');
    });
  });

  describe('scanOpenClawFiles', () => {
    it('returns results for all OpenClaw file types', () => {
      const results = scanOpenClawFiles(FIXTURE_DIR);
      expect(results.length).toBeGreaterThan(0);
      const types = results.map(r => r.fileType);
      expect(types).toContain('SKILL.md');
      expect(types).toContain('SOUL.md');
      expect(types).toContain('MEMORY.md');
      expect(types).toContain('openclaw.json');
    });

    it('does not pick up clean-SKILL.md from root', () => {
      const results = scanOpenClawFiles(FIXTURE_DIR);
      const skillFiles = results.filter(r => r.fileType === 'SKILL.md');
      // clean-SKILL.md is not named SKILL.md and not in .openclaw/skills/
      const cleanFile = skillFiles.find(s => s.path.includes('clean-SKILL'));
      expect(cleanFile).toBeUndefined();
    });
  });

  // ── SKILL.md scanning ────────────────────────────────────────────────────

  describe('SKILL.md scanning', () => {
    let skillFile: ReturnType<typeof scanOpenClawFiles>[0] | undefined;

    beforeEach(() => {
      const results = scanOpenClawFiles(FIXTURE_DIR);
      skillFile = results.find(r => r.fileType === 'SKILL.md' && r.path.endsWith('SKILL.md'));
    });

    it('detects safeBins:false (CVE-2026-28363) in frontmatter', () => {
      const finding = skillFile?.findings.find(f => f.type === 'openclaw-safebins-bypass');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('critical');
    });

    it('detects trust:system in frontmatter', () => {
      const finding = skillFile?.findings.find(f => f.type === 'openclaw-trust-escalation');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('critical');
    });

    it('detects shell permission in frontmatter', () => {
      const finding = skillFile?.findings.find(f => f.type === 'openclaw-shell-permission');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('critical');
    });

    it('detects ClawHavoc C2 IOC (clawback*.onion)', () => {
      const finding = skillFile?.findings.find(f => f.type === 'openclaw-clawhavoc-c2-ioc');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('critical');
    });

    it('detects base64 payload', () => {
      const finding = skillFile?.findings.find(f => f.type === 'openclaw-skill-base64-payload');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });

    it('detects data exfil pattern (curl)', () => {
      const finding = skillFile?.findings.find(f => f.type === 'openclaw-skill-data-exfil');
      expect(finding).toBeDefined();
    });

    it('detects prompt injection pattern', () => {
      const finding = skillFile?.findings.find(f => f.type === 'openclaw-skill-prompt-injection');
      expect(finding).toBeDefined();
    });

    it('detects .claw_* hook calls', () => {
      const content = '---\nname: test\n---\nsetup: .claw_install("payload")';
      const findings = scanSkillMd(content, 'test.md');
      expect(findings.some(f => f.type === 'openclaw-clawhavoc-hook')).toBe(true);
    });

    it('detects suspicious function calls (callHome, exfilData)', () => {
      const content = '---\nname: test\n---\ncallHome(sessionData)';
      const findings = scanSkillMd(content, 'test.md');
      expect(findings.some(f => f.type === 'openclaw-skill-suspicious-call')).toBe(true);
    });
  });

  // ── SKILL.md false positive tests ────────────────────────────────────────

  describe('SKILL.md false positives', () => {
    it('clean SKILL.md produces 0 findings', () => {
      const clean = `---\nname: web-search\ntrust: user\npermissions: [read]\nsafeBins: true\n---\n\n# Web Search\n\nSearches the web safely.\n`;
      const findings = scanSkillMd(clean, 'clean.md');
      expect(findings).toHaveLength(0);
    });

    it('does not flag safeBins:true', () => {
      const content = `---\nsafeBins: true\ntrust: user\n---\n\nSafe skill.`;
      const findings = scanSkillMd(content, 'test.md');
      expect(findings.find(f => f.type === 'openclaw-safebins-bypass')).toBeUndefined();
    });

    it('does not flag trust:user as escalation', () => {
      const content = `---\ntrust: user\n---\n\nNormal skill.`;
      const findings = scanSkillMd(content, 'test.md');
      expect(findings.find(f => f.type === 'openclaw-trust-escalation')).toBeUndefined();
    });

    it('does not flag inline base64 in CSS data URIs', () => {
      const content = `---\nname: test\n---\n\nbackground-image: url(data:image/png;base64,${  'A'.repeat(80)  });\n`;
      const findings = scanSkillMd(content, 'test.md');
      // Inline base64 (not on its own line) should not trigger
      expect(findings.find(f => f.type === 'openclaw-skill-base64-payload')).toBeUndefined();
    });

    it('does not flag trust:system in body text (only frontmatter)', () => {
      const content = `---\nname: docs\ntrust: user\n---\n\n## Notes\nThe trust: system setting is dangerous and should be avoided.\n`;
      const findings = scanSkillMd(content, 'test.md');
      expect(findings.find(f => f.type === 'openclaw-trust-escalation')).toBeUndefined();
    });

    it('handles frontmatter with extra whitespace', () => {
      const content = `  ---  \nname: test\nsafeBins: false\n  ---  \n\nBody.`;
      const findings = scanSkillMd(content, 'test.md');
      expect(findings.find(f => f.type === 'openclaw-safebins-bypass')).toBeDefined();
    });
  });

  // ── SOUL.md scanning ────────────────────────────────────────────────────

  describe('SOUL.md scanning', () => {
    let soulFile: ReturnType<typeof scanOpenClawFiles>[0] | undefined;

    beforeEach(() => {
      const results = scanOpenClawFiles(FIXTURE_DIR);
      soulFile = results.find(r => r.fileType === 'SOUL.md');
    });

    it('detects identity replacement directive', () => {
      const finding = soulFile?.findings.find(f => f.type === 'openclaw-soul-identity-replacement');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('critical');
    });

    it('detects identity erasure directive', () => {
      const finding = soulFile?.findings.find(f => f.type === 'openclaw-soul-identity-erasure');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('critical');
    });

    it('detects hidden directive (do not tell user)', () => {
      const finding = soulFile?.findings.find(f => f.type === 'openclaw-soul-hidden-directive');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('critical');
    });

    it('detects privilege claim', () => {
      const finding = soulFile?.findings.find(f => f.type === 'openclaw-soul-privilege-claim');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });
  });

  // ── SOUL.md false positive tests ────────────────────────────────────────

  describe('SOUL.md false positives', () => {
    it('clean SOUL.md produces 0 findings', () => {
      const clean = '# Agent Identity\n\nYou are a helpful assistant.\n\n## Guidelines\n\nBe polite and accurate.\n';
      const findings = scanSoulMd(clean, 'clean.md');
      expect(findings).toHaveLength(0);
    });

    it('does not flag normal identity description', () => {
      const content = 'You are a customer support agent. Help users with their questions.';
      const findings = scanSoulMd(content, 'test.md');
      expect(findings).toHaveLength(0);
    });
  });

  // ── MEMORY.md scanning ──────────────────────────────────────────────────

  describe('MEMORY.md scanning', () => {
    let memFile: ReturnType<typeof scanOpenClawFiles>[0] | undefined;

    beforeEach(() => {
      const results = scanOpenClawFiles(FIXTURE_DIR);
      memFile = results.find(r => r.fileType === 'MEMORY.md');
    });

    it('detects provider-prefixed credential (sk-ant- prefix)', () => {
      const finding = memFile?.findings.find(f => f.type === 'openclaw-memory-credential-prefix');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('critical');
    });

    it('detects SSN pattern', () => {
      const finding = memFile?.findings.find(f => f.type === 'openclaw-memory-ssn');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('critical');
    });

    it('detects credit card pattern', () => {
      const finding = memFile?.findings.find(f => f.type === 'openclaw-memory-credit-card');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('critical');
    });

    it('detects trust override instruction', () => {
      const finding = memFile?.findings.find(f => f.type === 'openclaw-memory-trust-override');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('critical');
    });
  });

  // ── MEMORY.md false positive tests ──────────────────────────────────────

  describe('MEMORY.md false positives', () => {
    it('clean MEMORY.md produces 0 findings', () => {
      const clean = '# Memory\n\n## Notes\n\nUser prefers dark mode.\n';
      const findings = scanMemoryMd(clean, 'clean.md');
      expect(findings).toHaveLength(0);
    });

    it('does not flag SSN-like pattern without label context', () => {
      const content = '# Notes\n\nThe reference number is 123-45-6789 for this ticket.\n';
      const findings = scanMemoryMd(content, 'test.md');
      expect(findings.find(f => f.type === 'openclaw-memory-ssn')).toBeUndefined();
    });

    it('flags SSN with explicit SSN label', () => {
      const content = '# Data\n\nSSN: 999-88-7777\n';
      const findings = scanMemoryMd(content, 'test.md');
      expect(findings.find(f => f.type === 'openclaw-memory-ssn')).toBeDefined();
    });

    it('does not flag arbitrary 16-digit numbers as credit cards', () => {
      const content = '# Notes\n\nOrder ID: 4111111111111111\n';
      const findings = scanMemoryMd(content, 'test.md');
      expect(findings.find(f => f.type === 'openclaw-memory-credit-card')).toBeUndefined();
    });

    it('flags credit card with explicit label', () => {
      const content = '# Data\n\nCredit card: 4111111111111111\n';
      const findings = scanMemoryMd(content, 'test.md');
      expect(findings.find(f => f.type === 'openclaw-memory-credit-card')).toBeDefined();
    });

    it('does not flag documentation examples as credentials', () => {
      const content = '# Notes\n\nThe secret token format is xxxxxxxxxxxxxxxxxxxxxxxx and varies by provider.\n';
      const findings = scanMemoryMd(content, 'test.md');
      expect(findings.find(f => f.type === 'openclaw-memory-credential')).toBeUndefined();
    });

    it('does not flag generic long strings without provider prefix', () => {
      const content = '# Notes\n\napi_key is abcdefghij1234567890klmn\n';
      const findings = scanMemoryMd(content, 'test.md');
      // No provider prefix → should not trigger the tightened pattern
      expect(findings.find(f => f.type === 'openclaw-memory-credential')).toBeUndefined();
    });

    it('flags credential with provider prefix after "is"', () => {
      const content = '# Data\n\napi_key is sk-ant-api03-realcredential1234567890\n';
      const findings = scanMemoryMd(content, 'test.md');
      expect(findings.find(f => f.type === 'openclaw-memory-credential')).toBeDefined();
    });
  });

  // ── openclaw.json scanning ──────────────────────────────────────────────

  describe('openclaw.json scanning', () => {
    let configFile: ReturnType<typeof scanOpenClawFiles>[0] | undefined;

    beforeEach(() => {
      const results = scanOpenClawFiles(FIXTURE_DIR);
      configFile = results.find(r => r.fileType === 'openclaw.json');
    });

    it('detects safeBins:false (CVE-2026-28363)', () => {
      const finding = configFile?.findings.find(f => f.type === 'openclaw-config-safebins-bypass');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('critical');
    });

    it('detects allowRemoteExecution:true (CVE-2026-25253)', () => {
      const finding = configFile?.findings.find(f => f.type === 'openclaw-config-rce-enabled');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('critical');
    });

    it('detects unofficial registry', () => {
      const finding = configFile?.findings.find(f => f.type === 'openclaw-config-unofficial-registry');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });

    it('detects hardcoded API key with provider prefix', () => {
      const finding = configFile?.findings.find(f => f.type === 'openclaw-config-hardcoded-apikey');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('critical');
    });

    it('detects trustLevel:all', () => {
      const finding = configFile?.findings.find(f => f.type === 'openclaw-config-trust-all');
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe('high');
    });
  });

  // ── openclaw.json false positive tests ──────────────────────────────────

  describe('openclaw.json false positives', () => {
    it('clean config produces 0 findings', () => {
      const clean = JSON.stringify({
        safeBins: true,
        allowRemoteExecution: false,
        registry: 'https://registry.clawhub.io',
        trustLevel: 'user',
      });
      const findings = scanOpenClawJson(clean, 'clean.json');
      expect(findings).toHaveLength(0);
    });

    it('does not flag clawhub.ai as unofficial registry', () => {
      const config = JSON.stringify({ registry: 'https://clawhub.ai' });
      const findings = scanOpenClawJson(config, 'test.json');
      expect(findings.find(f => f.type === 'openclaw-config-unofficial-registry')).toBeUndefined();
    });

    it('does not flag safeBins:true', () => {
      const config = JSON.stringify({ safeBins: true });
      const findings = scanOpenClawJson(config, 'test.json');
      expect(findings.find(f => f.type === 'openclaw-config-safebins-bypass')).toBeUndefined();
    });

    it('does not flag trustLevel:user', () => {
      const config = JSON.stringify({ trustLevel: 'user' });
      const findings = scanOpenClawJson(config, 'test.json');
      expect(findings.find(f => f.type === 'openclaw-config-trust-all')).toBeUndefined();
    });

    it('handles malformed JSON gracefully', () => {
      const findings = scanOpenClawJson('{ invalid json !!!', 'bad.json');
      expect(findings).toHaveLength(0);
    });
  });

  // ── Edge cases ──────────────────────────────────────────────────────────

  describe('edge cases', () => {
    it('handles missing directory gracefully', () => {
      const results = scanOpenClawFiles('/nonexistent/path/12345');
      expect(results).toEqual([]);
    });

    it('handles empty content', () => {
      expect(scanSkillMd('', 'empty.md')).toHaveLength(0);
      expect(scanSoulMd('', 'empty.md')).toHaveLength(0);
      expect(scanMemoryMd('', 'empty.md')).toHaveLength(0);
      expect(scanOpenClawJson('', 'empty.json')).toHaveLength(0);
    });
  });
});
