import { describe, it, expect } from 'vitest';

describe('falco-rules', () => {
  describe('generateFalcoRules', () => {
    it('generates rules with correct structure', async () => {
      const { generateFalcoRules } = await import('../../src/endpoint/falco-rules.js');

      const result = generateFalcoRules({
        agentDataPath: '/data/.openclaw/agents',
      });

      expect(result.ruleCount).toBe(9);
      expect(result.macros.length).toBeGreaterThanOrEqual(2);
      expect(result.lists.length).toBeGreaterThanOrEqual(2);
    });

    it('includes egress violation rule', async () => {
      const { generateFalcoRules } = await import('../../src/endpoint/falco-rules.js');

      const result = generateFalcoRules({
        agentDataPath: '/data/agents',
      });

      expect(result.yaml).toContain('g0_openclaw_unexpected_egress');
      expect(result.yaml).toContain('tags: [g0, openclaw, network, egress, C1]');
    });

    it('includes cross-agent data access rule', async () => {
      const { generateFalcoRules } = await import('../../src/endpoint/falco-rules.js');

      const result = generateFalcoRules({
        agentDataPath: '/data/agents',
      });

      expect(result.yaml).toContain('g0_openclaw_cross_agent_access');
      expect(result.yaml).toContain('C4');
    });

    it('includes credential access rule', async () => {
      const { generateFalcoRules } = await import('../../src/endpoint/falco-rules.js');

      const result = generateFalcoRules({
        agentDataPath: '/data/agents',
      });

      expect(result.yaml).toContain('g0_openclaw_credential_access');
      expect(result.yaml).toContain('.env');
    });

    it('includes session transcript access rule', async () => {
      const { generateFalcoRules } = await import('../../src/endpoint/falco-rules.js');

      const result = generateFalcoRules({
        agentDataPath: '/data/agents',
      });

      expect(result.yaml).toContain('g0_openclaw_session_access');
      expect(result.yaml).toContain('L1');
    });

    it('includes root container detection rule', async () => {
      const { generateFalcoRules } = await import('../../src/endpoint/falco-rules.js');

      const result = generateFalcoRules({
        agentDataPath: '/data/agents',
      });

      expect(result.yaml).toContain('g0_openclaw_root_container');
      expect(result.yaml).toContain('H1');
    });

    it('includes sensitive binary execution rule', async () => {
      const { generateFalcoRules } = await import('../../src/endpoint/falco-rules.js');

      const result = generateFalcoRules({
        agentDataPath: '/data/agents',
      });

      expect(result.yaml).toContain('g0_openclaw_sensitive_binary');
      expect(result.yaml).toContain('curl');
      expect(result.yaml).toContain('wget');
    });

    it('includes docker socket access rule', async () => {
      const { generateFalcoRules } = await import('../../src/endpoint/falco-rules.js');

      const result = generateFalcoRules({
        agentDataPath: '/data/agents',
      });

      expect(result.yaml).toContain('g0_openclaw_docker_socket_access');
      expect(result.yaml).toContain('docker.sock');
      expect(result.yaml).toContain('C3');
    });

    it('includes gateway bind detection rule', async () => {
      const { generateFalcoRules } = await import('../../src/endpoint/falco-rules.js');

      const result = generateFalcoRules({
        agentDataPath: '/data/agents',
        gatewayPort: 18789,
      });

      expect(result.yaml).toContain('g0_openclaw_gateway_external_bind');
      expect(result.yaml).toContain('18789');
    });

    it('includes log tampering detection rule', async () => {
      const { generateFalcoRules } = await import('../../src/endpoint/falco-rules.js');

      const result = generateFalcoRules({
        agentDataPath: '/data/agents',
      });

      expect(result.yaml).toContain('g0_openclaw_log_tampering');
      expect(result.yaml).toContain('C5');
    });

    it('uses custom image pattern', async () => {
      const { generateFalcoRules } = await import('../../src/endpoint/falco-rules.js');

      const result = generateFalcoRules({
        agentDataPath: '/data/agents',
        imagePattern: 'my-custom-openclaw',
      });

      expect(result.yaml).toContain('my-custom-openclaw');
    });

    it('includes egress allowlist in list definition', async () => {
      const { generateFalcoRules } = await import('../../src/endpoint/falco-rules.js');

      const result = generateFalcoRules({
        agentDataPath: '/data/agents',
        egressAllowlist: ['api.anthropic.com', '8.8.8.8'],
      });

      expect(result.yaml).toContain('g0_allowed_egress');
      expect(result.yaml).toContain('api.anthropic.com');
      expect(result.yaml).toContain('8.8.8.8');
      expect(result.lists).toContain('g0_allowed_egress');
    });

    it('skips wildcards in egress list', async () => {
      const { generateFalcoRules } = await import('../../src/endpoint/falco-rules.js');

      const result = generateFalcoRules({
        agentDataPath: '/data/agents',
        egressAllowlist: ['*.openai.com', '8.8.8.8'],
      });

      // Wildcard should be filtered out of the Falco list
      expect(result.yaml).not.toContain('*.openai.com');
      expect(result.yaml).toContain('8.8.8.8');
    });

    it('uses custom container patterns', async () => {
      const { generateFalcoRules } = await import('../../src/endpoint/falco-rules.js');

      const result = generateFalcoRules({
        agentDataPath: '/data/agents',
        containerPatterns: ['oc-prod-*', 'oc-staging-*'],
      });

      expect(result.yaml).toContain('oc-prod-*');
      expect(result.yaml).toContain('oc-staging-*');
    });

    it('uses custom priority', async () => {
      const { generateFalcoRules } = await import('../../src/endpoint/falco-rules.js');

      const result = generateFalcoRules({
        agentDataPath: '/data/agents',
        defaultPriority: 'CRITICAL',
      });

      // Default-priority rules should use CRITICAL
      expect(result.yaml).toContain('priority: CRITICAL');
    });
  });

  describe('formatFalcoRulesFile', () => {
    it('returns valid YAML string', async () => {
      const { generateFalcoRules, formatFalcoRulesFile } = await import('../../src/endpoint/falco-rules.js');

      const ruleSet = generateFalcoRules({ agentDataPath: '/data/agents' });
      const content = formatFalcoRulesFile(ruleSet);

      expect(content).toContain('- rule:');
      expect(content).toContain('- macro:');
      expect(content).toContain('- list:');
      expect(content.endsWith('\n')).toBe(true);
    });
  });
});
