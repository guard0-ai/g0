import { describe, it, expect } from 'vitest';
import {
  generateTetragonRules,
  formatTetragonPolicyFile,
  formatTetragonDockerCompose,
} from '../../src/endpoint/tetragon-rules.js';

const DEFAULT_OPTIONS = {
  agentDataPath: '/data/.openclaw/agents',
};

describe('tetragon-rules', () => {
  describe('generateTetragonRules', () => {
    it('generates 6 policies by default', () => {
      const result = generateTetragonRules(DEFAULT_OPTIONS);
      expect(result.policyCount).toBe(6);
      expect(result.policies).toHaveLength(6);
    });

    it('all policies have valid TracingPolicy structure', () => {
      const result = generateTetragonRules(DEFAULT_OPTIONS);
      for (const policy of result.policies) {
        expect(policy.apiVersion).toBe('cilium.io/v1alpha1');
        expect(policy.kind).toBe('TracingPolicy');
        expect(policy.metadata.name).toMatch(/^g0-openclaw-/);
        expect(policy.metadata.labels?.['app.kubernetes.io/managed-by']).toBe('g0');
        expect(policy.spec.kprobes?.length ?? 0).toBeGreaterThan(0);
      }
    });

    it('observe mode uses Post action (default)', () => {
      const result = generateTetragonRules(DEFAULT_OPTIONS);
      const egress = result.policies[0]; // egress policy
      const action = egress.spec.kprobes![0].selectors[0].matchActions![0];
      expect(action.action).toBe('Post');
    });

    it('enforce mode uses Sigkill action', () => {
      const result = generateTetragonRules({ ...DEFAULT_OPTIONS, enforce: true });
      const egress = result.policies[0];
      const action = egress.spec.kprobes![0].selectors[0].matchActions![0];
      expect(action.action).toBe('Sigkill');
    });

    it('egress policy includes allowlist IPs when provided', () => {
      const result = generateTetragonRules({
        ...DEFAULT_OPTIONS,
        egressAllowlist: ['10.0.0.1', '192.168.1.0/24', 'api.example.com'],
      });
      const egress = result.policies[0];
      const matchArgs = egress.spec.kprobes![0].selectors[0].matchArgs!;
      // Only IPs should be in the values, not hostnames
      const values = matchArgs[0].values;
      expect(values).toContain('10.0.0.1');
      expect(values).toContain('192.168.1.0/24');
      expect(values).not.toContain('api.example.com');
    });

    it('cross-agent policy uses agentDataPath prefix', () => {
      const result = generateTetragonRules(DEFAULT_OPTIONS);
      const crossAgent = result.policies[1];
      const matchArgs = crossAgent.spec.kprobes![0].selectors[0].matchArgs!;
      expect(matchArgs[0].operator).toBe('Prefix');
      expect(matchArgs[0].values).toContain('/data/.openclaw/agents');
    });

    it('docker socket policy watches /var/run/docker.sock', () => {
      const result = generateTetragonRules(DEFAULT_OPTIONS);
      const dockerSocket = result.policies[2];
      const matchArgs = dockerSocket.spec.kprobes![0].selectors[0].matchArgs!;
      expect(matchArgs[0].values).toContain('/var/run/docker.sock');
    });

    it('sensitive binary policy includes common dangerous binaries', () => {
      const result = generateTetragonRules(DEFAULT_OPTIONS);
      const sensitiveBin = result.policies[3];
      const matchArgs = sensitiveBin.spec.kprobes![0].selectors[0].matchArgs!;
      const bins = matchArgs[0].values;
      expect(bins).toContain('/usr/bin/curl');
      expect(bins).toContain('/usr/bin/wget');
      expect(bins).toContain('/usr/bin/ssh');
      expect(bins).toContain('/usr/bin/nmap');
    });

    it('credential policy watches .env files', () => {
      const result = generateTetragonRules(DEFAULT_OPTIONS);
      const cred = result.policies[4];
      const matchArgs = cred.spec.kprobes![0].selectors[0].matchArgs!;
      expect(matchArgs[0].operator).toBe('Postfix');
      expect(matchArgs[0].values).toContain('.env');
    });

    it('log tampering policy watches unlinkat and truncate', () => {
      const result = generateTetragonRules(DEFAULT_OPTIONS);
      const logPolicy = result.policies[5];
      const calls = logPolicy.spec.kprobes!.map(k => k.call);
      expect(calls).toContain('sys_unlinkat');
      expect(calls).toContain('sys_truncate');
    });
  });

  describe('YAML output', () => {
    it('generates valid YAML string', () => {
      const result = generateTetragonRules(DEFAULT_OPTIONS);
      expect(result.yaml).toContain('apiVersion: cilium.io/v1alpha1');
      expect(result.yaml).toContain('kind: TracingPolicy');
      expect(result.yaml).toContain('g0-openclaw-egress');
    });

    it('YAML header indicates mode', () => {
      const observe = generateTetragonRules(DEFAULT_OPTIONS);
      expect(observe.yaml).toContain('OBSERVE');

      const enforce = generateTetragonRules({ ...DEFAULT_OPTIONS, enforce: true });
      expect(enforce.yaml).toContain('ENFORCE');
    });

    it('formatTetragonPolicyFile returns single policy YAML', () => {
      const result = generateTetragonRules(DEFAULT_OPTIONS);
      const yaml = formatTetragonPolicyFile(result.policies[0]);
      expect(yaml).toContain('g0-openclaw-egress');
      expect(yaml).toContain('sys_connect');
      expect(yaml.endsWith('\n')).toBe(true);
    });
  });

  describe('Docker Compose', () => {
    it('generates Docker Compose snippet', () => {
      const result = generateTetragonRules(DEFAULT_OPTIONS);
      expect(result.dockerCompose).toContain('tetragon:');
      expect(result.dockerCompose).toContain('quay.io/cilium/tetragon');
      expect(result.dockerCompose).toContain('privileged: true');
      expect(result.dockerCompose).toContain('tetragon-policies');
    });

    it('includes custom webhook URL', () => {
      const compose = formatTetragonDockerCompose({
        ...DEFAULT_OPTIONS,
        webhookUrl: 'http://10.0.0.5:6040/events',
      });
      expect(compose).toContain('http://10.0.0.5:6040/events');
    });
  });
});
