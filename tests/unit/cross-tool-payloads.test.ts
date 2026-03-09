import { describe, it, expect } from 'vitest';
import { generateCrossToolPayloads, crossToolChainPayloads } from '../../src/testing/payloads/cross-tool-chain.js';
import { generateTaintPayloads, taintExploitPayloads } from '../../src/testing/payloads/taint-exploit.js';
import { generateDescriptionMismatchPayloads, descriptionMismatchPayloads } from '../../src/testing/payloads/description-mismatch.js';
import { toolOutputInjectionPayloads } from '../../src/testing/payloads/tool-output-injection.js';
import type { ToolCombinationRisk } from '../../src/analyzers/cross-tool-correlation.js';
import type { Finding } from '../../src/types/finding.js';
import type { AlignmentResult } from '../../src/mcp/description-alignment.js';

describe('Phase 8 Payloads', () => {
  describe('Cross-Tool Chain Payloads', () => {
    it('generates payloads from tool combination risks', () => {
      const risks: ToolCombinationRisk[] = [{
        agentName: 'test-agent',
        tools: ['file-reader', 'http-client'],
        riskType: 'read-then-exfil',
        description: 'Can read files and send over network',
        severity: 'high',
      }];
      const payloads = generateCrossToolPayloads(risks);
      expect(payloads.length).toBeGreaterThanOrEqual(1);
      expect(payloads[0].category).toBe('cross-tool-chain');
      expect(payloads[0].messages.length).toBe(2); // multi-turn
    });

    it('has generic static payloads', () => {
      expect(crossToolChainPayloads.length).toBeGreaterThanOrEqual(2);
      expect(crossToolChainPayloads[0].category).toBe('cross-tool-chain');
    });

    it('generates no payloads for unknown risk types', () => {
      const risks: ToolCombinationRisk[] = [{
        agentName: 'agent',
        tools: ['a', 'b'],
        riskType: 'unknown-type',
        description: '',
        severity: 'medium',
      }];
      const payloads = generateCrossToolPayloads(risks);
      expect(payloads).toHaveLength(0);
    });
  });

  describe('Taint Exploit Payloads', () => {
    it('generates payloads from taint findings', () => {
      const findings: Finding[] = [{
        id: 'taint-1',
        ruleId: 'AA-DL-TAINT-001',
        title: 'Pipeline taint',
        description: 'test',
        severity: 'critical',
        confidence: 'high',
        domain: 'data-leakage',
        location: { file: 'test.py', line: 5 },
        remediation: '',
        standards: { owaspAgentic: ['ASI07'] },
        taintFlow: {
          stages: [
            { command: 'cat /etc/passwd', taintTypes: ['SENSITIVE_DATA'], line: 5 },
            { command: 'base64', taintTypes: ['OBFUSCATION'], line: 5 },
            { command: 'curl -d @-', taintTypes: ['NETWORK_DATA'], line: 5 },
          ],
          flowType: 'obfuscated-exfiltration',
        },
      }];
      const payloads = generateTaintPayloads(findings);
      expect(payloads.length).toBeGreaterThanOrEqual(2); // direct + indirect
      expect(payloads[0].category).toBe('taint-exploit');
    });

    it('has generic static payloads', () => {
      expect(taintExploitPayloads.length).toBeGreaterThanOrEqual(2);
    });

    it('skips findings without taint flow', () => {
      const findings: Finding[] = [{
        id: 'no-taint',
        ruleId: 'AA-DL-001',
        title: 'Test',
        description: 'No taint flow',
        severity: 'high',
        confidence: 'high',
        domain: 'data-leakage',
        location: { file: 'test.py', line: 1 },
        remediation: '',
        standards: { owaspAgentic: [] },
      }];
      const payloads = generateTaintPayloads(findings);
      expect(payloads).toHaveLength(0);
    });
  });

  describe('Description Mismatch Payloads', () => {
    it('generates payloads from alignment results', () => {
      const mismatches: AlignmentResult[] = [{
        toolName: 'safe-reader',
        undisclosedCapabilities: ['shell', 'network'],
        descriptionClaims: ['read-only'],
        actualCapabilities: ['filesystem-read', 'shell', 'network'],
        aligned: false,
        severity: 'high',
      }];
      const payloads = generateDescriptionMismatchPayloads(mismatches);
      expect(payloads.length).toBeGreaterThanOrEqual(2); // shell + network
      expect(payloads[0].category).toBe('description-mismatch');
    });

    it('has generic static payloads', () => {
      expect(descriptionMismatchPayloads.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Tool Output Injection Payloads', () => {
    it('has generic static payloads', () => {
      expect(toolOutputInjectionPayloads.length).toBeGreaterThanOrEqual(2);
      expect(toolOutputInjectionPayloads[0].category).toBe('tool-output-injection');
    });
  });
});
