import { describe, it, expect } from 'vitest';
import { toCycloneDX, computeBomHash, type BomMeta } from '../../src/inventory/cyclonedx.js';
import { generateKeyPair, signBomHash, verifyBomSignature } from '../../src/inventory/sign.js';
import type { InventoryResult } from '../../src/types/inventory.js';

const inv: InventoryResult = {
  models: [{ name: 'gpt-4o', provider: 'openai', framework: 'langchain', file: 'a.py', line: 1 }],
  frameworks: [{ name: 'langchain', version: '0.3.0', file: 'req.txt' }],
  tools: [{ name: 'run_command', framework: 'langchain', description: '', capabilities: ['shell'], hasSideEffects: true, hasValidation: false, file: 'a.py', line: 5 }],
  mcpServers: [{ name: 'postgres', command: 'npx', args: [], hasSecrets: true, isPinned: false, file: 'mcp.json' }],
  agents: [{ name: 'assistant', framework: 'langchain', toolCount: 1, hasDelegation: false, file: 'a.py', line: 10 }],
  vectorDBs: [],
  risks: [],
  summary: {
    totalModels: 1, totalFrameworks: 1, totalTools: 1, totalAgents: 1,
    totalMCPServers: 1, totalVectorDBs: 0, totalRisks: 0,
    riskBreakdown: { critical: 0, high: 0, medium: 0, low: 0 },
  },
};

const meta = (): BomMeta => ({
  projectName: 'demo',
  toolVersion: '2.0.0',
  timestamp: '2026-01-01T00:00:00Z',
  serialNumber: 'urn:uuid:00000000-0000-0000-0000-000000000000',
});

describe('CycloneDX AI-BOM', () => {
  it('produces a valid CycloneDX 1.6 envelope', () => {
    const bom = toCycloneDX(inv, meta());
    expect(bom.bomFormat).toBe('CycloneDX');
    expect(bom.specVersion).toBe('1.6');
    expect(bom.components.length).toBe(4); // model + framework + tool + agent
  });

  it('maps models, frameworks, tools, agents to components and MCP to services', () => {
    const bom = toCycloneDX(inv, meta());
    const types = bom.components.map(c => c.type).sort();
    expect(types).toContain('machine-learning-model'); // model
    expect(types).toContain('application');            // agent
    expect(bom.components.filter(c => c.type === 'library').length).toBe(2); // framework + tool
    expect(bom.services.map(s => s.name)).toEqual(['postgres']);
  });

  it('hash is stable across serial number and timestamp changes', () => {
    const a = toCycloneDX(inv, meta());
    const b = toCycloneDX(inv, {
      ...meta(),
      serialNumber: 'urn:uuid:ffffffff-ffff-ffff-ffff-ffffffffffff',
      timestamp: '2027-12-31T23:59:59Z',
    });
    const hashA = a.properties.find(p => p.name === 'g0:bomHash')!.value;
    const hashB = b.properties.find(p => p.name === 'g0:bomHash')!.value;
    expect(hashA).toBe(hashB);
  });

  it('hash changes when the inventory changes', () => {
    const a = toCycloneDX(inv, meta());
    const inv2 = { ...inv, tools: [] };
    const b = toCycloneDX(inv2 as InventoryResult, meta());
    const hashA = a.properties.find(p => p.name === 'g0:bomHash')!.value;
    const hashB = b.properties.find(p => p.name === 'g0:bomHash')!.value;
    expect(hashA).not.toBe(hashB);
  });
});

describe('AI-BOM signing', () => {
  it('signs and verifies a bom hash', () => {
    const { privateKeyPem } = generateKeyPair();
    const bom = toCycloneDX(inv, meta());
    const hash = bom.properties.find(p => p.name === 'g0:bomHash')!.value;
    const sig = signBomHash(hash, privateKeyPem, '2026-01-01T00:00:00Z');
    expect(verifyBomSignature(sig)).toBe(true);
  });

  it('fails verification if the hash is tampered', () => {
    const { privateKeyPem } = generateKeyPair();
    const sig = signBomHash('a'.repeat(64), privateKeyPem, '2026-01-01T00:00:00Z');
    const tampered = { ...sig, bomHash: 'b'.repeat(64) };
    expect(verifyBomSignature(tampered)).toBe(false);
  });

  it('fails verification with a different public key', () => {
    const k1 = generateKeyPair();
    const k2 = generateKeyPair();
    const sig = signBomHash('c'.repeat(64), k1.privateKeyPem, '2026-01-01T00:00:00Z');
    const wrong = { ...sig, publicKey: k2.publicKeyPem };
    expect(verifyBomSignature(wrong)).toBe(false);
  });
});
