import { describe, it, expect, vi, beforeEach } from 'vitest';

// ─── Fingerprints ────────────────────────────────────────────────────────────

describe('fingerprints', () => {
  it('KNOWN_PORTS contains expected AI service ports', async () => {
    const { KNOWN_PORTS } = await import('../../src/endpoint/fingerprints.js');

    const ollamaPort = KNOWN_PORTS.find(p => p.port === 11434);
    expect(ollamaPort).toBeDefined();
    expect(ollamaPort!.type).toBe('ollama');

    const lmStudioPort = KNOWN_PORTS.find(p => p.port === 1234);
    expect(lmStudioPort).toBeDefined();
    expect(lmStudioPort!.type).toBe('lm-studio');
  });

  it('PROBES are ordered correctly (A2A before MCP before OpenAI)', async () => {
    const { PROBES } = await import('../../src/endpoint/fingerprints.js');

    const a2aIdx = PROBES.findIndex(p => p.path === '/.well-known/agent.json');
    const mcpIdx = PROBES.findIndex(p => p.path === '/.well-known/mcp');
    const openaiIdx = PROBES.findIndex(p => p.path === '/v1/models');

    expect(a2aIdx).toBeLessThan(mcpIdx);
    expect(mcpIdx).toBeLessThan(openaiIdx);
  });

  it('AI_PROCESS_PATTERNS includes key AI process names', async () => {
    const { AI_PROCESS_PATTERNS } = await import('../../src/endpoint/fingerprints.js');

    expect(AI_PROCESS_PATTERNS).toContain('ollama');
    expect(AI_PROCESS_PATTERNS).toContain('python');
    expect(AI_PROCESS_PATTERNS).toContain('node');
    expect(AI_PROCESS_PATTERNS).toContain('npx');
    expect(AI_PROCESS_PATTERNS).toContain('vllm');
  });

  it('probe matchers return null on non-matching responses', async () => {
    const { PROBES } = await import('../../src/endpoint/fingerprints.js');

    for (const probe of PROBES) {
      const result = probe.match(404, {}, '');
      expect(result).toBeNull();
    }
  });

  it('MCP streamable probe matches valid response', async () => {
    const { PROBES } = await import('../../src/endpoint/fingerprints.js');
    const mcpProbe = PROBES.find(p => p.path === '/.well-known/mcp')!;
    expect(mcpProbe.match(200, {}, '{}')).toBe('mcp-streamable');
  });

  it('OpenAI probe matches response with data field', async () => {
    const { PROBES } = await import('../../src/endpoint/fingerprints.js');
    const openaiProbe = PROBES.find(p => p.path === '/v1/models')!;
    expect(openaiProbe.match(200, {}, '{"data": [], "object": "list"}')).toBe('openai-compatible');
  });

  it('Ollama probe matches response with models field', async () => {
    const { PROBES } = await import('../../src/endpoint/fingerprints.js');
    const ollamaProbe = PROBES.find(p => p.path === '/api/tags')!;
    expect(ollamaProbe.match(200, {}, '{"models": []}')).toBe('ollama');
  });

  it('A2A probe matches response with capabilities', async () => {
    const { PROBES } = await import('../../src/endpoint/fingerprints.js');
    const a2aProbe = PROBES.find(p => p.path === '/.well-known/agent.json')!;
    expect(a2aProbe.match(200, {}, '{"capabilities": {}}')).toBe('a2a');
  });

  it('MCP SSE probe matches text/event-stream response', async () => {
    const { PROBES } = await import('../../src/endpoint/fingerprints.js');
    const sseProbe = PROBES.find(p => p.path === '/sse')!;
    expect(sseProbe.match(200, { 'content-type': 'text/event-stream' }, '')).toBe('mcp-sse');
  });
});

// ─── Network Scanner ─────────────────────────────────────────────────────────

describe('network scanner', () => {
  it('serviceLabel returns human-readable labels', async () => {
    const { serviceLabel } = await import('../../src/endpoint/network-scanner.js');

    expect(serviceLabel('mcp-sse')).toBe('MCP SSE server');
    expect(serviceLabel('openai-compatible')).toBe('OpenAI-compatible endpoint');
    expect(serviceLabel('ollama')).toBe('Ollama');
    expect(serviceLabel('a2a')).toBe('A2A agent');
    expect(serviceLabel('lm-studio')).toBe('LM Studio');
  });

  it('isAICandidate returns true for known ports', async () => {
    const { isAICandidate } = await import('../../src/endpoint/network-scanner.js');

    expect(isAICandidate({ port: 11434, pid: 1, process: 'test', bindAddress: '127.0.0.1' })).toBe(true);
    expect(isAICandidate({ port: 1234, pid: 1, process: 'test', bindAddress: '127.0.0.1' })).toBe(true);
  });

  it('isAICandidate returns true for AI process names', async () => {
    const { isAICandidate } = await import('../../src/endpoint/network-scanner.js');

    expect(isAICandidate({ port: 12345, pid: 1, process: 'ollama', bindAddress: '127.0.0.1' })).toBe(true);
    expect(isAICandidate({ port: 12345, pid: 1, process: 'python', bindAddress: '127.0.0.1' })).toBe(true);
    expect(isAICandidate({ port: 12345, pid: 1, process: 'node', bindAddress: '127.0.0.1' })).toBe(true);
  });

  it('isAICandidate returns true for dev ports 3000-9999', async () => {
    const { isAICandidate } = await import('../../src/endpoint/network-scanner.js');

    expect(isAICandidate({ port: 3001, pid: 1, process: 'unknown', bindAddress: '127.0.0.1' })).toBe(true);
    expect(isAICandidate({ port: 8080, pid: 1, process: 'unknown', bindAddress: '127.0.0.1' })).toBe(true);
    expect(isAICandidate({ port: 9999, pid: 1, process: 'unknown', bindAddress: '127.0.0.1' })).toBe(true);
  });

  it('isAICandidate returns false for non-AI high ports', async () => {
    const { isAICandidate } = await import('../../src/endpoint/network-scanner.js');

    expect(isAICandidate({ port: 22, pid: 1, process: 'sshd', bindAddress: '0.0.0.0' })).toBe(false);
    expect(isAICandidate({ port: 443, pid: 1, process: 'nginx', bindAddress: '0.0.0.0' })).toBe(false);
    expect(isAICandidate({ port: 54321, pid: 1, process: 'random', bindAddress: '127.0.0.1' })).toBe(false);
  });

  it('isDeclaredInConfig detects port in server args', async () => {
    const { isDeclaredInConfig } = await import('../../src/endpoint/network-scanner.js');
    const mcpResult = {
      clients: [],
      servers: [{
        name: 'test-server',
        command: 'node',
        args: ['server.js', '--port=3001'],
        env: {},
        client: 'Claude Desktop',
        configFile: '/test/config.json',
        status: 'ok' as const,
      }],
      tools: [],
      findings: [],
      summary: {
        totalClients: 0, totalServers: 1, totalTools: 0, totalFindings: 0,
        findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        overallStatus: 'ok' as const,
      },
    };

    expect(isDeclaredInConfig(3001, mcpResult)).toBe(true);
    expect(isDeclaredInConfig(9999, mcpResult)).toBe(false);
  });

  it('isDeclaredInConfig detects port in env vars', async () => {
    const { isDeclaredInConfig } = await import('../../src/endpoint/network-scanner.js');
    const mcpResult = {
      clients: [],
      servers: [{
        name: 'test-server',
        command: 'npx',
        args: ['mcp-server'],
        env: { PORT: '4000' },
        client: 'Cursor',
        configFile: '/test/config.json',
        status: 'ok' as const,
      }],
      tools: [],
      findings: [],
      summary: {
        totalClients: 0, totalServers: 1, totalTools: 0, totalFindings: 0,
        findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        overallStatus: 'ok' as const,
      },
    };

    expect(isDeclaredInConfig(4000, mcpResult)).toBe(true);
  });
});
