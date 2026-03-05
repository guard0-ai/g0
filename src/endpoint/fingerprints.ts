import type { AIServiceType } from '../types/endpoint.js';

// ─── Known Port Signatures ───────────────────────────────────────────────────

export interface KnownPortSignature {
  port: number;
  type: AIServiceType;
  label: string;
}

/** Well-known default ports for AI services */
export const KNOWN_PORTS: KnownPortSignature[] = [
  { port: 11434, type: 'ollama', label: 'Ollama' },
  { port: 1234, type: 'lm-studio', label: 'LM Studio' },
  { port: 8080, type: 'vllm', label: 'vLLM' },
  { port: 1337, type: 'jan', label: 'Jan' },
  { port: 8000, type: 'vllm', label: 'vLLM / FastAPI' },
];

// ─── HTTP Probe Definitions ──────────────────────────────────────────────────

export interface ProbeDefinition {
  /** Path to request */
  path: string;
  /** HTTP method */
  method: 'GET' | 'POST';
  /** Optional request body (for POST probes) */
  body?: string;
  /** Optional Accept header */
  accept?: string;
  /** Content-Type for POST */
  contentType?: string;
  /** How to identify this service from the response */
  match: (status: number, headers: Record<string, string>, body: string) => AIServiceType | null;
}

/**
 * Probes are tried in order. First match wins.
 * Each probe is a lightweight HTTP request to a well-known path.
 */
export const PROBES: ProbeDefinition[] = [
  // A2A agent discovery
  {
    path: '/.well-known/agent.json',
    method: 'GET',
    match: (status, _headers, body) => {
      if (status === 200 && body.includes('"capabilities"')) return 'a2a';
      return null;
    },
  },

  // MCP Streamable HTTP (uses .well-known/mcp or responds to initialize on /)
  {
    path: '/.well-known/mcp',
    method: 'GET',
    match: (status, _headers, body) => {
      if (status === 200) return 'mcp-streamable';
      return null;
    },
  },

  // MCP SSE endpoint
  {
    path: '/sse',
    method: 'GET',
    accept: 'text/event-stream',
    match: (status, headers) => {
      const ct = headers['content-type'] || '';
      if (status === 200 && ct.includes('text/event-stream')) return 'mcp-sse';
      return null;
    },
  },

  // Ollama-specific endpoint
  {
    path: '/api/tags',
    method: 'GET',
    match: (status, _headers, body) => {
      if (status === 200 && body.includes('"models"')) return 'ollama';
      return null;
    },
  },

  // OpenAI-compatible (covers LM Studio, vLLM, local proxies, etc.)
  {
    path: '/v1/models',
    method: 'GET',
    match: (status, _headers, body) => {
      if (status === 200 && (body.includes('"data"') || body.includes('"object"'))) return 'openai-compatible';
      return null;
    },
  },

  // JSON-RPC initialize (generic MCP fallback)
  {
    path: '/',
    method: 'POST',
    contentType: 'application/json',
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'g0-probe', version: '1.0.0' },
      },
    }),
    match: (status, _headers, body) => {
      if (status === 200 && body.includes('"jsonrpc"') && body.includes('"serverInfo"')) {
        return 'mcp-streamable';
      }
      return null;
    },
  },
];

// ─── Auth Detection ──────────────────────────────────────────────────────────

/**
 * Paths to probe for checking if a service requires authentication.
 * If we get 401/403, it's authenticated. If we get 200, it's open.
 */
export const AUTH_PROBE_PATHS = [
  '/v1/models',
  '/api/tags',
  '/health',
  '/',
];

/**
 * Process names that indicate AI-related services.
 * Used to pre-filter ports before expensive HTTP probing.
 */
export const AI_PROCESS_PATTERNS = [
  'ollama',
  'lm-studio',
  'lmstudio',
  'llama',
  'vllm',
  'python',      // many AI services are Python
  'node',        // MCP servers often run via node
  'npx',         // npx @modelcontextprotocol/...
  'uvx',         // uvx mcp-server-...
  'uvicorn',     // FastAPI / ASGI servers
  'gunicorn',    // WSGI servers
  'jan',
  'localai',
  'text-generation', // TGI
  'triton',      // Triton inference server
];
