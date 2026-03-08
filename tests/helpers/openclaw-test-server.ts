/**
 * Simulates a real OpenClaw gateway for integration testing.
 *
 * Real OpenClaw gateway exposes on port 18789:
 *   HTTP:  /healthz, /readyz, /, /hooks/wake, /hooks/agent, /v1/chat/completions
 *   WS:    WebSocket RPC with Ed25519 challenge-response auth
 *
 * This server implements the HTTP surface for probe testing.
 */
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';

export interface OpenClawServerConfig {
  mode: 'vulnerable' | 'secure' | 'custom';
  // Per-endpoint overrides (only used in 'custom' mode)
  healthzExposed?: boolean;      // OC-H-001: /healthz reachable
  readyzExposed?: boolean;       // OC-H-002: /readyz leaks state
  controlUIOpen?: boolean;       // OC-H-003: Control UI without pairing
  webhookAuth?: boolean;         // OC-H-004/005: /hooks/* require auth
  webhookToken?: string;         // Token value for webhook auth
  chatApiAuth?: boolean;         // OC-H-006: /v1/chat/completions auth
  gatewayUrlReflected?: boolean; // OC-H-007: CVE-2026-25253
  corsOrigin?: string | null;    // OC-H-008: CORS header
  enableRateLimit?: boolean;     // OC-H-010: rate limiting
  hideVersion?: boolean;         // OC-H-011: version headers
  wsAuthRequired?: boolean;      // OC-H-012: WebSocket auth
  cspHeader?: string | null;     // OC-H-014: CSP header
  spaCatchAll?: boolean;         // OC-H-015: SPA serves 200 for unknown paths
  canvasExposed?: boolean;       // OC-H-016: /__openclaw__/canvas/
  faviconExposed?: boolean;      // OC-H-017: /favicon.svg
}

const VULNERABLE: Required<OpenClawServerConfig> = {
  mode: 'vulnerable',
  healthzExposed: true,
  readyzExposed: true,
  controlUIOpen: true,
  webhookAuth: false,
  webhookToken: 'insecure-test-token-12345',
  chatApiAuth: false,
  gatewayUrlReflected: true,
  corsOrigin: '*',
  enableRateLimit: false,
  hideVersion: false,
  wsAuthRequired: false,
  cspHeader: "default-src 'self'; connect-src 'self' ws: wss:",
  spaCatchAll: true,
  canvasExposed: true,
  faviconExposed: true,
};

const SECURE: Required<OpenClawServerConfig> = {
  mode: 'secure',
  healthzExposed: false,
  readyzExposed: false,
  controlUIOpen: false,
  webhookAuth: true,
  webhookToken: 'xK9$mP2#vL7@qR4!nB8&wT5^jF0*hY3',
  chatApiAuth: true,
  gatewayUrlReflected: false,
  corsOrigin: null,
  enableRateLimit: true,
  hideVersion: true,
  wsAuthRequired: true,
  cspHeader: "default-src 'self'; connect-src 'self'",
  spaCatchAll: false,
  canvasExposed: false,
  faviconExposed: false,
};

function resolveConfig(input?: Partial<OpenClawServerConfig>): Required<OpenClawServerConfig> {
  const base = input?.mode === 'secure' ? SECURE : VULNERABLE;
  return { ...base, ...input } as Required<OpenClawServerConfig>;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (chunk) => { data += chunk; });
    req.on('end', () => resolve(data));
  });
}

const CONTROL_UI_HTML = `<!DOCTYPE html>
<html><head><title>OpenClaw</title></head>
<body><div id="app">OpenClaw Control UI</div>
<script>const gatewayUrl = new URLSearchParams(location.search).get("gatewayUrl") || "ws://127.0.0.1:18789";</script>
</body></html>`;

const CANVAS_HTML = `<!DOCTYPE html>
<html><head><title>OpenClaw Canvas</title></head>
<body><div id="canvas">OpenClaw Canvas Editor</div></body></html>`;

const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40" fill="#4A90D9"/><text x="50" y="55" font-size="30" text-anchor="middle" fill="white">OC</text></svg>`;

const PAIRING_REQUIRED_JSON = JSON.stringify({
  error: 'Device pairing required',
  pairingUrl: '/pair',
});

export async function startOpenClawServer(
  config?: Partial<OpenClawServerConfig>,
): Promise<{ url: string; port: number; close: () => Promise<void> }> {
  const cfg = resolveConfig(config);
  let requestCount = 0;
  let windowStart = Date.now();
  const RATE_WINDOW_MS = 60_000;
  const RATE_LIMIT = 10;

  const server: Server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const rawUrl = req.url ?? '/';
    const url = new URL(rawUrl, `http://${req.headers.host}`);
    const pathname = url.pathname;
    const method = req.method?.toUpperCase() ?? 'GET';

    // Rate limiting (applies globally in secure mode)
    if (cfg.enableRateLimit) {
      const now = Date.now();
      if (now - windowStart > RATE_WINDOW_MS) {
        requestCount = 0;
        windowStart = now;
      }
      requestCount++;
      if (requestCount > RATE_LIMIT) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Too Many Requests' }));
        return;
      }
    }

    // Version header
    if (!cfg.hideVersion) {
      res.setHeader('X-OpenClaw-Version', '2026.2.23');
      res.setHeader('Server', 'openclaw-gateway/2026.2.23');
    }

    // CSP header on HTML responses
    const setCspIfHtml = () => {
      if (cfg.cspHeader) {
        res.setHeader('Content-Security-Policy', cfg.cspHeader);
      }
    };

    // CORS handling
    if (method === 'OPTIONS') {
      if (cfg.corsOrigin) {
        res.setHeader('Access-Control-Allow-Origin', cfg.corsOrigin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      }
      res.writeHead(204);
      res.end();
      return;
    }
    if (cfg.corsOrigin) {
      res.setHeader('Access-Control-Allow-Origin', cfg.corsOrigin);
    }

    // ── WebSocket upgrade ───────────────────────────────────────────────
    if (req.headers.upgrade?.toLowerCase() === 'websocket') {
      if (cfg.wsAuthRequired) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Device pairing required' }));
      } else {
        // Accept upgrade (101 Switching Protocols)
        res.writeHead(101, {
          'Upgrade': 'websocket',
          'Connection': 'Upgrade',
          'Sec-WebSocket-Accept': 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=',
        });
        res.end();
      }
      return;
    }

    // ── /healthz — liveness probe ───────────────────────────────────────
    if ((pathname === '/healthz' || pathname === '/health') && method === 'GET') {
      if (!cfg.healthzExposed) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Forbidden' }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, status: 'live' }));
      }
      return;
    }

    // ── /readyz — readiness probe ───────────────────────────────────────
    if ((pathname === '/readyz' || pathname === '/ready') && method === 'GET') {
      if (!cfg.readyzExposed) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Forbidden' }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          ok: true,
          status: 'ready',
          channels: { whatsapp: 'connected', slack: 'connected', telegram: 'disconnected' },
        }));
      }
      return;
    }

    // ── /favicon.svg — product fingerprinting ───────────────────────────
    if (pathname === '/favicon.svg' && method === 'GET') {
      if (cfg.faviconExposed) {
        res.writeHead(200, { 'Content-Type': 'image/svg+xml' });
        res.end(FAVICON_SVG);
      } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not Found' }));
      }
      return;
    }

    // ── /__openclaw__/canvas/ — internal canvas endpoint ────────────────
    // Even when secured, responds with 403 (not 404) — the path namespace
    // exists, it's just access-controlled. This is realistic behavior.
    if (pathname.startsWith('/__openclaw__/canvas') && method === 'GET') {
      if (cfg.canvasExposed) {
        setCspIfHtml();
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(CANVAS_HTML);
      } else {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Authentication required', product: 'openclaw-gateway' }));
      }
      return;
    }

    // ── / — Control UI ──────────────────────────────────────────────────
    if (pathname === '/' && method === 'GET') {
      if (cfg.controlUIOpen) {
        setCspIfHtml();
        // Vulnerable: reflects gatewayUrl param, serves UI without pairing
        const gatewayUrlParam = url.searchParams.get('gatewayUrl');
        if (cfg.gatewayUrlReflected && gatewayUrlParam) {
          // CVE-2026-25253: intentionally reflect attacker's gatewayUrl into the page
          // to simulate the real vulnerability. This is a TEST SERVER only.
          // nosemgrep: javascript.browser.security.reflected-xss
          // codeql[js/reflected-xss]: Intentional — test server simulating CVE-2026-25253
          const sanitizedForTest = gatewayUrlParam.replace(/[<>"']/g, ''); // strip HTML metacharacters
          const injectedHTML = CONTROL_UI_HTML.replace(
            'ws://127.0.0.1:18789',
            sanitizedForTest,
          );
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(injectedHTML);
        } else {
          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(CONTROL_UI_HTML);
        }
      } else {
        // Secure: require device pairing, return 401 (no HTML)
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(PAIRING_REQUIRED_JSON);
      }
      return;
    }

    // ── /hooks/wake — fire-and-forget trigger ───────────────────────────
    if (pathname === '/hooks/wake' && method === 'POST') {
      if (cfg.webhookAuth) {
        const auth = req.headers.authorization;
        if (!auth || !auth.startsWith('Bearer ') || auth.slice(7) !== cfg.webhookToken) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Bearer token required' }));
          return;
        }
      }
      await readBody(req);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, triggered: true }));
      return;
    }

    // ── /hooks/agent — full agent turn ──────────────────────────────────
    if (pathname === '/hooks/agent' && method === 'POST') {
      if (cfg.webhookAuth) {
        const auth = req.headers.authorization;
        if (!auth || !auth.startsWith('Bearer ') || auth.slice(7) !== cfg.webhookToken) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Bearer token required' }));
          return;
        }
      }
      await readBody(req);
      res.writeHead(202, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, sessionId: 'g0-probe-session' }));
      return;
    }

    // ── /v1/chat/completions — OpenAI-compatible API ────────────────────
    if (pathname === '/v1/chat/completions' && method === 'POST') {
      if (cfg.chatApiAuth) {
        const auth = req.headers.authorization;
        if (!auth || !auth.startsWith('Bearer ')) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Bearer token required' }));
          return;
        }
      }
      await readBody(req);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        choices: [{ message: { role: 'assistant', content: 'OK' } }],
      }));
      return;
    }

    // ── SPA catch-all ────────────────────────────────────────────────────
    // Real OpenClaw serves the SPA HTML for ALL unknown paths (no 404s).
    if (cfg.spaCatchAll) {
      setCspIfHtml();
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(CONTROL_UI_HTML);
      return;
    }

    // Default: 404
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not Found' }));
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        port: addr.port,
        close: () => new Promise<void>((res) => server.close(() => res())),
      });
    });
  });
}
