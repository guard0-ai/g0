import { statSync } from 'node:fs';
import type { AIProvider } from '../ai/provider.js';

export type HardeningCheckStatus = 'pass' | 'fail' | 'error' | 'skip';
export type HardeningSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface HardeningCheck {
  id: string;
  name: string;
  severity: HardeningSeverity;
  status: HardeningCheckStatus;
  detail: string;
}

export interface FingerprintResult {
  confidence: 'confirmed' | 'likely' | 'unknown';
  signals: string[];
  version?: string;
}

export interface AISecurityInsight {
  title: string;
  severity: HardeningSeverity;
  detail: string;
}

export interface OpenClawHardeningResult {
  targetUrl: string;
  fingerprint: FingerprintResult;
  checks: HardeningCheck[];
  aiAnalysis?: {
    provider: string;
    model: string;
    insights: AISecurityInsight[];
  };
  summary: {
    total: number;
    passed: number;
    failed: number;
    errors: number;
    overallStatus: 'secure' | 'warn' | 'critical';
  };
}

export interface ProbeOptions {
  /** Local config path for file permission checks (OC-H-018) */
  configPath?: string;
  /** Custom wordlist for webhook token brute-force (OC-H-013) */
  weakTokens?: string[];
  /** AI provider for fingerprint verification + deep analysis */
  aiProvider?: AIProvider;
}

const DEFAULT_TIMEOUT_MS = 6000;

const DEFAULT_WEAK_TOKENS = [
  'test', 'password', 'admin', 'token', 'secret',
  'openclaw', '12345', 'webhook', 'hook',
  'insecure-test-token-12345',
];

// ── HTTP helpers ──────────────────────────────────────────────────────────

async function httpProbe(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const response = await fetch(url, { ...init, signal: controller.signal });
    clearTimeout(timer);
    return response;
  } catch {
    return null;
  }
}

interface TextResponse {
  status: number;
  body: string;
  headers: Response['headers'];
}

async function httpProbeText(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<TextResponse | null> {
  const res = await httpProbe(url, init, timeoutMs);
  if (!res) return null;
  try {
    const body = await res.text();
    return { status: res.status, body, headers: res.headers };
  } catch {
    return { status: res.status, body: '', headers: res.headers };
  }
}

// ── Phase 1: Fingerprint ─────────────────────────────────────────────────
// Makes 3 targeted requests and scores OpenClaw-specific signals.
// No per-probe body validation needed after this.

async function fingerprintTarget(
  base: string,
  timeoutMs: number,
): Promise<{ fp: FingerprintResult; rootRes: TextResponse | null; healthRes: TextResponse | null }> {
  const signals: string[] = [];
  let version: string | undefined;
  let score = 0;

  // Request 1: GET / — Control UI
  const rootRes = await httpProbeText(`${base}/`, { method: 'GET' }, timeoutMs);

  // Request 2: GET /healthz — health endpoint + headers
  const healthRes = await httpProbeText(`${base}/healthz`, { method: 'GET' }, timeoutMs);

  // Request 3: GET /__openclaw__/ — OpenClaw-specific path prefix
  const openclawRes = await httpProbeText(`${base}/__openclaw__/canvas/`, { method: 'GET' }, timeoutMs);

  // Signal: X-OpenClaw-Version header (definitive)
  const versionHeader = healthRes?.headers.get('X-OpenClaw-Version')
    ?? rootRes?.headers.get('X-OpenClaw-Version');
  if (versionHeader) {
    score += 3;
    version = versionHeader;
    signals.push(`X-OpenClaw-Version: ${versionHeader}`);
  }

  // Signal: Server header contains "openclaw" (definitive)
  const serverHeader = healthRes?.headers.get('server') ?? rootRes?.headers.get('server');
  if (serverHeader && /\bopenclaw\b/i.test(serverHeader)) {
    score += 3;
    if (!version) {
      const m = serverHeader.match(/[\d.]+/);
      if (m) version = m[0];
    }
    signals.push(`Server: ${serverHeader}`);
  }

  // Signal: HTML body contains "openclaw" branding
  if (rootRes && rootRes.status === 200 && rootRes.body.includes('<html') &&
      rootRes.body.toLowerCase().includes('openclaw')) {
    score += 2;
    signals.push('Control UI HTML contains "openclaw" branding');
  }

  // Signal: /__openclaw__/ path responds with anything other than 404.
  // This namespace is OpenClaw-specific — non-OpenClaw servers return 404.
  if (openclawRes && openclawRes.status !== 404) {
    score += 1;
    signals.push(`/__openclaw__/ path prefix responds (${openclawRes.status})`);
    if (openclawRes.body.toLowerCase().includes('openclaw')) {
      score += 1;
      signals.push('/__openclaw__/ response contains OpenClaw branding');
    }
  }

  // Signal: /healthz returns OpenClaw-shaped JSON {"ok":true,"status":"live"}
  if (healthRes && healthRes.status === 200 &&
      /\{\s*"ok"\s*:\s*true/.test(healthRes.body) && /"status"\s*:/.test(healthRes.body)) {
    score += 1;
    signals.push('/healthz returns OpenClaw health JSON');
  }

  const confidence: FingerprintResult['confidence'] =
    score >= 3 ? 'confirmed' : score >= 1 ? 'likely' : 'unknown';

  return {
    fp: { confidence, signals, version },
    rootRes,
    healthRes,
  };
}

// ── Phase 2: AI Verification ─────────────────────────────────────────────

const AI_FINGERPRINT_PROMPT = `You are a security researcher identifying whether an HTTP target is an OpenClaw gateway.

OpenClaw is a self-hosted AI assistant framework (https://openclaw.ai/) that exposes:
- GET /healthz, /readyz — health/readiness probes
- GET / — Control UI (SPA with "openclaw" branding)
- POST /hooks/wake, /hooks/agent — webhook endpoints
- POST /v1/chat/completions — OpenAI-compatible API
- GET /__openclaw__/canvas/ — internal canvas editor
- WebSocket RPC with Ed25519 challenge-response auth
- Headers: X-OpenClaw-Version, Server: openclaw-gateway/*

Known CVEs: CVE-2026-25253 (gatewayUrl WebSocket hijack), CVE-2026-28363 (safeBins bypass)

Analyze the HTTP responses and respond ONLY with JSON (no markdown fences):
{
  "isOpenClaw": boolean,
  "confidence": "high" | "medium" | "low",
  "version": string | null,
  "reasoning": string,
  "securityIssues": [
    { "title": string, "severity": "critical" | "high" | "medium" | "low", "detail": string }
  ]
}`;

async function aiVerifyAndAnalyze(
  base: string,
  fp: FingerprintResult,
  responses: Map<string, TextResponse>,
  provider: AIProvider,
): Promise<{ isOpenClaw: boolean; confidence: string; insights: AISecurityInsight[] }> {
  // Build context from collected responses
  let context = `Target: ${base}\nFingerprint signals: ${fp.signals.join(', ') || 'none'}\n\n`;
  for (const [path, res] of responses) {
    context += `--- ${path} ---\n`;
    context += `Status: ${res.status}\n`;
    // Collect relevant headers
    const headerNames = ['server', 'x-openclaw-version', 'x-powered-by',
      'content-security-policy', 'content-type', 'access-control-allow-origin'];
    for (const h of headerNames) {
      const v = res.headers.get(h);
      if (v) context += `${h}: ${v}\n`;
    }
    // Truncate body to avoid token waste
    const bodyPreview = res.body.slice(0, 2000);
    context += `Body (${res.body.length} bytes):\n${bodyPreview}\n\n`;
  }

  try {
    const raw = await provider.analyze(AI_FINGERPRINT_PROMPT, context);
    // Strip markdown fences if present
    const cleaned = raw.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim();
    const result = JSON.parse(cleaned);
    return {
      isOpenClaw: result.isOpenClaw === true,
      confidence: result.confidence ?? 'low',
      insights: (result.securityIssues ?? []).map((i: Record<string, string>) => ({
        title: i.title,
        severity: i.severity as HardeningSeverity,
        detail: i.detail,
      })),
    };
  } catch {
    return { isOpenClaw: false, confidence: 'low', insights: [] };
  }
}

// ── Phase 3: Hardening Checks ────────────────────────────────────────────
// All checks are simplified — fingerprint already confirmed it's OpenClaw,
// so we only check status codes and header values, not response bodies.

export async function probeOpenClawInstance(
  targetUrl: string,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  options?: ProbeOptions,
): Promise<OpenClawHardeningResult> {
  const base = targetUrl.replace(/\/$/, '');
  const checks: HardeningCheck[] = [];

  // ── Phase 1: Fingerprint ────────────────────────────────────────────────
  const { fp, rootRes, healthRes } = await fingerprintTarget(base, timeoutMs);

  // ── Phase 2: AI verification + analysis (optional) ──────────────────────
  const collectedResponses = new Map<string, TextResponse>();
  if (rootRes) collectedResponses.set('GET /', rootRes);
  if (healthRes) collectedResponses.set('GET /healthz', healthRes);

  let aiInsights: AISecurityInsight[] = [];
  let aiMeta: OpenClawHardeningResult['aiAnalysis'];

  if (options?.aiProvider) {
    // Collect more responses for AI to analyze
    const readyzRes = await httpProbeText(`${base}/readyz`, { method: 'GET' }, timeoutMs);
    if (readyzRes) collectedResponses.set('GET /readyz', readyzRes);

    const gatewayUrlRes = await httpProbeText(
      `${base}/?gatewayUrl=ws://g0-probe.invalid:18789`,
      { method: 'GET' },
      timeoutMs,
    );
    if (gatewayUrlRes) collectedResponses.set('GET /?gatewayUrl=...', gatewayUrlRes);

    const aiResult = await aiVerifyAndAnalyze(base, fp, collectedResponses, options.aiProvider);
    aiInsights = aiResult.insights;
    aiMeta = {
      provider: options.aiProvider.name,
      model: options.aiProvider.model,
      insights: aiInsights,
    };

    // AI can upgrade unknown → likely
    if (fp.confidence === 'unknown' && aiResult.isOpenClaw) {
      fp.confidence = 'likely';
      fp.signals.push(`AI verification (${aiResult.confidence} confidence): confirmed as OpenClaw`);
    }
  }

  // ── Gate: skip hardening if target is not identified as OpenClaw ────────
  if (fp.confidence === 'unknown') {
    const skipCheck = (id: string, name: string, severity: HardeningSeverity): HardeningCheck => ({
      id, name, severity, status: 'skip',
      detail: 'Target not identified as OpenClaw — skipped',
    });
    checks.push(
      skipCheck('OC-H-001', 'Gateway health endpoint exposed', 'high'),
      skipCheck('OC-H-002', 'Readiness endpoint leaks channel state', 'high'),
      skipCheck('OC-H-003', 'Control UI accessible without device pairing', 'critical'),
      skipCheck('OC-H-004', 'Webhook /hooks/wake accepts unauthenticated requests', 'critical'),
      skipCheck('OC-H-005', 'Webhook /hooks/agent accepts unauthenticated requests', 'critical'),
      skipCheck('OC-H-006', 'OpenAI-compatible API exposed without bearer token', 'critical'),
      skipCheck('OC-H-007', 'CVE-2026-25253 gatewayUrl hijack', 'critical'),
      skipCheck('OC-H-008', 'CORS wildcard on gateway', 'high'),
      skipCheck('OC-H-009', 'TLS enforcement absent', 'high'),
      skipCheck('OC-H-010', 'Rate limiting absent', 'medium'),
      skipCheck('OC-H-011', 'Version/server header disclosure', 'low'),
      skipCheck('OC-H-012', 'WebSocket upgrade without auth challenge', 'critical'),
      skipCheck('OC-H-013', 'Weak webhook token', 'critical'),
      skipCheck('OC-H-014', 'CSP allows unrestricted WebSocket origins', 'high'),
      skipCheck('OC-H-015', 'SPA catch-all masks 404 responses', 'medium'),
      skipCheck('OC-H-016', 'Canvas endpoint publicly accessible', 'medium'),
      skipCheck('OC-H-017', 'Product fingerprinting via favicon', 'low'),
      skipCheck('OC-H-018', 'Config file permissions', 'high'),
    );

    return {
      targetUrl, fingerprint: fp, checks, aiAnalysis: aiMeta,
      summary: { total: 18, passed: 0, failed: 0, errors: 0, overallStatus: 'secure' },
    };
  }

  // ── Phase 3: Hardening checks (fingerprint confirmed) ──────────────────
  // Body validation is no longer needed — fingerprint already proved this is OpenClaw.
  // Checks now use simple status code + header logic.

  // OC-H-001: Health endpoint exposed
  // Guard against SPA catch-all: real /healthz returns application/json, not HTML.
  // If response is identical to root HTML or has text/html content-type, it's a catch-all.
  {
    const status = healthRes?.status;
    const ct = healthRes?.headers.get('content-type') ?? '';
    const isJson = ct.includes('application/json');
    const isSpaFallback = status === 200 && (
      ct.includes('text/html') ||
      (rootRes && healthRes?.body === rootRes.body)
    );
    const isRealEndpoint = status === 200 && isJson;
    checks.push({
      id: 'OC-H-001',
      name: 'Gateway health endpoint exposed',
      severity: 'high',
      status: isRealEndpoint ? 'fail' : (isSpaFallback ? 'pass' : (healthRes ? 'pass' : 'error')),
      detail: isRealEndpoint
        ? `GET /healthz returned 200 application/json — health status exposed`
        : isSpaFallback
          ? `GET /healthz returned SPA catch-all HTML (not a real health endpoint)`
          : (healthRes ? `GET /healthz returned ${status}` : 'Probe failed or timed out'),
    });
  }

  // OC-H-002: Readiness endpoint leaks channel state
  // Same SPA catch-all guard: real /readyz returns application/json.
  {
    const res = await httpProbeText(`${base}/readyz`, { method: 'GET' }, timeoutMs);
    const ct = res?.headers.get('content-type') ?? '';
    const isJson = ct.includes('application/json');
    const isSpaFallback = res?.status === 200 && (
      ct.includes('text/html') ||
      (rootRes && res?.body === rootRes.body)
    );
    const isRealEndpoint = res?.status === 200 && isJson;
    checks.push({
      id: 'OC-H-002',
      name: 'Readiness endpoint leaks channel state',
      severity: 'high',
      status: isRealEndpoint ? 'fail' : (isSpaFallback ? 'pass' : (res ? 'pass' : 'error')),
      detail: isRealEndpoint
        ? `GET /readyz returned 200 application/json — readiness/channel state exposed`
        : isSpaFallback
          ? `GET /readyz returned SPA catch-all HTML (not a real readiness endpoint)`
          : (res ? `GET /readyz returned ${res.status}` : 'Probe failed or timed out'),
    });
  }

  // OC-H-003: Control UI accessible without device pairing
  {
    const hasUI = rootRes?.status === 200 && rootRes.body.includes('<html');
    checks.push({
      id: 'OC-H-003',
      name: 'Control UI accessible without device pairing',
      severity: 'critical',
      status: hasUI ? 'fail' : (rootRes ? 'pass' : 'error'),
      detail: hasUI
        ? `GET / returned HTML dashboard (${rootRes.body.length} bytes) — Control UI accessible without device pairing`
        : (rootRes ? `GET / returned ${rootRes.status}` : 'Probe failed or timed out'),
    });
  }

  // OC-H-004: Webhook /hooks/wake accepts unauthenticated requests
  {
    const res = await httpProbe(
      `${base}/hooks/wake`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: 'g0-security-probe', mode: 'test' }),
      },
      timeoutMs,
    );
    const isFail = res?.status === 200 || res?.status === 202;
    checks.push({
      id: 'OC-H-004',
      name: 'Webhook /hooks/wake accepts unauthenticated requests',
      severity: 'critical',
      status: isFail ? 'fail' : (res ? 'pass' : 'error'),
      detail: isFail
        ? `POST /hooks/wake returned ${res?.status} without auth — can trigger agent actions remotely`
        : (res ? `POST /hooks/wake returned ${res?.status} (rejected)` : 'Probe failed or timed out'),
    });
  }

  // OC-H-005: Agent webhook accepts unauthenticated requests
  {
    const res = await httpProbe(
      `${base}/hooks/agent`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: 'g0-security-probe: echo test', mode: 'test' }),
      },
      timeoutMs,
    );
    const isFail = res?.status === 200 || res?.status === 202;
    checks.push({
      id: 'OC-H-005',
      name: 'Webhook /hooks/agent accepts unauthenticated requests',
      severity: 'critical',
      status: isFail ? 'fail' : (res ? 'pass' : 'error'),
      detail: isFail
        ? `POST /hooks/agent returned ${res?.status} without auth — full agent turns can be triggered remotely (RCE risk)`
        : (res ? `POST /hooks/agent returned ${res?.status} (rejected)` : 'Probe failed or timed out'),
    });
  }

  // OC-H-006: OpenAI-compatible API exposed without bearer token
  // 200 = exploitable, 500/502/503 = enabled but broken, 401/403/404 = pass
  {
    const res = await httpProbe(
      `${base}/v1/chat/completions`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'default',
          messages: [{ role: 'user', content: 'g0 security probe — respond with OK' }],
        }),
      },
      timeoutMs,
    );
    const isExploitable = res?.status === 200;
    const isEnabled = res && (res.status === 500 || res.status === 502 || res.status === 503);
    checks.push({
      id: 'OC-H-006',
      name: 'OpenAI-compatible API exposed without bearer token',
      severity: 'critical',
      status: (isExploitable || isEnabled) ? 'fail' : (res ? 'pass' : 'error'),
      detail: isExploitable
        ? `POST /v1/chat/completions returned 200 without Bearer token — agent can be hijacked`
        : isEnabled
          ? `POST /v1/chat/completions returned ${res?.status} — endpoint enabled but misconfigured`
          : (res ? `POST /v1/chat/completions returned ${res?.status} (rejected or disabled)` : 'Probe failed or timed out'),
    });
  }

  // OC-H-007: CVE-2026-25253 gatewayUrl hijack
  {
    const res = await httpProbeText(
      `${base}/?gatewayUrl=ws://g0-probe.invalid:18789`,
      { method: 'GET' },
      timeoutMs,
    );
    const reflected = res?.status === 200 && res.body.includes('g0-probe.invalid');
    checks.push({
      id: 'OC-H-007',
      name: 'CVE-2026-25253 gatewayUrl hijack',
      severity: 'critical',
      status: reflected ? 'fail' : (res ? 'pass' : 'error'),
      detail: reflected
        ? `Control UI reflects attacker-supplied gatewayUrl — WebSocket hijack possible (CVE-2026-25253)`
        : (res ? `gatewayUrl parameter not reflected in response` : 'Probe failed or timed out'),
    });
  }

  // OC-H-008: CORS wildcard
  {
    const evilOrigin = 'https://evil.example.com';
    const res = await httpProbe(
      `${base}/healthz`,
      { method: 'OPTIONS', headers: { 'Origin': evilOrigin } },
      timeoutMs,
    );
    const corsHeader = res?.headers.get('Access-Control-Allow-Origin');
    const isFail = corsHeader === '*' || corsHeader === evilOrigin;
    checks.push({
      id: 'OC-H-008',
      name: 'CORS wildcard on gateway',
      severity: 'high',
      status: res ? (isFail ? 'fail' : 'pass') : 'error',
      detail: corsHeader === '*'
        ? `Access-Control-Allow-Origin: * — wildcard CORS`
        : corsHeader === evilOrigin
          ? `Access-Control-Allow-Origin reflects attacker origin`
          : (res ? `CORS: ${corsHeader ?? 'not set'} (restricted)` : 'Probe failed or timed out'),
    });
  }

  // OC-H-009: TLS enforcement
  {
    const httpUrl = base.replace(/^https:/, 'http:');
    const res = await httpProbe(`${httpUrl}/healthz`, { method: 'GET', redirect: 'manual' }, timeoutMs);
    const isHttpRedirect = res?.status === 301 || res?.status === 302 || res?.status === 307 || res?.status === 308;
    const redirectsToHttps = isHttpRedirect && (res?.headers.get('location') ?? '').startsWith('https://');
    const isHttpsAlready = base.startsWith('https://');
    let status: HardeningCheckStatus;
    let detail: string;
    if (isHttpsAlready && base === httpUrl) {
      status = 'skip'; detail = 'Target is already HTTPS — TLS check skipped';
    } else if (redirectsToHttps) {
      status = 'pass'; detail = `HTTP redirects to HTTPS (${res?.status})`;
    } else if (res?.status === 200) {
      status = 'fail'; detail = 'HTTP 200 without TLS redirect — unencrypted';
    } else {
      status = 'error'; detail = res ? `HTTP probe returned ${res.status}` : 'Probe failed or timed out';
    }
    checks.push({ id: 'OC-H-009', name: 'TLS enforcement absent', severity: 'high', status, detail });
  }

  // OC-H-010: Rate limiting
  {
    const REQUESTS = 20;
    let lastStatus = 0;
    let gotRateLimited = false;
    for (let i = 0; i < REQUESTS; i++) {
      const res = await httpProbe(`${base}/healthz`, { method: 'GET' }, timeoutMs);
      if (res) lastStatus = res.status;
      if (res?.status === 429) { gotRateLimited = true; break; }
    }
    checks.push({
      id: 'OC-H-010',
      name: 'Rate limiting absent',
      severity: 'medium',
      status: gotRateLimited ? 'pass' : (lastStatus > 0 ? 'fail' : 'error'),
      detail: gotRateLimited
        ? 'Rate limiting active (429 received)'
        : (lastStatus > 0 ? `${REQUESTS} requests without 429 — no rate limiting` : 'Probe failed'),
    });
  }

  // OC-H-011: Version header disclosure (already extracted in fingerprint)
  {
    const discloses = fp.version != null || fp.signals.some(s => s.startsWith('Server:'));
    checks.push({
      id: 'OC-H-011',
      name: 'Version/server header disclosure',
      severity: 'low',
      status: discloses ? 'fail' : 'pass',
      detail: discloses
        ? `${fp.signals.filter(s => s.includes('Version') || s.startsWith('Server:')).join('; ')} — version info aids targeted exploitation`
        : 'No version information in response headers',
    });
  }

  // OC-H-012: WebSocket upgrade without auth
  {
    const wsUrl = base.replace(/^http/, 'ws');
    let status: HardeningCheckStatus = 'skip';
    let detail = 'WebSocket upgrade probe requires ws library (Node.js fetch does not support HTTP Upgrade)';
    try {
      const res = await httpProbe(
        `${base}/`,
        {
          method: 'GET',
          headers: {
            'Upgrade': 'websocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
            'Sec-WebSocket-Version': '13',
          },
        },
        timeoutMs,
      );
      if (res?.status === 101) {
        status = 'fail';
        detail = `WebSocket upgrade accepted (101) at ${wsUrl} — no Ed25519 auth`;
      } else if (res?.status === 401 || res?.status === 403) {
        status = 'pass';
        detail = `WebSocket upgrade rejected (${res.status}) — auth required`;
      } else if (res) {
        status = 'pass';
        detail = `WebSocket upgrade returned ${res.status} (not 101)`;
      }
    } catch {
      detail = 'WebSocket probe failed or timed out';
    }
    checks.push({ id: 'OC-H-012', name: 'WebSocket upgrade without auth challenge', severity: 'critical', status, detail });
  }

  // OC-H-013: Weak webhook token brute-force
  {
    const tokens = options?.weakTokens ?? DEFAULT_WEAK_TOKENS;
    const noAuth = await httpProbe(
      `${base}/hooks/wake`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: 'g0-probe-auth-check' }),
      },
      timeoutMs,
    );
    const noAuthAccepted = noAuth && (noAuth.status === 200 || noAuth.status === 202);
    const requiresAuth = noAuth && (noAuth.status === 401 || noAuth.status === 403);

    if (!noAuth) {
      checks.push({ id: 'OC-H-013', name: 'Weak webhook token', severity: 'critical', status: 'error', detail: 'Probe failed or timed out' });
    } else if (noAuthAccepted) {
      checks.push({ id: 'OC-H-013', name: 'Weak webhook token', severity: 'critical', status: 'skip', detail: 'Webhooks do not require auth — skipped (see OC-H-004)' });
    } else if (noAuth.status === 404) {
      checks.push({ id: 'OC-H-013', name: 'Weak webhook token', severity: 'critical', status: 'skip', detail: 'Webhook endpoint not found (404) — skipped' });
    } else if (!requiresAuth) {
      checks.push({ id: 'OC-H-013', name: 'Weak webhook token', severity: 'critical', status: 'error', detail: `Webhook returned ${noAuth.status} — cannot determine auth requirement` });
    } else {
      let guessed: string | null = null;
      for (const token of tokens) {
        const res = await httpProbe(
          `${base}/hooks/wake`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ text: 'g0-probe-brute' }),
          },
          timeoutMs,
        );
        if (res?.status === 200) { guessed = token; break; }
      }
      checks.push({
        id: 'OC-H-013',
        name: 'Weak webhook token',
        severity: 'critical',
        status: guessed ? 'fail' : 'pass',
        detail: guessed
          ? `Webhook token guessed: "${guessed}" — trivially brute-forceable`
          : `Token not in common wordlist (${tokens.length} tested)`,
      });
    }
  }

  // OC-H-014: CSP allows ws:/wss:
  // Reuse rootRes from fingerprint.
  // Severity levels:
  //   - No CSP at all → critical (fail)
  //   - CSP exists but connect-src allows ws:/wss: scheme-wide → medium (fail)
  //   - CSP exists with restricted connect-src → pass
  {
    const csp = rootRes?.headers.get('content-security-policy') ?? '';
    let status: HardeningCheckStatus;
    let detail: string;
    if (!rootRes || rootRes.status !== 200) {
      status = 'pass'; detail = `Control UI not served (${rootRes?.status ?? 'unreachable'}) — CSP not applicable`;
    } else if (!csp) {
      status = 'fail'; detail = 'No Content-Security-Policy header — no connect-src restrictions';
    } else if (/connect-src[^;]*\bws:/.test(csp) || /connect-src[^;]*\bwss:/.test(csp)) {
      status = 'fail'; detail = `CSP present but connect-src allows ws:/wss: scheme-wide — WebSocket connections to any origin permitted. CSP: ${csp.slice(0, 150)}`;
    } else {
      status = 'pass'; detail = `CSP present with restricted connect-src: ${csp.slice(0, 120)}`;
    }
    // Downgrade severity when CSP exists but has loose WebSocket policy vs missing entirely
    const severity: HardeningSeverity = !csp && rootRes?.status === 200 ? 'high' : 'medium';
    checks.push({ id: 'OC-H-014', name: 'CSP allows unrestricted WebSocket origins', severity, status, detail });
  }

  // OC-H-015: SPA catch-all masks 404s
  {
    const sentinels = ['/.env', '/.git/config', '/admin'];
    let matchCount = 0;
    let probesFailed = 0;
    for (const path of sentinels) {
      const res = await httpProbeText(`${base}${path}`, { method: 'GET' }, timeoutMs);
      if (!res) { probesFailed++; continue; }
      if (res.status === 200 && res.body.includes('<html')) matchCount++;
    }
    const allMatch = matchCount === sentinels.length;
    checks.push({
      id: 'OC-H-015',
      name: 'SPA catch-all masks 404 responses',
      severity: 'medium',
      status: probesFailed === sentinels.length ? 'error' : allMatch ? 'fail' : 'pass',
      detail: allMatch
        ? `All ${sentinels.length} sentinel paths return 200 HTML — SPA catch-all masks 404s`
        : (probesFailed === sentinels.length ? 'All probes failed' : `${matchCount}/${sentinels.length} paths return HTML`),
    });
  }

  // OC-H-016: Canvas endpoint exposure
  // Reuse the /__openclaw__/canvas/ response from fingerprint if available
  {
    const res = await httpProbeText(`${base}/__openclaw__/canvas/`, { method: 'GET' }, timeoutMs);
    const exposed = res?.status === 200 && res.body.toLowerCase().includes('canvas');
    checks.push({
      id: 'OC-H-016',
      name: 'Canvas endpoint publicly accessible',
      severity: 'medium',
      status: exposed ? 'fail' : (res ? 'pass' : 'error'),
      detail: exposed
        ? `GET /__openclaw__/canvas/ returned 200 (${res.body.length} bytes) — canvas endpoint exposed`
        : (res ? `GET /__openclaw__/canvas/ returned ${res.status}` : 'Probe failed or timed out'),
    });
  }

  // OC-H-017: Product fingerprinting via favicon
  {
    const res = await httpProbe(`${base}/favicon.svg`, { method: 'GET' }, timeoutMs);
    const ct = res?.headers.get('content-type') ?? '';
    const isImage = ct.startsWith('image/');
    const svgFound = res?.status === 200 && isImage;
    const resFallback = res?.status === 404
      ? await httpProbe(`${base}/favicon.ico`, { method: 'GET' }, timeoutMs)
      : null;
    const fallbackCt = resFallback?.headers.get('content-type') ?? '';
    const icoFound = resFallback?.status === 200 && fallbackCt.startsWith('image/');
    const found = svgFound || icoFound;
    checks.push({
      id: 'OC-H-017',
      name: 'Product fingerprinting via favicon',
      severity: 'low',
      status: found ? 'fail' : (res ? 'pass' : 'error'),
      detail: found
        ? `Favicon served (${svgFound ? ct : fallbackCt}) — enables fingerprinting`
        : (res ? 'No favicon with image content-type found' : 'Probe failed or timed out'),
    });
  }

  // OC-H-018: Config file permissions
  {
    const configPath = options?.configPath;
    if (!configPath) {
      checks.push({ id: 'OC-H-018', name: 'Config file permissions', severity: 'high', status: 'skip', detail: 'No configPath provided — skipped' });
    } else {
      try {
        const stat = statSync(configPath);
        const mode = (stat.mode & 0o777).toString(8);
        const isSecure = mode === '600' || mode === '400';
        checks.push({
          id: 'OC-H-018', name: 'Config file permissions', severity: 'high',
          status: isSecure ? 'pass' : 'fail',
          detail: isSecure ? `Permissions: ${mode} (secure)` : `Permissions: ${mode} — should be 600`,
        });
      } catch {
        checks.push({ id: 'OC-H-018', name: 'Config file permissions', severity: 'high', status: 'error', detail: `Could not stat: ${configPath}` });
      }
    }
  }

  // ── Summary ─────────────────────────────────────────────────────────────
  const failed = checks.filter(c => c.status === 'fail');
  const passed = checks.filter(c => c.status === 'pass');
  const errors = checks.filter(c => c.status === 'error');
  const hasCriticalFail = failed.some(c => c.severity === 'critical');
  const hasHighFail = failed.some(c => c.severity === 'high');

  return {
    targetUrl,
    fingerprint: fp,
    checks,
    aiAnalysis: aiMeta,
    summary: {
      total: checks.length,
      passed: passed.length,
      failed: failed.length,
      errors: errors.length,
      overallStatus: hasCriticalFail ? 'critical' : hasHighFail ? 'warn' : 'secure',
    },
  };
}
