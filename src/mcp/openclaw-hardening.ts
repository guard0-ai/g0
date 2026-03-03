export type HardeningCheckStatus = 'pass' | 'fail' | 'error' | 'skip';
export type HardeningSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface HardeningCheck {
  id: string;
  name: string;
  severity: HardeningSeverity;
  status: HardeningCheckStatus;
  detail: string;
}

export interface OpenClawHardeningResult {
  targetUrl: string;
  checks: HardeningCheck[];
  summary: {
    total: number;
    passed: number;
    failed: number;
    errors: number;
    overallStatus: 'secure' | 'warn' | 'critical';
  };
}

const DEFAULT_TIMEOUT_MS = 6000;

async function probe(
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

export async function probeOpenClawInstance(
  targetUrl: string,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<OpenClawHardeningResult> {
  const base = targetUrl.replace(/\/$/, '');
  const checks: HardeningCheck[] = [];

  // OC-H-001: Unauthenticated skill listing
  {
    const res = await probe(`${base}/api/skills`, { method: 'GET' }, timeoutMs);
    checks.push({
      id: 'OC-H-001',
      name: 'Unauthenticated skill listing',
      severity: 'critical',
      status: res?.status === 200 ? 'fail' : (res ? 'pass' : 'error'),
      detail: res?.status === 200
        ? `GET /api/skills returned ${res.status} without authentication — skill inventory exposed`
        : (res ? `GET /api/skills returned ${res.status} (expected 401/403)` : 'Probe failed or timed out'),
    });
  }

  // OC-H-002: Admin API exposed
  {
    const res = await probe(`${base}/api/admin/config`, { method: 'GET' }, timeoutMs);
    checks.push({
      id: 'OC-H-002',
      name: 'Admin API exposed',
      severity: 'critical',
      status: res?.status === 200 ? 'fail' : (res ? 'pass' : 'error'),
      detail: res?.status === 200
        ? `GET /api/admin/config returned 200 without authentication — admin config exposed`
        : (res ? `GET /api/admin/config returned ${res.status}` : 'Probe failed or timed out'),
    });
  }

  // OC-H-003: SOUL.md readable via API
  {
    const res = await probe(`${base}/api/soul`, { method: 'GET' }, timeoutMs);
    checks.push({
      id: 'OC-H-003',
      name: 'SOUL.md readable via API',
      severity: 'critical',
      status: res?.status === 200 ? 'fail' : (res ? 'pass' : 'error'),
      detail: res?.status === 200
        ? `GET /api/soul returned 200 — agent identity/persona file is publicly readable`
        : (res ? `GET /api/soul returned ${res.status}` : 'Probe failed or timed out'),
    });
  }

  // OC-H-004: MEMORY.md readable via API
  {
    const res = await probe(`${base}/api/memory`, { method: 'GET' }, timeoutMs);
    checks.push({
      id: 'OC-H-004',
      name: 'MEMORY.md readable via API',
      severity: 'critical',
      status: res?.status === 200 ? 'fail' : (res ? 'pass' : 'error'),
      detail: res?.status === 200
        ? `GET /api/memory returned 200 — agent memory file is publicly readable`
        : (res ? `GET /api/memory returned ${res.status}` : 'Probe failed or timed out'),
    });
  }

  // OC-H-005: CVE-2026-25253 RCE probe
  {
    const res = await probe(
      `${base}/api/skills/install`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: 'clawhub://install?skill=probe&exec=true&source=https://g0-probe.invalid/' }),
      },
      timeoutMs,
    );
    const isFail = res?.status === 200 || res?.status === 201;
    checks.push({
      id: 'OC-H-005',
      name: 'CVE-2026-25253 RCE probe (skill install endpoint)',
      severity: 'critical',
      status: isFail ? 'fail' : (res ? 'pass' : 'error'),
      detail: isFail
        ? `POST /api/skills/install accepted crafted URI (${res?.status}) — possible RCE vector (CVE-2026-25253)`
        : (res ? `POST /api/skills/install returned ${res?.status} (rejected)` : 'Probe failed or timed out'),
    });
  }

  // OC-H-006: CVE-2026-28363 safeBins probe
  {
    const res = await probe(
      `${base}/api/exec`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: '/tmp/g0_probe_binary', args: ['--version'] }),
      },
      timeoutMs,
    );
    const isFail = res?.status === 200 || res?.status === 201;
    checks.push({
      id: 'OC-H-006',
      name: 'CVE-2026-28363 safeBins bypass probe (exec endpoint)',
      severity: 'critical',
      status: isFail ? 'fail' : (res ? 'pass' : 'error'),
      detail: isFail
        ? `POST /api/exec accepted non-allowlisted binary (${res?.status}) — safeBins bypass (CVE-2026-28363)`
        : (res ? `POST /api/exec returned ${res?.status} (binary rejected)` : 'Probe failed or timed out'),
    });
  }

  // OC-H-007: Debug endpoint exposed
  {
    const res = await probe(`${base}/api/debug`, { method: 'GET' }, timeoutMs);
    checks.push({
      id: 'OC-H-007',
      name: 'Debug endpoint exposed',
      severity: 'high',
      status: res?.status === 200 ? 'fail' : (res ? 'pass' : 'error'),
      detail: res?.status === 200
        ? 'GET /api/debug returned 200 — debug endpoint is publicly accessible'
        : (res ? `GET /api/debug returned ${res?.status}` : 'Probe failed or timed out'),
    });
  }

  // OC-H-008: CORS wildcard on API
  {
    const res = await probe(
      `${base}/api/skills`,
      { method: 'OPTIONS', headers: { 'Origin': 'https://evil.example.com' } },
      timeoutMs,
    );
    const corsHeader = res?.headers.get('Access-Control-Allow-Origin');
    const isFail = corsHeader === '*';
    checks.push({
      id: 'OC-H-008',
      name: 'CORS wildcard on API',
      severity: 'high',
      status: res ? (isFail ? 'fail' : 'pass') : 'error',
      detail: isFail
        ? `Access-Control-Allow-Origin: * — wildcard CORS allows cross-origin requests from any domain`
        : (res ? `CORS header: ${corsHeader ?? 'not set'} (restricted)` : 'Probe failed or timed out'),
    });
  }

  // OC-H-009: TLS enforcement absent
  {
    const httpUrl = base.replace(/^https:/, 'http:');
    const res = await probe(`${httpUrl}/api/skills`, { method: 'GET', redirect: 'manual' }, timeoutMs);
    const isHttpRedirect = res?.status === 301 || res?.status === 302 || res?.status === 307 || res?.status === 308;
    const redirectsToHttps = isHttpRedirect && (res?.headers.get('location') ?? '').startsWith('https://');
    const isHttpsAlready = base.startsWith('https://');
    let status: HardeningCheckStatus;
    let detail: string;
    if (isHttpsAlready && base === httpUrl) {
      status = 'skip';
      detail = 'Target is already HTTPS — TLS enforcement check skipped';
    } else if (redirectsToHttps) {
      status = 'pass';
      detail = `HTTP redirects to HTTPS (${res?.status})`;
    } else if (res?.status === 200) {
      status = 'fail';
      detail = 'HTTP endpoint returns 200 without TLS redirect — communications may be unencrypted';
    } else {
      status = 'error';
      detail = res ? `HTTP probe returned ${res.status}` : 'Probe failed or timed out';
    }
    checks.push({ id: 'OC-H-009', name: 'TLS enforcement absent', severity: 'high', status, detail });
  }

  // OC-H-010: Rate limiting absent
  {
    const REQUESTS = 20;
    let lastStatus = 0;
    let gotRateLimited = false;
    for (let i = 0; i < REQUESTS; i++) {
      const res = await probe(`${base}/api/skills`, { method: 'GET' }, timeoutMs);
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
        : (lastStatus > 0 ? `${REQUESTS} requests completed without 429 — no rate limiting detected` : 'Probe failed'),
    });
  }

  // OC-H-011: Version header disclosure
  {
    const res = await probe(`${base}/api/skills`, { method: 'GET' }, timeoutMs);
    const versionHeader = res?.headers.get('X-OpenClaw-Version');
    checks.push({
      id: 'OC-H-011',
      name: 'Version header disclosure',
      severity: 'low',
      status: res ? (versionHeader ? 'fail' : 'pass') : 'error',
      detail: versionHeader
        ? `X-OpenClaw-Version: ${versionHeader} — version information disclosed in response headers`
        : (res ? 'X-OpenClaw-Version header not present' : 'Probe failed or timed out'),
    });
  }

  // OC-H-012: Default credentials accepted
  {
    const res = await probe(
      `${base}/api/auth/login`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'admin' }),
      },
      timeoutMs,
    );
    const isFail = res?.status === 200 || res?.status === 201;
    checks.push({
      id: 'OC-H-012',
      name: 'Default credentials accepted',
      severity: 'critical',
      status: isFail ? 'fail' : (res ? 'pass' : 'error'),
      detail: isFail
        ? `POST /api/auth/login with admin/admin returned ${res?.status} — default credentials accepted`
        : (res ? `POST /api/auth/login with admin/admin returned ${res?.status} (rejected)` : 'Probe failed or timed out'),
    });
  }

  const failed = checks.filter(c => c.status === 'fail');
  const passed = checks.filter(c => c.status === 'pass');
  const errors = checks.filter(c => c.status === 'error');
  const hasCriticalFail = failed.some(c => c.severity === 'critical');
  const hasHighFail = failed.some(c => c.severity === 'high');

  return {
    targetUrl,
    checks,
    summary: {
      total: checks.length,
      passed: passed.length,
      failed: failed.length,
      errors: errors.length,
      overallStatus: hasCriticalFail ? 'critical' : hasHighFail ? 'warn' : 'secure',
    },
  };
}
