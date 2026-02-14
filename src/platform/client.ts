import { resolveToken } from './auth.js';
import {
  DEFAULT_PLATFORM_CONFIG,
  type PlatformConfig,
  type UploadPayload,
  type UploadResponse,
  type EndpointRegisterPayload,
  type EndpointRegisterResponse,
  type HeartbeatPayload,
  type HeartbeatResponse,
} from './types.js';

export class PlatformClient {
  private baseUrl: string;
  private apiVersion: string;

  constructor(config?: Partial<PlatformConfig>) {
    const resolved = { ...DEFAULT_PLATFORM_CONFIG, ...config };
    this.baseUrl = process.env.G0_PLATFORM_URL ?? resolved.baseUrl;
    this.apiVersion = resolved.apiVersion;
  }

  private get apiBase(): string {
    return `${this.baseUrl}/api/${this.apiVersion}`;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const token = resolveToken();
    if (!token) {
      throw new Error(
        'Not authenticated. Run `g0 auth login` or set G0_API_TOKEN.',
      );
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'g0-cli/1.0.0',
    };

    // Determine auth header: API keys use X-API-Key, JWTs use Authorization
    if (token.startsWith('g0_')) {
      headers['X-API-Key'] = token;
    } else {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const url = `${this.apiBase}${path}`;
    const response = await fetch(url, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30_000),
    });

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new PlatformError(response.status, text, url);
    }

    return response.json() as Promise<T>;
  }

  async upload(payload: UploadPayload): Promise<UploadResponse> {
    return this.request<UploadResponse>('POST', '/upload', payload);
  }

  async registerEndpoint(
    payload: EndpointRegisterPayload,
  ): Promise<EndpointRegisterResponse> {
    return this.request<EndpointRegisterResponse>(
      'POST',
      '/endpoints/register',
      payload,
    );
  }

  async heartbeat(payload: HeartbeatPayload): Promise<HeartbeatResponse> {
    return this.request<HeartbeatResponse>(
      'POST',
      '/endpoints/heartbeat',
      payload,
    );
  }

  async checkAuth(): Promise<{ email?: string; orgId?: string }> {
    return this.request<{ email?: string; orgId?: string }>('GET', '/auth/me');
  }
}

export class PlatformError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string,
    public readonly url: string,
  ) {
    super(`Platform API error ${status}: ${body || 'No response body'} (${url})`);
    this.name = 'PlatformError';
  }
}
