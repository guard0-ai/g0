import type { WebhookEvent } from './types.js';

const DEFAULT_WEBHOOK_URL = 'http://localhost:6040/events';

export class WebhookClient {
  private url: string;
  private authToken: string | undefined;
  private quiet: boolean;
  private queue: WebhookEvent[] = [];
  private flushing = false;

  constructor(url?: string, authToken?: string, opts?: { quiet?: boolean }) {
    this.url = url ?? DEFAULT_WEBHOOK_URL;
    this.authToken = authToken;
    this.quiet = opts?.quiet ?? false;
  }

  async send(event: WebhookEvent): Promise<void> {
    this.queue.push(event);
    if (!this.flushing) {
      this.flushing = true;
      // Drain queue asynchronously without blocking the hook
      queueMicrotask(() => this.flush());
    }
  }

  private async flush(): Promise<void> {
    while (this.queue.length > 0) {
      const event = this.queue.shift()!;
      try {
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
        };
        if (this.authToken) {
          headers['Authorization'] = `Bearer ${this.authToken}`;
        }
        const resp = await fetch(this.url, {
          method: 'POST',
          headers,
          body: JSON.stringify(event),
          signal: AbortSignal.timeout(5000),
        });
        if (!resp.ok && !this.quiet) {
          console.error(`[g0-plugin] webhook ${resp.status}: ${resp.statusText}`);
        }
      } catch (err) {
        if (!this.quiet) {
          console.error(`[g0-plugin] webhook error: ${err instanceof Error ? err.message : err}`);
        }
      }
    }
    this.flushing = false;
  }
}
