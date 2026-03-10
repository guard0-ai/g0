import * as http from 'node:http';
import * as fs from 'node:fs';
import type { DaemonLogger } from './logger.js';

// ── Event Types ──────────────────────────────────────────────────────────────

export type EventSource = 'g0-plugin' | 'falcosidekick' | 'tetragon' | 'custom';

export interface ReceivedEvent {
  source: EventSource;
  type: string;
  timestamp: string;
  agentId?: string;
  sessionId?: string;
  data: Record<string, unknown>;
}

export type EventHandler = (event: ReceivedEvent) => void | Promise<void>;

// ── Event Receiver ───────────────────────────────────────────────────────────

export interface EventReceiverOptions {
  port?: number;
  bind?: string;
  authToken?: string;
  logFile?: string;
  logger?: DaemonLogger;
  onEvent?: EventHandler;
}

export class EventReceiver {
  private server: http.Server | null = null;
  private port: number;
  private bind: string;
  private authToken: string | null;
  private logger: DaemonLogger;
  private onEvent: EventHandler;
  private eventCount = 0;
  private recentEvents: ReceivedEvent[] = [];
  private maxRecent = 100;
  private logStream: fs.WriteStream | null = null;
  private logFile: string | null;
  private readonly maxLogSize = 100 * 1024 * 1024; // 100MB

  constructor(options: EventReceiverOptions) {
    this.port = options.port ?? 6040;
    this.bind = options.bind ?? '127.0.0.1';
    this.authToken = options.authToken ?? null;
    const noop = () => {};
    this.logger = options.logger ?? { info: noop, warn: noop, error: noop } as unknown as DaemonLogger;
    this.onEvent = options.onEvent ?? (() => {});
    this.logFile = options.logFile ?? null;
    if (this.logFile) {
      this.logStream = fs.createWriteStream(this.logFile, { flags: 'a' });
      this.logStream.on('error', (err) => {
        this.logger.error(`Log stream error: ${err.message}`);
      });
    }
  }

  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => this.handleRequest(req, res));

      this.server.on('error', (err) => {
        this.logger.error(`Event receiver error: ${err.message}`);
        reject(err);
      });

      this.server.listen(this.port, this.bind, () => {
        this.logger.info(`Event receiver listening on ${this.bind}:${this.port}`);
        resolve();
      });
    });
  }

  stop(): Promise<void> {
    if (this.logStream) {
      this.logStream.end();
      this.logStream = null;
    }
    return new Promise((resolve) => {
      if (!this.server) {
        resolve();
        return;
      }
      this.server.close(() => {
        this.logger.info('Event receiver stopped');
        this.server = null;
        resolve();
      });
    });
  }

  getStats(): { eventCount: number; recentEvents: ReceivedEvent[] } {
    return { eventCount: this.eventCount, recentEvents: [...this.recentEvents] };
  }

  private handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    // CORS preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '127.0.0.1',
        'Access-Control-Allow-Methods': 'POST, GET',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      });
      res.end();
      return;
    }

    // Health check
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', events: this.eventCount }));
      return;
    }

    // Stats endpoint
    if (req.method === 'GET' && req.url === '/stats') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(this.getStats()));
      return;
    }

    // Event ingestion
    if (req.method === 'POST' && (req.url === '/events' || req.url === '/')) {
      this.handleEvent(req, res);
      return;
    }

    // Falcosidekick format
    if (req.method === 'POST' && req.url === '/falco') {
      this.handleFalcoEvent(req, res);
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  }

  private readBody(req: http.IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      const maxSize = 1_048_576; // 1MB
      const timeout = setTimeout(() => {
        req.destroy();
        reject(new Error('Request timeout'));
      }, 30_000);

      req.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > maxSize) {
          clearTimeout(timeout);
          req.destroy();
          reject(new Error('Payload too large'));
          return;
        }
        chunks.push(chunk);
      });

      req.on('end', () => {
        clearTimeout(timeout);
        resolve(Buffer.concat(chunks).toString('utf-8'));
      });
      req.on('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });
  }

  private checkAuth(req: http.IncomingMessage): boolean {
    if (!this.authToken) return true; // no auth configured
    const authHeader = req.headers.authorization;
    if (!authHeader) return false;
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
    return token === this.authToken;
  }

  private async handleEvent(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (!this.checkAuth(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    try {
      const body = await this.readBody(req);
      const parsed = JSON.parse(body);

      const event: ReceivedEvent = {
        source: parsed.source ?? 'g0-plugin',
        type: parsed.type ?? 'unknown',
        timestamp: parsed.timestamp ?? new Date().toISOString(),
        agentId: parsed.agentId,
        sessionId: parsed.sessionId,
        data: parsed.data ?? parsed,
      };

      this.recordEvent(event);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ received: true }));
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
    }
  }

  private async handleFalcoEvent(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (!this.checkAuth(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }

    try {
      const body = await this.readBody(req);
      const parsed = JSON.parse(body);

      // Falcosidekick webhook format
      const event: ReceivedEvent = {
        source: 'falcosidekick',
        type: parsed.rule ?? 'falco.alert',
        timestamp: parsed.time ?? new Date().toISOString(),
        data: {
          rule: parsed.rule,
          priority: parsed.priority,
          output: parsed.output,
          outputFields: parsed.output_fields,
          tags: parsed.tags,
          hostname: parsed.hostname,
        },
      };

      this.recordEvent(event);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ received: true }));
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
    }
  }

  private recordEvent(event: ReceivedEvent): void {
    this.eventCount++;
    this.recentEvents.push(event);
    if (this.recentEvents.length > this.maxRecent) {
      this.recentEvents.shift();
    }

    // Persist to JSONL
    if (this.logStream && this.logFile) {
      const ok = this.logStream.write(JSON.stringify(event) + '\n');
      if (!ok) {
        this.logStream.once('drain', () => { /* backpressure relieved */ });
      }
      // Check rotation
      try {
        const stat = fs.statSync(this.logFile);
        if (stat.size > this.maxLogSize) {
          this.logStream.end();
          fs.renameSync(this.logFile, this.logFile + '.1');
          this.logStream = fs.createWriteStream(this.logFile, { flags: 'a' });
        }
      } catch { /* rotation check failed — non-fatal */ }
    }

    // Log based on event type
    const level = event.type.includes('injection') || event.type.includes('blocked')
      ? 'warn' : 'info';

    if (level === 'warn') {
      this.logger.warn(`[event] ${event.source}/${event.type} agent=${event.agentId ?? 'unknown'}`);
    } else {
      this.logger.info(`[event] ${event.source}/${event.type} agent=${event.agentId ?? 'unknown'}`);
    }

    // Fire handler (don't await — non-blocking)
    try {
      const result = this.onEvent(event);
      if (result instanceof Promise) {
        result.catch(err => {
          this.logger.error(`Event handler error: ${err instanceof Error ? err.message : err}`);
        });
      }
    } catch (err) {
      this.logger.error(`Event handler error: ${err instanceof Error ? (err as Error).message : err}`);
    }
  }
}
