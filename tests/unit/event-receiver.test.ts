import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { EventReceiver, type ReceivedEvent } from '../../src/daemon/event-receiver.js';

// Minimal mock logger
const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};

let receiver: EventReceiver;
let port: number;
const events: ReceivedEvent[] = [];

function getPort(): number {
  // Use a random high port to avoid conflicts
  return 10000 + Math.floor(Math.random() * 50000);
}

describe('EventReceiver', () => {
  beforeEach(async () => {
    events.length = 0;
    port = getPort();
    receiver = new EventReceiver({
      port,
      bind: '127.0.0.1',
      logger: mockLogger as any,
      onEvent: (event) => { events.push(event); },
    });
    await receiver.start();
  });

  afterEach(async () => {
    await receiver.stop();
  });

  it('responds to health check', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/health`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe('ok');
    expect(body.events).toBe(0);
  });

  it('receives g0-plugin events on /events', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'tool.executed',
        timestamp: '2026-01-01T00:00:00Z',
        agentId: 'agent-1',
        data: { toolName: 'bash', durationMs: 42 },
      }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.received).toBe(true);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('tool.executed');
    expect(events[0].source).toBe('g0-plugin');
    expect(events[0].agentId).toBe('agent-1');
  });

  it('receives events on / (root)', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'test', data: {} }),
    });
    expect(res.status).toBe(200);
    expect(events).toHaveLength(1);
  });

  it('receives Falco events on /falco', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/falco`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        rule: 'OpenClaw Egress Violation',
        priority: 'Warning',
        output: 'connection to 1.2.3.4:443',
        time: '2026-01-01T00:00:00Z',
        tags: ['openclaw', 'egress'],
      }),
    });
    expect(res.status).toBe(200);
    expect(events).toHaveLength(1);
    expect(events[0].source).toBe('falcosidekick');
    expect(events[0].type).toBe('OpenClaw Egress Violation');
  });

  it('returns 404 for unknown routes', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/unknown`);
    expect(res.status).toBe(404);
  });

  it('returns 400 for invalid JSON', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not json',
    });
    expect(res.status).toBe(400);
  });

  it('tracks event count and recent events', async () => {
    for (let i = 0; i < 3; i++) {
      await fetch(`http://127.0.0.1:${port}/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: `event-${i}`, data: {} }),
      });
    }

    const stats = receiver.getStats();
    expect(stats.eventCount).toBe(3);
    expect(stats.recentEvents).toHaveLength(3);
  });

  it('handles CORS preflight', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/events`, {
      method: 'OPTIONS',
    });
    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe('127.0.0.1');
  });
});

describe('EventReceiver with auth', () => {
  beforeEach(async () => {
    events.length = 0;
    port = getPort();
    receiver = new EventReceiver({
      port,
      bind: '127.0.0.1',
      authToken: 'test-secret-token',
      logger: mockLogger as any,
      onEvent: (event) => { events.push(event); },
    });
    await receiver.start();
  });

  afterEach(async () => {
    await receiver.stop();
  });

  it('rejects requests without auth token', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'test', data: {} }),
    });
    expect(res.status).toBe(401);
  });

  it('accepts requests with valid auth token', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer test-secret-token',
      },
      body: JSON.stringify({ type: 'test', data: {} }),
    });
    expect(res.status).toBe(200);
    expect(events).toHaveLength(1);
  });

  it('rejects requests with wrong auth token', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer wrong-token',
      },
      body: JSON.stringify({ type: 'test', data: {} }),
    });
    expect(res.status).toBe(401);
  });
});

describe('EventReceiver with JSONL persistence', () => {
  let tmpDir: string;
  let logFilePath: string;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-events-'));
    logFilePath = path.join(tmpDir, 'events.jsonl');
    events.length = 0;
    port = getPort();
    receiver = new EventReceiver({
      port,
      bind: '127.0.0.1',
      logFile: logFilePath,
      logger: mockLogger as any,
      onEvent: (event) => { events.push(event); },
    });
    await receiver.start();
  });

  afterEach(async () => {
    await receiver.stop();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('writes events to JSONL file', async () => {
    await fetch(`http://127.0.0.1:${port}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'test.event', data: { foo: 'bar' } }),
    });

    await fetch(`http://127.0.0.1:${port}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'test.event2', data: { baz: 1 } }),
    });

    // Small delay for write stream to flush
    await new Promise(r => setTimeout(r, 100));

    expect(fs.existsSync(logFilePath)).toBe(true);
    const lines = fs.readFileSync(logFilePath, 'utf-8').trim().split('\n');
    expect(lines).toHaveLength(2);

    const event1 = JSON.parse(lines[0]);
    expect(event1.type).toBe('test.event');
    expect(event1.source).toBe('g0-plugin');

    const event2 = JSON.parse(lines[1]);
    expect(event2.type).toBe('test.event2');
  });

  it('events survive receiver stop/restart', async () => {
    await fetch(`http://127.0.0.1:${port}/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'persist.test', data: {} }),
    });

    await new Promise(r => setTimeout(r, 100));
    await receiver.stop();

    // File should still exist with the event
    expect(fs.existsSync(logFilePath)).toBe(true);
    const lines = fs.readFileSync(logFilePath, 'utf-8').trim().split('\n');
    expect(lines).toHaveLength(1);
    const event = JSON.parse(lines[0]);
    expect(event.type).toBe('persist.test');
  });
});
