import type { TestProvider, TestTarget, ConversationMessage } from '../../types/test.js';
import { randomUUID } from 'node:crypto';

export function createA2AProvider(target: TestTarget): TestProvider {
  let taskId = randomUUID();

  async function sendJsonRpc(method: string, params: Record<string, unknown>): Promise<unknown> {
    const body = {
      jsonrpc: '2.0',
      id: randomUUID(),
      method,
      params,
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), target.timeout ?? 30_000);

    try {
      const response = await fetch(target.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...target.headers,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`A2A HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json() as {
        result?: { status?: string; artifacts?: Array<{ parts?: Array<{ type: string; text?: string }> }> };
        error?: { message: string; code: number };
      };

      if (data.error) {
        throw new Error(`A2A RPC error ${data.error.code}: ${data.error.message}`);
      }

      return data.result;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  function extractText(result: unknown): string {
    const r = result as {
      status?: string;
      artifacts?: Array<{ parts?: Array<{ type: string; text?: string }> }>;
    } | undefined;

    if (!r?.artifacts?.length) return '';

    return r.artifacts
      .flatMap(a => a.parts ?? [])
      .filter(p => p.type === 'text' && p.text)
      .map(p => p.text!)
      .join('\n');
  }

  return {
    name: target.name ?? `a2a:${target.endpoint}`,
    type: 'a2a',

    async send(message: string): Promise<string> {
      taskId = randomUUID();
      const result = await sendJsonRpc('tasks/send', {
        id: taskId,
        message: {
          role: 'user',
          parts: [{ type: 'text', text: message }],
        },
      });
      return extractText(result);
    },

    async sendConversation(messages: ConversationMessage[]): Promise<string[]> {
      taskId = randomUUID();
      const responses: string[] = [];

      for (const msg of messages) {
        if (msg.delayMs) {
          await new Promise(resolve => setTimeout(resolve, msg.delayMs));
        }

        const result = await sendJsonRpc('tasks/send', {
          id: taskId,
          message: {
            role: msg.role === 'system' ? 'user' : 'user',
            parts: [{ type: 'text', text: msg.content }],
          },
        });

        responses.push(extractText(result));
      }

      return responses;
    },

    async close(): Promise<void> {
      // A2A tasks are stateless from the client side
    },
  };
}
