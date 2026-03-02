import type { TestProvider, TestTarget, ConversationMessage } from '../../types/test.js';

type ModelProvider = 'openai' | 'anthropic' | 'google';

const DEFAULT_MODELS: Record<ModelProvider, string> = {
  openai: 'gpt-4o',
  anthropic: 'claude-sonnet-4-5-20250929',
  google: 'gemini-2.5-flash',
};

const API_KEY_ENV: Record<ModelProvider, string> = {
  openai: 'OPENAI_API_KEY',
  anthropic: 'ANTHROPIC_API_KEY',
  google: 'GOOGLE_API_KEY',
};

const RETRYABLE_STATUS_CODES = new Set([429, 502, 503, 504]);
const MAX_RETRIES = 3;
const BASE_DELAY_MS = 1000;

export function createDirectModelProvider(target: TestTarget): TestProvider {
  const providerName: ModelProvider = target.provider ?? 'openai';
  const envVar = API_KEY_ENV[providerName];
  const rawApiKey = process.env[envVar];

  if (!rawApiKey) {
    throw new Error('Missing API key for direct-model provider');
  }

  const apiKey: string = rawApiKey;

  const model = target.model ?? DEFAULT_MODELS[providerName];
  const systemPrompt = target.systemPrompt;
  const timeoutMs = target.timeout ?? 60_000;

  // Conversation history for multi-turn attacks
  const conversationHistory: Array<{ role: 'user' | 'assistant'; content: string }> = [];

  async function fetchWithRetry(url: string, init: RequestInit): Promise<Response> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      let response: Response;
      try {
        response = await fetch(url, { ...init, signal: controller.signal });
      } catch (err) {
        clearTimeout(timeoutId);
        lastError = err instanceof Error ? err : new Error(String(err));
        if (lastError.name === 'AbortError') {
          throw new Error(`Request timed out after ${timeoutMs}ms`);
        }
        if (attempt < MAX_RETRIES) {
          await sleep(BASE_DELAY_MS * Math.pow(2, attempt));
          continue;
        }
        throw lastError;
      } finally {
        clearTimeout(timeoutId);
      }

      if (response.ok) {
        return response;
      }

      if (RETRYABLE_STATUS_CODES.has(response.status) && attempt < MAX_RETRIES) {
        const retryAfter = response.headers.get('Retry-After');
        const parsed = retryAfter ? parseInt(retryAfter, 10) : NaN;
        const delayMs = Number.isNaN(parsed)
          ? BASE_DELAY_MS * Math.pow(2, attempt)
          : Math.max(Math.min(parsed * 1000, 30_000), 100);
        await sleep(delayMs);
        continue;
      }

      const body = await response.text().catch(() => '');
      throw new Error(`${providerName} API error ${response.status}: ${response.statusText}${body ? ` - ${body}` : ''}`);
    }

    throw lastError ?? new Error('Request failed after retries');
  }

  // --- OpenAI ---
  async function callOpenAI(
    messages: Array<{ role: string; content: string }>
  ): Promise<string> {
    const apiMessages: Array<{ role: string; content: string }> = [];
    if (systemPrompt) {
      apiMessages.push({ role: 'system', content: systemPrompt });
    }
    apiMessages.push(...messages);

    const response = await fetchWithRetry('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages: apiMessages,
        max_tokens: 4096,
      }),
    });

    const data = (await response.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    return data.choices?.[0]?.message?.content ?? '';
  }

  // --- Anthropic ---
  async function callAnthropic(
    messages: Array<{ role: string; content: string }>
  ): Promise<string> {
    const body: Record<string, unknown> = {
      model,
      max_tokens: 4096,
      messages,
    };
    if (systemPrompt) {
      body.system = systemPrompt;
    }

    const response = await fetchWithRetry('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(body),
    });

    const data = (await response.json()) as {
      content?: Array<{ text?: string }>;
    };
    return data.content?.[0]?.text ?? '';
  }

  // --- Google ---
  async function callGoogle(
    messages: Array<{ role: string; content: string }>
  ): Promise<string> {
    const contents: Array<{ role: string; parts: Array<{ text: string }> }> = [];

    // Google uses a different role mapping: user -> user, assistant -> model
    // System prompt is passed as systemInstruction
    for (const msg of messages) {
      const role = msg.role === 'assistant' ? 'model' : 'user';
      contents.push({ role, parts: [{ text: msg.content }] });
    }

    const body: Record<string, unknown> = {
      contents,
      generationConfig: { maxOutputTokens: 4096 },
    };
    if (systemPrompt) {
      body.systemInstruction = { parts: [{ text: systemPrompt }] };
    }

    const response = await fetchWithRetry(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }
    );

    const data = (await response.json()) as {
      candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
    };
    return data.candidates?.[0]?.content?.parts?.[0]?.text ?? '';
  }

  async function callModel(
    messages: Array<{ role: string; content: string }>
  ): Promise<string> {
    switch (providerName) {
      case 'openai':
        return callOpenAI(messages);
      case 'anthropic':
        return callAnthropic(messages);
      case 'google':
        return callGoogle(messages);
      default:
        throw new Error(`Unsupported provider: ${providerName}`);
    }
  }

  return {
    name: target.name ?? `${providerName}/${model}`,
    type: 'direct-model',

    async send(message: string): Promise<string> {
      const messages = [{ role: 'user', content: message }];
      return callModel(messages);
    },

    async sendConversation(messages: ConversationMessage[]): Promise<string[]> {
      const responses: string[] = [];
      // Reset history for each conversation
      conversationHistory.length = 0;

      for (const msg of messages) {
        if (msg.delayMs) {
          await sleep(msg.delayMs);
        }

        // Build messages array with full history
        const apiMessages: Array<{ role: string; content: string }> = [];

        // Add prior history
        for (const h of conversationHistory) {
          apiMessages.push({ role: h.role, content: h.content });
        }

        // Add current message
        apiMessages.push({
          role: msg.role === 'system' ? 'user' : 'user',
          content: msg.content,
        });

        const resp = await callModel(apiMessages);
        responses.push(resp);

        // Update conversation history
        conversationHistory.push({ role: 'user', content: msg.content });
        conversationHistory.push({ role: 'assistant', content: resp });
      }

      return responses;
    },

    async close(): Promise<void> {
      conversationHistory.length = 0;
    },
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
