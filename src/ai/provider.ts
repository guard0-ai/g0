export interface AIProvider {
  name: string;
  model: string;
  analyze(prompt: string, context: string): Promise<string>;
}

export interface AIProviderOptions {
  model?: string;
}

const DEFAULT_MODELS: Record<string, string> = {
  anthropic: 'claude-sonnet-4-5-20250929',
  openai: 'gpt-5-mini',
  google: 'gemini-2.5-flash',
};

export function getAIProviderBySpec(spec: string): AIProvider | null {
  const parts = spec.split('/');
  const providerName = parts[0];
  const modelOverride = parts.length > 1 ? parts.slice(1).join('/') : undefined;

  if (providerName === 'anthropic') {
    const key = process.env.ANTHROPIC_API_KEY;
    if (!key) return null;
    return createAnthropicProvider(key, modelOverride);
  }
  if (providerName === 'openai') {
    const key = process.env.OPENAI_API_KEY;
    if (!key) return null;
    return createOpenAIProvider(key, modelOverride);
  }
  if (providerName === 'google') {
    const key = process.env.GOOGLE_API_KEY;
    if (!key) return null;
    return createGoogleProvider(key, modelOverride);
  }
  if (providerName === 'ollama') {
    const model = modelOverride ?? 'mistral';
    return createOllamaProvider(model);
  }
  if (providerName === 'huggingface') {
    const token = process.env.HF_API_TOKEN;
    if (!token) return null;
    const modelId = modelOverride;
    if (!modelId) return null;
    return createHuggingFaceProvider(token, modelId);
  }
  return null;
}

export function getAIProvider(options?: AIProviderOptions): AIProvider | null {
  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  if (anthropicKey) {
    return createAnthropicProvider(anthropicKey, options?.model);
  }

  const openaiKey = process.env.OPENAI_API_KEY;
  if (openaiKey) {
    return createOpenAIProvider(openaiKey, options?.model);
  }

  const googleKey = process.env.GOOGLE_API_KEY;
  if (googleKey) {
    return createGoogleProvider(googleKey, options?.model);
  }

  return null;
}

function createAnthropicProvider(apiKey: string, modelOverride?: string): AIProvider {
  const model = modelOverride || DEFAULT_MODELS.anthropic;
  return {
    name: 'anthropic',
    model,
    async analyze(prompt: string, context: string): Promise<string> {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model,
          max_tokens: 4096,
          messages: [
            { role: 'user', content: `${prompt}\n\n${context}` },
          ],
        }),
      });

      if (!response.ok) {
        throw new Error(`Anthropic API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as { content: Array<{ text: string }> };
      return data.content[0]?.text ?? '';
    },
  };
}

function createOpenAIProvider(apiKey: string, modelOverride?: string): AIProvider {
  const model = modelOverride || DEFAULT_MODELS.openai;
  return {
    name: 'openai',
    model,
    async analyze(prompt: string, context: string): Promise<string> {
      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model,
          max_tokens: 4096,
          messages: [
            { role: 'system', content: prompt },
            { role: 'user', content: context },
          ],
        }),
      });

      if (!response.ok) {
        throw new Error(`OpenAI API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as { choices: Array<{ message: { content: string } }> };
      return data.choices[0]?.message?.content ?? '';
    },
  };
}

function createGoogleProvider(apiKey: string, modelOverride?: string): AIProvider {
  const model = modelOverride || DEFAULT_MODELS.google;
  return {
    name: 'google',
    model,
    async analyze(prompt: string, context: string): Promise<string> {
      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ parts: [{ text: `${prompt}\n\n${context}` }] }],
            generationConfig: { maxOutputTokens: 4096 },
          }),
        }
      );

      if (!response.ok) {
        throw new Error(`Google AI API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as {
        candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
      };
      return data.candidates?.[0]?.content?.parts?.[0]?.text ?? '';
    },
  };
}

function createOllamaProvider(model: string): AIProvider {
  const baseUrl = process.env.OLLAMA_BASE_URL ?? 'http://localhost:11434';
  return {
    name: 'ollama',
    model,
    async analyze(prompt: string, context: string): Promise<string> {
      const response = await fetch(`${baseUrl}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model,
          prompt: `${prompt}\n\n${context}`,
          stream: false,
        }),
      });

      if (!response.ok) {
        throw new Error(`Ollama API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as { response?: string };
      return data.response ?? '';
    },
  };
}

function createHuggingFaceProvider(token: string, modelId: string): AIProvider {
  return {
    name: 'huggingface',
    model: modelId,
    async analyze(prompt: string, context: string): Promise<string> {
      const input = context ? `${prompt}\n\n${context}` : prompt;
      const url = `https://api-inference.huggingface.co/models/${modelId}`;

      let lastError: Error | null = null;
      // Retry up to 3 times to handle HF cold-start warm-up
      for (let attempt = 0; attempt < 3; attempt++) {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          },
          body: JSON.stringify({ inputs: input, parameters: { max_new_tokens: 2048 } }),
        });

        if (response.ok) {
          const data = await response.json() as
            | Array<{ generated_text?: string }>
            | { generated_text?: string }
            | { error?: string };

          if (Array.isArray(data)) {
            return data[0]?.generated_text ?? '';
          }
          if ('generated_text' in data) {
            return data.generated_text ?? '';
          }
          return '';
        }

        // Model loading — wait and retry
        if (response.status === 503) {
          lastError = new Error('Model is loading');
          await new Promise(r => setTimeout(r, 5000 * (attempt + 1)));
          continue;
        }

        throw new Error(`HuggingFace API error: ${response.status} ${response.statusText}`);
      }

      throw lastError ?? new Error('HuggingFace API failed after retries');
    },
  };
}
