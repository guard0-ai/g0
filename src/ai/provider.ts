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
