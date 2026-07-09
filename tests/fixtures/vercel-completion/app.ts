import { generateText, streamText, tool } from 'ai';
import { openai } from '@ai-sdk/openai';
import { z } from 'zod';

// Bare completion — NOT an agent (no tools, no steps)
export async function summarize(text: string) {
  const { text: out } = await generateText({
    model: openai('gpt-4o'),
    system: 'You summarize text.',
    prompt: text,
  });
  return out;
}

// Another bare completion via streamText
export async function chat(msg: string) {
  return streamText({ model: openai('gpt-4o'), prompt: msg });
}

// Agentic — has tools
const weather = tool({
  description: 'Get weather',
  parameters: z.object({ city: z.string() }),
  execute: async ({ city }) => `sunny in ${city}`,
});
export async function assistant(q: string) {
  return generateText({
    model: openai('gpt-4o'),
    prompt: q,
    tools: { weather },
    maxSteps: 5,
  });
}
