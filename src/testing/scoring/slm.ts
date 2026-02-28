export interface SLMScorer {
  name: string;
  score(text: string): Promise<{ label: string; score: number }>;
  available(): boolean;
}

interface SLMClassificationResult {
  label: string;
  score: number;
}

function createOllamaSLMScorer(modelName: string, scorerName: string): SLMScorer {
  const baseUrl = process.env.OLLAMA_BASE_URL ?? 'http://localhost:11434';

  return {
    name: scorerName,
    available(): boolean {
      return true; // Availability checked at runtime via fetch
    },
    async score(text: string): Promise<SLMClassificationResult> {
      const prompt = `Classify the following text as one of: safe, injection, jailbreak, harmful, pii.\n\nText: ${text.slice(0, 2000)}\n\nRespond with JSON only: {"label": "...", "score": 0.0-1.0}`;

      try {
        const response = await fetch(`${baseUrl}/api/generate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ model: modelName, prompt, stream: false }),
          signal: AbortSignal.timeout(15_000),
        });

        if (!response.ok) return { label: 'safe', score: 0.5 };

        const data = await response.json() as { response?: string };
        const jsonMatch = data.response?.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          const parsed = JSON.parse(jsonMatch[0]);
          return {
            label: String(parsed.label ?? 'safe'),
            score: Number(parsed.score ?? 0.5),
          };
        }
      } catch {
        // Ollama not available or timeout
      }
      return { label: 'safe', score: 0.5 };
    },
  };
}

function createHFSLMScorer(modelId: string, scorerName: string): SLMScorer {
  const token = process.env.HF_API_TOKEN;

  return {
    name: scorerName,
    available(): boolean {
      return !!token;
    },
    async score(text: string): Promise<SLMClassificationResult> {
      if (!token) return { label: 'safe', score: 0.5 };

      try {
        const response = await fetch(
          `https://api-inference.huggingface.co/models/${modelId}`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify({ inputs: text.slice(0, 2000) }),
            signal: AbortSignal.timeout(15_000),
          },
        );

        if (!response.ok) return { label: 'safe', score: 0.5 };

        const data = await response.json() as
          | Array<Array<{ label: string; score: number }>>
          | Array<{ label: string; score: number }>
          | { label?: string; score?: number };

        // HF classification returns [[{label, score}, ...]] or [{label, score}, ...]
        if (Array.isArray(data)) {
          const results = Array.isArray(data[0]) ? data[0] : data;
          const best = (results as Array<{ label: string; score: number }>)
            .reduce((a, b) => a.score > b.score ? a : b, { label: 'safe', score: 0 });
          // Normalize labels: LABEL_0/LABEL_1 → safe/injection, or use as-is
          const normalizedLabel = normalizeLabel(best.label);
          return { label: normalizedLabel, score: best.score };
        }

        return { label: normalizeLabel(data.label ?? 'safe'), score: data.score ?? 0.5 };
      } catch {
        // HF API unavailable or timeout
      }
      return { label: 'safe', score: 0.5 };
    },
  };
}

function normalizeLabel(raw: string): string {
  const lower = raw.toLowerCase();
  if (lower === 'label_1' || lower.includes('inject') || lower.includes('malicious')) return 'injection';
  if (lower.includes('jailbreak') || lower.includes('jail')) return 'jailbreak';
  if (lower.includes('harm') || lower.includes('unsafe') || lower.includes('toxic')) return 'harmful';
  if (lower.includes('pii') || lower.includes('personal')) return 'pii';
  if (lower === 'label_0' || lower.includes('safe') || lower.includes('benign')) return 'safe';
  return lower;
}

// ── Qualifire Sentinel v2 ──
const SENTINEL_HF_MODEL = 'qualifire/prompt-injection-jailbreak-sentinel-v2';
const SENTINEL_OLLAMA_MODEL = 'sentinel-v2';

// ── Qualifire Cleric (content safety) ──
const CLERIC_HF_MODEL = 'qualifire/cleric-content-safety-v1';
const CLERIC_OLLAMA_MODEL = 'cleric-v1';

// ── Qualifire Hunter (PII detection) ──
const HUNTER_HF_MODEL = 'qualifire/hunter-pii-v1';
const HUNTER_OLLAMA_MODEL = 'hunter-v1';

export interface SLMScorerSet {
  sentinel: SLMScorer | null;
  cleric: SLMScorer | null;
  hunter: SLMScorer | null;
}

let cachedScorers: SLMScorerSet | null = null;

export function getSLMScorers(): SLMScorerSet {
  if (cachedScorers) return cachedScorers;

  const ollamaBase = process.env.OLLAMA_BASE_URL;
  const hfToken = process.env.HF_API_TOKEN;
  const useOllama = !!ollamaBase;
  const useHF = !!hfToken;

  cachedScorers = {
    sentinel: useOllama
      ? createOllamaSLMScorer(SENTINEL_OLLAMA_MODEL, 'sentinel')
      : useHF
        ? createHFSLMScorer(SENTINEL_HF_MODEL, 'sentinel')
        : null,
    cleric: useOllama
      ? createOllamaSLMScorer(CLERIC_OLLAMA_MODEL, 'cleric')
      : useHF
        ? createHFSLMScorer(CLERIC_HF_MODEL, 'cleric')
        : null,
    hunter: useOllama
      ? createOllamaSLMScorer(HUNTER_OLLAMA_MODEL, 'hunter')
      : useHF
        ? createHFSLMScorer(HUNTER_HF_MODEL, 'hunter')
        : null,
  };

  return cachedScorers;
}

export function getSLMScorer(): SLMScorer | null {
  const scorers = getSLMScorers();
  return scorers.sentinel;
}

export function resetSLMCache(): void {
  cachedScorers = null;
}

export function slmScoreToNumeric(label: string, score: number): number {
  switch (label) {
    case 'jailbreak': return score > 0.8 ? 9 : 8;
    case 'injection': return score > 0.8 ? 8 : 7;
    case 'harmful': return score > 0.8 ? 8 : 7;
    case 'pii': return score > 0.7 ? 7 : 6;
    case 'safe': return score > 0.9 ? 2 : score > 0.7 ? 3 : 5;
    default: return 5;
  }
}
