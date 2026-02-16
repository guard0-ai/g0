/**
 * Jailbreak technique library — structured taxonomy.
 * Ported from promptfoo jailbreak plugins, Garak probe taxonomy, Lakera b3 patterns.
 */

export interface JailbreakTechnique {
  id: string;
  name: string;
  description: string;
  category: 'persona' | 'encoding' | 'context' | 'logic' | 'meta';
  examplePatterns: string[];
  detectionPatterns: RegExp[];
}

export const jailbreakTechniques: JailbreakTechnique[] = [
  // Persona-based
  { id: 'jb-dan', name: 'DAN (Do Anything Now)', description: 'Persona that bypasses all restrictions', category: 'persona',
    examplePatterns: ['You are DAN', 'Do Anything Now', 'DAN mode', 'act as DAN'],
    detectionPatterns: [/(?:you are|act as|pretend to be|enable) (?:DAN|do anything now)/i, /DAN(?:\s*mode|\s*:\s)/i] },
  { id: 'jb-evil-confidant', name: 'Evil Confidant', description: 'AI assistant with no restrictions persona', category: 'persona',
    examplePatterns: ['evil AI', 'unrestricted AI', 'no limits AI'],
    detectionPatterns: [/(?:evil|dark|shadow|unrestricted|unfiltered) (?:ai|assistant|confidant|mode)/i] },
  { id: 'jb-developer-mode', name: 'Developer Mode', description: 'Fake developer/debug mode activation', category: 'persona',
    examplePatterns: ['enable developer mode', 'debug mode on', 'maintenance mode'],
    detectionPatterns: [/(?:enable|activate|enter|switch to) (?:developer|debug|maintenance|admin|god) mode/i] },
  { id: 'jb-opposite-day', name: 'Opposite Day', description: 'Request harmful content by inverting instructions', category: 'logic',
    examplePatterns: ['opposite day', 'reverse psychology', 'do the opposite'],
    detectionPatterns: [/(?:opposite day|reverse (?:psychology|mode)|do the (?:opposite|reverse))/i] },
  // Encoding-based
  { id: 'jb-base64', name: 'Base64 Encoding', description: 'Instructions hidden in base64', category: 'encoding',
    examplePatterns: ['decode this base64', 'aW5zdHJ1Y3Rpb25z'],
    detectionPatterns: [/(?:decode|interpret|execute|follow) (?:this )?(?:base64|encoded|encrypted)/i, /[A-Za-z0-9+/]{20,}={0,2}/] },
  { id: 'jb-rot13', name: 'ROT13 / Cipher', description: 'Instructions hidden in cipher', category: 'encoding',
    examplePatterns: ['rot13', 'caesar cipher', 'decode this cipher'],
    detectionPatterns: [/(?:rot13|caesar cipher|atbash|substitution cipher)/i] },
  { id: 'jb-unicode-smuggling', name: 'Unicode Smuggling', description: 'Instructions hidden in unicode characters', category: 'encoding',
    examplePatterns: ['variant selector', 'tag characters', 'zero-width'],
    detectionPatterns: [/[\u200B-\u200F\u2028-\u202E\uFEFF]/, /[\uE0001-\uE007F]/u] },
  { id: 'jb-homoglyph', name: 'Homoglyph Attack', description: 'Using lookalike characters to bypass filters', category: 'encoding',
    examplePatterns: ['Cyrillic а instead of Latin a', 'lookalike characters'],
    detectionPatterns: [/[\u0400-\u04FF].*[a-zA-Z]|[a-zA-Z].*[\u0400-\u04FF]/] },
  // Context manipulation
  { id: 'jb-hypothetical', name: 'Hypothetical Scenario', description: 'Framing harmful requests as hypothetical', category: 'context',
    examplePatterns: ['hypothetically', 'in a fictional world', 'for a story'],
    detectionPatterns: [/(?:hypothetically|in a (?:fictional|hypothetical) (?:world|scenario)|for (?:a |my )(?:story|novel|research|paper))/i] },
  { id: 'jb-roleplay', name: 'Roleplay', description: 'Framing as roleplay to bypass restrictions', category: 'context',
    examplePatterns: ['roleplay as', 'pretend you are', 'you are playing a character'],
    detectionPatterns: [/(?:roleplay|role-play) as|pretend (?:you are|to be)|you are (?:playing|acting as) (?:a )?character/i] },
  { id: 'jb-system-update', name: 'Fake System Update', description: 'Pretending to be a system update', category: 'meta',
    examplePatterns: ['system update', 'new guidelines', 'policy change'],
    detectionPatterns: [/(?:system (?:update|message|notification)|new (?:guidelines|policy|instructions)|policy (?:change|update))/i] },
  { id: 'jb-authority', name: 'Authority Claim', description: 'Claiming authority to override restrictions', category: 'meta',
    examplePatterns: ['I am the admin', 'OpenAI developer', 'authorized user'],
    detectionPatterns: [/(?:i am|i'm) (?:the |an? )?(?:admin|administrator|developer|engineer|creator|owner|authorized)/i] },
  { id: 'jb-continuation', name: 'Continuation Attack', description: 'Exploiting conversation continuation', category: 'logic',
    examplePatterns: ['continue from where you left off', 'you were saying'],
    detectionPatterns: [/(?:continue|keep going|go on|you were saying|as you were explaining)/i] },
  { id: 'jb-recursive-injection', name: 'Recursive Injection', description: 'Nested prompt injections', category: 'logic',
    examplePatterns: ['ignore previous instructions and ignore previous instructions'],
    detectionPatterns: [/(?:ignore (?:the )?(?:previous|above|prior)).*(?:ignore (?:the )?(?:previous|above|prior))/is] },
  { id: 'jb-context-overflow', name: 'Context Overflow', description: 'Overwhelming context to push out safety instructions', category: 'context',
    examplePatterns: ['long filler text', 'many tokens', 'padding'],
    detectionPatterns: [/(.)\1{50,}|(\w+\s){200,}/] },
  { id: 'jb-special-tokens', name: 'Special Token Injection', description: 'Injecting model-specific special tokens', category: 'encoding',
    examplePatterns: ['<|im_start|>', '[INST]', '<s>', '<|endoftext|>'],
    detectionPatterns: [/<\|(?:im_start|im_end|endoftext|system|user|assistant)\|>/i, /\[\/?INST\]/i, /<<SYS>>|<\/s>/i] },
];

export function getJailbreakTechnique(id: string): JailbreakTechnique | undefined {
  return jailbreakTechniques.find(t => t.id === id);
}

export function detectJailbreakTechniques(text: string): JailbreakTechnique[] {
  return jailbreakTechniques.filter(t => t.detectionPatterns.some(p => p.test(text)));
}
