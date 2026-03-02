/**
 * Text normalization for robust heuristic matching.
 * Handles Unicode confusables, diacritics, zero-width characters,
 * and provides fuzzy word-level matching.
 */

// Reverse confusable map: Cyrillic/Greek lookalikes → ASCII
const CONFUSABLE_TO_ASCII: Record<string, string> = {
  '\u0251': 'a', // ɑ
  '\u03F2': 'c', // ϲ
  '\u0435': 'e', // Cyrillic е
  '\u043E': 'o', // Cyrillic о
  '\u0440': 'p', // Cyrillic р
  '\u0455': 's', // Cyrillic ѕ
  '\u0445': 'x', // Cyrillic х
  '\u0443': 'y', // Cyrillic у
  // Additional common confusables
  '\u0410': 'A', // Cyrillic А
  '\u0412': 'B', // Cyrillic В
  '\u0415': 'E', // Cyrillic Е
  '\u041A': 'K', // Cyrillic К
  '\u041C': 'M', // Cyrillic М
  '\u041D': 'H', // Cyrillic Н
  '\u041E': 'O', // Cyrillic О
  '\u0420': 'P', // Cyrillic Р
  '\u0421': 'C', // Cyrillic С
  '\u0422': 'T', // Cyrillic Т
  '\u0425': 'X', // Cyrillic Х
  '\u0430': 'a', // Cyrillic а
  '\u0441': 'c', // Cyrillic с
  '\u0456': 'i', // Cyrillic і
  '\u0458': 'j', // Cyrillic ј
  '\u03B1': 'a', // Greek α
  '\u03BF': 'o', // Greek ο
  '\u03C1': 'p', // Greek ρ
  '\u0391': 'A', // Greek Α
  '\u0392': 'B', // Greek Β
  '\u0395': 'E', // Greek Ε
  '\u0397': 'H', // Greek Η
  '\u0399': 'I', // Greek Ι
  '\u039A': 'K', // Greek Κ
  '\u039C': 'M', // Greek Μ
  '\u039D': 'N', // Greek Ν
  '\u039F': 'O', // Greek Ο
  '\u03A1': 'P', // Greek Ρ
  '\u03A4': 'T', // Greek Τ
  '\u03A5': 'Y', // Greek Υ
  '\u03A7': 'X', // Greek Χ
  '\u03B5': 'e', // Greek ε (close enough)
};

// Zero-width and invisible characters to strip
const ZERO_WIDTH_RE = /[\u200B\u200C\u200D\u200E\u200F\u2060\u2061\u2062\u2063\u2064\uFEFF\u00AD\u034F\u180E\u061C]/g;

// Unicode tag characters (U+E0000 range)
const TAG_CHARS_RE = /[\u{E0000}-\u{E007F}]/gu;

/**
 * Normalize text for robust matching:
 * 1. NFD decompose → strip combining marks (removes diacritics)
 * 2. Map Cyrillic/Greek confusables to ASCII
 * 3. Strip zero-width and invisible characters
 * 4. Strip Unicode tag characters
 * 5. Collapse whitespace
 */
export function normalizeText(text: string): string {
  // NFD decompose and strip combining marks (U+0300–U+036F)
  let result = text.normalize('NFD').replace(/[\u0300-\u036F]/g, '');

  // Map confusable characters
  result = result.replace(/./gu, ch => CONFUSABLE_TO_ASCII[ch] ?? ch);

  // Strip zero-width and invisible characters
  result = result.replace(ZERO_WIDTH_RE, '');

  // Strip Unicode tag characters
  result = result.replace(TAG_CHARS_RE, '');

  // Collapse whitespace
  result = result.replace(/\s+/g, ' ').trim();

  return result;
}

/**
 * Word-level Levenshtein distance.
 */
function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost,
      );
    }
  }

  return dp[m][n];
}

/**
 * Fuzzy phrase matching: checks if `phrase` appears in `text` with
 * at most `maxDistance` Levenshtein edits per word.
 * Splits both into words and slides a window over text words.
 */
export function fuzzyContains(text: string, phrase: string, maxDistance = 2): boolean {
  const textWords = text.toLowerCase().split(/\s+/).filter(w => w.length > 0);
  const phraseWords = phrase.toLowerCase().split(/\s+/).filter(w => w.length > 0);

  if (phraseWords.length === 0) return true;
  if (textWords.length < phraseWords.length) return false;

  for (let i = 0; i <= textWords.length - phraseWords.length; i++) {
    let allMatch = true;
    for (let j = 0; j < phraseWords.length; j++) {
      const dist = levenshteinDistance(textWords[i + j], phraseWords[j]);
      if (dist > maxDistance) {
        allMatch = false;
        break;
      }
    }
    if (allMatch) return true;
  }

  return false;
}
