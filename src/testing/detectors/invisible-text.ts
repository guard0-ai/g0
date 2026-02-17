/**
 * Invisible text detector — detects zero-width characters, bidi control,
 * BOM markers, tag characters, variation selectors, and other invisible
 * Unicode that can be used for encoding bypass attacks.
 *
 * Inspired by LLM Guard's invisible text detection.
 */

export interface InvisibleTextMatch {
  type: string;
  char: string;
  codePoint: number;
  index: number;
}

// Character ranges that are invisible or control characters
const INVISIBLE_RANGES: Array<{ name: string; start: number; end: number }> = [
  // Zero-width characters
  { name: 'zero-width-space', start: 0x200B, end: 0x200B },
  { name: 'zero-width-non-joiner', start: 0x200C, end: 0x200C },
  { name: 'zero-width-joiner', start: 0x200D, end: 0x200D },
  { name: 'word-joiner', start: 0x2060, end: 0x2060 },
  { name: 'zero-width-no-break', start: 0xFEFF, end: 0xFEFF }, // BOM
  // Bidi control characters
  { name: 'bidi-control', start: 0x200E, end: 0x200F },
  { name: 'bidi-embedding', start: 0x202A, end: 0x202E },
  { name: 'bidi-isolate', start: 0x2066, end: 0x2069 },
  // Tag characters (U+E0000 range)
  { name: 'tag-character', start: 0xE0001, end: 0xE007F },
  // Variation selectors
  { name: 'variation-selector', start: 0xFE00, end: 0xFE0F },
  { name: 'variation-selector-supplement', start: 0xE0100, end: 0xE01EF },
  // Soft hyphen and other format chars
  { name: 'soft-hyphen', start: 0x00AD, end: 0x00AD },
  // Interlinear annotation
  { name: 'interlinear-annotation', start: 0xFFF9, end: 0xFFFB },
  // Object replacement
  { name: 'object-replacement', start: 0xFFFC, end: 0xFFFD },
  // C0/C1 control characters (excluding common ones like \n, \t, \r)
  { name: 'c0-control', start: 0x0001, end: 0x0008 },
  { name: 'c0-control', start: 0x000B, end: 0x000C },
  { name: 'c0-control', start: 0x000E, end: 0x001F },
  { name: 'c1-control', start: 0x007F, end: 0x009F },
];

/**
 * Detect invisible/hidden characters in text.
 * Returns an array of matches with their type and position.
 */
export function detectInvisibleText(text: string): InvisibleTextMatch[] {
  const matches: InvisibleTextMatch[] = [];

  for (let i = 0; i < text.length; i++) {
    const codePoint = text.codePointAt(i)!;

    // Skip surrogate pair second half
    if (codePoint > 0xFFFF) i++;

    for (const range of INVISIBLE_RANGES) {
      if (codePoint >= range.start && codePoint <= range.end) {
        matches.push({
          type: range.name,
          char: String.fromCodePoint(codePoint),
          codePoint,
          index: i,
        });
        break;
      }
    }
  }

  return matches;
}

/**
 * Check if text contains significant invisible content.
 * Returns true if the invisible character count exceeds the threshold.
 */
export function hasSignificantInvisibleText(
  text: string,
  threshold = 3,
): boolean {
  const matches = detectInvisibleText(text);
  return matches.length >= threshold;
}

/**
 * Strip invisible characters from text, preserving normal whitespace.
 */
export function stripInvisibleText(text: string): string {
  let result = '';
  for (let i = 0; i < text.length; i++) {
    const codePoint = text.codePointAt(i)!;
    if (codePoint > 0xFFFF) i++; // Skip surrogate pair

    let isInvisible = false;
    for (const range of INVISIBLE_RANGES) {
      if (codePoint >= range.start && codePoint <= range.end) {
        isInvisible = true;
        break;
      }
    }

    if (!isInvisible) {
      result += String.fromCodePoint(codePoint);
    }
  }
  return result;
}
