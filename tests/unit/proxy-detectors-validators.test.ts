import { describe, it, expect } from 'vitest';
import {
  luhn,
  iban,
  abaRouting,
  shannonEntropy,
  hasHighEntropy,
  keyFormat,
} from '../../src/proxy/detectors/validators.js';

describe('luhn', () => {
  it('validates published test PANs (Visa, Mastercard, Amex)', () => {
    expect(luhn('4111111111111111')).toBe(true); // Visa test PAN
    expect(luhn('5555555555554444')).toBe(true); // Mastercard test PAN
    expect(luhn('378282246310005')).toBe(true); // Amex test PAN
  });

  it('rejects a 16-digit number that fails the checksum (THE false-positive-cut case)', () => {
    // Same shape/length as a real PAN, differs only in the last digit.
    expect(luhn('4111111111111112')).toBe(false);
  });

  it('rejects non-digit input without throwing', () => {
    expect(luhn('411a111111111111')).toBe(false);
    expect(luhn('')).toBe(false);
    expect(luhn('not a card at all')).toBe(false);
  });

  it('never throws on adversarial input', () => {
    expect(() => luhn('9'.repeat(100000))).not.toThrow();
    expect(() => luhn(undefined as unknown as string)).not.toThrow();
    expect(() => luhn(null as unknown as string)).not.toThrow();
  });
});

describe('iban', () => {
  it('validates well-known published IBAN examples (mod-97)', () => {
    expect(iban('GB82WEST12345698765432')).toBe(true); // canonical example
    expect(iban('DE89370400440532013000')).toBe(true); // Bundesbank example
  });

  it('accepts the same IBAN with human-readable 4-char grouping spaces', () => {
    expect(iban('GB82 WEST 1234 5698 7654 32')).toBe(true);
  });

  it('rejects a corrupted check digit', () => {
    expect(iban('GB82WEST12345698765431')).toBe(false);
  });

  it('rejects malformed/garbage input without throwing', () => {
    expect(iban('not an iban')).toBe(false);
    expect(iban('')).toBe(false);
    expect(iban('12GB82WEST')).toBe(false);
  });

  it('never throws on adversarial input', () => {
    expect(() => iban('A'.repeat(100000))).not.toThrow();
    expect(() => iban(undefined as unknown as string)).not.toThrow();
  });
});

describe('abaRouting', () => {
  it('validates real published US bank routing numbers', () => {
    expect(abaRouting('026009593')).toBe(true); // Bank of America
    expect(abaRouting('021000021')).toBe(true); // JPMorgan Chase, NY
    expect(abaRouting('121042882')).toBe(true); // Wells Fargo, CA
  });

  it('rejects a 9-digit number that fails the ABA checksum', () => {
    expect(abaRouting('123456789')).toBe(false);
  });

  it('rejects wrong-length input without throwing', () => {
    expect(abaRouting('12345')).toBe(false);
    expect(abaRouting('1234567890')).toBe(false);
    expect(abaRouting('')).toBe(false);
  });

  it('never throws on adversarial input', () => {
    expect(() => abaRouting('9'.repeat(100000))).not.toThrow();
    expect(() => abaRouting(undefined as unknown as string)).not.toThrow();
  });
});

describe('shannonEntropy', () => {
  it('returns 0 for a single repeated character', () => {
    expect(shannonEntropy('aaaaaaaaaa')).toBe(0);
  });

  it('returns near-maximal entropy for a fully random-looking token', () => {
    const entropy = shannonEntropy('Zx9pQmT4vK2sR8wN1yB6cD3eF7gH0jL5');
    expect(entropy).toBeGreaterThan(4.5);
  });

  it('returns a low-to-mid value for ordinary English prose', () => {
    const entropy = shannonEntropy('lorem ipsum dolor sit amet');
    expect(entropy).toBeLessThan(4.5);
  });

  it('never throws on empty or adversarial input', () => {
    expect(shannonEntropy('')).toBe(0);
    expect(() => shannonEntropy('a'.repeat(1_000_000))).not.toThrow();
  });
});

describe('hasHighEntropy', () => {
  it('is true above the threshold, false below it', () => {
    expect(hasHighEntropy('Zx9pQmT4vK2sR8wN1yB6cD3eF7gH0jL5', 4.0)).toBe(true);
    expect(hasHighEntropy('aaaaaaaaaa', 4.0)).toBe(false);
  });

  it('is INCLUSIVE at the boundary — entropy exactly equal to the threshold passes', () => {
    // 'abcd' has 4 equiprobable symbols -> entropy is exactly log2(4) = 2.0.
    // Pin the boundary semantics explicitly (>= not >), since the detectors'
    // thresholds are tuned against measured values and an off-by-one-epsilon
    // flip here would silently change what they report.
    expect(shannonEntropy('abcd')).toBe(2);

    expect(hasHighEntropy('abcd', 2)).toBe(true); // exactly at threshold -> included
    expect(hasHighEntropy('abcd', 1.9999)).toBe(true); // just below -> included
    expect(hasHighEntropy('abcd', 2.0001)).toBe(false); // just above -> excluded
  });

  it('never throws on adversarial input', () => {
    expect(() => hasHighEntropy(undefined as unknown as string, 4.0)).not.toThrow();
    expect(hasHighEntropy(undefined as unknown as string, 4.0)).toBe(false);
  });
});

describe('keyFormat', () => {
  it('recognizes a real-shaped AWS access key', () => {
    const result = keyFormat('AKIAIOSFODNN7EXAMPLE'); // AWS's own published example key
    expect(result).not.toBeNull();
    expect(result!.vendor).toBe('aws');
    expect(result!.structurallyValid).toBe(true);
  });

  it('recognizes an OpenAI-style sk- key', () => {
    const result = keyFormat('sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345');
    expect(result).not.toBeNull();
    expect(result!.vendor).toBe('openai');
  });

  it('recognizes a GitHub personal access token', () => {
    const result = keyFormat('ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8');
    expect(result).not.toBeNull();
    expect(result!.vendor).toBe('github');
  });

  it('recognizes a Slack bot token', () => {
    const result = keyFormat('xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx');
    expect(result).not.toBeNull();
    expect(result!.vendor).toBe('slack');
  });

  it('recognizes a structurally valid JWT (decodable header)', () => {
    // The canonical jwt.io example token.
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const result = keyFormat(jwt);
    expect(result).not.toBeNull();
    expect(result!.vendor).toBe('jwt');
    expect(result!.structurallyValid).toBe(true);
  });

  it('rejects a dot-separated string shaped like a JWT but with an undecodable header', () => {
    const fake = 'not-base64!!.also-not-base64!!.definitely-not';
    expect(keyFormat(fake)).toBeNull();
  });

  it('rejects a JWT-shaped string whose header decodes but is not a JWT header object', () => {
    const header = Buffer.from(JSON.stringify(['just', 'an', 'array']))
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const fake = `${header}.eyJmb28iOiJiYXIifQ.abcdef`;
    expect(keyFormat(fake)).toBeNull();
  });

  it('returns null for ordinary text', () => {
    expect(keyFormat('the quick brown fox')).toBeNull();
    expect(keyFormat('')).toBeNull();
  });

  it('never throws on adversarial input', () => {
    expect(() => keyFormat('.'.repeat(100000))).not.toThrow();
    expect(() => keyFormat(undefined as unknown as string)).not.toThrow();
    expect(() => keyFormat('A'.repeat(100000) + '.' + 'B'.repeat(100000) + '.' + 'C'.repeat(100000))).not.toThrow();
  });
});
