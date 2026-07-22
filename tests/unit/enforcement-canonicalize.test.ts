import { describe, it, expect } from 'vitest';
import { canonicalize } from '../../src/enforcement/canonicalize.js';
import { inspectResponseText } from '../../src/enforcement/response-inspector.js';

const ZW = '​';
const AWS = 'AKIAIOSFODNN7EXAMPLE';
const larded = `AWS_ACCESS_KEY_ID=${AWS.split('').join(ZW)}`;

describe('canonicalize', () => {
  it('strips zero-width and applies NFKC', () => {
    expect(canonicalize(`a${ZW}b⁠c`)).toBe('abc');
    expect(canonicalize('ﬁle')).toBe('file'); // NFKC ligature fold
  });
  it('is identity on plain ASCII', () => {
    const s = 'hello key=abc123';
    expect(canonicalize(s)).toBe(s);
  });
});

describe('inspectResponseText canonicalPass', () => {
  it('OFF by default: zero-width-larded key yields no secret finding (regression pin)', () => {
    const r = inspectResponseText(larded);
    expect(r.findings.filter((f) => f.category === 'secret')).toEqual([]);
  });
  it('ON: detects the larded key, tagged canonicalized, without redaction offsets', () => {
    const r = inspectResponseText(larded, { canonicalPass: true, redactSecrets: true });
    const hit = r.findings.find((f) => f.category === 'secret');
    expect(hit).toBeDefined();
    expect(hit!.signals).toContain('canonicalized');
    // raw text still carries the larded key — canonical hits never redact
    expect(r.redactedText === undefined || r.redactedText.includes(ZW)).toBe(true);
  });
  it('ON: unicode-trick injection detection still fires on raw text', () => {
    const r = inspectResponseText(`normal${ZW}text${ZW}here${ZW}now`, { canonicalPass: true });
    expect(r.findings.some((f) => f.category === 'injection')).toBe(true);
  });
});
