import { describe, it, expect } from 'vitest';
import { classifyText, mergeCounts, PII_CLASSES } from '../../src/sentinel/pii.js';

describe('PII classifier — classes + counts, never raw values', () => {
  it('detects emails (distinct only)', () => {
    const c = classifyText('a@x.com, a@x.com, b@y.io');
    expect(c.email).toBe(2); // deduped
  });

  it('detects Luhn-valid credit cards and rejects invalid ones', () => {
    // 4111111111111111 is a canonical Luhn-valid test Visa; 4111111111111112 is not.
    const c = classifyText('card 4111 1111 1111 1111 and bad 4111111111111112');
    expect(c.credit_card).toBe(1);
  });

  it('detects US SSN, IPv4, AWS keys, sk- tokens, JWT, private keys', () => {
    const sample = [
      'ssn 123-45-6789',
      'ip 10.0.0.5 and 999.1.1.1',            // second is not a valid IPv4
      'AKIAIOSFODNN7EXAMPLE',                   // AWS access key id
      'sk-abcdefghijklmnopqrstuvwx1234567890',  // api token
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig', // jwt-ish
      '-----BEGIN RSA PRIVATE KEY-----',
    ].join('\n');
    const c = classifyText(sample);
    expect(c.us_ssn).toBe(1);
    expect(c.ipv4).toBe(1); // only the valid one
    expect(c.aws_access_key).toBe(1);
    expect(c.api_token).toBeGreaterThanOrEqual(1);
    expect(c.jwt).toBe(1);
    expect(c.private_key).toBe(1);
  });

  it('returns an empty object for clean text', () => {
    expect(Object.keys(classifyText('the quick brown fox jumps'))).toHaveLength(0);
  });

  it('never returns raw values — only class => count', () => {
    const c = classifyText('secret a@x.com 4111111111111111');
    for (const [k, v] of Object.entries(c)) {
      expect(PII_CLASSES).toContain(k);
      expect(typeof v).toBe('number');
    }
  });

  it('mergeCounts sums per class across artifacts', () => {
    const merged = mergeCounts([{ email: 2, ipv4: 1 }, { email: 3, us_ssn: 1 }]);
    expect(merged).toEqual({ email: 5, ipv4: 1, us_ssn: 1 });
  });
});
