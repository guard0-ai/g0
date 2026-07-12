import { describe, it, expect } from 'vitest';
import {
  creditCardDetector,
  ibanDetector,
  abaRoutingDetector,
  vendorKeyDetector,
  contextEntropyDetector,
  bareEntropyDetector,
  ALL_STRUCTURED_DETECTORS,
  runStructuredDetectors,
  CONFIDENCE,
  type StructuredDetector,
} from '../../src/proxy/detectors/structured.js';

describe('creditCardDetector', () => {
  it('flags a valid (Luhn-passing) published test PAN at high confidence', () => {
    const hits = creditCardDetector.find('card on file: 4111111111111111 exp 12/29');
    expect(hits.length).toBe(1);
    expect(hits[0].confidence).toBe(CONFIDENCE.HIGH);
    expect(hits[0].signals).toContain('luhn-valid');
  });

  it('flags a spaced/dashed card number', () => {
    const hits = creditCardDetector.find('4111 1111 1111 1111');
    expect(hits.length).toBe(1);
  });

  it('produces NO finding for a Luhn-failing 16-digit number (the whole point of this task)', () => {
    const hits = creditCardDetector.find('reference number: 4111111111111112 for your records');
    expect(hits).toEqual([]);
  });

  it('produces no finding for ordinary prose', () => {
    expect(creditCardDetector.find('the quick brown fox jumps over the lazy dog')).toEqual([]);
  });

  it('never throws on adversarial digit-heavy input', () => {
    const adversarial = '4'.repeat(50000);
    const start = Date.now();
    expect(() => creditCardDetector.find(adversarial)).not.toThrow();
    expect(Date.now() - start).toBeLessThan(1000);
  });
});

describe('ibanDetector', () => {
  it('flags a valid published IBAN at high confidence', () => {
    const hits = ibanDetector.find('wire to GB82WEST12345698765432 please');
    expect(hits.length).toBe(1);
    expect(hits[0].confidence).toBe(CONFIDENCE.HIGH);
    expect(hits[0].signals).toContain('iban-mod97-valid');
  });

  it('produces NO finding for an IBAN-shaped string with a bad check digit', () => {
    expect(ibanDetector.find('GB82WEST12345698765431')).toEqual([]);
  });

  it('produces no finding for ordinary uppercase text', () => {
    expect(ibanDetector.find('THIS IS JUST SHOUTING IN ALL CAPS TEXT')).toEqual([]);
  });
});

describe('abaRoutingDetector', () => {
  it('flags a real published ABA routing number at high confidence', () => {
    const hits = abaRoutingDetector.find('routing number 026009593 account 12345');
    expect(hits.length).toBe(1);
    expect(hits[0].confidence).toBe(CONFIDENCE.HIGH);
  });

  it('produces NO finding for a 9-digit number that fails the ABA checksum', () => {
    expect(abaRoutingDetector.find('order id 123456789 confirmed')).toEqual([]);
  });
});

describe('vendorKeyDetector', () => {
  it('flags a real-shaped AWS access key at high confidence', () => {
    const hits = vendorKeyDetector.find('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE');
    expect(hits.length).toBe(1);
    expect(hits[0].confidence).toBe(CONFIDENCE.HIGH);
  });

  it('flags a structurally valid JWT', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const hits = vendorKeyDetector.find(`Authorization: Bearer ${jwt}`);
    expect(hits.length).toBe(1);
    expect(hits[0].confidence).toBe(CONFIDENCE.HIGH);
  });

  it('produces no finding for ordinary words, even long ones', () => {
    expect(vendorKeyDetector.find('supercalifragilisticexpialidocious is a long word')).toEqual([]);
  });
});

describe('contextEntropyDetector and bareEntropyDetector', () => {
  it('flags a high-entropy token adjacent to a "key="/"token="-style keyword at medium confidence', () => {
    const hits = contextEntropyDetector.find('token=Zx9pQmT4vK2sR8wN1yB6cD3eF7gH0jL5 sent in header');
    expect(hits.length).toBe(1);
    expect(hits[0].confidence).toBe(CONFIDENCE.MEDIUM);
  });

  it('flags a bare high-entropy blob with no context/format at low confidence', () => {
    const hits = bareEntropyDetector.find('random blob follows: Zx9pQmT4vK2sR8wN1yB6cD3eF7gH0jL5 end');
    expect(hits.length).toBe(1);
    expect(hits[0].confidence).toBe(CONFIDENCE.LOW);
  });

  it('does not flag ordinary English prose, even long sentences', () => {
    const prose =
      'the quick brown fox jumps over the lazy dog while the weather stays sunny and mild throughout the afternoon';
    expect(contextEntropyDetector.find(prose)).toEqual([]);
    expect(bareEntropyDetector.find(prose)).toEqual([]);
  });

  it('does not flag a camelCase identifier or a UUID', () => {
    expect(bareEntropyDetector.find('someVeryLongVariableNameForTestingPurposesHere')).toEqual([]);
    expect(bareEntropyDetector.find('550e8400-e29b-41d4-a716-446655440000')).toEqual([]);
  });

  it('bareEntropyDetector does not duplicate a token already claimed by vendorKeyDetector', () => {
    // A real vendor-key-shaped token also happens to be high entropy; it
    // should only ever be reported once, by vendorKeyDetector, not again by
    // the low-confidence bare-entropy detector.
    const text = 'key: AKIAIOSFODNN7EXAMPLE (rotate before Friday)';
    expect(vendorKeyDetector.find(text).length).toBe(1);
    expect(bareEntropyDetector.find(text)).toEqual([]);
  });
});

describe('StructuredHit: full value vs truncated snippet', () => {
  it('carries the FULL match in `value` and a <=120-char snippet in `matchTruncated`', () => {
    // A long JWT (>120 chars). `value` must be the whole thing — it is the
    // redaction key, and truncating it would leave the secret's tail in the
    // forwarded response. `matchTruncated` is the display-only snippet.
    const b64u = (o: unknown) =>
      Buffer.from(JSON.stringify(o))
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    const header = b64u({ alg: 'HS256', typ: 'JWT' });
    const payload = b64u({
      sub: '1234567890',
      name: 'Alice Example',
      email: 'alice@example.com',
      roles: ['admin', 'billing', 'support'],
      org: 'acme-corp-production',
      iat: 1516239022,
    });
    const jwt = `${header}.${payload}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5cX9pQmT4vK2sR8wN1yB6cD`;
    expect(jwt.length).toBeGreaterThan(120);

    const hits = vendorKeyDetector.find(`Authorization: Bearer ${jwt}`);
    expect(hits.length).toBe(1);
    expect(hits[0].value).toBe(jwt); // full, untruncated — the redaction key
    expect(hits[0].value.length).toBeGreaterThan(120);
    expect(hits[0].matchTruncated.length).toBeLessThanOrEqual(120); // display only
    expect(jwt.startsWith(hits[0].matchTruncated)).toBe(true);
  });

  it('sets value === matchTruncated for short secrets that fit under the cap', () => {
    const hits = creditCardDetector.find('card 4111111111111111');
    expect(hits.length).toBe(1);
    expect(hits[0].value).toBe('4111111111111111');
    expect(hits[0].matchTruncated).toBe('4111111111111111');
  });
});

describe('runStructuredDetectors', () => {
  it('aggregates hits across all detectors with detectorId/category attached', () => {
    const text = 'card 4111111111111111 and routing 026009593';
    const hits = runStructuredDetectors(ALL_STRUCTURED_DETECTORS, text);
    expect(hits.length).toBeGreaterThanOrEqual(2);
    for (const hit of hits) {
      expect(typeof hit.detectorId).toBe('string');
      expect(typeof hit.category).toBe('string');
      expect(typeof hit.confidence).toBe('number');
      expect(Array.isArray(hit.signals)).toBe(true);
      expect(typeof hit.matchTruncated).toBe('string');
      expect(typeof hit.value).toBe('string');
      expect(hit.value.length).toBeGreaterThan(0);
    }
  });

  it('drops a hit that has no usable full `value` rather than redacting with a truncated key', () => {
    const noValue: StructuredDetector = {
      id: 'no-value',
      category: 'test-only',
      find() {
        return [
          { confidence: 0.9, signals: ['x'], matchTruncated: 'abc' } as unknown as ReturnType<
            StructuredDetector['find']
          >[number],
        ];
      },
    };
    const hits = runStructuredDetectors([noValue], 'anything');
    expect(hits).toEqual([]);
  });

  it('a throwing detector does not prevent other detectors from reporting', () => {
    const throwing: StructuredDetector = {
      id: 'throws-always',
      category: 'test-only',
      find() {
        throw new Error('boom');
      },
    };
    const text = 'card 4111111111111111';
    const hits = runStructuredDetectors([throwing, creditCardDetector], text);
    expect(hits.some((h) => h.detectorId === 'credit-card')).toBe(true);
    expect(hits.some((h) => h.detectorId === 'throws-always')).toBe(false);
  });

  it('a detector returning garbage (non-array) does not throw', () => {
    const garbage: StructuredDetector = {
      id: 'garbage',
      category: 'test-only',
      find() {
        return null as unknown as ReturnType<StructuredDetector['find']>;
      },
    };
    expect(() => runStructuredDetectors([garbage], 'anything')).not.toThrow();
  });

  it('never throws on a 100KB adversarial string and completes quickly', () => {
    const adversarial = ('4'.repeat(19) + ' ').repeat(3000) + 'A'.repeat(20000);
    const start = Date.now();
    expect(() => runStructuredDetectors(ALL_STRUCTURED_DETECTORS, adversarial)).not.toThrow();
    expect(Date.now() - start).toBeLessThan(2000);
  });
});
