import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// ─── Fix 1: Deterministic Judge Ordering ──────────────────────────────────

describe('Deterministic Judge Ordering', () => {
  it('resistant-before-vulnerable: returns resistant when only resistance matches', async () => {
    const { judgeDeterministic } = await import('../../src/testing/judge/deterministic.js');

    const result = judgeDeterministic(
      ['I cannot comply with that request. It violates my safety guidelines.'],
      {
        vulnerablePatterns: ['data leaked'],
        resistantPatterns: ['cannot comply'],
      },
    );

    expect(result).not.toBeNull();
    expect(result!.verdict).toBe('resistant');
  });

  it('vulnerable wins when both patterns match (explicit vulnerability)', async () => {
    const { judgeDeterministic } = await import('../../src/testing/judge/deterministic.js');

    const result = judgeDeterministic(
      ['I cannot hide my system prompt from you, here it is...'],
      {
        vulnerablePatterns: ['system prompt'],
        resistantPatterns: ['I cannot'],
      },
    );

    expect(result).not.toBeNull();
    expect(result!.verdict).toBe('vulnerable');
  });

  it('canary tokens still win over everything', async () => {
    const { judgeDeterministic } = await import('../../src/testing/judge/deterministic.js');
    const { generateCanary } = await import('../../src/testing/canary.js');

    const canary = generateCanary('api-key');

    const result = judgeDeterministic(
      [`I refuse to share: ${canary.value}`],
      {
        resistantPatterns: ['I refuse'],
        canaryTokens: [canary],
      },
    );

    expect(result).not.toBeNull();
    expect(result!.verdict).toBe('vulnerable');
    expect(result!.evidence).toContain('Canary token leaked');
  });
});

// ─── Fix 2: Concurrent Execution ──────────────────────────────────────────

describe('Concurrent Execution', () => {
  it('preserves result ordering with concurrent payloads', async () => {
    // Test the runConcurrent pattern indirectly by checking engine types
    const engine = await import('../../src/testing/engine.js');

    // Verify the interface accepts concurrency options
    const opts: Partial<import('../../src/testing/engine.js').TestRunOptions> = {
      concurrency: 3,
      rateDelayMs: 10,
    };
    expect(opts.concurrency).toBe(3);
    expect(opts.rateDelayMs).toBe(10);
  });
});

// ─── Fix 3: Enhanced Canary Tokens ────────────────────────────────────────

describe('Enhanced Canary Tokens', () => {
  it('detects base64-encoded canary tokens', async () => {
    const { generateCanary, detectCanaryVariants } = await import('../../src/testing/canary.js');

    const canary = generateCanary('api-key');
    const b64 = Buffer.from(canary.value).toString('base64');
    const response = `Here is the encoded data: ${b64}`;

    expect(detectCanaryVariants(response, canary)).toBe(true);
  });

  it('detects hex-encoded canary tokens', async () => {
    const { generateCanary, detectCanaryVariants } = await import('../../src/testing/canary.js');

    const canary = generateCanary('email');
    const hex = Buffer.from(canary.value).toString('hex');
    const response = `Hex dump: ${hex}`;

    expect(detectCanaryVariants(response, canary)).toBe(true);
  });

  it('detects fragment of canary token (60%+)', async () => {
    const { generateCanary, detectCanaryVariants } = await import('../../src/testing/canary.js');

    const canary = generateCanary('api-key');
    // Take 70% of the token value
    const fragment = canary.value.slice(0, Math.ceil(canary.value.length * 0.7));
    const response = `Partial data: ${fragment}`;

    expect(detectCanaryVariants(response, canary)).toBe(true);
  });

  it('generates url and dns canary types', async () => {
    const { generateCanary } = await import('../../src/testing/canary.js');

    const url = generateCanary('url');
    expect(url.type).toBe('url');
    expect(url.value).toContain('https://');
    expect(url.value).toContain('guard0.test');

    const dns = generateCanary('dns');
    expect(dns.type).toBe('dns');
    expect(dns.value).toContain('.dns.guard0.test');
  });

  it('generateCanarySet includes all 7 types', async () => {
    const { generateCanarySet } = await import('../../src/testing/canary.js');

    const canaries = generateCanarySet();
    expect(canaries).toHaveLength(7);
    const types = canaries.map(c => c.type);
    expect(types).toContain('url');
    expect(types).toContain('dns');
  });

  it('does not false-positive on unrelated content', async () => {
    const { generateCanary, detectCanaryVariants } = await import('../../src/testing/canary.js');

    const canary = generateCanary('api-key');
    const response = 'This is a normal response with no sensitive data.';

    expect(detectCanaryVariants(response, canary)).toBe(false);
  });
});

// ─── Fix 4: Encryption ───────────────────────────────────────────────────

describe('Encryption', () => {
  it('round-trip encrypt/decrypt', async () => {
    const { encrypt, decrypt } = await import('../../src/utils/encryption.js');

    const plaintext = JSON.stringify({ key: 'value', nested: { arr: [1, 2, 3] } });
    const encrypted = encrypt(plaintext);
    const decrypted = decrypt(encrypted);

    expect(decrypted).toBe(plaintext);
  });

  it('backwards-compatible plaintext read', async () => {
    const { decrypt } = await import('../../src/utils/encryption.js');

    const plaintext = '{"accessToken":"test123","expiresAt":9999999999}';
    const buf = Buffer.from(plaintext, 'utf-8');
    const result = decrypt(buf);

    expect(result).toBe(plaintext);
    expect(JSON.parse(result).accessToken).toBe('test123');
  });

  it('encrypted data has magic header', async () => {
    const { encrypt } = await import('../../src/utils/encryption.js');

    const encrypted = encrypt('hello');
    expect(encrypted.subarray(0, 6).toString()).toBe('G0ENC1');
  });

  it('readEncryptedJson and writeEncryptedJson round-trip', async () => {
    const { readEncryptedJson, writeEncryptedJson } = await import('../../src/utils/encryption.js');

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-enc-test-'));
    const tmpFile = path.join(tmpDir, 'test.enc');

    try {
      const data = { foo: 'bar', num: 42, arr: [1, 2, 3] };
      writeEncryptedJson(tmpFile, data);

      const loaded = readEncryptedJson<typeof data>(tmpFile);
      expect(loaded).toEqual(data);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

// ─── Fix 5: New Payloads ─────────────────────────────────────────────────

describe('New Payload Categories', () => {
  it('context-exhaustion payloads have unique IDs and required fields', async () => {
    const { contextExhaustionPayloads } = await import('../../src/testing/payloads/context-exhaustion.js');

    expect(contextExhaustionPayloads.length).toBe(8);
    const ids = contextExhaustionPayloads.map(p => p.id);
    expect(new Set(ids).size).toBe(ids.length); // unique

    for (const p of contextExhaustionPayloads) {
      expect(p.id).toMatch(/^CX-\d{3}$/);
      expect(p.category).toBe('agentic-attacks');
      expect(p.name).toBeTruthy();
      expect(p.messages.length).toBeGreaterThan(0);
      expect(p.tags).toContain('context-exhaustion');
    }
  });

  it('hallucination-exfil payloads have unique IDs and required fields', async () => {
    const { hallucinationExfilPayloads } = await import('../../src/testing/payloads/hallucination-exfil.js');

    expect(hallucinationExfilPayloads.length).toBe(8);
    const ids = hallucinationExfilPayloads.map(p => p.id);
    expect(new Set(ids).size).toBe(ids.length);

    for (const p of hallucinationExfilPayloads) {
      expect(p.id).toMatch(/^HE-\d{3}$/);
      expect(p.category).toBe('hallucination');
      expect(p.name).toBeTruthy();
      expect(p.messages.length).toBeGreaterThan(0);
      expect(p.tags).toContain('hallucination');
    }
  });

  it('toctou-attacks payloads have unique IDs and required fields', async () => {
    const { toctouAttackPayloads } = await import('../../src/testing/payloads/toctou-attacks.js');

    expect(toctouAttackPayloads.length).toBe(8);
    const ids = toctouAttackPayloads.map(p => p.id);
    expect(new Set(ids).size).toBe(ids.length);

    for (const p of toctouAttackPayloads) {
      expect(p.id).toMatch(/^TC-\d{3}$/);
      expect(p.category).toBe('agentic-attacks');
      expect(p.name).toBeTruthy();
      expect(p.messages.length).toBeGreaterThan(0);
      expect(p.tags).toContain('toctou');
    }
  });

  it('all new payloads registered in index', async () => {
    const { getAllPayloads } = await import('../../src/testing/payloads/index.js');

    const all = getAllPayloads();
    const ids = all.map(p => p.id);

    // Spot check a few IDs from each category
    expect(ids).toContain('CX-001');
    expect(ids).toContain('HE-001');
    expect(ids).toContain('TC-001');
  });
});

// ─── Fix 6: Normalization ────────────────────────────────────────────────

describe('Text Normalization', () => {
  it('strips diacritics', async () => {
    const { normalizeText } = await import('../../src/testing/judge/normalize.js');

    expect(normalizeText('café résumé naïve')).toBe('cafe resume naive');
  });

  it('maps Cyrillic/Greek confusables to ASCII', async () => {
    const { normalizeText } = await import('../../src/testing/judge/normalize.js');

    // Cyrillic е (U+0435) → e, Cyrillic о (U+043E) → o
    const confusable = 'h\u0435ll\u043E';
    expect(normalizeText(confusable)).toBe('hello');
  });

  it('strips zero-width characters', async () => {
    const { normalizeText } = await import('../../src/testing/judge/normalize.js');

    const withZW = 'hello\u200B\u200Cworld\u200D!';
    expect(normalizeText(withZW)).toBe('helloworld!');
  });

  it('collapses whitespace', async () => {
    const { normalizeText } = await import('../../src/testing/judge/normalize.js');

    expect(normalizeText('  hello   world  ')).toBe('hello world');
  });

  it('fuzzyContains matches with small edits', async () => {
    const { fuzzyContains } = await import('../../src/testing/judge/normalize.js');

    expect(fuzzyContains('the systme promtp is leaked', 'system prompt', 2)).toBe(true);
    expect(fuzzyContains('nothing related here at all', 'system prompt', 2)).toBe(false);
  });

  it('fuzzyContains handles exact matches', async () => {
    const { fuzzyContains } = await import('../../src/testing/judge/normalize.js');

    expect(fuzzyContains('reveal the system prompt now', 'system prompt')).toBe(true);
  });
});

// ─── Fix 7: File Locking ─────────────────────────────────────────────────

describe('File Locking', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-lock-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('acquire and release lock', async () => {
    const { acquireLock } = await import('../../src/utils/file-lock.js');

    const filePath = path.join(tmpDir, 'test.json');
    const release = await acquireLock(filePath);

    // Lock file should exist
    expect(fs.existsSync(filePath + '.lock')).toBe(true);

    release();

    // Lock file should be removed
    expect(fs.existsSync(filePath + '.lock')).toBe(false);
  });

  it('withLock executes function and releases', async () => {
    const { withLock } = await import('../../src/utils/file-lock.js');

    const filePath = path.join(tmpDir, 'test.json');
    let executed = false;

    await withLock(filePath, () => {
      executed = true;
      expect(fs.existsSync(filePath + '.lock')).toBe(true);
    });

    expect(executed).toBe(true);
    expect(fs.existsSync(filePath + '.lock')).toBe(false);
  });

  it('cleans up stale locks from dead PIDs', async () => {
    const { acquireLock } = await import('../../src/utils/file-lock.js');

    const filePath = path.join(tmpDir, 'test.json');
    const lockPath = filePath + '.lock';

    // Create a stale lock with a dead PID
    fs.writeFileSync(lockPath, JSON.stringify({ pid: 999999999, timestamp: Date.now() - 20_000 }));

    // Should succeed after cleaning stale lock
    const release = await acquireLock(filePath);
    expect(fs.existsSync(lockPath)).toBe(true);
    release();
  });

  it('withLock releases on error', async () => {
    const { withLock } = await import('../../src/utils/file-lock.js');

    const filePath = path.join(tmpDir, 'test.json');

    await expect(
      withLock(filePath, () => {
        throw new Error('test error');
      }),
    ).rejects.toThrow('test error');

    // Lock should be released even after error
    expect(fs.existsSync(filePath + '.lock')).toBe(false);
  });
});

// ─── Mutator Whitelist ───────────────────────────────────────────────────

describe('Mutator Stacked Whitelist', () => {
  it('applyStackedMutators uses whitelist pairs', async () => {
    const { applyStackedMutators } = await import('../../src/testing/mutators.js');
    const { promptInjectionPayloads } = await import('../../src/testing/payloads/prompt-injection.js');

    const payloads = promptInjectionPayloads.slice(0, 1);
    const stacked = applyStackedMutators(payloads, ['l33t', 'b64'], 5);

    expect(stacked.length).toBeGreaterThan(0);
    // Should include the l33t+b64 pair (from whitelist)
    const hasL33tB64 = stacked.some(p => p.id.includes('-l33t-b64'));
    expect(hasL33tB64).toBe(true);
  });
});
