/**
 * Exact-Data-Match (EDM) / fingerprinting for `g0 proxy`.
 *
 * The user fingerprints their own sensitive corpus once — API keys, a DB
 * column dump, confidential doc lines — via `g0 proxy fingerprint <file>`.
 * The proxy then flags any of that EXACT data appearing in MCP traffic: in
 * a tool response, or (the exfil case) inside an outbound `tools/call`
 * request argument. Unlike the entropy/regex detectors in
 * `./detectors/structured.ts`, EDM has near-zero false positives — it never
 * "thinks something looks like a secret," it only ever confirms "this is
 * BYTE-FOR-BYTE a value the user told us to watch for" — and it is
 * sub-millisecond because matching is a hash-set/bloom-filter lookup, not a
 * regex scan.
 *
 * ── The plaintext-never-persists guarantee (read before touching this file) ─
 *
 * The whole point of fingerprinting is that the user's secrets/PII corpus
 * itself never has to be written to disk in recoverable form. The persisted
 * index file (`~/.g0/proxy/fingerprints/<name>.jsonl`) contains ONLY:
 *   - a per-index random salt (not secret — see below),
 *   - a typed-array bloom bitset (a lossy Bloom filter over salted hashes —
 *     not reversible to the inputs that set its bits),
 *   - a `Set` of full SHA-256 hex digests of `sha256(salt + '\0' + token)`.
 * A SHA-256 digest is a one-way function: recovering `token` from the
 * digest is computationally infeasible. The salt is deliberately NOT
 * treated as secret (it is stored right next to the hashes it salts) — its
 * job is only to stop the SAME token hashing to the same digest across two
 * DIFFERENT users'/indexes' fingerprint files (defeating cross-index rainbow
 * correlation), not to add secrecy on top of SHA-256 itself.
 * `tests/unit/proxy-edm.test.ts` asserts, on the raw persisted bytes, that
 * no corpus plaintext survives.
 *
 * ── Never throw / fail open ──────────────────────────────────────────────
 *
 * `EdmIndex.load` and `EdmIndex.match` run in `runProxy`'s per-line hot
 * path (see `proxy-core.ts`). A missing file, a corrupt/malformed file, or
 * any unexpected error during matching must never throw and must never
 * block the proxied JSON-RPC stream — they degrade to "no fingerprints
 * loaded" / "no matches found", exactly as if EDM were switched off.
 *
 * ── Tokenization / matching granularity (read this before wiring Task 5) ──
 *
 * A fingerprinted corpus is one entry per line (`g0 proxy fingerprint`
 * reads the corpus file one line at a time). What counts as a "match unit"
 * for that line depends on `--mode`:
 *
 *   `line` (default) — for secrets, keys, and DB column dumps: the WHOLE
 *   trimmed line is the token. A hit requires the exact value to appear
 *   somewhere in the scanned text, either as its own line or as a
 *   delimiter-bounded run of "value" characters (so `"apiKey":
 *   "sk-abc..."` embedded in JSON still matches the fingerprinted
 *   `sk-abc...` line). Case-sensitive — secrets are case-sensitive.
 *
 *   `shingle` — for prose/confidential doc lines, where the *exact same
 *   line* reappearing verbatim is a fragile signal (rewrapping, quoting, or
 *   partial pasting all break a whole-line match). Each corpus line is
 *   split into words and hashed as overlapping `shingleSize`-word n-grams
 *   (default 5), so a 5-word verbatim fragment of a fingerprinted line
 *   appearing anywhere in scanned text is enough to match. Matching is
 *   case-insensitive and whitespace-normalized (both at fingerprint time and
 *   match time) so re-flowed text still lines up.
 *
 * Both modes share the exact same hash/bloom machinery — only tokenization
 * differs. `EdmMatch` never carries the matched value, only the matching
 * index's name, a fixed `confidence: 0.99` (an exact hash match is the
 * strongest possible evidence — see the confidence-scale docblock in
 * `./detectors/structured.ts`), and machine-readable `signals`.
 *
 * ── Bounded work ─────────────────────────────────────────────────────────
 *
 * `match()` is called on untrusted, potentially huge text in the proxy's
 * hot path. It is gated by the SAME `maxScanBytes` budget the rest of the
 * proxy respects (see `response-inspector.ts`) — text past the budget is
 * skipped entirely, never scanned. Below that budget, tokenization is a
 * single linear pass (regex/`split`, no nested quantifiers) and each
 * candidate is hashed exactly ONCE (the same digest is reused for both the
 * bloom check and the exact-set confirmation) — so total work is strictly
 * `O(min(text.length, maxScanBytes))`, with no candidate-count cap that a
 * malicious server could exhaust with filler ahead of the real payload
 * (that exact class of bug — a count-based cap that becomes an evasion
 * vector — is why `./detectors/structured.ts` removed its own hit cap; see
 * that file's docblock. We don't reintroduce it here).
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// ─────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────

const DEFAULT_PROXY_DIR = path.join(os.homedir(), '.g0', 'proxy');

/** Same default as `response-inspector.ts`'s `DEFAULT_MAX_SCAN_BYTES` — one scan budget, one number. */
const DEFAULT_MAX_SCAN_BYTES = 1_000_000;

/** Target Bloom false-positive rate used when sizing a new index at build time. A bloom FP only costs one extra `Set.has()` — it can NEVER produce an incorrect EDM finding, because the exact hash set is the final arbiter — so this is tuned for compact storage, not for correctness. */
const DEFAULT_TARGET_FP_RATE = 0.01;

/** Minimum bloom bitset size, so a 1-entry corpus still gets a usable (if oversized-per-entry) filter rather than a degenerate few-bit one. */
const MIN_BLOOM_BITS = 64;

/** Hard ceiling on derived hash-function count — purely a sanity bound, not a correctness knob (see `bloomIndices`). */
const MAX_HASH_COUNT = 16;

const DEFAULT_SHINGLE_SIZE = 5;

/** Below this length a candidate token/shingle is not worth hashing — filters out stray single characters/punctuation runs without affecting real secrets (which are always longer). */
const MIN_TOKEN_LEN = 4;

export type EdmMode = 'line' | 'shingle';

// ─────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────

/**
 * A single index's match result for one `match()` call. Deliberately
 * carries NO matched value/snippet — see the module docblock's
 * plaintext-never-persists guarantee, which this type extends to
 * "plaintext never even transits a finding object."
 */
export interface EdmMatch {
  /** Name of the fingerprint index that matched (e.g. `"prod-secrets"`) — metadata only. */
  indexName: string;
  /** Always `0.99` — an exact hash match is the strongest possible evidence (see `./detectors/structured.ts`'s confidence-scale docblock). */
  confidence: number;
  /** Machine-readable signal labels, e.g. `['edm-exact-match', 'mode:line', 'hits:2']`. Never contains the matched value. */
  signals: string[];
}

/** On-disk shape of one fingerprint index file. Every field here is either non-secret metadata or a one-way hash — see the module docblock. */
interface PersistedEdmIndex {
  version: 1;
  name: string;
  mode: EdmMode;
  shingleSize?: number;
  /** Hex-encoded random salt — not secret, defeats cross-index correlation only. */
  salt: string;
  bloom: {
    bits: number;
    hashCount: number;
    /** Base64-encoded bitset. */
    bitset: string;
  };
  /** SHA-256 hex digests of `sha256(salt + '\0' + token)`. One-way; the corpus token cannot be recovered from these. */
  hashes: string[];
  /** Number of distinct tokens/shingles fingerprinted — a count, not the values themselves. */
  count: number;
}

function isPersistedEdmIndex(v: unknown): v is PersistedEdmIndex {
  if (v === null || typeof v !== 'object') return false;
  const o = v as Record<string, unknown>;
  if (typeof o.name !== 'string' || o.name.length === 0) return false;
  if (o.mode !== 'line' && o.mode !== 'shingle') return false;
  if (typeof o.salt !== 'string' || o.salt.length === 0) return false;
  if (!Array.isArray(o.hashes) || !o.hashes.every((h) => typeof h === 'string')) return false;
  const bloom = o.bloom as Record<string, unknown> | undefined;
  if (!bloom || typeof bloom !== 'object') return false;
  if (typeof bloom.bits !== 'number' || !Number.isFinite(bloom.bits) || bloom.bits <= 0) return false;
  if (typeof bloom.hashCount !== 'number' || !Number.isFinite(bloom.hashCount) || bloom.hashCount <= 0) return false;
  if (typeof bloom.bitset !== 'string') return false;
  return true;
}

// ─────────────────────────────────────────────────────────────────────────
// Bloom sizing
// ─────────────────────────────────────────────────────────────────────────

/**
 * Classic Bloom-filter sizing formulas, rounded to sane bounds:
 *   bits     = ceil(-(n * ln(p)) / (ln 2)^2)
 *   hashCount = round((bits / n) * ln 2)
 * `p` is the TARGET false-positive rate for the bloom prefilter, not for
 * EDM matching overall — a bloom false positive only costs one extra exact
 * `Set.has()` call; it can never itself produce a false EDM finding.
 */
export function bloomParams(n: number, targetFpRate: number = DEFAULT_TARGET_FP_RATE): { bits: number; hashCount: number } {
  const count = Math.max(1, Math.floor(Number.isFinite(n) ? n : 1));
  const p = Number.isFinite(targetFpRate) ? Math.min(0.5, Math.max(1e-6, targetFpRate)) : DEFAULT_TARGET_FP_RATE;
  let bits = Math.ceil(-(count * Math.log(p)) / (Math.LN2 * Math.LN2));
  bits = Math.max(MIN_BLOOM_BITS, bits);
  bits = Math.ceil(bits / 8) * 8; // byte-align
  let hashCount = Math.round((bits / count) * Math.LN2);
  hashCount = Math.min(MAX_HASH_COUNT, Math.max(1, hashCount));
  return { bits, hashCount };
}

// ─────────────────────────────────────────────────────────────────────────
// Tokenization (shared by build-time indexing and match-time scanning)
// ─────────────────────────────────────────────────────────────────────────

/**
 * `line` mode candidate extraction over arbitrary (untrusted) text: every
 * non-empty trimmed LINE (catches a fingerprinted line reappearing whole)
 * plus every delimiter-bounded run of "value" characters (catches a
 * fingerprinted secret embedded inline, e.g. `"apiKey": "sk-..."` in JSON).
 * Delimiters are whitespace and common wrapping/structural punctuation
 * (`"'\`,;(){}[]<>|`) — chosen so ordinary secret shapes (dots, dashes,
 * underscores, colons, slashes, `+`/`=` base64 padding, `@`) stay inside a
 * single candidate. Case-sensitive: secrets are case-sensitive.
 *
 * Single linear pass over `text` (`split` + one `/g` regex scan); no
 * candidate-count early-exit — see the module docblock's "bounded work"
 * section for why that would be an evasion vector, not a safety feature.
 */
const LINE_TOKEN_RE = /[^\s"'`,;(){}[\]<>|]+/g;

function lineModeCandidates(text: string): Iterable<string> {
  const seen = new Set<string>();
  for (const rawLine of text.split('\n')) {
    const t = rawLine.trim();
    if (t.length >= MIN_TOKEN_LEN) seen.add(t);
  }
  LINE_TOKEN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = LINE_TOKEN_RE.exec(text)) !== null) {
    if (m[0].length >= MIN_TOKEN_LEN) seen.add(m[0]);
  }
  return seen;
}

/** Word extraction for `shingle` mode: alnum runs, allowing an internal apostrophe/hyphen (so "don't"/"exfil-ready" stay one word). Lowercased for case-insensitive prose matching. */
const WORD_RE = /[A-Za-z0-9]+(?:['’-][A-Za-z0-9]+)*/g;

function wordsOf(text: string): string[] {
  const out: string[] = [];
  WORD_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = WORD_RE.exec(text)) !== null) {
    out.push(m[0].toLowerCase());
  }
  return out;
}

/**
 * `shingle` mode candidate extraction: overlapping `shingleSize`-word
 * n-grams across the whole (word-tokenized) text, space-joined and
 * lowercased — matches at fragment granularity and survives re-wrapping,
 * unlike a whole-line comparison. Sliding window over an already-bounded
 * word list -> `O(words.length * shingleSize)`, and `shingleSize` is a
 * small fixed constant (default 5), so this is linear in `text.length`.
 */
function shingleModeCandidates(text: string, shingleSize: number): Iterable<string> {
  const words = wordsOf(text);
  const size = Math.max(1, shingleSize);
  const seen = new Set<string>();
  if (words.length < size) {
    if (words.length > 0) {
      const whole = words.join(' ');
      if (whole.length >= MIN_TOKEN_LEN) seen.add(whole);
    }
    return seen;
  }
  for (let i = 0; i + size <= words.length; i++) {
    const shingle = words.slice(i, i + size).join(' ');
    if (shingle.length >= MIN_TOKEN_LEN) seen.add(shingle);
  }
  return seen;
}

// ─────────────────────────────────────────────────────────────────────────
// Hashing helpers (shared by build + match)
// ─────────────────────────────────────────────────────────────────────────

function digestFor(salt: string, token: string): Buffer {
  return crypto.createHash('sha256').update(salt, 'utf8').update('\0').update(token, 'utf8').digest();
}

/** Derive `hashCount` bit positions from one SHA-256 digest via double hashing (Kirsch-Mitzenmacher): `g_i(x) = h1(x) + i*h2(x) mod bits`. Reuses the SAME digest as the exact-set hex key — one hash per candidate, not `hashCount` hashes. */
function bloomIndices(digest: Buffer, bits: number, hashCount: number): number[] {
  const h1 = digest.readUInt32BE(0);
  const h2 = digest.readUInt32BE(4);
  const idxs: number[] = new Array(hashCount);
  for (let i = 0; i < hashCount; i++) {
    idxs[i] = ((h1 + i * h2) >>> 0) % bits;
  }
  return idxs;
}

function bitsetSet(bitset: Uint8Array, idx: number): void {
  bitset[idx >>> 3] |= 1 << (idx & 7);
}

function bitsetHas(bitset: Uint8Array, idx: number): boolean {
  return (bitset[idx >>> 3] & (1 << (idx & 7))) !== 0;
}

// ─────────────────────────────────────────────────────────────────────────
// EdmIndex
// ─────────────────────────────────────────────────────────────────────────

/**
 * One loaded fingerprint index: an in-memory exact-hash `Set` plus a
 * typed-array Bloom bitset prefilter. Construct via `EdmIndex.load(path)`
 * (never throws) or `EdmIndex.empty()` (an index that matches nothing, used
 * as the fail-open fallback).
 */
export class EdmIndex {
  private constructor(
    public readonly name: string,
    private readonly mode: EdmMode,
    private readonly shingleSize: number,
    private readonly salt: string,
    private readonly bits: number,
    private readonly hashCount: number,
    private readonly bitset: Uint8Array,
    private readonly hashes: Set<string>,
  ) {}

  /** An index with zero entries — `match()` short-circuits to `[]` immediately. Used for the missing/corrupt-file no-op path. */
  static empty(name = ''): EdmIndex {
    return new EdmIndex(name, 'line', DEFAULT_SHINGLE_SIZE, '', MIN_BLOOM_BITS, 1, new Uint8Array(1), new Set());
  }

  /** Number of distinct tokens/shingles this index was built from. */
  get size(): number {
    return this.hashes.size;
  }

  /**
   * Load a persisted fingerprint index. Never throws:
   *  - missing file (`ENOENT`) -> silently returns `EdmIndex.empty()`.
   *  - unreadable file, malformed JSON, or a JSON shape that fails
   *    `isPersistedEdmIndex`'s validation -> logs one diagnostic to stderr
   *    and returns `EdmIndex.empty()`. This runs once at proxy startup
   *    (not per-line), so the stderr write is safe and useful rather than
   *    hot-path noise.
   */
  static load(filePath: string): EdmIndex {
    let raw: string;
    try {
      raw = fs.readFileSync(filePath, 'utf-8');
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code !== 'ENOENT') {
        console.error(`g0 proxy: failed to read fingerprint index "${filePath}" (${(err as Error).message}); EDM disabled for this index`);
      }
      return EdmIndex.empty(path.basename(filePath).replace(/\.jsonl?$/, ''));
    }

    try {
      const parsed: unknown = JSON.parse(raw.trim().split('\n')[0] ?? raw);
      if (!isPersistedEdmIndex(parsed)) {
        console.error(`g0 proxy: fingerprint index "${filePath}" has an unrecognized shape; EDM disabled for this index`);
        return EdmIndex.empty(path.basename(filePath).replace(/\.jsonl?$/, ''));
      }

      const bitset = new Uint8Array(Buffer.from(parsed.bloom.bitset, 'base64'));
      const expectedBytes = Math.ceil(parsed.bloom.bits / 8);
      if (bitset.length < expectedBytes) {
        console.error(`g0 proxy: fingerprint index "${filePath}" has a truncated bloom bitset; EDM disabled for this index`);
        return EdmIndex.empty(parsed.name);
      }

      return new EdmIndex(
        parsed.name,
        parsed.mode,
        typeof parsed.shingleSize === 'number' && parsed.shingleSize > 0 ? parsed.shingleSize : DEFAULT_SHINGLE_SIZE,
        parsed.salt,
        parsed.bloom.bits,
        parsed.bloom.hashCount,
        bitset,
        new Set(parsed.hashes),
      );
    } catch (err) {
      console.error(
        `g0 proxy: failed to parse fingerprint index "${filePath}" (${(err as Error).message}); EDM disabled for this index`,
      );
      return EdmIndex.empty(path.basename(filePath).replace(/\.jsonl?$/, ''));
    }
  }

  private bloomMaybeHas(digest: Buffer): boolean {
    for (const idx of bloomIndices(digest, this.bits, this.hashCount)) {
      if (!bitsetHas(this.bitset, idx)) return false;
    }
    return true;
  }

  /**
   * Scan `text` for exact matches against this index. Never throws; always
   * bounded by `opts.maxScanBytes` (default matches
   * `response-inspector.ts`'s `DEFAULT_MAX_SCAN_BYTES`, 1 MB). Returns at
   * most ONE `EdmMatch` (this index either matched or it didn't — `signals`
   * carries a bounded hit COUNT, never the matched values) so callers never
   * have to further cap the result themselves.
   */
  match(text: string, opts?: { maxScanBytes?: number }): EdmMatch[] {
    try {
      if (this.hashes.size === 0) return []; // empty/no-op index
      if (typeof text !== 'string' || text.length === 0) return [];
      const maxScanBytes = opts?.maxScanBytes ?? DEFAULT_MAX_SCAN_BYTES;
      if (text.length > maxScanBytes) return []; // respect the scan budget; skip rather than truncate-scan

      const candidates =
        this.mode === 'shingle' ? shingleModeCandidates(text, this.shingleSize) : lineModeCandidates(text);

      let hits = 0;
      for (const candidate of candidates) {
        const digest = digestFor(this.salt, candidate);
        if (!this.bloomMaybeHas(digest)) continue; // cheap reject — the common case
        if (this.hashes.has(digest.toString('hex'))) hits++; // bloom can false-positive; the exact set cannot
      }

      if (hits === 0) return [];
      return [
        {
          indexName: this.name,
          confidence: 0.99,
          signals: ['edm-exact-match', `mode:${this.mode}`, `hits:${Math.min(hits, 9999)}`],
        },
      ];
    } catch {
      return []; // never throw out of the proxy's message loop
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────
// Session-level loading (all fingerprint indexes under one proxy dir)
// ─────────────────────────────────────────────────────────────────────────

/** `<dir>/fingerprints` — where `g0 proxy fingerprint` writes and `loadEdmIndexes` reads. */
export function fingerprintsDir(dir: string = DEFAULT_PROXY_DIR): string {
  return path.join(dir, 'fingerprints');
}

/**
 * Load every `*.jsonl` fingerprint index under `<dir>/fingerprints`. Never
 * throws: a missing/unreadable directory yields `[]` (no fingerprints
 * configured — EDM is a no-op), exactly like a missing single file. Meant
 * to be called ONCE per proxy session (see `runProxy` in `proxy-core.ts`,
 * right next to `loadPolicy`), not per message.
 */
export function loadEdmIndexes(dir: string = DEFAULT_PROXY_DIR): EdmIndex[] {
  try {
    const root = fingerprintsDir(dir);
    const files = fs.readdirSync(root).filter((f) => f.endsWith('.jsonl'));
    return files.map((f) => EdmIndex.load(path.join(root, f)));
  } catch {
    return []; // missing/unreadable fingerprints dir -> no indexes -> no-op
  }
}

/**
 * Run `text` through every loaded index and aggregate the (bounded, at most
 * one-per-index) matches. Never throws — an individual index's `match`
 * already can't throw, but this is defensive in case a future index
 * implementation does, mirroring `runStructuredDetectors`'s
 * one-bad-detector-can't-break-the-rest isolation.
 */
export function matchEdmIndexes(indexes: EdmIndex[], text: string, opts?: { maxScanBytes?: number }): EdmMatch[] {
  if (!Array.isArray(indexes) || indexes.length === 0) return [];
  const out: EdmMatch[] = [];
  for (const index of indexes) {
    try {
      out.push(...index.match(text, opts));
    } catch {
      continue;
    }
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────
// Builder — `g0 proxy fingerprint <file>`
// ─────────────────────────────────────────────────────────────────────────

export interface BuildEdmIndexOptions {
  name: string;
  mode: EdmMode;
  /** Only used when `mode === 'shingle'`. Defaults to 5. */
  shingleSize?: number;
  targetFpRate?: number;
}

export interface BuildEdmIndexResult {
  name: string;
  mode: EdmMode;
  /** Non-empty corpus lines read from the input file. */
  entryCount: number;
  /** Distinct tokens/shingles actually fingerprinted (what got hashed). */
  tokenCount: number;
  filePath: string;
}

/**
 * Build the JSON-serializable index structure for a corpus file, WITHOUT
 * writing anything to disk. Pure aside from the one `fs.readFileSync` of
 * the corpus. Split out from `buildAndWriteEdmIndex` so tests can inspect
 * the in-memory structure directly, independent of the write path.
 *
 * This is an offline, operator-invoked builder (`g0 proxy fingerprint`),
 * NOT part of the proxy's per-message hot path — unlike `EdmIndex.load`/
 * `match`, it is allowed to throw on I/O errors (missing corpus file, bad
 * permissions); the CLI action catches and reports those.
 */
export function buildEdmIndexData(
  corpusPath: string,
  opts: BuildEdmIndexOptions,
): { data: PersistedEdmIndex; entryCount: number } {
  const raw = fs.readFileSync(corpusPath, 'utf-8');
  const lines = raw.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const shingleSize = opts.shingleSize && opts.shingleSize > 0 ? Math.floor(opts.shingleSize) : DEFAULT_SHINGLE_SIZE;

  const tokens = new Set<string>();
  if (opts.mode === 'shingle') {
    for (const line of lines) {
      for (const shingle of shingleModeCandidates(line, shingleSize)) tokens.add(shingle);
    }
  } else {
    for (const line of lines) {
      const t = line.trim();
      if (t.length > 0) tokens.add(t);
    }
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const { bits, hashCount } = bloomParams(Math.max(1, tokens.size), opts.targetFpRate);
  const bitset = new Uint8Array(Math.ceil(bits / 8));
  const hashes: string[] = [];

  for (const token of tokens) {
    const digest = digestFor(salt, token);
    for (const idx of bloomIndices(digest, bits, hashCount)) bitsetSet(bitset, idx);
    hashes.push(digest.toString('hex'));
  }

  const data: PersistedEdmIndex = {
    version: 1,
    name: opts.name,
    mode: opts.mode,
    ...(opts.mode === 'shingle' ? { shingleSize } : {}),
    salt,
    bloom: { bits, hashCount, bitset: Buffer.from(bitset).toString('base64') },
    hashes,
    count: hashes.length,
  };

  return { data, entryCount: lines.length };
}

/**
 * Build a fingerprint index from `corpusPath` and write it to
 * `<outDir>/<name>.jsonl`. Only salted hashes + the bloom bitset are ever
 * written — see the module docblock's plaintext-never-persists guarantee.
 * Creates `outDir` (mode `0700`) if needed; the index file is written mode
 * `0600`. Throws on I/O failure (see `buildEdmIndexData`'s doc comment for
 * why that's fine here, unlike the rest of this module).
 */
export function buildAndWriteEdmIndex(corpusPath: string, outDir: string, opts: BuildEdmIndexOptions): BuildEdmIndexResult {
  const { data, entryCount } = buildEdmIndexData(corpusPath, opts);

  fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
  const filePath = path.join(outDir, `${opts.name}.jsonl`);
  fs.writeFileSync(filePath, JSON.stringify(data) + '\n', { mode: 0o600 });

  return { name: opts.name, mode: opts.mode, entryCount, tokenCount: data.count, filePath };
}
