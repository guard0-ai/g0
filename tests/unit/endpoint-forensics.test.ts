import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// ─── Store Locations ────────────────────────────────────────────────────────

describe('forensics store locations', () => {
  it('covers major AI conversation tools', async () => {
    const { STORE_LOCATIONS } = await import('../../src/endpoint/forensics-scanner.js');

    const toolNames = STORE_LOCATIONS.map(l => l.tool);
    expect(toolNames).toContain('Claude Desktop');
    expect(toolNames).toContain('Claude Code');
    expect(toolNames).toContain('ChatGPT Desktop');
    expect(toolNames).toContain('Cursor');
    expect(toolNames).toContain('Cline');
    expect(toolNames).toContain('Continue');
    expect(toolNames).toContain('Roo Code');
  });

  it('each location has valid store type', async () => {
    const { STORE_LOCATIONS } = await import('../../src/endpoint/forensics-scanner.js');

    const validTypes = ['sqlite', 'json', 'leveldb'];
    for (const loc of STORE_LOCATIONS) {
      expect(validTypes).toContain(loc.type);
      expect(loc.paths.length).toBeGreaterThan(0);
      expect(loc.dbPatterns.length).toBeGreaterThan(0);
    }
  });
});

// ─── JSON Metadata Extraction ───────────────────────────────────────────────

describe('extractJsonMetadata', () => {
  it('counts JSON files in a directory', async () => {
    const { extractJsonMetadata } = await import('../../src/endpoint/forensics-scanner.js');

    // Create a temp dir with some JSON files
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-forensics-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'session1.json'), '{"id":1}');
      fs.writeFileSync(path.join(tmpDir, 'session2.json'), '{"id":2}');

      const meta = extractJsonMetadata(tmpDir, ['*.json']);
      expect(meta.conversationCount).toBe(2);
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it('counts subdirectories as conversations', async () => {
    const { extractJsonMetadata } = await import('../../src/endpoint/forensics-scanner.js');

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-forensics-'));
    try {
      const subDir = path.join(tmpDir, 'conv1');
      fs.mkdirSync(subDir);
      fs.writeFileSync(path.join(subDir, 'messages.jsonl'), '{"role":"user"}\n{"role":"assistant"}\n');

      const meta = extractJsonMetadata(tmpDir, ['*.jsonl']);
      expect(meta.conversationCount).toBe(1);
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  });

  it('returns zeros for non-existent directory', async () => {
    const { extractJsonMetadata } = await import('../../src/endpoint/forensics-scanner.js');

    const meta = extractJsonMetadata('/nonexistent/path', ['*.json']);
    expect(meta.conversationCount).toBe(0);
    expect(meta.messageCount).toBe(0);
  });
});

// ─── SQLite Encryption Check ────────────────────────────────────────────────

describe('isSQLiteEncrypted', () => {
  it('returns false for standard SQLite file', async () => {
    const { isSQLiteEncrypted } = await import('../../src/endpoint/forensics-scanner.js');

    const tmpFile = path.join(os.tmpdir(), `g0-test-${Date.now()}.db`);
    try {
      // Write standard SQLite header
      const header = Buffer.from('SQLite format 3\0');
      fs.writeFileSync(tmpFile, header);

      expect(isSQLiteEncrypted(tmpFile)).toBe(false);
    } finally {
      try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
    }
  });

  it('returns true for non-SQLite file', async () => {
    const { isSQLiteEncrypted } = await import('../../src/endpoint/forensics-scanner.js');

    const tmpFile = path.join(os.tmpdir(), `g0-test-${Date.now()}.db`);
    try {
      // Write encrypted/non-standard header
      fs.writeFileSync(tmpFile, 'NOT_SQLITE_DATA_HERE');

      expect(isSQLiteEncrypted(tmpFile)).toBe(true);
    } finally {
      try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
    }
  });

  it('returns false for non-existent file', async () => {
    const { isSQLiteEncrypted } = await import('../../src/endpoint/forensics-scanner.js');
    expect(isSQLiteEncrypted('/nonexistent/file.db')).toBe(false);
  });
});

// ─── Full Scan Shape ────────────────────────────────────────────────────────

describe('scanForensics', () => {
  it('returns valid ForensicsScanResult shape', async () => {
    const { scanForensics } = await import('../../src/endpoint/forensics-scanner.js');

    const result = scanForensics();

    expect(result).toHaveProperty('stores');
    expect(result).toHaveProperty('summary');
    expect(Array.isArray(result.stores)).toBe(true);
    expect(typeof result.summary.totalStores).toBe('number');
    expect(typeof result.summary.totalConversations).toBe('number');
    expect(typeof result.summary.totalMessages).toBe('number');
    expect(typeof result.summary.totalSizeBytes).toBe('number');
  });
});
