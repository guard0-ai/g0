import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { execFileSync } from 'node:child_process';
import type { ConversationStore, ForensicsScanResult } from '../types/endpoint.js';

const HOME = os.homedir();

// ─── Conversation Store Locations ───────────────────────────────────────────

interface StoreLocation {
  tool: string;
  paths: string[];
  type: 'sqlite' | 'json' | 'leveldb';
  /** Glob-like patterns for DB files within the directory */
  dbPatterns: string[];
}

const STORE_LOCATIONS: StoreLocation[] = [
  {
    tool: 'Claude Desktop',
    paths: [
      path.join(HOME, 'Library/Application Support/Claude'),
      path.join(HOME, '.config/claude'),
    ],
    type: 'sqlite',
    dbPatterns: ['*.db', '*.sqlite', '*.sqlite3'],
  },
  {
    tool: 'ChatGPT Desktop',
    paths: [
      path.join(HOME, 'Library/Application Support/com.openai.chat'),
    ],
    type: 'sqlite',
    dbPatterns: ['*.db', '*.sqlite'],
  },
  {
    tool: 'Cursor',
    paths: [
      path.join(HOME, 'Library/Application Support/Cursor/User/globalStorage'),
      path.join(HOME, '.config/Cursor/User/globalStorage'),
    ],
    type: 'sqlite',
    dbPatterns: ['*.db', '*.sqlite', '*.vscdb'],
  },
  {
    tool: 'Claude Code',
    paths: [
      path.join(HOME, '.claude/projects'),
    ],
    type: 'json',
    dbPatterns: ['*.jsonl'],
  },
  {
    tool: 'Cline',
    paths: [
      path.join(HOME, 'Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev'),
      path.join(HOME, '.config/Code/User/globalStorage/saoudrizwan.claude-dev'),
    ],
    type: 'json',
    dbPatterns: ['*.json'],
  },
  {
    tool: 'Continue',
    paths: [
      path.join(HOME, '.continue/sessions'),
    ],
    type: 'json',
    dbPatterns: ['*.json'],
  },
  {
    tool: 'Roo Code',
    paths: [
      path.join(HOME, 'Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline'),
      path.join(HOME, '.config/Code/User/globalStorage/rooveterinaryinc.roo-cline'),
    ],
    type: 'json',
    dbPatterns: ['*.json'],
  },
];

// ─── SQLite Metadata Extraction ─────────────────────────────────────────────

/**
 * Extract conversation metadata from a SQLite DB using the `sqlite3` CLI.
 * We only read metadata (counts, dates) — never conversation content.
 */
function extractSQLiteMetadata(dbPath: string): {
  conversationCount: number;
  messageCount: number;
  oldestDate: string | null;
  newestDate: string | null;
} {
  // List of common table/column names for conversations
  const queries = [
    // Claude Desktop schema
    `SELECT COUNT(DISTINCT conversation_id), COUNT(*), MIN(created_at), MAX(created_at) FROM messages;`,
    // Generic "conversations" + "messages" schema
    `SELECT (SELECT COUNT(*) FROM conversations), COUNT(*), MIN(created_at), MAX(created_at) FROM messages;`,
    // Cursor/VSCode schema
    `SELECT COUNT(DISTINCT session_id), COUNT(*), MIN(timestamp), MAX(timestamp) FROM entries;`,
  ];

  for (const query of queries) {
    try {
      const output = execFileSync('sqlite3', ['-separator', '|', dbPath, query], {
        encoding: 'utf-8',
        timeout: 5000,
        stdio: ['pipe', 'pipe', 'pipe'],
      }).trim();

      if (!output) continue;

      const parts = output.split('|');
      if (parts.length >= 4) {
        return {
          conversationCount: parseInt(parts[0], 10) || 0,
          messageCount: parseInt(parts[1], 10) || 0,
          oldestDate: parts[2] || null,
          newestDate: parts[3] || null,
        };
      }
    } catch {
      // Query failed (table doesn't exist), try next
    }
  }

  // Fallback: just count tables and get file modification date
  try {
    const output = execFileSync('sqlite3', [dbPath, `.tables`], {
      encoding: 'utf-8',
      timeout: 3000,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();

    const tableCount = output ? output.split(/\s+/).length : 0;
    const stat = fs.statSync(dbPath);
    return {
      conversationCount: tableCount > 0 ? -1 : 0, // -1 = unknown but tables exist
      messageCount: 0,
      oldestDate: null,
      newestDate: stat.mtime.toISOString(),
    };
  } catch {
    return { conversationCount: 0, messageCount: 0, oldestDate: null, newestDate: null };
  }
}

// ─── JSON/JSONL Metadata Extraction ─────────────────────────────────────────

function extractJsonMetadata(dirPath: string, patterns: string[]): {
  conversationCount: number;
  messageCount: number;
  oldestDate: string | null;
  newestDate: string | null;
} {
  let convCount = 0;
  let msgCount = 0;
  let oldest: Date | null = null;
  let newest: Date | null = null;

  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });

    for (const entry of entries) {
      if (entry.isDirectory()) {
        // Each subdirectory may be a conversation (e.g., Claude Code projects)
        convCount++;
        const subFiles = safeReaddir(path.join(dirPath, entry.name));
        for (const sf of subFiles) {
          if (sf.endsWith('.jsonl') || sf.endsWith('.json')) {
            msgCount += countJsonlLines(path.join(dirPath, entry.name, sf));
            updateDateRange(path.join(dirPath, entry.name, sf));
          }
        }
      } else if (matchesPatterns(entry.name, patterns)) {
        convCount++;
        if (entry.name.endsWith('.jsonl')) {
          msgCount += countJsonlLines(path.join(dirPath, entry.name));
        }
        updateDateRange(path.join(dirPath, entry.name));
      }
    }

    function updateDateRange(filePath: string) {
      try {
        const stat = fs.statSync(filePath);
        if (!oldest || stat.birthtime < oldest) oldest = stat.birthtime;
        if (!newest || stat.mtime > newest) newest = stat.mtime;
      } catch { /* skip */ }
    }
  } catch {
    // Dir not readable
  }

  return {
    conversationCount: convCount,
    messageCount: msgCount,
    oldestDate: oldest ? (oldest as Date).toISOString() : null,
    newestDate: newest ? (newest as Date).toISOString() : null,
  };
}

function countJsonlLines(filePath: string): number {
  try {
    // Read first 1MB max to estimate line count
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(1024 * 1024);
    const bytesRead = fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);

    const content = buf.toString('utf-8', 0, bytesRead);
    return content.split('\n').filter(l => l.trim()).length;
  } catch {
    return 0;
  }
}

function matchesPatterns(name: string, patterns: string[]): boolean {
  for (const p of patterns) {
    const ext = p.replace('*', '');
    if (name.endsWith(ext)) return true;
  }
  return false;
}

function safeReaddir(dir: string): string[] {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}

// ─── Check SQLite Encryption ────────────────────────────────────────────────

function isSQLiteEncrypted(filePath: string): boolean {
  try {
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(16);
    fs.readSync(fd, buf, 0, 16, 0);
    fs.closeSync(fd);
    return buf.toString('utf-8', 0, 15) !== 'SQLite format 3';
  } catch {
    return false;
  }
}

// ─── Main Scanner ───────────────────────────────────────────────────────────

export function scanForensics(): ForensicsScanResult {
  const stores: ConversationStore[] = [];

  for (const loc of STORE_LOCATIONS) {
    for (const dirPath of loc.paths) {
      try {
        if (!fs.existsSync(dirPath)) continue;
        const stat = fs.statSync(dirPath);
        if (!stat.isDirectory()) continue;

        if (loc.type === 'sqlite') {
          // Find SQLite files
          const dbFiles = findDBFiles(dirPath, loc.dbPatterns);
          for (const dbFile of dbFiles) {
            const meta = extractSQLiteMetadata(dbFile);
            if (meta.conversationCount === 0 && meta.messageCount === 0) continue;

            const fileStat = fs.statSync(dbFile);
            stores.push({
              tool: loc.tool,
              path: dbFile,
              storeType: 'sqlite',
              conversationCount: meta.conversationCount,
              messageCount: meta.messageCount,
              oldestDate: meta.oldestDate,
              newestDate: meta.newestDate,
              sizeBytes: fileStat.size,
              encrypted: isSQLiteEncrypted(dbFile),
            });
          }
        } else {
          // JSON/JSONL — scan directory
          const meta = extractJsonMetadata(dirPath, loc.dbPatterns);
          if (meta.conversationCount === 0) continue;

          const dirSize = getDirectorySize(dirPath, 1);
          stores.push({
            tool: loc.tool,
            path: dirPath,
            storeType: 'json',
            conversationCount: meta.conversationCount,
            messageCount: meta.messageCount,
            oldestDate: meta.oldestDate,
            newestDate: meta.newestDate,
            sizeBytes: dirSize,
            encrypted: false,
          });
        }
      } catch {
        // Skip inaccessible locations
      }
    }
  }

  // Build summary
  let totalConversations = 0;
  let totalMessages = 0;
  let oldestActivity: string | null = null;
  let newestActivity: string | null = null;
  let totalSize = 0;

  for (const store of stores) {
    if (store.conversationCount > 0) totalConversations += store.conversationCount;
    totalMessages += store.messageCount;
    totalSize += store.sizeBytes;

    if (store.oldestDate) {
      if (!oldestActivity || store.oldestDate < oldestActivity) oldestActivity = store.oldestDate;
    }
    if (store.newestDate) {
      if (!newestActivity || store.newestDate > newestActivity) newestActivity = store.newestDate;
    }
  }

  return {
    stores,
    summary: {
      totalStores: stores.length,
      totalConversations,
      totalMessages,
      oldestActivity,
      newestActivity,
      totalSizeBytes: totalSize,
    },
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function findDBFiles(dir: string, patterns: string[]): string[] {
  const files: string[] = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isFile() && matchesPatterns(entry.name, patterns)) {
        files.push(path.join(dir, entry.name));
      }
      // Check one level deep
      if (entry.isDirectory()) {
        try {
          const subEntries = fs.readdirSync(path.join(dir, entry.name));
          for (const sub of subEntries) {
            if (matchesPatterns(sub, patterns)) {
              files.push(path.join(dir, entry.name, sub));
            }
          }
        } catch { /* skip */ }
      }
    }
  } catch { /* skip */ }
  return files;
}

function getDirectorySize(dirPath: string, maxDepth: number): number {
  if (maxDepth < 0) return 0;
  let total = 0;
  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      try {
        if (entry.isFile()) {
          total += fs.statSync(fullPath).size;
        } else if (entry.isDirectory()) {
          total += getDirectorySize(fullPath, maxDepth - 1);
        }
      } catch { /* skip */ }
    }
  } catch { /* skip */ }
  return total;
}

// Exported for testing
export { STORE_LOCATIONS, extractJsonMetadata, isSQLiteEncrypted };
