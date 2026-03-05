import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type {
  CredentialExposure,
  DataStoreExposure,
  ArtifactScanResult,
  ArtifactFinding,
  KeyType,
} from '../types/endpoint.js';
import type { MCPFindingSeverity } from '../types/mcp-scan.js';
import type { MCPScanResult } from '../types/mcp-scan.js';

const HOME = os.homedir();

// ─── API Key Patterns ────────────────────────────────────────────────────────

interface KeyPattern {
  type: KeyType;
  label: string;
  /** Regex that captures the key value */
  pattern: RegExp;
  /** Env var names that typically hold this key */
  envVars: string[];
}

const KEY_PATTERNS: KeyPattern[] = [
  {
    type: 'anthropic',
    label: 'Anthropic',
    pattern: /\b(sk-ant-api03-[A-Za-z0-9_-]{80,})\b/,
    envVars: ['ANTHROPIC_API_KEY'],
  },
  {
    type: 'openai',
    label: 'OpenAI',
    pattern: /\b(sk-proj-[A-Za-z0-9_-]{40,})\b/,
    envVars: ['OPENAI_API_KEY'],
  },
  {
    type: 'openai',
    label: 'OpenAI (legacy)',
    pattern: /\b(sk-[A-Za-z0-9]{32,})\b/,
    envVars: [],
  },
  {
    type: 'google',
    label: 'Google AI',
    pattern: /\b(AIza[A-Za-z0-9_-]{35})\b/,
    envVars: ['GOOGLE_API_KEY', 'GEMINI_API_KEY'],
  },
  {
    type: 'aws',
    label: 'AWS',
    pattern: /\b(AKIA[A-Z0-9]{16})\b/,
    envVars: ['AWS_ACCESS_KEY_ID'],
  },
  {
    type: 'github',
    label: 'GitHub',
    pattern: /\b(gh[ps]_[A-Za-z0-9]{36,})\b/,
    envVars: ['GITHUB_TOKEN', 'GH_TOKEN'],
  },
  {
    type: 'azure',
    label: 'Azure',
    pattern: /\b([a-f0-9]{32})\b/,
    envVars: ['AZURE_OPENAI_API_KEY'],
  },
  {
    type: 'huggingface',
    label: 'Hugging Face',
    pattern: /\b(hf_[A-Za-z0-9]{34,})\b/,
    envVars: ['HF_TOKEN', 'HUGGING_FACE_HUB_TOKEN'],
  },
];

// All env var names we scan for
const ALL_KEY_ENV_VARS = new Set(KEY_PATTERNS.flatMap(k => k.envVars));

// ─── Shell Profile Scanning ─────────────────────────────────────────────────

const SHELL_PROFILES = [
  '.zshrc',
  '.bashrc',
  '.bash_profile',
  '.profile',
  '.zshenv',
  '.zprofile',
];

function scanShellProfiles(): CredentialExposure[] {
  const exposures: CredentialExposure[] = [];

  for (const profile of SHELL_PROFILES) {
    const filePath = path.join(HOME, profile);
    let content: string;
    try {
      content = fs.readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }

    for (const line of content.split('\n')) {
      // Skip comments
      const trimmed = line.trim();
      if (trimmed.startsWith('#')) continue;

      // Check for export KEY=value or KEY=value patterns
      for (const kp of KEY_PATTERNS) {
        // Check env var assignment
        for (const envVar of kp.envVars) {
          const envPattern = new RegExp(`(?:export\\s+)?${envVar}\\s*=\\s*["']?([^"'\\s]+)["']?`);
          const match = trimmed.match(envPattern);
          if (match && match[1] && match[1] !== '$' && !match[1].startsWith('${')) {
            exposures.push({
              tool: 'shell',
              keyType: kp.type,
              location: filePath,
              redactedValue: redactKey(match[1]),
              issue: 'plaintext',
              severity: 'critical',
              filePermissions: getFilePermissions(filePath),
            });
          }
        }

        // Check for key patterns in any line (catches arbitrary variable names)
        const keyMatch = trimmed.match(kp.pattern);
        if (keyMatch && !exposures.some(e => e.location === filePath && e.keyType === kp.type)) {
          exposures.push({
            tool: 'shell',
            keyType: kp.type,
            location: filePath,
            redactedValue: redactKey(keyMatch[1]),
            issue: 'plaintext',
            severity: 'critical',
            filePermissions: getFilePermissions(filePath),
          });
        }
      }
    }
  }

  return exposures;
}

// ─── Env File Scanning ───────────────────────────────────────────────────────

const ENV_FILE_LOCATIONS = [
  path.join(HOME, '.env'),
];

function scanEnvFiles(): CredentialExposure[] {
  const exposures: CredentialExposure[] = [];

  for (const envPath of ENV_FILE_LOCATIONS) {
    let content: string;
    try {
      content = fs.readFileSync(envPath, 'utf-8');
    } catch {
      continue;
    }

    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      for (const kp of KEY_PATTERNS) {
        for (const envVar of kp.envVars) {
          const match = trimmed.match(new RegExp(`^${envVar}\\s*=\\s*["']?([^"'\\s]+)["']?`));
          if (match && match[1]) {
            exposures.push({
              tool: 'env-file',
              keyType: kp.type,
              location: envPath,
              redactedValue: redactKey(match[1]),
              issue: 'plaintext',
              severity: 'high',
              filePermissions: getFilePermissions(envPath),
            });
          }
        }
      }
    }
  }

  return exposures;
}

// ─── MCP Config Env Block Scanning ───────────────────────────────────────────

function scanMCPConfigKeys(mcpResult: MCPScanResult): CredentialExposure[] {
  const exposures: CredentialExposure[] = [];

  for (const server of mcpResult.servers) {
    for (const [envKey, envVal] of Object.entries(server.env)) {
      // Check if the env var name matches a known key env var
      if (ALL_KEY_ENV_VARS.has(envKey)) {
        const kp = KEY_PATTERNS.find(k => k.envVars.includes(envKey));
        if (kp && envVal && !envVal.startsWith('${') && !envVal.startsWith('$')) {
          exposures.push({
            tool: `MCP:${server.name}`,
            keyType: kp.type,
            location: server.configFile,
            redactedValue: redactKey(envVal),
            issue: 'config-embedded',
            severity: 'high',
          });
        }
      }

      // Check if the value matches a key pattern regardless of env var name
      for (const kp of KEY_PATTERNS) {
        const match = envVal.match(kp.pattern);
        if (match && !exposures.some(e =>
          e.location === server.configFile &&
          e.keyType === kp.type &&
          e.tool === `MCP:${server.name}`
        )) {
          exposures.push({
            tool: `MCP:${server.name}`,
            keyType: kp.type,
            location: server.configFile,
            redactedValue: redactKey(match[1]),
            issue: 'config-embedded',
            severity: 'high',
          });
        }
      }
    }
  }

  return exposures;
}

// ─── Token / Auth File Scanning ──────────────────────────────────────────────

interface AuthFileCheck {
  tool: string;
  path: string;
  expectedPerms: string;
}

const AUTH_FILE_CHECKS: AuthFileCheck[] = [
  { tool: 'Cursor', path: path.join(HOME, '.cursor', 'auth.json'), expectedPerms: '600' },
  { tool: 'Continue', path: path.join(HOME, '.continue', 'config.json'), expectedPerms: '600' },
  { tool: 'Claude Code', path: path.join(HOME, '.claude', 'credentials.json'), expectedPerms: '600' },
  { tool: 'Augment', path: path.join(HOME, '.augment', 'settings.json'), expectedPerms: '600' },
  { tool: 'g0', path: path.join(HOME, '.g0', 'auth.json'), expectedPerms: '600' },
];

function scanAuthFilePermissions(): CredentialExposure[] {
  const exposures: CredentialExposure[] = [];

  for (const check of AUTH_FILE_CHECKS) {
    try {
      const stat = fs.statSync(check.path);
      const mode = (stat.mode & 0o777).toString(8);

      // Check if file is world-readable or group-readable
      if (stat.mode & 0o044) {
        exposures.push({
          tool: check.tool,
          keyType: 'other',
          location: check.path,
          redactedValue: '(auth file)',
          issue: 'bad-permissions',
          severity: stat.mode & 0o004 ? 'high' : 'medium',
          filePermissions: mode,
        });
      }
    } catch {
      // File doesn't exist, skip
    }
  }

  return exposures;
}

// ─── Data Store Scanning ─────────────────────────────────────────────────────

interface DataStoreLocation {
  tool: string;
  paths: string[];
  storeType: 'sqlite' | 'json' | 'model-cache' | 'log';
  /** Glob patterns for files within the directory */
  filePatterns?: string[];
}

const DATA_STORE_LOCATIONS: DataStoreLocation[] = [
  {
    tool: 'Claude Desktop',
    paths: [
      path.join(HOME, 'Library/Application Support/Claude'),
      path.join(HOME, '.config/claude'),
    ],
    storeType: 'sqlite',
    filePatterns: ['*.db', '*.sqlite', '*.sqlite3'],
  },
  {
    tool: 'ChatGPT Desktop',
    paths: [
      path.join(HOME, 'Library/Application Support/com.openai.chat'),
    ],
    storeType: 'sqlite',
    filePatterns: ['*.db', '*.sqlite'],
  },
  {
    tool: 'Cursor',
    paths: [
      path.join(HOME, 'Library/Application Support/Cursor/User/globalStorage'),
      path.join(HOME, '.config/Cursor/User/globalStorage'),
    ],
    storeType: 'sqlite',
  },
  {
    tool: 'Claude Code',
    paths: [
      path.join(HOME, '.claude/projects'),
    ],
    storeType: 'json',
  },
  {
    tool: 'Cline',
    paths: [
      path.join(HOME, 'Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev'),
      path.join(HOME, '.config/Code/User/globalStorage/saoudrizwan.claude-dev'),
    ],
    storeType: 'json',
  },
  {
    tool: 'Roo Code',
    paths: [
      path.join(HOME, 'Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline'),
      path.join(HOME, '.config/Code/User/globalStorage/rooveterinaryinc.roo-cline'),
    ],
    storeType: 'json',
  },
  {
    tool: 'Ollama',
    paths: [
      path.join(HOME, '.ollama/models'),
    ],
    storeType: 'model-cache',
  },
  {
    tool: 'LM Studio',
    paths: [
      path.join(HOME, '.lmstudio'),
      path.join(HOME, '.cache/lm-studio'),
    ],
    storeType: 'model-cache',
  },
  {
    tool: 'Continue',
    paths: [
      path.join(HOME, '.continue/sessions'),
      path.join(HOME, '.continue/dev_data'),
    ],
    storeType: 'json',
  },
];

function scanDataStores(): DataStoreExposure[] {
  const stores: DataStoreExposure[] = [];

  for (const loc of DATA_STORE_LOCATIONS) {
    for (const dirPath of loc.paths) {
      try {
        const stat = fs.statSync(dirPath);
        if (!stat.isDirectory()) continue;

        const totalSize = getDirectorySize(dirPath, 2); // max 2 levels deep
        if (totalSize === 0) continue;

        const permissions = (stat.mode & 0o777).toString(8);
        const lastModified = stat.mtime.toISOString();

        // Check for SQLite encryption (look for common SQLCipher header)
        let encrypted = false;
        if (loc.storeType === 'sqlite') {
          encrypted = checkSQLiteEncryption(dirPath);
        }

        stores.push({
          tool: loc.tool,
          storeType: loc.storeType,
          path: dirPath,
          sizeBytes: totalSize,
          encrypted,
          permissions,
          lastModified,
        });
      } catch {
        // Directory doesn't exist or not accessible
      }
    }
  }

  return stores;
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
        } else if (entry.isDirectory() && !entry.name.startsWith('.')) {
          total += getDirectorySize(fullPath, maxDepth - 1);
        }
      } catch {
        // Skip inaccessible files
      }
    }
  } catch {
    // Skip inaccessible directories
  }

  return total;
}

function checkSQLiteEncryption(dirPath: string): boolean {
  try {
    const entries = fs.readdirSync(dirPath);
    for (const entry of entries) {
      if (!entry.endsWith('.db') && !entry.endsWith('.sqlite') && !entry.endsWith('.sqlite3')) continue;
      const filePath = path.join(dirPath, entry);
      const fd = fs.openSync(filePath, 'r');
      const buf = Buffer.alloc(16);
      fs.readSync(fd, buf, 0, 16, 0);
      fs.closeSync(fd);

      // Standard SQLite header starts with "SQLite format 3\0"
      // If it doesn't, the DB is likely encrypted
      const header = buf.toString('utf-8', 0, 15);
      if (header !== 'SQLite format 3') return true;
    }
  } catch {
    // Can't check
  }
  return false;
}

// ─── Finding Generation ─────────────────────────────────────────────────────

function generateFindings(
  credentials: CredentialExposure[],
  dataStores: DataStoreExposure[],
): ArtifactFinding[] {
  const findings: ArtifactFinding[] = [];

  for (const cred of credentials) {
    findings.push({
      severity: cred.severity,
      type: `credential-${cred.issue}`,
      title: `${cred.keyType === 'other' ? 'Auth file' : `${capitalize(cred.keyType)} API key`} — ${cred.issue.replace('-', ' ')}`,
      description: cred.issue === 'bad-permissions'
        ? `${shortenPath(cred.location)} has permissions ${cred.filePermissions} (should be 600).`
        : `${capitalize(cred.keyType)} key found in ${shortenPath(cred.location)} (${cred.redactedValue}).`,
      location: cred.location,
    });
  }

  for (const store of dataStores) {
    // Only flag conversation data stores, not model caches
    if (store.storeType === 'model-cache') continue;

    const sizeMB = store.sizeBytes / (1024 * 1024);
    if (sizeMB < 1) continue; // Skip tiny stores

    // World-readable is concerning for large data stores with conversation data
    const worldReadable = parseInt(store.permissions, 8) & 0o004;
    const severity: MCPFindingSeverity =
      worldReadable && sizeMB > 10 ? 'high' :
      sizeMB > 50 ? 'medium' : 'low';

    findings.push({
      severity,
      type: 'data-store-exposure',
      title: `${store.tool} — ${sizeMB.toFixed(0)}MB ${store.storeType} store${store.encrypted ? '' : ' (unencrypted)'}`,
      description: `${shortenPath(store.path)} contains ${store.storeType} data (${formatBytes(store.sizeBytes)}). Permissions: ${store.permissions}.`,
      location: store.path,
    });
  }

  return findings;
}

// ─── Main Scanner ────────────────────────────────────────────────────────────

export function scanArtifacts(mcpResult: MCPScanResult): ArtifactScanResult {
  // Credential scanning
  const shellCreds = scanShellProfiles();
  const envCreds = scanEnvFiles();
  const mcpCreds = scanMCPConfigKeys(mcpResult);
  const authPerms = scanAuthFilePermissions();
  const credentials = [...shellCreds, ...envCreds, ...mcpCreds, ...authPerms];

  // Deduplicate: same key in the same file
  const dedupedCreds = deduplicateCredentials(credentials);

  // Data store scanning
  const dataStores = scanDataStores();

  // Generate findings
  const findings = generateFindings(dedupedCreds, dataStores);

  const totalDataSize = dataStores.reduce((sum, s) => sum + s.sizeBytes, 0);

  return {
    credentials: dedupedCreds,
    dataStores,
    findings,
    summary: {
      totalCredentials: dedupedCreds.length,
      totalDataStores: dataStores.length,
      totalDataSizeBytes: totalDataSize,
      totalFindings: findings.length,
    },
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function redactKey(key: string): string {
  if (key.length <= 12) return key.slice(0, 4) + '...' + key.slice(-4);
  return key.slice(0, 8) + '...' + key.slice(-4);
}

function getFilePermissions(filePath: string): string {
  try {
    const stat = fs.statSync(filePath);
    return (stat.mode & 0o777).toString(8);
  } catch {
    return 'unknown';
  }
}

function shortenPath(p: string): string {
  if (p.startsWith(HOME)) return '~' + p.slice(HOME.length);
  return p;
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)}KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(0)}MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)}GB`;
}

function deduplicateCredentials(creds: CredentialExposure[]): CredentialExposure[] {
  const seen = new Set<string>();
  return creds.filter(c => {
    const key = `${c.location}:${c.keyType}:${c.redactedValue}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// Exported for testing
export {
  scanShellProfiles,
  scanEnvFiles,
  scanMCPConfigKeys,
  scanAuthFilePermissions,
  scanDataStores,
  redactKey,
  KEY_PATTERNS,
  DATA_STORE_LOCATIONS,
};
