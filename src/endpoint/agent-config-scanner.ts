import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

// ─── Interfaces ─────────────────────────────────────────────────────────────

export interface AgentConfigScanOptions {
  /** Root path to OpenClaw agents directory (e.g. /data/.openclaw/agents) */
  agentDataPath: string;
  /** Optional: path to check agent SKILL.md files for capability cross-reference */
  skillsBasePath?: string;
}

export interface AgentCredential {
  agent: string;
  file: string;
  key: string;
  valueHash: string;
  provider?: string;
}

export interface DuplicateGroup {
  key: string;
  valueHash: string;
  agents: string[];
  files: string[];
  severity: 'critical' | 'high';
}

export interface OverprivilegedAgent {
  agent: string;
  credential: string;
  reason: string;
}

export interface PermissionIssue {
  agent: string;
  file: string;
  currentMode: string;
  expectedMode: string;
  severity: 'critical' | 'high';
}

export interface AgentConfigScanResult {
  agentsScanned: number;
  totalCredentials: number;
  duplicateGroups: DuplicateGroup[];
  overprivileged: OverprivilegedAgent[];
  permissionIssues: PermissionIssue[];
  findings: AgentConfigFinding[];
  duration: number;
}

export interface AgentConfigFinding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  detail: string;
  agent?: string;
  file?: string;
}

// ─── Provider Detection ─────────────────────────────────────────────────────

const PROVIDER_PREFIXES: Array<{ pattern: RegExp; provider: string }> = [
  { pattern: /^OUTLOOK_/i, provider: 'outlook/microsoft' },
  { pattern: /^MICROSOFT_/i, provider: 'outlook/microsoft' },
  { pattern: /^AZURE_/i, provider: 'azure/microsoft' },
  { pattern: /^OPENAI_/i, provider: 'openai' },
  { pattern: /^ANTHROPIC_/i, provider: 'anthropic' },
  { pattern: /^GOOGLE_/i, provider: 'google' },
  { pattern: /^GEMINI_/i, provider: 'google' },
  { pattern: /^AWS_/i, provider: 'aws' },
  { pattern: /^GITHUB_/i, provider: 'github' },
  { pattern: /^GH_/i, provider: 'github' },
  { pattern: /^SLACK_/i, provider: 'slack' },
  { pattern: /^NOTION_/i, provider: 'notion' },
  { pattern: /^DISCORD_/i, provider: 'discord' },
  { pattern: /^TWILIO_/i, provider: 'twilio' },
  { pattern: /^STRIPE_/i, provider: 'stripe' },
  { pattern: /^SENDGRID_/i, provider: 'sendgrid' },
  { pattern: /^DATADOG_/i, provider: 'datadog' },
  { pattern: /^SUPABASE_/i, provider: 'supabase' },
  { pattern: /^FIREBASE_/i, provider: 'firebase/google' },
  { pattern: /^REDIS_/i, provider: 'redis' },
  { pattern: /^POSTGRES/i, provider: 'postgres' },
  { pattern: /^MONGO/i, provider: 'mongodb' },
  { pattern: /^REPLICATE_/i, provider: 'replicate' },
  { pattern: /^HUGGINGFACE_/i, provider: 'huggingface' },
  { pattern: /^HF_/i, provider: 'huggingface' },
  { pattern: /^TOGETHER_/i, provider: 'together' },
  { pattern: /^COHERE_/i, provider: 'cohere' },
  { pattern: /^MISTRAL_/i, provider: 'mistral' },
  { pattern: /^PERPLEXITY_/i, provider: 'perplexity' },
  { pattern: /^GROQ_/i, provider: 'groq' },
];

const GENERIC_PATTERNS: RegExp[] = [
  /_API_KEY$/i,
  /_SECRET$/i,
  /_TOKEN$/i,
  /_PASSWORD$/i,
  /_PRIVATE_KEY$/i,
  /_CLIENT_SECRET$/i,
  /_ACCESS_KEY$/i,
];

/** Detect the provider for a given env var name. */
export function detectProvider(key: string): string | undefined {
  for (const { pattern, provider } of PROVIDER_PREFIXES) {
    if (pattern.test(key)) return provider;
  }
  for (const pat of GENERIC_PATTERNS) {
    if (pat.test(key)) return 'generic';
  }
  return undefined;
}

// ─── Credential File Detection ──────────────────────────────────────────────

/** Filename patterns that indicate credential content. */
const CRED_FILE_PATTERNS: RegExp[] = [
  /^\.env$/i,
  /^\.env\./i,
  /secret/i,
  /credential/i,
  /token/i,
  /\.key$/i,
  /\.pem$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /^service[-_]?account/i,
];

function isCredentialFile(filename: string): boolean {
  return CRED_FILE_PATTERNS.some(p => p.test(filename));
}

// ─── Env File Parser ────────────────────────────────────────────────────────

/**
 * Parse a .env-style file into key-value pairs.
 * Handles:
 * - Comments (lines starting with #)
 * - Blank lines
 * - Quoted values (single and double)
 * - Inline comments after unquoted values
 * - export prefix (e.g. `export FOO=bar`)
 * - Keys with dots (e.g. `spring.datasource.password=x`)
 */
export function parseEnvFile(content: string): Map<string, string> {
  const result = new Map<string, string>();

  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim();

    // Skip empty and comment lines
    if (!line || line.startsWith('#')) continue;

    // Strip optional `export ` prefix
    const stripped = line.startsWith('export ') ? line.slice(7).trim() : line;

    // Find the first `=` separator
    const eqIdx = stripped.indexOf('=');
    if (eqIdx <= 0) continue;

    const key = stripped.slice(0, eqIdx).trim();
    let value = stripped.slice(eqIdx + 1).trim();

    // Validate the key: allow alphanumerics, underscores, dots, hyphens
    if (!/^[A-Za-z_][A-Za-z0-9_.:-]*$/.test(key)) continue;

    // Handle quoted values
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    } else {
      // Strip inline comments for unquoted values
      const commentIdx = value.indexOf(' #');
      if (commentIdx >= 0) {
        value = value.slice(0, commentIdx).trim();
      }
    }

    // Skip empty values — no secret to hash
    if (!value) continue;

    result.set(key, value);
  }

  return result;
}

// ─── Hashing ────────────────────────────────────────────────────────────────

/** SHA-256 hash of a credential value. Never stores the raw value. */
export function hashValue(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

// ─── File Permission Check ──────────────────────────────────────────────────

/** Extract octal mode string and determine permission issues. */
export function checkFilePermissions(
  filePath: string,
  agent: string,
): PermissionIssue | null {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(filePath);
  } catch {
    return null; // can't stat — skip
  }

  // Extract permission bits (last 9 bits)
  const mode = stat.mode & 0o777;
  const modeStr = mode.toString(8).padStart(3, '0');

  // Acceptable modes: 600 (owner rw), 400 (owner r-only), 640 is borderline
  if (mode === 0o600 || mode === 0o400) return null;

  const worldBits = mode & 0o007;
  const groupBits = mode & 0o070;

  let severity: 'critical' | 'high';
  if (worldBits !== 0) {
    severity = 'critical'; // world-readable
  } else if (groupBits !== 0) {
    severity = 'high'; // group-readable
  } else {
    severity = 'high'; // other non-standard (e.g. 700)
  }

  return {
    agent,
    file: filePath,
    currentMode: modeStr,
    expectedMode: '600',
    severity,
  };
}

// ─── Capability Keywords ────────────────────────────────────────────────────

interface CapabilityMapping {
  /** Env var prefix patterns that require this capability */
  credPatterns: RegExp[];
  /** Keywords that indicate the agent has this capability */
  keywords: string[];
  /** Label for the capability (used in reason strings) */
  label: string;
}

const CAPABILITY_MAPPINGS: CapabilityMapping[] = [
  {
    credPatterns: [/^OUTLOOK_/i, /^SMTP_/i, /^IMAP_/i, /^SENDGRID_/i, /^MAILGUN_/i, /^EMAIL_/i, /^GMAIL_/i],
    keywords: ['email', 'outlook', 'gmail', 'smtp', 'imap', 'mailbox', 'mail', 'sendgrid', 'mailgun'],
    label: 'email',
  },
  {
    credPatterns: [/^SLACK_/i],
    keywords: ['slack', 'message', 'chat', 'notification'],
    label: 'slack',
  },
  {
    credPatterns: [/^NOTION_/i],
    keywords: ['notion', 'wiki', 'knowledge base', 'document'],
    label: 'notion',
  },
  {
    credPatterns: [/^GITHUB_/i, /^GH_/i],
    keywords: ['github', 'git', 'repository', 'pull request', 'issue', 'code review'],
    label: 'github',
  },
  {
    credPatterns: [/^DISCORD_/i],
    keywords: ['discord', 'chat', 'message'],
    label: 'discord',
  },
  {
    credPatterns: [/^STRIPE_/i],
    keywords: ['stripe', 'payment', 'billing', 'invoice', 'charge'],
    label: 'stripe/payment',
  },
  {
    credPatterns: [/^TWILIO_/i],
    keywords: ['twilio', 'sms', 'phone', 'call', 'text message'],
    label: 'twilio/sms',
  },
  {
    credPatterns: [/^AWS_/i],
    keywords: ['aws', 'amazon', 's3', 'lambda', 'ec2', 'cloud', 'dynamo', 'sqs', 'sns'],
    label: 'aws',
  },
  {
    credPatterns: [/^OPENAI_/i],
    keywords: ['openai', 'gpt', 'chatgpt', 'dall-e', 'whisper', 'embedding', 'completion'],
    label: 'openai',
  },
  {
    credPatterns: [/^ANTHROPIC_/i],
    keywords: ['anthropic', 'claude', 'completion', 'llm'],
    label: 'anthropic',
  },
  {
    credPatterns: [/^GOOGLE_/i, /^GEMINI_/i, /^FIREBASE_/i],
    keywords: ['google', 'gemini', 'firebase', 'vertex', 'gcp', 'bigquery', 'cloud'],
    label: 'google',
  },
];

// ─── Directory Walking Helpers ──────────────────────────────────────────────

/** Safely list directories under a given path. Returns directory names. */
function listDirs(dirPath: string): string[] {
  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    return entries.filter(e => e.isDirectory()).map(e => e.name);
  } catch {
    return [];
  }
}

/** Safely list files in a directory. Returns full paths. */
function listFiles(dirPath: string): string[] {
  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    return entries
      .filter(e => e.isFile())
      .map(e => path.join(dirPath, e.name));
  } catch {
    return [];
  }
}

/** Read file content safely. Returns null on failure. */
function readFileSafe(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
}

// ─── Core Scan Logic ────────────────────────────────────────────────────────

/** Discover credential files for a single agent. */
function discoverCredentialFiles(agentPath: string): string[] {
  const results: string[] = [];

  // Search in multiple potential config locations
  const searchDirs = [
    agentPath,
    path.join(agentPath, 'config'),
    path.join(agentPath, 'agent', 'config'),
    path.join(agentPath, 'agent'),
    path.join(agentPath, '.config'),
    path.join(agentPath, 'secrets'),
    path.join(agentPath, 'env'),
  ];

  const seen = new Set<string>();

  for (const dir of searchDirs) {
    for (const filePath of listFiles(dir)) {
      const filename = path.basename(filePath);
      const resolved = path.resolve(filePath);
      if (seen.has(resolved)) continue;
      if (isCredentialFile(filename)) {
        seen.add(resolved);
        results.push(resolved);
      }
    }
  }

  return results;
}

/** Extract credentials from a single file. */
function extractCredentials(
  agentName: string,
  filePath: string,
): AgentCredential[] {
  const content = readFileSafe(filePath);
  if (!content) return [];

  const pairs = parseEnvFile(content);
  const creds: AgentCredential[] = [];

  for (const [key, value] of pairs) {
    creds.push({
      agent: agentName,
      file: filePath,
      key,
      valueHash: hashValue(value),
      provider: detectProvider(key),
    });
  }

  return creds;
}

/** Build duplicate groups from all collected credentials. */
function buildDuplicateGroups(credentials: AgentCredential[]): DuplicateGroup[] {
  // Group by (key, valueHash)
  const groupKey = (c: AgentCredential) => `${c.key}::${c.valueHash}`;
  const groups = new Map<string, AgentCredential[]>();

  for (const cred of credentials) {
    const k = groupKey(cred);
    const existing = groups.get(k);
    if (existing) {
      existing.push(cred);
    } else {
      groups.set(k, [cred]);
    }
  }

  const duplicates: DuplicateGroup[] = [];

  for (const creds of groups.values()) {
    // Get unique agents in this group
    const agents = [...new Set(creds.map(c => c.agent))];
    if (agents.length < 2) continue;

    const files = [...new Set(creds.map(c => c.file))];
    const key = creds[0].key;
    const valueHash = creds[0].valueHash;

    // Determine severity: critical for secrets/passwords/tokens
    const isSensitive = /SECRET|PASSWORD|TOKEN|PRIVATE_KEY/i.test(key);
    const severity: 'critical' | 'high' = isSensitive ? 'critical' : 'high';

    duplicates.push({ key, valueHash, agents, files, severity });
  }

  // Sort by severity (critical first), then by number of agents descending
  duplicates.sort((a, b) => {
    if (a.severity !== b.severity) return a.severity === 'critical' ? -1 : 1;
    return b.agents.length - a.agents.length;
  });

  return duplicates;
}

/** Read SKILL.md for a given agent. Searches multiple locations. */
function readSkillMd(agentName: string, agentDataPath: string, skillsBasePath?: string): string | null {
  const candidates: string[] = [];

  if (skillsBasePath) {
    candidates.push(
      path.join(skillsBasePath, agentName, 'SKILL.md'),
      path.join(skillsBasePath, agentName, 'skill.md'),
    );
  }

  candidates.push(
    path.join(agentDataPath, agentName, 'SKILL.md'),
    path.join(agentDataPath, agentName, 'skill.md'),
    path.join(agentDataPath, agentName, 'agent', 'SKILL.md'),
  );

  for (const candidate of candidates) {
    const content = readFileSafe(candidate);
    if (content !== null) return content;
  }

  return null;
}

/** Check if a SKILL.md contains keywords indicating a given capability. */
function skillHasCapability(skillContent: string, keywords: string[]): boolean {
  const lower = skillContent.toLowerCase();
  return keywords.some(kw => lower.includes(kw.toLowerCase()));
}

/** Detect overprivileged agents by cross-referencing creds with SKILL.md capabilities. */
function detectOverprivileged(
  credentials: AgentCredential[],
  agentDataPath: string,
  skillsBasePath?: string,
): OverprivilegedAgent[] {
  const results: OverprivilegedAgent[] = [];

  // Group credentials by agent
  const byAgent = new Map<string, AgentCredential[]>();
  for (const cred of credentials) {
    const existing = byAgent.get(cred.agent);
    if (existing) {
      existing.push(cred);
    } else {
      byAgent.set(cred.agent, [cred]);
    }
  }

  for (const [agentName, agentCreds] of byAgent) {
    const skillContent = readSkillMd(agentName, agentDataPath, skillsBasePath);
    if (!skillContent) continue; // Can't check without SKILL.md

    for (const cred of agentCreds) {
      for (const mapping of CAPABILITY_MAPPINGS) {
        const matchesCred = mapping.credPatterns.some(p => p.test(cred.key));
        if (!matchesCred) continue;

        if (!skillHasCapability(skillContent, mapping.keywords)) {
          results.push({
            agent: agentName,
            credential: cred.key,
            reason: `Agent has ${cred.key} but no ${mapping.label} capability in SKILL.md`,
          });
        }
      }
    }
  }

  // Deduplicate: same agent + credential combination
  const seen = new Set<string>();
  return results.filter(r => {
    const key = `${r.agent}::${r.credential}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ─── Finding Generation ─────────────────────────────────────────────────────

function generateFindings(
  duplicateGroups: DuplicateGroup[],
  overprivileged: OverprivilegedAgent[],
  permissionIssues: PermissionIssue[],
): AgentConfigFinding[] {
  const findings: AgentConfigFinding[] = [];
  let counter = 0;

  // OC-AGENT-001: Duplicate credentials
  for (const group of duplicateGroups) {
    counter++;
    findings.push({
      id: 'OC-AGENT-001',
      title: `Same credential ${group.key} shared across ${group.agents.length} agents`,
      severity: group.severity,
      detail: `Credential ${group.key} (hash: ${group.valueHash.slice(0, 12)}...) is duplicated across agents: ${group.agents.join(', ')}. ` +
        `Shared credentials prevent per-agent revocation and violate the principle of least privilege. ` +
        `Each agent should have its own service account or API key.`,
      agent: group.agents.join(', '),
      file: group.files.join(', '),
    });
  }

  // OC-AGENT-002: Overprivileged credential injection
  for (const op of overprivileged) {
    counter++;
    findings.push({
      id: 'OC-AGENT-002',
      title: `Overprivileged credential injection: ${op.credential}`,
      severity: 'high',
      detail: op.reason + '. ' +
        'Injecting credentials that an agent does not need expands the blast radius if the agent is compromised. ' +
        'Remove the credential or add the corresponding capability to the agent manifest.',
      agent: op.agent,
    });
  }

  // OC-AGENT-003: Credential file permissions too open
  for (const pi of permissionIssues) {
    counter++;
    const readableBy = pi.severity === 'critical' ? 'world-readable' : 'group-readable';
    findings.push({
      id: 'OC-AGENT-003',
      title: `Credential file permissions too open (${pi.currentMode})`,
      severity: pi.severity,
      detail: `File ${pi.file} for agent ${pi.agent} has mode ${pi.currentMode} (${readableBy}). ` +
        `Expected mode ${pi.expectedMode}. Credential files must not be readable by other users or groups. ` +
        `Run: chmod ${pi.expectedMode} "${pi.file}"`,
      agent: pi.agent,
      file: pi.file,
    });
  }

  return findings;
}

// ─── Main Entry Point ───────────────────────────────────────────────────────

export async function scanAgentConfigs(
  options: AgentConfigScanOptions,
): Promise<AgentConfigScanResult> {
  const startTime = Date.now();

  const {
    agentDataPath,
    skillsBasePath,
  } = options;

  // Validate the root path exists
  let agentNames: string[];
  try {
    agentNames = listDirs(agentDataPath);
  } catch {
    // Path doesn't exist or isn't readable — return empty result
    return {
      agentsScanned: 0,
      totalCredentials: 0,
      duplicateGroups: [],
      overprivileged: [],
      permissionIssues: [],
      findings: [],
      duration: Date.now() - startTime,
    };
  }

  if (agentNames.length === 0) {
    return {
      agentsScanned: 0,
      totalCredentials: 0,
      duplicateGroups: [],
      overprivileged: [],
      permissionIssues: [],
      findings: [],
      duration: Date.now() - startTime,
    };
  }

  // ── Step 1: Collect all credentials and permission issues ─────────────

  const allCredentials: AgentCredential[] = [];
  const allPermissionIssues: PermissionIssue[] = [];

  for (const agentName of agentNames) {
    const agentPath = path.join(agentDataPath, agentName);
    const credFiles = discoverCredentialFiles(agentPath);

    for (const credFile of credFiles) {
      // Extract credentials
      const creds = extractCredentials(agentName, credFile);
      allCredentials.push(...creds);

      // Check file permissions
      const permIssue = checkFilePermissions(credFile, agentName);
      if (permIssue) {
        allPermissionIssues.push(permIssue);
      }
    }
  }

  // ── Step 2: Detect duplicates ─────────────────────────────────────────

  const duplicateGroups = buildDuplicateGroups(allCredentials);

  // ── Step 3: Detect overprivileged agents ──────────────────────────────

  const overprivileged = detectOverprivileged(
    allCredentials,
    agentDataPath,
    skillsBasePath,
  );

  // ── Step 4: Generate findings ─────────────────────────────────────────

  const findings = generateFindings(
    duplicateGroups,
    overprivileged,
    allPermissionIssues,
  );

  return {
    agentsScanned: agentNames.length,
    totalCredentials: allCredentials.length,
    duplicateGroups,
    overprivileged,
    permissionIssues: allPermissionIssues,
    findings,
    duration: Date.now() - startTime,
  };
}
