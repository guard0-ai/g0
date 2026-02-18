import * as fs from 'node:fs';
import * as path from 'node:path';
import type { FileInventory, FileInfo } from '../types/common.js';
import type {
  AgentGraph,
  PromptPermission,
  APIEndpoint,
  DatabaseAccess,
  AuthFlow,
  PermissionCheck,
  PIIReference,
  MessageQueue,
  RateLimitConfig,
  CallGraphEdge,
} from '../types/agent-graph.js';
import { isCommentLine } from './ast/queries.js';

function langFromPath(filePath: string): string {
  if (filePath.endsWith('.py')) return 'python';
  if (filePath.endsWith('.ts') || filePath.endsWith('.tsx')) return 'typescript';
  if (filePath.endsWith('.js') || filePath.endsWith('.jsx')) return 'javascript';
  if (filePath.endsWith('.java')) return 'java';
  if (filePath.endsWith('.go')) return 'go';
  return 'unknown';
}

/**
 * Post-parser enrichment layer.
 * Runs after all framework parsers finish, extracting deeper
 * security-relevant metadata from the AgentGraph and raw source files.
 */
export function enrichAgentGraph(graph: AgentGraph, files: FileInventory): void {
  const allFiles = files.all;

  // 1. Permission inference from prompts (graph-only, no file I/O)
  extractPromptPermissions(graph);

  // Global symbol table for cross-file call graph resolution
  const globalFunctions = new Map<string, { file: string; line: number; isAsync: boolean }>();

  // Cached file contents for second pass
  const fileContents = new Map<string, string[]>();

  // 2-9. File-based extraction (first pass)
  for (const fileInfo of allFiles) {
    const fullPath = path.isAbsolute(fileInfo.path)
      ? fileInfo.path
      : path.join(graph.rootPath, fileInfo.path);

    let content: string;
    try {
      content = fs.readFileSync(fullPath, 'utf-8');
    } catch {
      continue;
    }

    const filePath = fileInfo.path;
    const lines = content.split('\n');
    fileContents.set(filePath, lines);

    extractAPIEndpoints(graph, filePath, lines);
    extractDatabaseAccesses(graph, filePath, lines);
    extractAuthFlows(graph, filePath, lines);
    extractPermissionChecks(graph, filePath, lines);
    extractPIIReferences(graph, filePath, lines);
    extractMessageQueues(graph, filePath, lines);
    extractRateLimits(graph, filePath, lines);
    extractCallGraphEdges(graph, filePath, lines, globalFunctions);
  }

  // 10. Cross-file call graph resolution (second pass)
  resolveCrossFileCallGraph(graph, fileContents, globalFunctions);

  // 11. Return-value taint tracking
  for (const [filePath, lines] of fileContents) {
    extractReturnValueTaints(graph, filePath, lines);
  }
}

// ─── 1. Permission Inference from Prompts ───────────────────────────

const ALLOWED_PATTERNS = [
  /\byou (?:can|may|should|are allowed to) (.+?)(?:\.|,|;|$)/i,
  /\ballowed to (.+?)(?:\.|,|;|$)/i,
  /\benable(?:d)? to (.+?)(?:\.|,|;|$)/i,
];

const FORBIDDEN_PATTERNS = [
  /\byou (?:must not|cannot|can't|should not|shouldn't|shall not|are not allowed to) (.+?)(?:\.|,|;|$)/i,
  /\bnever (.+?)(?:\.|,|;|$)/i,
  /\bdo not (.+?)(?:\.|,|;|$)/i,
  /\bdon't (.+?)(?:\.|,|;|$)/i,
  /\bprohibited from (.+?)(?:\.|,|;|$)/i,
  /\bforbidden (?:from|to) (.+?)(?:\.|,|;|$)/i,
];

const BOUNDARY_PATTERNS = [
  /\bonly (.+?)(?:\.|,|;|$)/i,
  /\brestricted to (.+?)(?:\.|,|;|$)/i,
  /\blimited to (.+?)(?:\.|,|;|$)/i,
  /\bexclusively (.+?)(?:\.|,|;|$)/i,
];

export function extractPromptPermissions(graph: AgentGraph): void {
  for (const prompt of graph.prompts) {
    if (!prompt.content) continue;

    const promptLines = prompt.content.split('\n');

    for (let i = 0; i < promptLines.length; i++) {
      const line = promptLines[i];

      for (const pattern of ALLOWED_PATTERNS) {
        const match = pattern.exec(line);
        if (match?.[1]) {
          const perm: PromptPermission = {
            type: 'allowed',
            action: match[1].trim().substring(0, 200),
            source: prompt.id,
            file: prompt.file,
            line: prompt.line + i,
          };
          graph.permissions.push(perm);
          if (!prompt.permissions) prompt.permissions = [];
          prompt.permissions.push(perm);
        }
      }

      for (const pattern of FORBIDDEN_PATTERNS) {
        const match = pattern.exec(line);
        if (match?.[1]) {
          const perm: PromptPermission = {
            type: 'forbidden',
            action: match[1].trim().substring(0, 200),
            source: prompt.id,
            file: prompt.file,
            line: prompt.line + i,
          };
          graph.permissions.push(perm);
          if (!prompt.permissions) prompt.permissions = [];
          prompt.permissions.push(perm);
        }
      }

      for (const pattern of BOUNDARY_PATTERNS) {
        const match = pattern.exec(line);
        if (match?.[1]) {
          const perm: PromptPermission = {
            type: 'boundary',
            action: match[1].trim().substring(0, 200),
            source: prompt.id,
            file: prompt.file,
            line: prompt.line + i,
          };
          graph.permissions.push(perm);
          if (!prompt.permissions) prompt.permissions = [];
          prompt.permissions.push(perm);
        }
      }
    }
  }
}

// ─── 2. API URL Extraction ──────────────────────────────────────────

const API_URL_PATTERNS: { pattern: RegExp; methodGroup?: number }[] = [
  // Python requests
  { pattern: /requests\.(get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]/gi, methodGroup: 1 },
  // Python httpx
  { pattern: /httpx\.(get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]/gi, methodGroup: 1 },
  // Python urllib
  { pattern: /urllib\.request\.urlopen\s*\(\s*["'`]([^"'`]+)["'`]/gi },
  // JS/TS fetch
  { pattern: /fetch\s*\(\s*["'`]([^"'`]+)["'`]/gi },
  // JS/TS axios
  { pattern: /axios\.(get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]/gi, methodGroup: 1 },
  // Java RestTemplate
  { pattern: /RestTemplate\.\w+\s*\(\s*"([^"]+)"/gi },
  // Java/Spring annotations
  { pattern: /@(?:Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/gi },
  // Go http
  { pattern: /http\.(Get|Post|NewRequest)\s*\(\s*(?:"[A-Z]+"\s*,\s*)?["'`]([^"'`]+)["'`]/gi, methodGroup: 1 },
];

const URL_LITERAL = /["'`](https?:\/\/[^\s"'`]{5,})["'`]/g;

function isExternalURL(url: string): boolean {
  return /^https?:\/\//i.test(url) && !/localhost|127\.0\.0\.1|0\.0\.0\.0/i.test(url);
}

function inferMethod(methodStr?: string): string | undefined {
  if (!methodStr) return undefined;
  const m = methodStr.toUpperCase();
  if (['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'NEWREQUEST'].includes(m)) {
    return m === 'NEWREQUEST' ? undefined : m;
  }
  return m;
}

export function extractAPIEndpoints(graph: AgentGraph, filePath: string, lines: string[]): void {
  const content = lines.join('\n');
  const seen = new Set<string>();

  for (const { pattern, methodGroup } of API_URL_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = re.exec(content)) !== null) {
      if (isCommentLine(content, match.index, langFromPath(filePath))) continue;
      const url = methodGroup ? match[2] : match[1];
      if (!url || url.length < 5) continue;

      const lineNum = content.substring(0, match.index).split('\n').length;
      const key = `${filePath}:${lineNum}:${url}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const method = methodGroup ? inferMethod(match[1]) : undefined;

      graph.apiEndpoints.push({
        url,
        method,
        file: filePath,
        line: lineNum,
        framework: graph.primaryFramework,
        isExternal: isExternalURL(url),
      });
    }
  }

  // Also scan for standalone URL literals not already captured
  const urlRe = new RegExp(URL_LITERAL.source, 'g');
  let match: RegExpExecArray | null;
  while ((match = urlRe.exec(content)) !== null) {
    if (isCommentLine(content, match.index, langFromPath(filePath))) continue;
    const url = match[1];
    const lineNum = content.substring(0, match.index).split('\n').length;
    const key = `${filePath}:${lineNum}:${url}`;
    if (seen.has(key)) continue;
    seen.add(key);

    graph.apiEndpoints.push({
      url,
      file: filePath,
      line: lineNum,
      framework: graph.primaryFramework,
      isExternal: isExternalURL(url),
    });
  }
}

// ─── 3. Database Table/Query Tracking ───────────────────────────────

const SQL_PATTERNS: { pattern: RegExp; operation: DatabaseAccess['operation'] }[] = [
  { pattern: /\bSELECT\b.+?\bFROM\s+[`"]?(\w+)[`"]?/gi, operation: 'read' },
  { pattern: /\bINSERT\s+INTO\s+[`"]?(\w+)[`"]?/gi, operation: 'write' },
  { pattern: /\bUPDATE\s+[`"]?(\w+)[`"]?\s+SET\b/gi, operation: 'write' },
  { pattern: /\bDELETE\s+FROM\s+[`"]?(\w+)[`"]?/gi, operation: 'delete' },
  { pattern: /\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?[`"]?(\w+)[`"]?/gi, operation: 'admin' },
  { pattern: /\bTRUNCATE\s+TABLE\s+[`"]?(\w+)[`"]?/gi, operation: 'admin' },
  { pattern: /\bALTER\s+TABLE\s+[`"]?(\w+)[`"]?/gi, operation: 'admin' },
  { pattern: /\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"]?(\w+)[`"]?/gi, operation: 'admin' },
];

const ORM_PATTERNS: { pattern: RegExp; type: DatabaseAccess['type']; operation: DatabaseAccess['operation'] }[] = [
  // Python Django/SQLAlchemy
  { pattern: /\.objects\.(filter|get|all|exclude|create|update|delete)\s*\(/gi, type: 'orm', operation: 'read' },
  { pattern: /\.query\s*\(\s*["'`](\w+)["'`]\s*\)/gi, type: 'orm', operation: 'read' },
  { pattern: /session\.(add|delete|merge|flush|commit)\s*\(/gi, type: 'orm', operation: 'write' },
  // JS/TS Prisma, Sequelize, TypeORM, Drizzle
  { pattern: /\.(findMany|findFirst|findUnique|findOne|find)\s*\(/gi, type: 'orm', operation: 'read' },
  { pattern: /\.(create|insert|save|upsert)\s*\(/gi, type: 'orm', operation: 'write' },
  { pattern: /\.(update|updateMany)\s*\(/gi, type: 'orm', operation: 'write' },
  { pattern: /\.(delete|deleteMany|destroy|remove)\s*\(/gi, type: 'orm', operation: 'delete' },
  // NoSQL (MongoDB)
  { pattern: /\.(insertOne|insertMany|updateOne|updateMany|replaceOne)\s*\(/gi, type: 'nosql', operation: 'write' },
  { pattern: /\.(findOne|findMany|aggregate|countDocuments)\s*\(/gi, type: 'nosql', operation: 'read' },
  { pattern: /\.(deleteOne|deleteMany)\s*\(/gi, type: 'nosql', operation: 'delete' },
];

const PARAMETERIZED_QUERY = /\?|%s|\$\d+|:\w+|@\w+/;

export function extractDatabaseAccesses(graph: AgentGraph, filePath: string, lines: string[]): void {
  const content = lines.join('\n');

  // SQL patterns
  for (const { pattern, operation } of SQL_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = re.exec(content)) !== null) {
      if (isCommentLine(content, match.index, langFromPath(filePath))) continue;
      const lineNum = content.substring(0, match.index).split('\n').length;
      const table = match[1];
      const surrounding = content.substring(Math.max(0, match.index - 100), match.index + match[0].length + 100);

      graph.databaseAccesses.push({
        type: 'sql',
        operation,
        table,
        file: filePath,
        line: lineNum,
        hasParameterizedQuery: PARAMETERIZED_QUERY.test(surrounding),
      });
    }
  }

  // ORM patterns
  for (const { pattern, type, operation } of ORM_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = re.exec(content)) !== null) {
      if (isCommentLine(content, match.index, langFromPath(filePath))) continue;
      const lineNum = content.substring(0, match.index).split('\n').length;
      graph.databaseAccesses.push({
        type,
        operation,
        file: filePath,
        line: lineNum,
        hasParameterizedQuery: true, // ORMs typically parameterize
      });
    }
  }
}

// ─── 4. OAuth/OIDC Detection ────────────────────────────────────────

const AUTH_LIB_PATTERNS: { pattern: RegExp; type: AuthFlow['type']; provider?: string }[] = [
  // OAuth2 libraries
  { pattern: /\bpassport\.(?:use|authenticate|initialize|session)\b/gi, type: 'oauth2' },
  { pattern: /\boauth2client\b/gi, type: 'oauth2' },
  { pattern: /\bauthlib\b/gi, type: 'oauth2' },
  { pattern: /\bspring-security-oauth2\b/gi, type: 'oauth2' },
  { pattern: /\bgrant_type\s*[:=]\s*["']authorization_code["']/gi, type: 'oauth2' },
  { pattern: /\bgrant_type\s*[:=]\s*["']client_credentials["']/gi, type: 'oauth2' },
  // OIDC
  { pattern: /\.well-known\/openid-configuration/gi, type: 'oidc' },
  { pattern: /\bjwks_uri\b/gi, type: 'oidc' },
  { pattern: /\bid_token\b/gi, type: 'oidc' },
  // JWT
  { pattern: /\bjwt\.(sign|verify|decode)\s*\(/gi, type: 'jwt' },
  { pattern: /\bjsonwebtoken\b/gi, type: 'jwt' },
  { pattern: /\bjose\b.*\b(SignJWT|jwtVerify)\b/gi, type: 'jwt' },
  { pattern: /\bJwtParser\b|\bJwts\.\w+/gi, type: 'jwt' },
  // API key
  { pattern: /[\b_]api[_-]?key\s*[:=]/gi, type: 'api-key' },
  { pattern: /x-api-key/gi, type: 'api-key' },
  // Bearer
  { pattern: /Authorization.*Bearer/gi, type: 'bearer' },
  // Basic
  { pattern: /Authorization.*Basic/gi, type: 'basic' },
];

const AUTH_PROVIDER_PATTERNS: { pattern: RegExp; provider: string }[] = [
  { pattern: /auth0/gi, provider: 'auth0' },
  { pattern: /clerk/gi, provider: 'clerk' },
  { pattern: /okta/gi, provider: 'okta' },
  { pattern: /cognito/gi, provider: 'cognito' },
  { pattern: /firebase[_-]?auth|FirebaseAuth/gi, provider: 'firebase' },
  { pattern: /supabase[_-]?auth|supabase\.auth/gi, provider: 'supabase' },
  { pattern: /GoogleOAuth|google-auth|google_auth/gi, provider: 'google' },
  { pattern: /next-?auth|NextAuth/gi, provider: 'nextauth' },
];

const TOKEN_VALIDATION = /verify|validate|check.*token|decode.*token|jwt\.verify|jwtVerify/i;
const TOKEN_EXPIRY = /expires?[_\s]?(?:in|at)|exp[_\s]?(?:time|date)|maxAge|max_age|ttl/i;

export function extractAuthFlows(graph: AgentGraph, filePath: string, lines: string[]): void {
  const content = lines.join('\n');
  const seen = new Set<string>();

  for (const { pattern, type } of AUTH_LIB_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = re.exec(content)) !== null) {
      if (isCommentLine(content, match.index, langFromPath(filePath))) continue;
      const lineNum = content.substring(0, match.index).split('\n').length;
      const key = `${filePath}:${lineNum}:${type}`;
      if (seen.has(key)) continue;
      seen.add(key);

      // Detect provider
      let provider: string | undefined;
      for (const pp of AUTH_PROVIDER_PATTERNS) {
        if (pp.pattern.test(content)) {
          provider = pp.provider;
          break;
        }
      }

      graph.authFlows.push({
        type,
        file: filePath,
        line: lineNum,
        provider,
        hasTokenValidation: TOKEN_VALIDATION.test(content),
        hasTokenExpiry: TOKEN_EXPIRY.test(content),
      });
    }
  }
}

// ─── 5. RBAC/Permission Checks ──────────────────────────────────────

const RBAC_PATTERNS: { pattern: RegExp; type: PermissionCheck['type'] }[] = [
  // Python decorators
  { pattern: /@require_role\s*\(\s*["']([^"']+)["']/gi, type: 'rbac' },
  { pattern: /@has_permission\s*\(\s*["']([^"']+)["']/gi, type: 'rbac' },
  { pattern: /@permission_required\s*\(\s*["']([^"']+)["']/gi, type: 'rbac' },
  // Java annotations
  { pattern: /@PreAuthorize\s*\(\s*"([^"]+)"/gi, type: 'rbac' },
  { pattern: /@Secured\s*\(\s*\{?\s*"([^"]+)"/gi, type: 'rbac' },
  { pattern: /@RolesAllowed\s*\(\s*\{?\s*"([^"]+)"/gi, type: 'rbac' },
  // Function calls
  { pattern: /check_permission\s*\(\s*["']([^"']+)["']/gi, type: 'rbac' },
  { pattern: /has_role\s*\(\s*["']([^"']+)["']/gi, type: 'role-check' },
  { pattern: /hasRole\s*\(\s*["']([^"']+)["']/gi, type: 'role-check' },
  { pattern: /authorize\s*\(\s*["']([^"']+)["']/gi, type: 'rbac' },
  // JS middleware
  { pattern: /requireAuth|isAdmin|isAuthenticated|checkScope|requireRole/gi, type: 'role-check' },
  // Scope checks
  { pattern: /\.scope\s*(?:===?\s*|\.includes\s*\(\s*)["']([^"']+)["']/gi, type: 'scope' },
  { pattern: /hasScope\s*\(\s*["']([^"']+)["']/gi, type: 'scope' },
];

export function extractPermissionChecks(graph: AgentGraph, filePath: string, lines: string[]): void {
  const content = lines.join('\n');
  const seen = new Set<string>();

  for (const { pattern, type } of RBAC_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = re.exec(content)) !== null) {
      if (isCommentLine(content, match.index, langFromPath(filePath))) continue;
      const lineNum = content.substring(0, match.index).split('\n').length;
      const key = `${filePath}:${lineNum}:${type}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const value = match[1];
      const roles = type === 'rbac' || type === 'role-check' ? [value].filter(Boolean) : undefined;
      const scopes = type === 'scope' ? [value].filter(Boolean) : undefined;

      graph.permissionChecks.push({
        type,
        file: filePath,
        line: lineNum,
        roles,
        scopes,
      });
    }
  }
}

// ─── 6. PII Reference Detection ────────────────────────────────────

const PII_FIELD_PATTERNS: { pattern: RegExp; type: PIIReference['type'] }[] = [
  { pattern: /\b(?:email|e_mail|email_address|emailAddr)\b/gi, type: 'email' },
  { pattern: /\b(?:phone|phone_number|phoneNumber|mobile|telephone)\b/gi, type: 'phone' },
  { pattern: /\b(?:ssn|social_security|socialSecurity|social_security_number)\b/gi, type: 'ssn' },
  { pattern: /\b(?:street_address|streetAddress|home_address|mailing_address|postal_address)\b/gi, type: 'address' },
  { pattern: /\b(?:full_name|fullName|first_name|firstName|last_name|lastName|surname)\b/gi, type: 'name' },
  { pattern: /\b(?:date_of_birth|dateOfBirth|dob|birth_date|birthDate|birthday)\b/gi, type: 'dob' },
  { pattern: /\b(?:credit_card|creditCard|card_number|cardNumber|cvv|ccn)\b/gi, type: 'financial' },
  { pattern: /\b(?:bank_account|bankAccount|routing_number|iban|swift_code)\b/gi, type: 'financial' },
  { pattern: /\b(?:medical_record|diagnosis|patient_id|patientId|health_id)\b/gi, type: 'health' },
];

const LOGGING_CONTEXT = /\b(?:log|logger|logging|console|print|puts|fmt\.Print|System\.out)\b/i;
const STORAGE_CONTEXT = /\b(?:save|store|write|insert|persist|put|set|cache)\b/i;
const TRANSMISSION_CONTEXT = /\b(?:send|post|emit|publish|transmit|forward|fetch|request)\b/i;
const MASKING_PATTERNS = /\b(?:mask|redact|anonymize|obfuscate|sanitize|scrub)\b|\*{3,}/i;
const ENCRYPTION_PATTERNS = /\b(?:encrypt|cipher|aes|rsa|hash|bcrypt|argon|scrypt|crypto)\b/i;

function detectPIIContext(line: string): PIIReference['context'] {
  if (LOGGING_CONTEXT.test(line)) return 'logging';
  if (TRANSMISSION_CONTEXT.test(line)) return 'transmission';
  if (STORAGE_CONTEXT.test(line)) return 'storage';
  return 'collection';
}

export function extractPIIReferences(graph: AgentGraph, filePath: string, lines: string[]): void {
  const seen = new Set<string>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trimStart().startsWith('//') || line.trimStart().startsWith('#')) continue;

    for (const { pattern, type } of PII_FIELD_PATTERNS) {
      const re = new RegExp(pattern.source, pattern.flags);
      if (re.test(line)) {
        const key = `${filePath}:${i + 1}:${type}`;
        if (seen.has(key)) continue;
        seen.add(key);

        // Check surrounding lines for context
        const contextWindow = lines.slice(Math.max(0, i - 2), Math.min(lines.length, i + 3)).join('\n');

        graph.piiReferences.push({
          type,
          file: filePath,
          line: i + 1,
          context: detectPIIContext(line),
          hasMasking: MASKING_PATTERNS.test(contextWindow),
          hasEncryption: ENCRYPTION_PATTERNS.test(contextWindow),
        });
      }
    }
  }
}

// ─── 7. Call Graph Edges ────────────────────────────────────────────

const FUNCTION_DEF_PATTERNS = [
  // Python
  /^\s*(?:async\s+)?def\s+(\w+)\s*\(/gm,
  // JS/TS function declaration
  /^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(/gm,
  // JS/TS const/let arrow or function expression
  /^\s*(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\([^)]*\)\s*=>|function)/gm,
  // Go
  /^\s*func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(/gm,
];

export function extractCallGraphEdges(
  graph: AgentGraph,
  filePath: string,
  lines: string[],
  globalFunctions?: Map<string, { file: string; line: number; isAsync: boolean }>,
): void {
  const content = lines.join('\n');
  const definedFunctions = new Map<string, { line: number; isAsync: boolean }>();

  // Collect function definitions
  for (const pattern of FUNCTION_DEF_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = re.exec(content)) !== null) {
      const name = match[1];
      const lineNum = content.substring(0, match.index).split('\n').length;
      const isAsync = /async\s/.test(match[0]);
      definedFunctions.set(name, { line: lineNum, isAsync });
      // Populate global symbol table
      if (globalFunctions && !globalFunctions.has(name)) {
        globalFunctions.set(name, { file: filePath, line: lineNum, isAsync });
      }
    }
  }

  if (definedFunctions.size === 0) return;

  // Build regex for call sites of defined functions
  const funcNames = [...definedFunctions.keys()].filter(n => n.length > 2);
  if (funcNames.length === 0) return;

  // Find which function scope each line belongs to
  const functionRanges: { name: string; startLine: number; endLine: number; isAsync: boolean }[] = [];
  const sortedDefs = [...definedFunctions.entries()].sort((a, b) => a[1].line - b[1].line);

  for (let i = 0; i < sortedDefs.length; i++) {
    const [name, { line: startLine, isAsync }] = sortedDefs[i];
    const endLine = i + 1 < sortedDefs.length ? sortedDefs[i + 1][1].line - 1 : lines.length;
    functionRanges.push({ name, startLine, endLine, isAsync });
  }

  function findEnclosingFunc(lineNum: number): { name: string; isAsync: boolean } | null {
    for (const range of functionRanges) {
      if (lineNum >= range.startLine && lineNum <= range.endLine) return range;
    }
    return null;
  }

  // Scan for call sites
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const funcName of funcNames) {
      // Look for funcName( but not def funcName( or function funcName(
      const callRe = new RegExp(`(?<!def |function |const |let |var |func )\\b${escapeRegExp(funcName)}\\s*\\(`, 'g');
      if (callRe.test(line)) {
        const caller = findEnclosingFunc(i + 1);
        if (caller && caller.name !== funcName) {
          graph.callGraph.push({
            caller: caller.name,
            callee: funcName,
            file: filePath,
            line: i + 1,
            isAsync: caller.isAsync || /\bawait\b/.test(line),
            crossesFile: false,
          });
        }
      }
    }
  }
}

// ─── 8. Rate Limiting Detection ─────────────────────────────────────

const RATE_LIMIT_PATTERNS: { pattern: RegExp; type: RateLimitConfig['type'] }[] = [
  // Libraries
  { pattern: /\bratelimit\b/gi, type: 'api' },
  { pattern: /\bslowapi\b/gi, type: 'api' },
  { pattern: /\bexpress-rate-limit\b|rateLimit\s*\(/gi, type: 'api' },
  { pattern: /@RateLimiter|bucket4j|RateLimitInterceptor/gi, type: 'api' },
  { pattern: /\bthrottle\s*\(/gi, type: 'general' },
  // Config patterns
  { pattern: /\brate_limit\s*[:=]/gi, type: 'api' },
  { pattern: /\bmax_requests\s*[:=]\s*(\d+)/gi, type: 'api' },
  { pattern: /\brequests_per_(?:minute|second|hour)\s*[:=]\s*(\d+)/gi, type: 'api' },
  // LLM-specific
  { pattern: /\bmax_tokens_per_minute\s*[:=]\s*(\d+)/gi, type: 'llm' },
  { pattern: /\bmax_requests_per_day\s*[:=]\s*(\d+)/gi, type: 'llm' },
  { pattern: /\btokens_per_minute\b/gi, type: 'llm' },
  { pattern: /\brequests_per_minute\b/gi, type: 'llm' },
];

export function extractRateLimits(graph: AgentGraph, filePath: string, lines: string[]): void {
  const content = lines.join('\n');
  const seen = new Set<string>();

  for (const { pattern, type } of RATE_LIMIT_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = re.exec(content)) !== null) {
      if (isCommentLine(content, match.index, langFromPath(filePath))) continue;
      const lineNum = content.substring(0, match.index).split('\n').length;
      const key = `${filePath}:${lineNum}:${type}`;
      if (seen.has(key)) continue;
      seen.add(key);

      graph.rateLimits.push({
        file: filePath,
        line: lineNum,
        type,
        hasLimit: true,
        limitValue: match[1] || undefined,
      });
    }
  }
}

// ─── 9. Message Queue Detection ─────────────────────────────────────

const MQ_PATTERNS: { pattern: RegExp; type: MessageQueue['type'] }[] = [
  // Kafka
  { pattern: /\bKafkaConsumer\b|\bKafkaProducer\b|\bKafkaClient\b/g, type: 'kafka' },
  { pattern: /@KafkaListener/g, type: 'kafka' },
  { pattern: /\bnew Kafka\s*\(/g, type: 'kafka' },
  // RabbitMQ
  { pattern: /\bpika\.BlockingConnection\b|\bramqp\b/g, type: 'rabbitmq' },
  { pattern: /@RabbitListener/g, type: 'rabbitmq' },
  { pattern: /\bamqplib\b|\bamqp\.connect\b/g, type: 'rabbitmq' },
  // SQS
  { pattern: /\bsqs\.(?:send_message|receive_message|SendMessage|ReceiveMessage)\b/g, type: 'sqs' },
  { pattern: /\bSQSClient\b|\bSqsClient\b/g, type: 'sqs' },
  // Redis pub/sub
  { pattern: /\bredis\.(?:subscribe|publish|psubscribe)\b/g, type: 'redis-pub-sub' },
  { pattern: /\b(?:createClient|Redis)\b.*\b(?:subscribe|publish)\b/g, type: 'redis-pub-sub' },
  // NATS
  { pattern: /\bnats\.connect\b|\bNATSClient\b/g, type: 'nats' },
  // Celery
  { pattern: /@(?:celery\.task|shared_task|app\.task)/g, type: 'celery' },
  { pattern: /\bCelery\s*\(/g, type: 'celery' },
  // Bull
  { pattern: /\bnew\s+(?:Queue|Bull)\s*\(/g, type: 'bull' },
  { pattern: /\bbullmq\b/g, type: 'bull' },
];

const MQ_AUTH_PATTERN = /\b(?:sasl\w*|credentials|username|password|auth\b)/i;
const MQ_ENCRYPTION_PATTERN = /\b(?:ssl|tls|encryption|encrypted)\b/i;

export function extractMessageQueues(graph: AgentGraph, filePath: string, lines: string[]): void {
  const content = lines.join('\n');
  const seen = new Set<string>();

  for (const { pattern, type } of MQ_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = re.exec(content)) !== null) {
      if (isCommentLine(content, match.index, langFromPath(filePath))) continue;
      const lineNum = content.substring(0, match.index).split('\n').length;
      const key = `${filePath}:${lineNum}:${type}`;
      if (seen.has(key)) continue;
      seen.add(key);

      // Check surrounding context for topic, auth, encryption
      const start = Math.max(0, match.index - 200);
      const end = Math.min(content.length, match.index + match[0].length + 200);
      const surrounding = content.substring(start, end);

      // Try to extract topic/queue name
      const topicMatch = surrounding.match(/(?:topic|queue|channel)\s*[:=]\s*["']([^"']+)["']/i);

      graph.messageQueues.push({
        type,
        file: filePath,
        line: lineNum,
        topic: topicMatch?.[1],
        hasAuthentication: MQ_AUTH_PATTERN.test(surrounding),
        hasEncryption: MQ_ENCRYPTION_PATTERN.test(surrounding),
      });
    }
  }
}

// ─── 10. Cross-File Call Graph Resolution ───────────────────────────

function resolveCrossFileCallGraph(
  graph: AgentGraph,
  fileContents: Map<string, string[]>,
  globalFunctions: Map<string, { file: string; line: number; isAsync: boolean }>,
): void {
  // Build set of existing intra-file edges for dedup
  const existingEdges = new Set(
    graph.callGraph.map(e => `${e.file}:${e.caller}->${e.callee}`),
  );

  for (const [filePath, lines] of fileContents) {
    // Collect local function definitions for this file
    const localFunctions = new Set<string>();
    for (const pattern of FUNCTION_DEF_PATTERNS) {
      const re = new RegExp(pattern.source, pattern.flags);
      const content = lines.join('\n');
      let match: RegExpExecArray | null;
      while ((match = re.exec(content)) !== null) {
        localFunctions.add(match[1]);
      }
    }

    // Build function ranges for caller detection
    const content = lines.join('\n');
    const definedFunctions = new Map<string, { line: number; isAsync: boolean }>();
    for (const pattern of FUNCTION_DEF_PATTERNS) {
      const re = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = re.exec(content)) !== null) {
        const name = match[1];
        const lineNum = content.substring(0, match.index).split('\n').length;
        const isAsync = /async\s/.test(match[0]);
        definedFunctions.set(name, { line: lineNum, isAsync });
      }
    }

    const sortedDefs = [...definedFunctions.entries()].sort((a, b) => a[1].line - b[1].line);
    const functionRanges: { name: string; startLine: number; endLine: number; isAsync: boolean }[] = [];
    for (let i = 0; i < sortedDefs.length; i++) {
      const [name, { line: startLine, isAsync }] = sortedDefs[i];
      const endLine = i + 1 < sortedDefs.length ? sortedDefs[i + 1][1].line - 1 : lines.length;
      functionRanges.push({ name, startLine, endLine, isAsync });
    }

    function findEnclosingFunc(lineNum: number): { name: string; isAsync: boolean } | null {
      for (const range of functionRanges) {
        if (lineNum >= range.startLine && lineNum <= range.endLine) return range;
      }
      return null;
    }

    // Scan for calls to functions defined in other files
    for (const [funcName, def] of globalFunctions) {
      if (funcName.length <= 2) continue;
      if (def.file === filePath) continue; // skip same-file
      if (localFunctions.has(funcName)) continue; // locally defined, skip

      for (let i = 0; i < lines.length; i++) {
        const callRe = new RegExp(`(?<!def |function |const |let |var |func )\\b${escapeRegExp(funcName)}\\s*\\(`, 'g');
        if (callRe.test(lines[i])) {
          const caller = findEnclosingFunc(i + 1);
          const callerName = caller?.name ?? '<module>';
          const edgeKey = `${filePath}:${callerName}->${funcName}`;
          if (existingEdges.has(edgeKey)) continue;
          existingEdges.add(edgeKey);

          graph.callGraph.push({
            caller: callerName,
            callee: funcName,
            file: filePath,
            line: i + 1,
            isAsync: (caller?.isAsync ?? false) || /\bawait\b/.test(lines[i]),
            crossesFile: true,
          });
        }
      }
    }
  }
}

// ─── 11. Return-Value Taint Tracking ────────────────────────────────

const TAINT_SOURCE_PATTERNS = [
  /\w+\s*=\s*(?:await\s+)?(?:\w+\.)?(?:execute|run|invoke|call)\s*\(/,   // tool execution results
  /\w+\s*=\s*(?:await\s+)?fetch\s*\(/,                                     // fetch results
  /\w+\s*=\s*(?:await\s+)?requests\.(?:get|post|put|delete|patch)\s*\(/,    // Python requests
  /\w+\s*=\s*(?:await\s+)?axios\.(?:get|post|put|delete|patch)\s*\(/,       // axios results
  /\w+\s*=\s*(?:await\s+)?httpx\.(?:get|post|put|delete|patch)\s*\(/,       // httpx results
  /\w+\s*=\s*(?:await\s+)?(?:\w+\.)?tool_call\s*\(/,                        // generic tool call
];

const TAINT_SINK_PATTERNS = [
  /f["'].*\{/,                                                               // Python f-string interpolation
  /`[^`]*\$\{/,                                                              // JS template literal
  /\.format\s*\(/,                                                           // .format() interpolation
  /(?:prompt|message|content)\s*[+=]\s*/,                                    // prompt construction
  /(?:system|user|assistant)\s*[:=]\s*.*\+/,                                 // role message construction
  /(?:ChatCompletion|completion|generate|invoke)\s*\(/,                      // LLM call with potential tainted input
];

const TAINT_SANITIZER_PATTERNS = [
  /\b(?:validate|sanitize|filter|clean|parse|escape|encode)\s*\(/,
  /\bJSON\.parse\s*\(/,
  /\b(?:parseInt|parseFloat|Number|Boolean)\s*\(/,
  /\b(?:strip|trim|replace)\s*\(/,
];

export function extractReturnValueTaints(graph: AgentGraph, filePath: string, lines: string[]): void {
  // Find sources, sinks, and sanitizers
  const sources: { line: number; text: string; type: 'tool' | 'api' }[] = [];
  const sinks: { line: number; text: string }[] = [];
  const sanitizerLines = new Set<number>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    for (const sp of TAINT_SOURCE_PATTERNS) {
      const m = sp.exec(line);
      if (m) {
        const isApi = /fetch|requests\.|axios\.|httpx\./.test(line);
        sources.push({ line: i, text: m[0], type: isApi ? 'api' : 'tool' });
        break;
      }
    }

    for (const sp of TAINT_SINK_PATTERNS) {
      if (sp.test(line)) {
        sinks.push({ line: i, text: line.trim().substring(0, 100) });
        break;
      }
    }

    for (const sp of TAINT_SANITIZER_PATTERNS) {
      if (sp.test(line)) {
        sanitizerLines.add(i);
      }
    }
  }

  // Check source → sink flows (within 30 lines, no sanitizer between)
  for (const source of sources) {
    for (const sink of sinks) {
      if (sink.line <= source.line) continue;
      if (sink.line - source.line > 30) continue;

      let sanitized = false;
      for (let l = source.line; l <= sink.line; l++) {
        if (sanitizerLines.has(l)) {
          sanitized = true;
          break;
        }
      }

      if (!sanitized) {
        const taintFlow = source.type === 'api' ? 'api-to-decision' as const : 'tool-to-prompt' as const;
        graph.callGraph.push({
          caller: source.text.split('=')[0].trim(),
          callee: sink.text.substring(0, 50),
          file: filePath,
          line: source.line + 1,
          isAsync: /await/.test(source.text),
          crossesFile: false,
          taintFlow,
        });
        break; // one taint flow per source is sufficient
      }
    }
  }
}

// ─── Helpers ────────────────────────────────────────────────────────

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
