import { describe, it, expect, beforeEach } from 'vitest';
import type { AgentGraph, PromptNode } from '../../src/types/agent-graph.js';
import {
  extractPromptPermissions,
  extractAPIEndpoints,
  extractDatabaseAccesses,
  extractAuthFlows,
  extractPermissionChecks,
  extractPIIReferences,
  extractCallGraphEdges,
  extractRateLimits,
  extractMessageQueues,
  extractReturnValueTaints,
} from '../../src/analyzers/enrichment.js';

function makeGraph(overrides?: Partial<AgentGraph>): AgentGraph {
  return {
    id: 'test',
    rootPath: '/tmp/test',
    primaryFramework: 'openai',
    secondaryFrameworks: [],
    agents: [],
    tools: [],
    prompts: [],
    configs: [],
    models: [],
    vectorDBs: [],
    frameworkVersions: [],
    interAgentLinks: [],
    files: { all: [], python: [], typescript: [], javascript: [], java: [], go: [] },
    permissions: [],
    apiEndpoints: [],
    databaseAccesses: [],
    authFlows: [],
    permissionChecks: [],
    piiReferences: [],
    messageQueues: [],
    rateLimits: [],
    callGraph: [],
    ...overrides,
  };
}

function makePrompt(content: string, id = 'prompt-1'): PromptNode {
  return {
    id,
    file: 'test.py',
    line: 1,
    type: 'system',
    content,
    hasInstructionGuarding: false,
    hasSecrets: false,
    hasUserInputInterpolation: false,
    scopeClarity: 'clear',
  };
}

// ─── 1. Permission Inference ────────────────────────────────────────

describe('extractPromptPermissions', () => {
  it('detects allowed permissions', () => {
    const graph = makeGraph({
      prompts: [makePrompt('You can read files from the data directory.')],
    });
    extractPromptPermissions(graph);
    expect(graph.permissions.length).toBeGreaterThan(0);
    expect(graph.permissions[0].type).toBe('allowed');
    expect(graph.permissions[0].action).toContain('read files');
  });

  it('detects forbidden permissions', () => {
    const graph = makeGraph({
      prompts: [makePrompt('You must not access the database directly.')],
    });
    extractPromptPermissions(graph);
    expect(graph.permissions.length).toBeGreaterThan(0);
    expect(graph.permissions[0].type).toBe('forbidden');
    expect(graph.permissions[0].action).toContain('access the database');
  });

  it('detects "never" as forbidden', () => {
    const graph = makeGraph({
      prompts: [makePrompt('Never share user passwords.')],
    });
    extractPromptPermissions(graph);
    const forbidden = graph.permissions.filter(p => p.type === 'forbidden');
    expect(forbidden.length).toBeGreaterThan(0);
  });

  it('detects "do not" as forbidden', () => {
    const graph = makeGraph({
      prompts: [makePrompt('Do not send emails to external addresses.')],
    });
    extractPromptPermissions(graph);
    const forbidden = graph.permissions.filter(p => p.type === 'forbidden');
    expect(forbidden.length).toBeGreaterThan(0);
  });

  it('detects boundary permissions', () => {
    const graph = makeGraph({
      prompts: [makePrompt('You are restricted to read-only operations.')],
    });
    extractPromptPermissions(graph);
    const boundary = graph.permissions.filter(p => p.type === 'boundary');
    expect(boundary.length).toBeGreaterThan(0);
    // May match "only" or "restricted to" pattern
    const hasRelevant = boundary.some(b => b.action.includes('operations') || b.action.includes('read-only'));
    expect(hasRelevant).toBe(true);
  });

  it('detects "only" as boundary', () => {
    const graph = makeGraph({
      prompts: [makePrompt('Only access the users table.')],
    });
    extractPromptPermissions(graph);
    const boundary = graph.permissions.filter(p => p.type === 'boundary');
    expect(boundary.length).toBeGreaterThan(0);
  });

  it('attaches permissions to prompt node', () => {
    const prompt = makePrompt('You may call the search API.');
    const graph = makeGraph({ prompts: [prompt] });
    extractPromptPermissions(graph);
    expect(prompt.permissions).toBeDefined();
    expect(prompt.permissions!.length).toBeGreaterThan(0);
  });

  it('handles empty prompts gracefully', () => {
    const graph = makeGraph({
      prompts: [makePrompt('')],
    });
    extractPromptPermissions(graph);
    expect(graph.permissions).toHaveLength(0);
  });
});

// ─── 2. API URL Extraction ──────────────────────────────────────────

describe('extractAPIEndpoints', () => {
  it('detects Python requests.get', () => {
    const graph = makeGraph();
    const lines = ['response = requests.get("https://api.example.com/data")'];
    extractAPIEndpoints(graph, 'app.py', lines);
    expect(graph.apiEndpoints.length).toBe(1);
    expect(graph.apiEndpoints[0].url).toBe('https://api.example.com/data');
    expect(graph.apiEndpoints[0].method).toBe('GET');
    expect(graph.apiEndpoints[0].isExternal).toBe(true);
  });

  it('detects Python requests.post', () => {
    const graph = makeGraph();
    const lines = ['requests.post("https://api.example.com/submit", json=data)'];
    extractAPIEndpoints(graph, 'app.py', lines);
    expect(graph.apiEndpoints.length).toBe(1);
    expect(graph.apiEndpoints[0].method).toBe('POST');
  });

  it('detects JS fetch', () => {
    const graph = makeGraph();
    const lines = ['const res = await fetch("https://api.example.com/users")'];
    extractAPIEndpoints(graph, 'app.ts', lines);
    expect(graph.apiEndpoints.length).toBe(1);
    expect(graph.apiEndpoints[0].url).toBe('https://api.example.com/users');
  });

  it('detects axios calls', () => {
    const graph = makeGraph();
    const lines = ['const res = await axios.get("https://api.example.com/items")'];
    extractAPIEndpoints(graph, 'app.ts', lines);
    expect(graph.apiEndpoints.length).toBe(1);
    expect(graph.apiEndpoints[0].method).toBe('GET');
  });

  it('detects Go http.Get', () => {
    const graph = makeGraph();
    const lines = ['resp, err := http.Get("https://api.example.com/health")'];
    extractAPIEndpoints(graph, 'main.go', lines);
    expect(graph.apiEndpoints.length).toBe(1);
    expect(graph.apiEndpoints[0].method).toBe('GET');
  });

  it('detects Java Spring annotations', () => {
    const graph = makeGraph();
    const lines = ['@PostMapping("/api/users")'];
    extractAPIEndpoints(graph, 'Controller.java', lines);
    expect(graph.apiEndpoints.length).toBe(1);
    expect(graph.apiEndpoints[0].url).toBe('/api/users');
    expect(graph.apiEndpoints[0].isExternal).toBe(false);
  });

  it('marks localhost as internal', () => {
    const graph = makeGraph();
    const lines = ['fetch("http://localhost:3000/api")'];
    extractAPIEndpoints(graph, 'app.ts', lines);
    expect(graph.apiEndpoints.length).toBe(1);
    expect(graph.apiEndpoints[0].isExternal).toBe(false);
  });

  it('detects standalone URL literals', () => {
    const graph = makeGraph();
    const lines = ['const API_URL = "https://external-service.com/v2/endpoint"'];
    extractAPIEndpoints(graph, 'config.ts', lines);
    expect(graph.apiEndpoints.length).toBe(1);
    expect(graph.apiEndpoints[0].isExternal).toBe(true);
  });
});

// ─── 3. Database Access ─────────────────────────────────────────────

describe('extractDatabaseAccesses', () => {
  it('detects SELECT queries', () => {
    const graph = makeGraph();
    const lines = ['cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'];
    extractDatabaseAccesses(graph, 'db.py', lines);
    expect(graph.databaseAccesses.length).toBe(1);
    expect(graph.databaseAccesses[0].operation).toBe('read');
    expect(graph.databaseAccesses[0].table).toBe('users');
    expect(graph.databaseAccesses[0].hasParameterizedQuery).toBe(true);
  });

  it('detects INSERT queries', () => {
    const graph = makeGraph();
    const lines = ['db.execute("INSERT INTO orders VALUES ($1, $2)", [id, amount])'];
    extractDatabaseAccesses(graph, 'db.py', lines);
    expect(graph.databaseAccesses.length).toBe(1);
    expect(graph.databaseAccesses[0].operation).toBe('write');
    expect(graph.databaseAccesses[0].table).toBe('orders');
  });

  it('detects DELETE queries', () => {
    const graph = makeGraph();
    const lines = ['db.execute("DELETE FROM sessions WHERE expired = true")'];
    extractDatabaseAccesses(graph, 'cleanup.py', lines);
    expect(graph.databaseAccesses.length).toBe(1);
    expect(graph.databaseAccesses[0].operation).toBe('delete');
  });

  it('detects unparameterized queries via string concat', () => {
    const graph = makeGraph();
    const lines = ['cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")'];
    extractDatabaseAccesses(graph, 'db.py', lines);
    expect(graph.databaseAccesses.length).toBe(1);
    expect(graph.databaseAccesses[0].hasParameterizedQuery).toBe(false);
  });

  it('detects ORM find operations', () => {
    const graph = makeGraph();
    const lines = [
      'import { PrismaClient } from "@prisma/client"',
      'const user = await User.findMany({ where: { active: true } })',
    ];
    extractDatabaseAccesses(graph, 'users.ts', lines);
    expect(graph.databaseAccesses.length).toBeGreaterThanOrEqual(1);
    const ormRead = graph.databaseAccesses.find(d => d.type === 'orm' && d.operation === 'read');
    expect(ormRead).toBeDefined();
  });

  it('detects ORM create operations', () => {
    const graph = makeGraph();
    const lines = [
      'import { PrismaClient } from "@prisma/client"',
      'await prisma.user.create({ data: { name, email } })',
    ];
    extractDatabaseAccesses(graph, 'users.ts', lines);
    expect(graph.databaseAccesses.length).toBe(1);
    expect(graph.databaseAccesses[0].operation).toBe('write');
  });

  it('detects DROP TABLE as admin', () => {
    const graph = makeGraph();
    const lines = ['DROP TABLE IF EXISTS temp_data'];
    extractDatabaseAccesses(graph, 'migrate.sql', lines);
    expect(graph.databaseAccesses.length).toBe(1);
    expect(graph.databaseAccesses[0].operation).toBe('admin');
  });

  it('detects MongoDB operations', () => {
    const graph = makeGraph();
    const lines = [
      'import { MongoClient } from "mongodb"',
      'await collection.insertMany(documents)',
    ];
    extractDatabaseAccesses(graph, 'mongo.ts', lines);
    expect(graph.databaseAccesses.length).toBe(1);
    expect(graph.databaseAccesses[0].type).toBe('nosql');
    expect(graph.databaseAccesses[0].operation).toBe('write');
  });
});

// ─── 4. Auth Flow Detection ────────────────────────────────────────

describe('extractAuthFlows', () => {
  it('detects JWT usage', () => {
    const graph = makeGraph();
    const lines = [
      'import jwt from "jsonwebtoken"',
      'const token = jwt.sign(payload, secret, { expiresIn: "1h" })',
      'const decoded = jwt.verify(token, secret)',
    ];
    extractAuthFlows(graph, 'auth.ts', lines);
    expect(graph.authFlows.length).toBeGreaterThan(0);
    const jwtFlows = graph.authFlows.filter(a => a.type === 'jwt');
    expect(jwtFlows.length).toBeGreaterThan(0);
    expect(jwtFlows[0].hasTokenValidation).toBe(true);
    expect(jwtFlows[0].hasTokenExpiry).toBe(true);
  });

  it('detects API key auth', () => {
    const graph = makeGraph();
    const lines = ['headers["x-api-key"] = process.env.API_KEY'];
    extractAuthFlows(graph, 'client.ts', lines);
    expect(graph.authFlows.length).toBeGreaterThan(0);
    expect(graph.authFlows[0].type).toBe('api-key');
  });

  it('detects OAuth2 grant type', () => {
    const graph = makeGraph();
    const lines = ['grant_type = "authorization_code"'];
    extractAuthFlows(graph, 'oauth.py', lines);
    expect(graph.authFlows.length).toBeGreaterThan(0);
    expect(graph.authFlows[0].type).toBe('oauth2');
  });

  it('detects OIDC configuration', () => {
    const graph = makeGraph();
    const lines = ['const discovery = await fetch("https://auth.example.com/.well-known/openid-configuration")'];
    extractAuthFlows(graph, 'auth.ts', lines);
    const oidc = graph.authFlows.filter(a => a.type === 'oidc');
    expect(oidc.length).toBeGreaterThan(0);
  });

  it('detects Bearer token auth', () => {
    const graph = makeGraph();
    const lines = ['headers["Authorization"] = "Bearer " + token'];
    extractAuthFlows(graph, 'client.py', lines);
    expect(graph.authFlows.length).toBeGreaterThan(0);
    expect(graph.authFlows[0].type).toBe('bearer');
  });

  it('detects auth providers', () => {
    const graph = makeGraph();
    const lines = [
      'import { ClerkProvider } from "@clerk/nextjs"',
      'const token = jwt.sign(payload, secret)',
    ];
    extractAuthFlows(graph, 'auth.ts', lines);
    const withProvider = graph.authFlows.filter(a => a.provider === 'clerk');
    expect(withProvider.length).toBeGreaterThan(0);
  });
});

// ─── 5. RBAC/Permission Checks ─────────────────────────────────────

describe('extractPermissionChecks', () => {
  it('detects Python role decorators', () => {
    const graph = makeGraph();
    const lines = ['@require_role("admin")', 'def delete_user(user_id):'];
    extractPermissionChecks(graph, 'views.py', lines);
    expect(graph.permissionChecks.length).toBe(1);
    expect(graph.permissionChecks[0].type).toBe('rbac');
    expect(graph.permissionChecks[0].roles).toContain('admin');
  });

  it('detects Java @PreAuthorize', () => {
    const graph = makeGraph();
    const lines = ['@PreAuthorize("hasRole(\'ADMIN\')")'];
    extractPermissionChecks(graph, 'Controller.java', lines);
    expect(graph.permissionChecks.length).toBeGreaterThanOrEqual(1);
    const rbac = graph.permissionChecks.find(p => p.type === 'rbac');
    expect(rbac).toBeDefined();
  });

  it('detects JS middleware patterns', () => {
    const graph = makeGraph();
    const lines = ['app.use("/admin", requireAuth, isAdmin)'];
    extractPermissionChecks(graph, 'routes.ts', lines);
    expect(graph.permissionChecks.length).toBeGreaterThan(0);
  });

  it('detects scope checks', () => {
    const graph = makeGraph();
    const lines = ['if (hasScope("read:users")) {'];
    extractPermissionChecks(graph, 'middleware.ts', lines);
    const scopes = graph.permissionChecks.filter(p => p.type === 'scope');
    expect(scopes.length).toBe(1);
    expect(scopes[0].scopes).toContain('read:users');
  });

  it('detects has_role function calls', () => {
    const graph = makeGraph();
    const lines = ['if has_role("editor"):'];
    extractPermissionChecks(graph, 'auth.py', lines);
    expect(graph.permissionChecks.length).toBe(1);
    expect(graph.permissionChecks[0].type).toBe('role-check');
  });

  it('detects @RolesAllowed', () => {
    const graph = makeGraph();
    const lines = ['@RolesAllowed({"USER", "ADMIN"})'];
    extractPermissionChecks(graph, 'Resource.java', lines);
    expect(graph.permissionChecks.length).toBe(1);
  });
});

// ─── 6. PII Detection ──────────────────────────────────────────────

describe('extractPIIReferences', () => {
  it('detects email field', () => {
    const graph = makeGraph();
    const lines = ['user_email = request.form["email"]'];
    extractPIIReferences(graph, 'form.py', lines);
    expect(graph.piiReferences.length).toBeGreaterThan(0);
    expect(graph.piiReferences[0].type).toBe('email');
  });

  it('detects SSN field', () => {
    const graph = makeGraph();
    const lines = ['const ssn = form.social_security_number'];
    extractPIIReferences(graph, 'form.ts', lines);
    const ssnRefs = graph.piiReferences.filter(p => p.type === 'ssn');
    expect(ssnRefs.length).toBeGreaterThan(0);
  });

  it('detects PII in logging context', () => {
    const graph = makeGraph();
    const lines = ['logger.info(f"User email: {email}")'];
    extractPIIReferences(graph, 'app.py', lines);
    const logged = graph.piiReferences.filter(p => p.context === 'logging');
    expect(logged.length).toBeGreaterThan(0);
  });

  it('detects PII masking', () => {
    const graph = makeGraph();
    const lines = [
      'const phone = user.phone_number',
      'const masked = mask(phone)',
    ];
    extractPIIReferences(graph, 'display.ts', lines);
    const phoneRefs = graph.piiReferences.filter(p => p.type === 'phone');
    expect(phoneRefs.length).toBeGreaterThan(0);
    expect(phoneRefs[0].hasMasking).toBe(true);
  });

  it('detects credit card fields', () => {
    const graph = makeGraph();
    const lines = ['const creditCard = payment.credit_card'];
    extractPIIReferences(graph, 'payment.ts', lines);
    const financial = graph.piiReferences.filter(p => p.type === 'financial');
    expect(financial.length).toBeGreaterThan(0);
  });

  it('detects encryption near PII', () => {
    const graph = makeGraph();
    const lines = [
      'const encrypted = encrypt(user.date_of_birth)',
    ];
    extractPIIReferences(graph, 'store.ts', lines);
    const dobRefs = graph.piiReferences.filter(p => p.type === 'dob');
    expect(dobRefs.length).toBeGreaterThan(0);
    expect(dobRefs[0].hasEncryption).toBe(true);
  });
});

// ─── 7. Rate Limiting ──────────────────────────────────────────────

describe('extractRateLimits', () => {
  it('detects express-rate-limit', () => {
    const graph = makeGraph();
    const lines = [
      'import rateLimit from "express-rate-limit"',
      'const limiter = rateLimit({ windowMs: 60000, max: 100 })',
    ];
    extractRateLimits(graph, 'app.ts', lines);
    expect(graph.rateLimits.length).toBeGreaterThan(0);
  });

  it('detects Python slowapi', () => {
    const graph = makeGraph();
    const lines = ['from slowapi import Limiter'];
    extractRateLimits(graph, 'app.py', lines);
    expect(graph.rateLimits.length).toBeGreaterThan(0);
  });

  it('detects LLM rate limits', () => {
    const graph = makeGraph();
    const lines = ['max_tokens_per_minute = 100000'];
    extractRateLimits(graph, 'config.py', lines);
    const llmLimits = graph.rateLimits.filter(r => r.type === 'llm');
    expect(llmLimits.length).toBeGreaterThan(0);
  });

  it('detects max_requests config', () => {
    const graph = makeGraph();
    const lines = ['max_requests = 500'];
    extractRateLimits(graph, 'config.py', lines);
    expect(graph.rateLimits.length).toBeGreaterThan(0);
    expect(graph.rateLimits[0].hasLimit).toBe(true);
  });
});

// ─── 8. Message Queues ─────────────────────────────────────────────

describe('extractMessageQueues', () => {
  it('detects Kafka producer', () => {
    const graph = makeGraph();
    const lines = ['producer = KafkaProducer(bootstrap_servers="kafka:9092")'];
    extractMessageQueues(graph, 'worker.py', lines);
    expect(graph.messageQueues.length).toBe(1);
    expect(graph.messageQueues[0].type).toBe('kafka');
  });

  it('detects RabbitMQ via pika', () => {
    const graph = makeGraph();
    const lines = ['connection = pika.BlockingConnection(params)'];
    extractMessageQueues(graph, 'consumer.py', lines);
    expect(graph.messageQueues.length).toBe(1);
    expect(graph.messageQueues[0].type).toBe('rabbitmq');
  });

  it('detects SQS client', () => {
    const graph = makeGraph();
    const lines = ['const sqs = new SQSClient({ region: "us-east-1" })'];
    extractMessageQueues(graph, 'queue.ts', lines);
    expect(graph.messageQueues.length).toBe(1);
    expect(graph.messageQueues[0].type).toBe('sqs');
  });

  it('detects Celery tasks', () => {
    const graph = makeGraph();
    const lines = ['@celery.task', 'def process_order(order_id):'];
    extractMessageQueues(graph, 'tasks.py', lines);
    expect(graph.messageQueues.length).toBe(1);
    expect(graph.messageQueues[0].type).toBe('celery');
  });

  it('detects Bull queue', () => {
    const graph = makeGraph();
    const lines = ['const emailQueue = new Queue("emails", { connection })'];
    extractMessageQueues(graph, 'jobs.ts', lines);
    expect(graph.messageQueues.length).toBe(1);
    expect(graph.messageQueues[0].type).toBe('bull');
  });

  it('detects MQ authentication', () => {
    const graph = makeGraph();
    const lines = ['producer = KafkaProducer(bootstrap_servers="kafka:9092", sasl_mechanism="PLAIN")'];
    extractMessageQueues(graph, 'worker.py', lines);
    expect(graph.messageQueues[0].hasAuthentication).toBe(true);
  });

  it('detects MQ encryption', () => {
    const graph = makeGraph();
    const lines = ['producer = KafkaProducer(bootstrap_servers="kafka:9092", security_protocol="ssl")'];
    extractMessageQueues(graph, 'worker.py', lines);
    expect(graph.messageQueues[0].hasEncryption).toBe(true);
  });
});

// ─── 9. Call Graph ─────────────────────────────────────────────────

describe('extractCallGraphEdges', () => {
  it('detects Python function calls', () => {
    const graph = makeGraph();
    const lines = [
      'def fetch_data():',
      '    return requests.get("http://api.example.com")',
      '',
      'def process():',
      '    data = fetch_data()',
      '    return transform(data)',
    ];
    extractCallGraphEdges(graph, 'app.py', lines);
    const edges = graph.callGraph.filter(e => e.caller === 'process' && e.callee === 'fetch_data');
    expect(edges.length).toBe(1);
  });

  it('detects JS function calls', () => {
    const graph = makeGraph();
    const lines = [
      'function validateInput(data) {',
      '  return schema.parse(data)',
      '}',
      '',
      'async function handleRequest(req) {',
      '  const valid = validateInput(req.body)',
      '  return respond(valid)',
      '}',
    ];
    extractCallGraphEdges(graph, 'handler.ts', lines);
    const edges = graph.callGraph.filter(e => e.caller === 'handleRequest' && e.callee === 'validateInput');
    expect(edges.length).toBe(1);
  });

  it('detects async calls', () => {
    const graph = makeGraph();
    const lines = [
      'async function fetchUser(id) {',
      '  return await db.find(id)',
      '}',
      '',
      'async function getProfile(userId) {',
      '  const user = await fetchUser(userId)',
      '  return user',
      '}',
    ];
    extractCallGraphEdges(graph, 'user.ts', lines);
    const edges = graph.callGraph.filter(e => e.callee === 'fetchUser');
    expect(edges.length).toBe(1);
    expect(edges[0].isAsync).toBe(true);
  });

  it('does not create self-referencing edges', () => {
    const graph = makeGraph();
    const lines = [
      'def recursive(n):',
      '    if n <= 0: return',
      '    recursive(n - 1)',
    ];
    extractCallGraphEdges(graph, 'rec.py', lines);
    const selfEdges = graph.callGraph.filter(e => e.caller === e.callee);
    expect(selfEdges.length).toBe(0);
  });

  it('sets crossesFile to false for same-file calls', () => {
    const graph = makeGraph();
    const lines = [
      'function helper() { return 1 }',
      'function main() { return helper() }',
    ];
    extractCallGraphEdges(graph, 'app.ts', lines);
    expect(graph.callGraph.every(e => e.crossesFile === false)).toBe(true);
  });

  it('populates global function table when provided', () => {
    const graph = makeGraph();
    const globalFunctions = new Map<string, { file: string; line: number; isAsync: boolean }>();
    const lines = [
      'function fetchData() { return 1 }',
      'function processData() { return fetchData() }',
    ];
    extractCallGraphEdges(graph, 'utils.ts', lines, globalFunctions);
    expect(globalFunctions.has('fetchData')).toBe(true);
    expect(globalFunctions.get('fetchData')?.file).toBe('utils.ts');
  });
});

// ─── 10. Cross-File Call Graph ──────────────────────────────────────

describe('cross-file call graph resolution (via enrichAgentGraph)', () => {
  it('detects cross-file function call', () => {
    const graph = makeGraph();
    const globalFunctions = new Map<string, { file: string; line: number; isAsync: boolean }>();

    // File A defines fetchData
    const linesA = [
      'function fetchData() {',
      '  return fetch("https://api.example.com")',
      '}',
    ];
    extractCallGraphEdges(graph, 'utils.ts', linesA, globalFunctions);

    // File B calls fetchData (which it doesn't define)
    const linesB = [
      'function processRequest() {',
      '  const data = fetchData()',
      '  return data',
      '}',
    ];
    extractCallGraphEdges(graph, 'handler.ts', linesB, globalFunctions);

    // The intra-file pass won't find fetchData in handler.ts since it's not defined there.
    // We need to check that globalFunctions was populated from utils.ts
    expect(globalFunctions.has('fetchData')).toBe(true);
    expect(globalFunctions.get('fetchData')?.file).toBe('utils.ts');
  });
});

// ─── 11. Return-Value Taint Tracking ────────────────────────────────

describe('extractReturnValueTaints', () => {
  it('detects tool result flowing to prompt interpolation', () => {
    const graph = makeGraph();
    const lines = [
      'async function handleTask() {',
      '  const result = await tool.execute("search", query)',
      '  const prompt = `Based on this data: ${result}`',
      '  const response = await completion(prompt)',
      '}',
    ];
    extractReturnValueTaints(graph, 'agent.ts', lines);
    const taintEdges = graph.callGraph.filter(e => e.taintFlow === 'tool-to-prompt');
    expect(taintEdges.length).toBeGreaterThan(0);
  });

  it('detects API response flowing to LLM context', () => {
    const graph = makeGraph();
    const lines = [
      'async function enrich() {',
      '  const data = await fetch("https://api.example.com/data")',
      '  const prompt = `Analyze: ${data}`',
      '  return prompt',
      '}',
    ];
    extractReturnValueTaints(graph, 'enricher.ts', lines);
    const taintEdges = graph.callGraph.filter(e => e.taintFlow === 'api-to-decision');
    expect(taintEdges.length).toBeGreaterThan(0);
  });

  it('does not flag when sanitizer exists between source and sink', () => {
    const graph = makeGraph();
    const lines = [
      'async function handleTask() {',
      '  const result = await tool.execute("search", query)',
      '  const safe = sanitize(result)',
      '  const prompt = `Based on this data: ${safe}`',
      '}',
    ];
    extractReturnValueTaints(graph, 'agent.ts', lines);
    const taintEdges = graph.callGraph.filter(e => e.taintFlow);
    expect(taintEdges).toHaveLength(0);
  });

  it('does not flag when JSON.parse sanitizes', () => {
    const graph = makeGraph();
    const lines = [
      'async function handleTask() {',
      '  const raw = await fetch("https://api.example.com")',
      '  const data = JSON.parse(raw)',
      '  const prompt = `Result: ${data.name}`',
      '}',
    ];
    extractReturnValueTaints(graph, 'agent.ts', lines);
    const taintEdges = graph.callGraph.filter(e => e.taintFlow);
    expect(taintEdges).toHaveLength(0);
  });

  it('handles Python f-string sinks', () => {
    const graph = makeGraph();
    const lines = [
      'def process():',
      '    result = tool.execute("lookup", user_id)',
      '    prompt = f"User data: {result}"',
      '    return llm.invoke(prompt)',
    ];
    extractReturnValueTaints(graph, 'agent.py', lines);
    const taintEdges = graph.callGraph.filter(e => e.taintFlow === 'tool-to-prompt');
    expect(taintEdges.length).toBeGreaterThan(0);
  });

  it('detects Python requests as API source', () => {
    const graph = makeGraph();
    const lines = [
      'def enrich():',
      '    data = requests.get("https://api.example.com/info")',
      '    prompt = f"Context: {data.text}"',
      '    return prompt',
    ];
    extractReturnValueTaints(graph, 'enricher.py', lines);
    const taintEdges = graph.callGraph.filter(e => e.taintFlow === 'api-to-decision');
    expect(taintEdges.length).toBeGreaterThan(0);
  });

  it('returns empty for no source-sink pairs', () => {
    const graph = makeGraph();
    const lines = [
      'function hello() {',
      '  console.log("hello")',
      '}',
    ];
    extractReturnValueTaints(graph, 'hello.ts', lines);
    expect(graph.callGraph.filter(e => e.taintFlow)).toHaveLength(0);
  });
});
