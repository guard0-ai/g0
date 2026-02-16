import { z } from 'zod';

const severitySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);
const confidenceSchema = z.enum(['high', 'medium', 'low']);

const domainSchema = z.enum([
  'goal-integrity',
  'tool-safety',
  'identity-access',
  'supply-chain',
  'code-execution',
  'memory-context',
  'data-leakage',
  'cascading-failures',
  'human-oversight',
  'inter-agent',
  'reliability-bounds',
  'rogue-agent',
]);

const standardsMappingSchema = z.object({
  owasp_agentic: z.array(z.string()).optional(),
  nist_ai_rmf: z.array(z.string()).optional(),
  iso42001: z.array(z.string()).optional(),
  iso23894: z.array(z.string()).optional(),
  owasp_aivss: z.array(z.string()).optional(),
  a2as_basic: z.array(z.string()).optional(),
  aiuc1: z.array(z.string()).optional(),
  eu_ai_act: z.array(z.string()).optional(),
  mitre_atlas: z.array(z.string()).optional(),
  owasp_llm_top10: z.array(z.string()).optional(),
}).optional();

const checkSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('prompt_contains'),
    pattern: z.string(),
    prompt_type: z.enum(['system', 'user', 'template', 'few_shot', 'any']).default('system'),
    message: z.string(),
  }),
  z.object({
    type: z.literal('prompt_missing'),
    pattern: z.string(),
    prompt_type: z.enum(['system', 'user', 'template', 'few_shot', 'any']).default('system'),
    message: z.string(),
  }),
  z.object({
    type: z.literal('tool_has_capability'),
    capability: z.string(),
    message: z.string(),
  }),
  z.object({
    type: z.literal('tool_missing_property'),
    property: z.enum(['hasInputValidation', 'hasSandboxing', 'hasSideEffects']),
    expected: z.boolean().default(true),
    message: z.string(),
  }),
  z.object({
    type: z.literal('config_matches'),
    pattern: z.string(),
    message: z.string(),
  }),
  z.object({
    type: z.literal('code_matches'),
    pattern: z.string(),
    language: z.enum(['python', 'typescript', 'javascript', 'java', 'go', 'yaml', 'json', 'any']).default('any'),
    message: z.string(),
  }),
  z.object({
    type: z.literal('agent_property'),
    property: z.string(),
    condition: z.enum(['missing', 'exists', 'equals']),
    value: z.union([z.string(), z.number(), z.boolean()]).optional(),
    message: z.string(),
  }),
  z.object({
    type: z.literal('model_property'),
    property: z.string(),
    condition: z.enum(['missing', 'exists', 'equals', 'matches']),
    value: z.union([z.string(), z.number(), z.boolean()]).optional(),
    message: z.string(),
  }),
  z.object({
    type: z.literal('project_missing'),
    control: z.enum([
      'rate-limiting', 'input-validation', 'output-sanitization',
      'authentication', 'authorization', 'encryption', 'logging',
      'error-handling', 'timeout', 'sandboxing', 'content-filtering',
      'access-control', 'csrf-protection', 'cors-configuration',
      'secret-management', 'data-classification', 'audit-trail',
      'human-approval', 'circuit-breaker', 'retry-backoff',
    ]),
    message: z.string(),
  }),
  z.object({
    type: z.literal('taint_flow'),
    sources: z.array(z.object({ pattern: z.string() })),
    sinks: z.array(z.object({ pattern: z.string() })),
    sanitizers: z.array(z.object({ pattern: z.string() })).optional(),
    language: z.enum(['python', 'typescript', 'javascript', 'java', 'go', 'any']).default('any'),
    message: z.string(),
  }),
  z.object({
    type: z.literal('no_check'),
    message: z.string().default('Dynamic-only control — no static check available'),
  }),
]);

export const yamlRuleSchema = z.object({
  id: z.string().regex(/^AA-[A-Z]{2}-\d{3}$/),
  info: z.object({
    name: z.string(),
    domain: domainSchema,
    severity: severitySchema,
    confidence: confidenceSchema,
    description: z.string(),
    frameworks: z.array(z.string()).default(['all']),
    owasp_agentic: z.array(z.string()).default([]),
    standards: standardsMappingSchema,
  }),
  check: checkSchema,
  suppressed_by: z.array(z.enum([
    'rate-limiting', 'input-validation', 'output-sanitization',
    'authentication', 'authorization', 'encryption', 'logging',
    'error-handling', 'timeout', 'sandboxing', 'content-filtering',
    'access-control', 'csrf-protection', 'cors-configuration',
    'secret-management', 'data-classification', 'audit-trail',
    'human-approval', 'circuit-breaker', 'retry-backoff',
  ])).optional(),
});

export type YamlRule = z.infer<typeof yamlRuleSchema>;
export type YamlCheckType = YamlRule['check']['type'];
