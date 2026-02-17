/**
 * Injection pattern library — regex patterns for common prompt injection techniques.
 * Inspired by Vigil YARA rules and LLM Guard patterns.
 */

export interface InjectionPattern {
  id: string;
  name: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium';
  category: string;
}

const injectionPatterns: InjectionPattern[] = [
  // Instruction override
  { id: 'INJ-001', name: 'Ignore previous instructions', pattern: /ignore (?:all |any )?(?:previous|prior|above|earlier|preceding) (?:instructions?|prompts?|rules?|guidelines?|directives?)/i, severity: 'critical', category: 'instruction-override' },
  { id: 'INJ-002', name: 'New instructions', pattern: /(?:new|updated|revised|changed|overriding) (?:instructions?|directives?|rules?|guidelines?|system prompt)/i, severity: 'high', category: 'instruction-override' },
  { id: 'INJ-003', name: 'Forget everything', pattern: /forget (?:everything|all|anything) (?:you (?:know|were told|learned)|above|before)/i, severity: 'critical', category: 'instruction-override' },
  { id: 'INJ-004', name: 'System prompt override', pattern: /(?:system|admin|root) ?(?:prompt|message|instruction|override|command)\s*[:=]/i, severity: 'critical', category: 'instruction-override' },
  { id: 'INJ-005', name: 'You are now', pattern: /you are now (?:a |an |the )?(?:different|new|unrestricted|unfiltered|helpful|compliant)/i, severity: 'high', category: 'instruction-override' },

  // Persona adoption
  { id: 'INJ-006', name: 'DAN/jailbreak persona', pattern: /(?:you are|act as|pretend to be|become|roleplay as) (?:DAN|AIM|STAN|DUDE|Kevin|Evil|Shadow|Maximum|BetterDAN)/i, severity: 'critical', category: 'persona-adoption' },
  { id: 'INJ-007', name: 'No restrictions', pattern: /(?:without|no|zero|remove all) (?:restrictions?|filters?|limitations?|constraints?|guardrails?|safety|censorship)/i, severity: 'high', category: 'persona-adoption' },
  { id: 'INJ-008', name: 'Developer mode', pattern: /(?:enter|enable|activate|switch to) (?:developer|debug|admin|maintenance|unrestricted|god|sudo) (?:mode|access)/i, severity: 'high', category: 'persona-adoption' },

  // Social engineering
  { id: 'INJ-009', name: 'Authority claim', pattern: /(?:i am|i'm|this is) (?:your |the |a )?(?:developer|creator|administrator|owner|manager|lead engineer|CTO|CEO)/i, severity: 'medium', category: 'social-engineering' },
  { id: 'INJ-010', name: 'Emergency override', pattern: /(?:emergency|urgent|critical|important) (?:override|update|patch|directive|protocol|action required)/i, severity: 'medium', category: 'social-engineering' },
  { id: 'INJ-011', name: 'Security audit claim', pattern: /(?:security (?:audit|assessment|review|test)|penetration test|authorized (?:testing|assessment)|red team)/i, severity: 'medium', category: 'social-engineering' },

  // Data extraction
  { id: 'INJ-012', name: 'Repeat instructions', pattern: /(?:repeat|output|print|show|display|reveal|share|tell me) (?:your |the |all )?(?:system (?:prompt|message|instructions?)|instructions?|rules?|guidelines?|configuration)/i, severity: 'high', category: 'data-extraction' },
  { id: 'INJ-013', name: 'Verbatim output', pattern: /(?:verbatim|word.for.word|exactly|literally|precisely) (?:repeat|output|reproduce|copy)/i, severity: 'high', category: 'data-extraction' },
  { id: 'INJ-014', name: 'Everything above', pattern: /(?:everything|all text|all content|anything) (?:above|before|preceding|prior to) (?:this|my) (?:message|input|prompt)/i, severity: 'high', category: 'data-extraction' },

  // Encoding bypass
  { id: 'INJ-015', name: 'Base64 decode instruction', pattern: /(?:decode|decipher|translate|interpret) (?:the )?(?:following |this )?(?:base64|hex|binary|encoded|cipher)/i, severity: 'medium', category: 'encoding-bypass' },
  { id: 'INJ-016', name: 'Hidden text instruction', pattern: /(?:hidden|invisible|embedded|secret) (?:text|message|instruction|command|content)/i, severity: 'medium', category: 'encoding-bypass' },

  // Tool abuse
  { id: 'INJ-017', name: 'Execute command', pattern: /(?:execute|run|eval|exec|spawn|system)\s*\(.*\)/i, severity: 'high', category: 'tool-abuse' },
  { id: 'INJ-018', name: 'File system access', pattern: /(?:read|write|delete|access|open|cat|head|tail)\s+(?:\/etc\/|\/var\/|\/tmp\/|\/root\/|\.\.\/|~\/)/i, severity: 'high', category: 'tool-abuse' },
  { id: 'INJ-019', name: 'Network exfiltration', pattern: /(?:fetch|curl|wget|http|request|post|send)\s+(?:https?:\/\/|ftp:\/\/)/i, severity: 'high', category: 'tool-abuse' },

  // Indirect injection markers
  { id: 'INJ-020', name: 'HTML hidden injection', pattern: /(?:display:\s*none|visibility:\s*hidden|font-size:\s*0|opacity:\s*0|position:\s*absolute.*left:\s*-\d)/i, severity: 'medium', category: 'indirect-injection' },
  { id: 'INJ-021', name: 'Markdown image exfil', pattern: /!\[.*?\]\(https?:\/\/.*?\?.*?(?:data|token|secret|key|password|ssn|credit)=/i, severity: 'high', category: 'indirect-injection' },
  { id: 'INJ-022', name: 'Processing instructions tag', pattern: /(?:<\?|<!--\s*(?:system|instruction|prompt|override))/i, severity: 'medium', category: 'indirect-injection' },

  // Framing attacks
  { id: 'INJ-023', name: 'Hypothetical framing', pattern: /(?:hypothetically|in a fictional|imagine a world|in theory|for academic purposes|for research)/i, severity: 'medium', category: 'framing' },
  { id: 'INJ-024', name: 'Translation framing', pattern: /translate (?:the following|this) (?:from|to) (?:ai.language|imaginary|fictional|secret)/i, severity: 'medium', category: 'framing' },
  { id: 'INJ-025', name: 'Opposite day', pattern: /opposite day|reverse psychology|when you say (?:no|cannot|refuse) you (?:actually )?mean (?:yes|can|will)/i, severity: 'medium', category: 'framing' },

  // Token manipulation
  { id: 'INJ-026', name: 'Payload splitting', pattern: /(?:combine|join|concatenate|merge) (?:the )?(?:following |these )?(?:parts|pieces|segments|fragments)/i, severity: 'medium', category: 'token-manipulation' },
  { id: 'INJ-027', name: 'Completion attack', pattern: /(?:complete|continue|finish) (?:the )?(?:following|this|my) (?:sentence|text|paragraph|prompt|instructions?)/i, severity: 'medium', category: 'token-manipulation' },

  // MCP-specific
  { id: 'INJ-028', name: 'Tool description injection', pattern: /(?:tool|function)_?(?:name|description|schema)\s*[:=]\s*['"]/i, severity: 'high', category: 'mcp-injection' },
  { id: 'INJ-029', name: 'JSON-RPC manipulation', pattern: /jsonrpc|method.*tools\/call|"params"\s*:\s*\{/i, severity: 'medium', category: 'mcp-injection' },
  { id: 'INJ-030', name: 'Tool result poisoning', pattern: /(?:tool|function) (?:result|output|response)\s*[:=].*(?:ignore|override|new instruction)/i, severity: 'high', category: 'mcp-injection' },
];

/**
 * Detect injection patterns in text.
 * Returns all matching patterns.
 */
export function detectInjectionPatterns(text: string): InjectionPattern[] {
  return injectionPatterns.filter(p => p.pattern.test(text));
}

/**
 * Check if text contains high-severity injection patterns.
 */
export function hasInjectionPatterns(text: string, minSeverity: 'critical' | 'high' | 'medium' = 'high'): boolean {
  const severityOrder = { critical: 3, high: 2, medium: 1 };
  const minLevel = severityOrder[minSeverity];
  return injectionPatterns.some(p => severityOrder[p.severity] >= minLevel && p.pattern.test(text));
}
