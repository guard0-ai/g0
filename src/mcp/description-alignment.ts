import type { MCPToolInfo, MCPFinding } from '../types/mcp-scan.js';

export interface AlignmentResult {
  toolName: string;
  undisclosedCapabilities: string[];
  descriptionClaims: string[];
  actualCapabilities: string[];
  aligned: boolean;
  severity: 'high' | 'medium' | 'low';
}

// Keywords in description that claim limited behavior
const RESTRICTIVE_CLAIMS: Record<string, RegExp> = {
  'read-only': /\b(?:read[- ]?only|readonly|just\s+reads?|only\s+reads?|fetche?s?\b)/i,
  'no-network': /\b(?:no\s+network|offline|local[- ]?only|does\s+not\s+(?:access|connect))/i,
  'no-write': /\b(?:no\s+writ|doesn'?t\s+write|read[- ]?only|non[- ]?destructive)/i,
  'no-execute': /\b(?:no\s+execut|doesn'?t\s+execut|safe|sandboxed)/i,
  'no-shell': /\b(?:no\s+shell|doesn'?t\s+(?:run|execute)\s+command)/i,
};

// Map capabilities to what they contradict
const CAPABILITY_CONTRADICTIONS: Record<string, string[]> = {
  'shell': ['read-only', 'no-execute', 'no-shell', 'no-write'],
  'filesystem-write': ['read-only', 'no-write'],
  'network': ['no-network'],
  'code-execution': ['read-only', 'no-execute'],
  'database': [],
  'email': ['no-network'],
  'filesystem-read': [],
};

// Overprivileged description patterns
const OVERPRIVILEGED_PATTERNS = [
  /\bany\s+file\b/i,
  /\ball\s+(?:files?|access|permissions?)\b/i,
  /\bunrestricted\b/i,
  /\bfull\s+(?:access|control|permissions?)\b/i,
  /\beverything\b/i,
  /\bno\s+(?:limits?|restrictions?|boundaries)\b/i,
];

export function checkDescriptionAlignment(tools: MCPToolInfo[]): AlignmentResult[] {
  const results: AlignmentResult[] = [];

  for (const tool of tools) {
    const description = tool.description ?? '';
    const caps = tool.capabilities ?? [];

    // Detect restrictive claims in description
    const claims: string[] = [];
    for (const [claim, pattern] of Object.entries(RESTRICTIVE_CLAIMS)) {
      if (pattern.test(description)) claims.push(claim);
    }

    // Find undisclosed capabilities that contradict claims
    const undisclosed: string[] = [];
    for (const cap of caps) {
      const contradicts = CAPABILITY_CONTRADICTIONS[cap] ?? [];
      for (const claim of claims) {
        if (contradicts.includes(claim)) {
          undisclosed.push(cap);
          break;
        }
      }
    }

    const aligned = undisclosed.length === 0;
    const severity = undisclosed.some(c => c === 'shell' || c === 'code-execution')
      ? 'high' as const
      : undisclosed.length > 0 ? 'medium' as const : 'low' as const;

    if (!aligned) {
      results.push({
        toolName: tool.name,
        undisclosedCapabilities: undisclosed,
        descriptionClaims: claims,
        actualCapabilities: caps,
        aligned: false,
        severity,
      });
    }
  }

  return results;
}

export function convertAlignmentToFindings(
  results: AlignmentResult[],
  serverName: string,
  filePath: string,
): MCPFinding[] {
  return results.map(r => ({
    severity: r.severity,
    type: 'description-mismatch' as const,
    title: `Tool description-behavior mismatch: ${r.toolName}`,
    description: `Tool "${r.toolName}" claims ${r.descriptionClaims.join(', ')} but has capabilities: ${r.undisclosedCapabilities.join(', ')}`,
    server: serverName,
    file: filePath,
  }));
}

export function detectOverprivilegedDescriptions(tools: MCPToolInfo[]): MCPFinding[] {
  const findings: MCPFinding[] = [];

  for (const tool of tools) {
    const description = tool.description ?? '';
    for (const pattern of OVERPRIVILEGED_PATTERNS) {
      if (pattern.test(description)) {
        findings.push({
          severity: 'medium',
          type: 'overprivileged-description',
          title: `Overprivileged description: ${tool.name}`,
          description: `Tool "${tool.name}" uses overprivileged language ("${description.match(pattern)?.[0]}") suggesting excessive access`,
          server: tool.name,
          file: tool.file ?? '',
        });
        break;
      }
    }
  }

  return findings;
}
