import * as fs from 'node:fs';
import type { AgentGraph } from '../types/agent-graph.js';
import type { Finding } from '../types/finding.js';

// Patterns that read sensitive data
const SENSITIVE_READ_PATTERNS = [
  /(?:readFile|readFileSync|open\s*\()\s*.*(?:secret|password|token|key|credential|\.env|\.pem)/i,
  /(?:cursor\.execute|\.query)\s*\(\s*['"]SELECT/i,
  /(?:getenv|environ\.get|process\.env)\s*\(\s*['"](?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE)/i,
  /(?:fs\.read|os\.read).*(?:\/etc\/passwd|\/etc\/shadow|\.ssh)/i,
];

// Patterns that send data externally
const NETWORK_WRITE_PATTERNS = [
  /(?:fetch|axios|requests|http\.request|urllib)\s*\(\s*['"]https?:\/\//i,
  /\.post\s*\(/i,
  /(?:sendmail|smtp|send_email|send_message)/i,
  /(?:WebSocket|ws)\s*\(/i,
];

export function detectCrossFileExfil(graph: AgentGraph): Finding[] {
  const findings: Finding[] = [];
  const moduleGraph = graph.moduleGraph;
  if (!moduleGraph) return findings;

  const sensitiveReaders: Array<{ file: string; pattern: string }> = [];
  const networkWriters: Array<{ file: string; pattern: string }> = [];

  for (const fileInfo of graph.files.all) {
    const filePath = fileInfo.path;
    if (!filePath.match(/\.(py|ts|tsx|js|jsx|mjs|go|java)$/)) continue;

    let content: string;
    try {
      content = fs.readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }

    for (const pattern of SENSITIVE_READ_PATTERNS) {
      if (pattern.test(content)) {
        sensitiveReaders.push({ file: filePath, pattern: pattern.source });
        break;
      }
    }

    for (const pattern of NETWORK_WRITE_PATTERNS) {
      if (pattern.test(content)) {
        networkWriters.push({ file: filePath, pattern: pattern.source });
        break;
      }
    }
  }

  // Check if any sensitive reader is connected to a network writer via imports
  for (const reader of sensitiveReaders) {
    const deps = moduleGraph.getDependenciesOf(reader.file);

    for (const writer of networkWriters) {
      if (reader.file === writer.file) continue;

      const writerDeps = moduleGraph.getDependenciesOf(writer.file);
      const isConnected = deps.includes(writer.file) ||
                          writerDeps.includes(reader.file);

      if (isConnected) {
        findings.push({
          id: `cross-file-exfil-${reader.file}-${writer.file}`,
          ruleId: 'AA-DL-CROSS-001',
          title: 'Cross-file exfiltration path',
          description: `Sensitive data read in ${reader.file} may flow to network write in ${writer.file} via module imports`,
          severity: 'high',
          confidence: 'medium',
          domain: 'data-leakage',
          location: { file: reader.file, line: 0 },
          remediation: 'Ensure sensitive data is not passed to modules with network capabilities without explicit authorization checks.',
          standards: { owaspAgentic: ['ASI07'] },
          relatedLocations: [
            { file: writer.file, line: 0, message: 'Network write destination' },
          ],
        });
      }
    }
  }

  // Cap at 10 findings
  return findings.slice(0, 10);
}
