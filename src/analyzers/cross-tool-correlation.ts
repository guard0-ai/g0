import type { AgentGraph, ToolCapability } from '../types/agent-graph.js';
import type { Finding } from '../types/finding.js';

export interface ToolCombinationRisk {
  agentName: string;
  tools: string[];
  riskType: string;
  description: string;
  severity: 'critical' | 'high' | 'medium';
}

interface CapabilityCombo {
  required: ToolCapability[];
  riskType: string;
  description: string;
  severity: 'critical' | 'high' | 'medium';
}

const DANGEROUS_COMBOS: CapabilityCombo[] = [
  {
    required: ['filesystem', 'network'],
    riskType: 'read-then-exfil',
    description: 'Agent can read local files and send data over network — potential data exfiltration path',
    severity: 'high',
  },
  {
    required: ['network', 'code-execution'],
    riskType: 'fetch-then-exec',
    description: 'Agent can fetch remote content and execute code — potential remote code execution path',
    severity: 'critical',
  },
  {
    required: ['database', 'network'],
    riskType: 'db-exfil',
    description: 'Agent can access database and send data over network — potential database exfiltration path',
    severity: 'high',
  },
  {
    required: ['database', 'code-execution'],
    riskType: 'db-code-exec',
    description: 'Agent can query database and execute arbitrary code — potential SQL injection to RCE',
    severity: 'critical',
  },
  {
    required: ['filesystem', 'code-execution'],
    riskType: 'write-then-exec',
    description: 'Agent can write files and execute code — potential dropper/payload execution path',
    severity: 'critical',
  },
  {
    required: ['email', 'filesystem'],
    riskType: 'read-then-email',
    description: 'Agent can read files and send emails — potential data exfiltration via email',
    severity: 'high',
  },
  {
    required: ['shell', 'network'],
    riskType: 'shell-network',
    description: 'Agent has shell access and network capabilities — potential reverse shell or C2 channel',
    severity: 'critical',
  },
];

export function detectDangerousToolCombinations(graph: AgentGraph): ToolCombinationRisk[] {
  const risks: ToolCombinationRisk[] = [];

  for (const agent of graph.agents) {
    // Get all capabilities across all tools bound to this agent
    const agentTools = graph.tools.filter(t =>
      agent.tools?.includes(t.name) || agent.tools?.includes(t.id),
    );
    const allCaps = new Set(agentTools.flatMap(t => t.capabilities));
    const toolNames = agentTools.map(t => t.name);

    for (const combo of DANGEROUS_COMBOS) {
      // Check if this combo's required capabilities are spread across different tools
      const hasAll = combo.required.every(cap => allCaps.has(cap));
      if (!hasAll) continue;

      // Find which tools provide which capabilities
      const involvedTools: string[] = [];
      for (const cap of combo.required) {
        const tool = agentTools.find(t => t.capabilities.includes(cap));
        if (tool && !involvedTools.includes(tool.name)) {
          involvedTools.push(tool.name);
        }
      }

      // Only flag if capabilities come from 2+ different tools (cross-tool)
      if (involvedTools.length >= 2) {
        risks.push({
          agentName: agent.name,
          tools: involvedTools,
          riskType: combo.riskType,
          description: combo.description,
          severity: combo.severity,
        });
      }
    }
  }

  return risks;
}

export function convertToolComboToFindings(risks: ToolCombinationRisk[]): Finding[] {
  return risks.map((risk, i) => ({
    id: `cross-tool-${risk.agentName}-${risk.riskType}-${i}`,
    ruleId: 'AA-TS-CROSS-001',
    title: `Cross-tool risk: ${risk.riskType}`,
    description: `Agent "${risk.agentName}" has dangerous tool combination [${risk.tools.join(' + ')}]: ${risk.description}`,
    severity: risk.severity,
    confidence: 'medium' as const,
    domain: 'tool-safety' as const,
    location: { file: '.', line: 0 },
    remediation: `Limit tool capabilities for agent "${risk.agentName}". Apply least-privilege: separate data-access tools from network/execution tools.`,
    standards: { owaspAgentic: ['ASI02', 'ASI03'] },
  }));
}
