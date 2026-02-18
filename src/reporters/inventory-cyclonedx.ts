import * as fs from 'node:fs';
import { randomUUID } from 'node:crypto';
import type { InventoryResult } from '../types/inventory.js';

interface CycloneDXBom {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: { vendor: string; name: string; version: string }[];
    properties?: { name: string; value: string }[];
  };
  components: CycloneDXComponent[];
  services: CycloneDXService[];
  dependencies: CycloneDXDependency[];
}

interface CycloneDXComponent {
  type: string;
  'bom-ref': string;
  name: string;
  version?: string;
  description?: string;
  group?: string;
  properties?: { name: string; value: string }[];
}

interface CycloneDXService {
  'bom-ref': string;
  name: string;
  description?: string;
  endpoints?: string[];
  properties?: { name: string; value: string }[];
}

interface CycloneDXDependency {
  ref: string;
  dependsOn: string[];
}

export function reportInventoryCycloneDX(inventory: InventoryResult, outputPath?: string): string {
  const components: CycloneDXComponent[] = [];
  const services: CycloneDXService[] = [];
  const dependencies: CycloneDXDependency[] = [];

  // Models → machine-learning-model
  for (const model of inventory.models) {
    const ref = `model:${model.name}:${model.provider}`;
    components.push({
      type: 'machine-learning-model',
      'bom-ref': ref,
      name: model.name,
      group: model.provider,
      properties: [
        { name: 'ai:framework', value: model.framework },
        { name: 'ai:file', value: model.file },
      ],
    });
  }

  // Frameworks → framework
  for (const fw of inventory.frameworks) {
    const ref = `framework:${fw.name}`;
    components.push({
      type: 'framework',
      'bom-ref': ref,
      name: fw.name,
      version: fw.version,
      properties: [
        { name: 'ai:file', value: fw.file },
      ],
    });
  }

  // Tools → library
  for (const tool of inventory.tools) {
    const ref = `tool:${tool.name}:${tool.framework}`;
    components.push({
      type: 'library',
      'bom-ref': ref,
      name: tool.name,
      description: tool.description,
      properties: [
        { name: 'ai:framework', value: tool.framework },
        { name: 'ai:capabilities', value: tool.capabilities.join(', ') },
        { name: 'ai:hasSideEffects', value: String(tool.hasSideEffects) },
        { name: 'ai:hasValidation', value: String(tool.hasValidation) },
      ],
    });
  }

  // MCP servers → services
  for (const server of inventory.mcpServers) {
    services.push({
      'bom-ref': `mcp:${server.name}`,
      name: server.name,
      description: `MCP server: ${server.command} ${server.args.join(' ')}`,
      properties: [
        { name: 'ai:command', value: server.command },
        { name: 'ai:hasSecrets', value: String(server.hasSecrets) },
        { name: 'ai:isPinned', value: String(server.isPinned) },
      ],
    });
  }

  // Agent-tool-model dependencies
  for (const agent of inventory.agents) {
    const agentRef = `agent:${agent.name}:${agent.framework}`;
    const deps: string[] = [];

    // Link to model
    if (agent.model) {
      const modelRef = components.find(c => c.type === 'machine-learning-model' && c.name === agent.model);
      if (modelRef) deps.push(modelRef['bom-ref']);
    }

    // Link to framework
    const fwRef = components.find(c => c.type === 'framework' && c.name === agent.framework);
    if (fwRef) deps.push(fwRef['bom-ref']);

    // Link to tools (by framework match)
    const toolRefs = components.filter(c => c.type === 'library' && c.properties?.some(p => p.name === 'ai:framework' && p.value === agent.framework));
    for (const tr of toolRefs) deps.push(tr['bom-ref']);

    if (deps.length > 0) {
      dependencies.push({ ref: agentRef, dependsOn: deps });
    }
  }

  // Enrichment: API endpoints as services
  if (inventory.summary.enrichment) {
    const e = inventory.summary.enrichment;
    // Group external API endpoints as a service
    if (e.totalAPIEndpoints > 0) {
      services.push({
        'bom-ref': 'enrichment:api-endpoints',
        name: 'External API Endpoints',
        description: `${e.totalAPIEndpoints} API endpoints detected (${e.totalExternalAPIs} external)`,
        properties: [
          { name: 'ai:security:totalEndpoints', value: String(e.totalAPIEndpoints) },
          { name: 'ai:security:externalEndpoints', value: String(e.totalExternalAPIs) },
        ],
      });
    }
  }

  // Enrichment metadata properties
  const metadataProperties: { name: string; value: string }[] = [];
  if (inventory.summary.enrichment) {
    const e = inventory.summary.enrichment;
    metadataProperties.push(
      { name: 'ai:security:apiEndpoints', value: String(e.totalAPIEndpoints) },
      { name: 'ai:security:externalAPIs', value: String(e.totalExternalAPIs) },
      { name: 'ai:security:databaseAccesses', value: String(e.totalDatabaseAccesses) },
      { name: 'ai:security:unparameterizedQueries', value: String(e.unparameterizedQueries) },
      { name: 'ai:security:authFlows', value: String(e.totalAuthFlows) },
      { name: 'ai:security:permissionChecks', value: String(e.totalPermissionChecks) },
      { name: 'ai:security:piiReferences', value: String(e.totalPIIReferences) },
      { name: 'ai:security:piiWithoutMasking', value: String(e.piiWithoutMasking) },
      { name: 'ai:security:messageQueues', value: String(e.totalMessageQueues) },
      { name: 'ai:security:rateLimits', value: String(e.totalRateLimits) },
      { name: 'ai:security:callGraphEdges', value: String(e.totalCallGraphEdges) },
    );
  }

  const bom: CycloneDXBom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'guard0', name: 'g0', version: '1.0.0' }],
      ...(metadataProperties.length > 0 ? { properties: metadataProperties } : {}),
    },
    components,
    services,
    dependencies,
  };

  const json = JSON.stringify(bom, null, 2);

  if (outputPath) {
    fs.writeFileSync(outputPath, json, 'utf-8');
  }

  return json;
}
