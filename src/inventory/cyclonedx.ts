/**
 * CycloneDX ML-BOM export for the AI Bill of Materials.
 *
 * Emits a CycloneDX 1.6 document so a g0 AI-BOM is an interchange artifact other
 * tools (and procurement/vendor-risk teams) can consume — "send me your g0
 * AI-BOM" the way SBOMs are exchanged today. The document carries a stable,
 * content-addressed hash (g0:bomHash) that is independent of the serial number
 * and timestamp, so two BOMs can be diffed and a signature can bind the content.
 */
import * as crypto from 'node:crypto';
import type { InventoryResult } from '../types/inventory.js';

export const CYCLONEDX_SPEC_VERSION = '1.6';

export interface BomMeta {
  projectName: string;
  toolVersion: string;
  timestamp: string;   // ISO — excluded from the content hash
  serialNumber: string; // urn:uuid:... — excluded from the content hash
}

interface CdxComponent {
  type: string;
  'bom-ref': string;
  name: string;
  group?: string;
  version?: string;
  properties?: Array<{ name: string; value: string }>;
}

interface CdxService {
  'bom-ref': string;
  name: string;
  properties?: Array<{ name: string; value: string }>;
}

export interface CycloneDXBom {
  bomFormat: 'CycloneDX';
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: Record<string, unknown>;
  components: CdxComponent[];
  services: CdxService[];
  properties: Array<{ name: string; value: string }>;
  /** Detached ed25519 signature over the g0:bomHash, when signing is requested. */
  signature?: import('./sign.js').BomSignature;
}

function prop(name: string, value: string) {
  return { name, value };
}

/** Build the component/service lists from an inventory (order-stable). */
function buildComponents(inv: InventoryResult): { components: CdxComponent[]; services: CdxService[] } {
  const components: CdxComponent[] = [];

  for (const m of inv.models) {
    components.push({
      type: 'machine-learning-model',
      'bom-ref': `model:${m.provider}/${m.name}`,
      name: m.name,
      group: m.provider,
      properties: [prop('g0:framework', m.framework), prop('g0:file', `${m.file}:${m.line}`)],
    });
  }

  for (const f of inv.frameworks) {
    components.push({
      type: 'library',
      'bom-ref': `framework:${f.name}@${f.version ?? 'unknown'}`,
      name: f.name,
      version: f.version,
      properties: [prop('g0:kind', 'framework')],
    });
  }

  for (const t of inv.tools) {
    components.push({
      type: 'library',
      'bom-ref': `tool:${t.framework}/${t.name}`,
      name: t.name,
      group: t.framework,
      properties: [
        prop('g0:kind', 'tool'),
        prop('g0:capabilities', t.capabilities.join(',')),
        prop('g0:hasSideEffects', String(t.hasSideEffects)),
        prop('g0:hasValidation', String(t.hasValidation)),
      ],
    });
  }

  for (const a of inv.agents) {
    components.push({
      type: 'application',
      'bom-ref': `agent:${a.framework}/${a.name}`,
      name: a.name,
      group: a.framework,
      properties: [
        prop('g0:kind', 'agent'),
        prop('g0:toolCount', String(a.toolCount)),
        prop('g0:hasDelegation', String(a.hasDelegation)),
        ...(a.model ? [prop('g0:model', a.model)] : []),
      ],
    });
  }

  const services: CdxService[] = inv.mcpServers.map(s => ({
    'bom-ref': `mcp:${s.name}`,
    name: s.name,
    properties: [
      prop('g0:kind', 'mcp-server'),
      prop('g0:hasSecrets', String(s.hasSecrets)),
      prop('g0:isPinned', String(s.isPinned)),
      ...(s.transport ? [prop('g0:transport', s.transport)] : []),
    ],
  }));

  return { components, services };
}

/**
 * Content-addressed hash of the BOM: a stable projection of components/services
 * that excludes the serial number and timestamp so the same inventory always
 * hashes identically (enables diffing and signing).
 */
export function computeBomHash(components: CdxComponent[], services: CdxService[]): string {
  const projection = {
    components: components
      .map(c => ({ type: c.type, ref: c['bom-ref'], name: c.name, group: c.group ?? '', version: c.version ?? '', properties: c.properties ?? [] }))
      .sort((a, b) => a.ref.localeCompare(b.ref)),
    services: services
      .map(s => ({ ref: s['bom-ref'], name: s.name, properties: s.properties ?? [] }))
      .sort((a, b) => a.ref.localeCompare(b.ref)),
  };
  return crypto.createHash('sha256').update(JSON.stringify(projection)).digest('hex');
}

/** Produce a CycloneDX 1.6 BOM from an inventory. */
export function toCycloneDX(inv: InventoryResult, meta: BomMeta): CycloneDXBom {
  const { components, services } = buildComponents(inv);
  const bomHash = computeBomHash(components, services);

  return {
    bomFormat: 'CycloneDX',
    specVersion: CYCLONEDX_SPEC_VERSION,
    serialNumber: meta.serialNumber,
    version: 1,
    metadata: {
      timestamp: meta.timestamp,
      tools: [{ vendor: 'Guard0', name: 'g0', version: meta.toolVersion }],
      component: { type: 'application', name: meta.projectName, 'bom-ref': `project:${meta.projectName}` },
    },
    components,
    services,
    properties: [prop('g0:bomHash', bomHash)],
  };
}
