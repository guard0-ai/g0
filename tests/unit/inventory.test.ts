import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { runDiscovery, runGraphBuild } from '../../src/pipeline.js';
import { buildInventory } from '../../src/inventory/builder.js';
import { reportInventoryJson } from '../../src/reporters/inventory-json.js';
import { reportInventoryMarkdown } from '../../src/reporters/inventory-markdown.js';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('buildInventory', () => {
  it('extracts models from inventory-agent fixture', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'inventory-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'inventory-agent'), discovery, true);
    const inventory = buildInventory(graph);

    expect(inventory.models.length).toBeGreaterThan(0);
    const gpt4o = inventory.models.find(m => m.name === 'gpt-4o');
    expect(gpt4o).toBeTruthy();
    expect(gpt4o?.provider).toBe('openai');
  });

  it('extracts framework versions from requirements.txt', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'inventory-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'inventory-agent'), discovery, true);
    const inventory = buildInventory(graph);

    expect(inventory.frameworks.length).toBeGreaterThan(0);
    const langchain = inventory.frameworks.find(f => f.name === 'langchain');
    expect(langchain).toBeTruthy();
    expect(langchain?.version).toBe('0.3.1');
  });

  it('extracts tools with descriptions', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'inventory-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'inventory-agent'), discovery, true);
    const inventory = buildInventory(graph);

    expect(inventory.tools.length).toBeGreaterThan(0);
    const searchTool = inventory.tools.find(t => t.name === 'search_knowledge');
    expect(searchTool).toBeTruthy();
  });

  it('extracts agents with tool counts', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'inventory-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'inventory-agent'), discovery, true);
    const inventory = buildInventory(graph);

    expect(inventory.agents.length).toBeGreaterThan(0);
    expect(inventory.agents[0].toolCount).toBeGreaterThan(0);
  });

  it('detects vector databases', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'inventory-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'inventory-agent'), discovery, true);
    const inventory = buildInventory(graph);

    expect(inventory.vectorDBs.length).toBeGreaterThan(0);
    const pinecone = inventory.vectorDBs.find(v => v.name === 'Pinecone');
    expect(pinecone).toBeTruthy();
  });

  it('identifies risks', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'inventory-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'inventory-agent'), discovery, true);
    const inventory = buildInventory(graph);

    expect(inventory.risks.length).toBeGreaterThan(0);
  });

  it('builds summary with correct totals', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'inventory-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'inventory-agent'), discovery, true);
    const inventory = buildInventory(graph);

    expect(inventory.summary.totalModels).toBe(inventory.models.length);
    expect(inventory.summary.totalTools).toBe(inventory.tools.length);
    expect(inventory.summary.totalAgents).toBe(inventory.agents.length);
  });
});

describe('Inventory reporters', () => {
  it('produces valid JSON', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'inventory-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'inventory-agent'), discovery, true);
    const inventory = buildInventory(graph);

    const json = reportInventoryJson(inventory);
    const parsed = JSON.parse(json);
    expect(parsed.models).toBeInstanceOf(Array);
    expect(parsed.tools).toBeInstanceOf(Array);
    expect(parsed.agents).toBeInstanceOf(Array);
    expect(parsed.summary).toBeTruthy();
  });

  it('produces valid Markdown', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'inventory-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'inventory-agent'), discovery, true);
    const inventory = buildInventory(graph);

    const md = reportInventoryMarkdown(inventory);
    expect(md).toContain('# AI Agent Bill of Materials');
    expect(md).toContain('## Models');
    expect(md).toContain('gpt-4o');
  });
});

describe('Inventory on vulnerable-agent', () => {
  it('extracts models and tools from vulnerable-agent', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'vulnerable-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'vulnerable-agent'), discovery, true);
    const inventory = buildInventory(graph);

    expect(inventory.models.length).toBeGreaterThan(0);
    expect(inventory.tools.length).toBeGreaterThan(0);
    expect(inventory.agents.length).toBeGreaterThan(0);
    expect(inventory.risks.length).toBeGreaterThan(0);
  });
});
