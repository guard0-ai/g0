import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { walkDirectory } from '../../src/discovery/walker.js';
import { detectFrameworks } from '../../src/discovery/detector.js';
import { filterTestFiles } from '../../src/discovery/graph.js';
import { runDiscovery, runGraphBuild } from '../../src/pipeline.js';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('walkDirectory', () => {
  it('discovers files in a project', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'vulnerable-agent'));
    expect(inventory.python.length).toBeGreaterThan(0);
  });

  it('categorizes Python files', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'langchain-basic'));
    expect(inventory.python.length).toBeGreaterThan(0);
    expect(inventory.python[0].language).toBe('python');
  });

  it('discovers config files', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'mcp-server'));
    expect(inventory.configs.length + inventory.json.length).toBeGreaterThan(0);
  });
});

describe('detectFrameworks', () => {
  it('detects LangChain', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'langchain-basic'));
    const result = detectFrameworks(inventory);
    expect(result.primary).toBe('langchain');
  });

  it('detects CrewAI', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'crewai-crew'));
    const result = detectFrameworks(inventory);
    expect(result.primary).toBe('crewai');
  });

  it('detects MCP', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'mcp-server'));
    const result = detectFrameworks(inventory);
    expect(result.primary).toBe('mcp');
  });

  it('detects OpenAI', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'openai-assistant'));
    const result = detectFrameworks(inventory);
    expect(result.primary).toBe('openai');
  });
});

describe('filterTestFiles', () => {
  it('judges test status relative to the scan root, not the absolute path', () => {
    // A project whose files sit under an absolute path containing "tests/" or
    // "fixtures/" must still be analyzed — the relativePath is what matters.
    const files = {
      all: [{ path: '/home/me/tests/fixtures/proj/agent.py', relativePath: 'agent.py', language: 'python' }],
      python: [{ path: '/home/me/tests/fixtures/proj/agent.py', relativePath: 'agent.py', language: 'python' }],
      typescript: [], javascript: [], java: [], go: [], all: undefined,
    } as any;
    files.all = files.python;
    const filtered = filterTestFiles(files);
    expect(filtered.python.length).toBe(1);
  });

  it('still filters test files that live under a tests/ dir within the project', () => {
    const files = {
      python: [
        { path: '/proj/src/agent.py', relativePath: 'src/agent.py', language: 'python' },
        { path: '/proj/tests/test_agent.py', relativePath: 'tests/test_agent.py', language: 'python' },
      ],
      typescript: [], javascript: [], java: [], go: [],
    } as any;
    files.all = files.python;
    const filtered = filterTestFiles(files);
    expect(filtered.python.map((f: any) => f.relativePath)).toEqual(['src/agent.py']);
  });
});

describe('graph build discovers agents/tools regardless of scan-root path', () => {
  it('finds agents and tools in the vulnerable-agent fixture (under tests/fixtures)', async () => {
    const root = path.join(FIXTURES, 'vulnerable-agent');
    const discovery = await runDiscovery(root);
    const graph = runGraphBuild(root, discovery);
    expect(graph.agents.length).toBeGreaterThan(0);
    expect(graph.tools.length).toBeGreaterThan(0);
    expect(graph.models.length).toBeGreaterThan(0);
  });
});
