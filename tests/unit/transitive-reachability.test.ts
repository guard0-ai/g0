import { describe, it, expect } from 'vitest';
import { ModuleGraph } from '../../src/analyzers/ast/module-graph.js';

describe('ModuleGraph.getTransitiveImporters', () => {
  it('finds direct importers', () => {
    const g = new ModuleGraph();
    g.addEdge('agent.py', 'utils.py');
    const importers = g.getTransitiveImporters('utils.py');
    expect(importers.has('agent.py')).toBe(true);
    expect(importers.size).toBe(1);
  });

  it('finds transitive importers through chain', () => {
    const g = new ModuleGraph();
    g.addEdge('agent.py', 'service.py');
    g.addEdge('service.py', 'db.py');
    const importers = g.getTransitiveImporters('db.py');
    expect(importers.has('service.py')).toBe(true);
    expect(importers.has('agent.py')).toBe(true);
    expect(importers.size).toBe(2);
  });

  it('handles diamond dependencies', () => {
    const g = new ModuleGraph();
    g.addEdge('agent.py', 'serviceA.py');
    g.addEdge('agent.py', 'serviceB.py');
    g.addEdge('serviceA.py', 'shared.py');
    g.addEdge('serviceB.py', 'shared.py');
    const importers = g.getTransitiveImporters('shared.py');
    expect(importers.has('serviceA.py')).toBe(true);
    expect(importers.has('serviceB.py')).toBe(true);
    expect(importers.has('agent.py')).toBe(true);
    expect(importers.size).toBe(3);
  });

  it('respects depth limit', () => {
    const g = new ModuleGraph();
    g.addEdge('a.py', 'b.py');
    g.addEdge('b.py', 'c.py');
    g.addEdge('c.py', 'd.py');
    g.addEdge('d.py', 'e.py');
    const importers = g.getTransitiveImporters('e.py', 2);
    expect(importers.has('d.py')).toBe(true);
    expect(importers.has('c.py')).toBe(true);
    // a.py is 4 hops away, beyond depth 2
    expect(importers.has('a.py')).toBe(false);
  });

  it('handles cycles without infinite loop', () => {
    const g = new ModuleGraph();
    g.addEdge('a.py', 'b.py');
    g.addEdge('b.py', 'a.py');
    const importers = g.getTransitiveImporters('b.py');
    expect(importers.has('a.py')).toBe(true);
  });

  it('does not include the file itself', () => {
    const g = new ModuleGraph();
    g.addEdge('agent.py', 'utils.py');
    const importers = g.getTransitiveImporters('utils.py');
    expect(importers.has('utils.py')).toBe(false);
  });
});
