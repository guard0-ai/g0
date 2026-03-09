import { describe, it, expect } from 'vitest';
import { computeAnalyzability, generateAnalyzabilityFindings } from '../../src/analyzers/analyzability.js';
import type { FileInventory, FileInfo } from '../../src/types/common.js';

function makeFile(relativePath: string, size = 1000): FileInfo {
  return { path: `/test/${relativePath}`, relativePath, language: 'other', size };
}

function makeInventory(files: FileInfo[]): FileInventory {
  return {
    all: files,
    python: files.filter(f => f.relativePath.endsWith('.py')),
    typescript: files.filter(f => f.relativePath.endsWith('.ts')),
    javascript: files.filter(f => f.relativePath.endsWith('.js')),
    java: files.filter(f => f.relativePath.endsWith('.java')),
    go: files.filter(f => f.relativePath.endsWith('.go')),
    yaml: files.filter(f => f.relativePath.endsWith('.yaml') || f.relativePath.endsWith('.yml')),
    json: files.filter(f => f.relativePath.endsWith('.json')),
    configs: [],
  };
}

describe('Analyzability Scoring', () => {
  it('scores 100% for all source files', () => {
    const files = makeInventory([
      makeFile('src/main.py', 2000),
      makeFile('src/utils.ts', 1500),
      makeFile('config.yaml', 500),
    ]);
    const result = computeAnalyzability(files);
    expect(result.score).toBe(100);
    expect(result.opaqueFiles).toHaveLength(0);
    expect(result.analyzableFiles).toBe(3);
  });

  it('classifies binaries as opaque', () => {
    const files = makeInventory([
      makeFile('src/main.py', 2000),
      makeFile('assets/logo.png', 50000),
      makeFile('lib/native.so', 100000),
    ]);
    const result = computeAnalyzability(files);
    expect(result.score).toBeLessThan(100);
    expect(result.opaqueFiles).toHaveLength(2);
    expect(result.opaqueFiles.map(f => f.path)).toContain('assets/logo.png');
    expect(result.opaqueFiles.map(f => f.path)).toContain('lib/native.so');
  });

  it('classifies minified files as opaque', () => {
    const files = makeInventory([
      makeFile('src/main.ts', 2000),
      makeFile('dist/bundle.min.js', 500000),
    ]);
    const result = computeAnalyzability(files);
    expect(result.opaqueFiles).toHaveLength(1);
    expect(result.opaqueFiles[0].reason).toContain('minified');
  });

  it('weights by log2(fileSize)', () => {
    // A large binary should matter more than a small one
    const files1 = makeInventory([
      makeFile('src/main.py', 2000),
      makeFile('tiny.wasm', 10),
    ]);
    const files2 = makeInventory([
      makeFile('src/main.py', 2000),
      makeFile('huge.wasm', 1000000),
    ]);
    const result1 = computeAnalyzability(files1);
    const result2 = computeAnalyzability(files2);
    expect(result1.score).toBeGreaterThan(result2.score);
  });

  it('handles empty inventory', () => {
    const files = makeInventory([]);
    const result = computeAnalyzability(files);
    expect(result.score).toBe(100);
    expect(result.totalFiles).toBe(0);
  });

  describe('Finding Generation', () => {
    it('generates medium finding for low analyzability', () => {
      const analyzability = {
        totalFiles: 100,
        analyzableFiles: 40,
        score: 45,
        opaqueFiles: Array(60).fill({ path: 'binary.wasm', reason: 'binary (.wasm)', size: 50000 }),
      };
      const findings = generateAnalyzabilityFindings(analyzability);
      expect(findings.some(f => f.ruleId === 'AA-ANALYZE-001')).toBe(true);
      expect(findings.find(f => f.ruleId === 'AA-ANALYZE-001')?.severity).toBe('medium');
    });

    it('generates findings for large opaque binaries', () => {
      const analyzability = {
        totalFiles: 10,
        analyzableFiles: 7,
        score: 80,
        opaqueFiles: [
          { path: 'big.wasm', reason: 'binary (.wasm)', size: 50000 },
          { path: 'small.lock', reason: 'lock file', size: 100 },
        ],
      };
      const findings = generateAnalyzabilityFindings(analyzability);
      const binaryFindings = findings.filter(f => f.ruleId === 'AA-ANALYZE-002');
      expect(binaryFindings).toHaveLength(1); // only big.wasm > 10KB
    });

    it('caps opaque binary findings at 5', () => {
      const analyzability = {
        totalFiles: 100,
        analyzableFiles: 50,
        score: 55,
        opaqueFiles: Array(20).fill(null).map((_, i) => ({
          path: `binary_${i}.wasm`, reason: 'binary (.wasm)', size: 50000,
        })),
      };
      const findings = generateAnalyzabilityFindings(analyzability);
      const binaryFindings = findings.filter(f => f.ruleId === 'AA-ANALYZE-002');
      expect(binaryFindings).toHaveLength(5);
    });

    it('no findings for high analyzability', () => {
      const analyzability = {
        totalFiles: 10,
        analyzableFiles: 10,
        score: 100,
        opaqueFiles: [],
      };
      const findings = generateAnalyzabilityFindings(analyzability);
      expect(findings).toHaveLength(0);
    });
  });
});
