import * as fs from 'node:fs';
import type { MCPServerInfo, MCPFinding } from '../types/mcp-scan.js';

export function scanMCPConfig(
  configPath: string,
  clientName: string,
  mcpKey: string,
): { servers: MCPServerInfo[]; findings: MCPFinding[] } {
  const servers: MCPServerInfo[] = [];
  const findings: MCPFinding[] = [];

  let content: string;
  try {
    content = fs.readFileSync(configPath, 'utf-8');
  } catch {
    return { servers, findings };
  }

  let parsed: Record<string, any>;
  try {
    parsed = JSON.parse(content);
  } catch {
    findings.push({
      severity: 'low',
      type: 'invalid-config',
      title: 'Invalid JSON config',
      description: `Config file at ${configPath} contains invalid JSON`,
      client: clientName,
      file: configPath,
    });
    return { servers, findings };
  }

  // Navigate to the MCP servers section
  const serversObj = parsed[mcpKey] ?? parsed.mcpServers ?? parsed.servers ?? {};

  if (typeof serversObj !== 'object' || Array.isArray(serversObj)) {
    return { servers, findings };
  }

  for (const [name, config] of Object.entries(serversObj)) {
    const serverConfig = config as Record<string, any>;
    const command = String(serverConfig.command ?? '');
    const args: string[] = Array.isArray(serverConfig.args)
      ? serverConfig.args.map(String)
      : [];
    const env: Record<string, string> = {};

    if (serverConfig.env && typeof serverConfig.env === 'object') {
      for (const [k, v] of Object.entries(serverConfig.env)) {
        env[k] = String(v);
      }
    }

    let status: MCPServerInfo['status'] = 'ok';

    // Check: npx auto-install
    if (command === 'npx') {
      if (args.includes('-y') || args.includes('--yes')) {
        findings.push({
          severity: 'high',
          type: 'npx-auto-install',
          title: 'NPX auto-install enabled',
          description: `Server "${name}" uses npx -y which auto-installs packages without confirmation`,
          server: name,
          client: clientName,
          file: configPath,
        });
        status = 'warn';
      }

      // Check: unpinned package version
      const pkgArg = args.find((a: string) => !a.startsWith('-'));
      if (pkgArg && !pkgArg.includes('@')) {
        findings.push({
          severity: 'medium',
          type: 'unpinned-package',
          title: 'Unpinned package version',
          description: `Server "${name}" uses unpinned package "${pkgArg}" — vulnerable to supply-chain attacks`,
          server: name,
          client: clientName,
          file: configPath,
        });
        if (status === 'ok') status = 'warn';
      }
    }

    // Check: hardcoded secrets in env
    for (const [key, value] of Object.entries(env)) {
      if (looksLikeSecret(value)) {
        findings.push({
          severity: 'critical',
          type: 'hardcoded-secret',
          title: 'Hardcoded secret in MCP config',
          description: `Server "${name}" has hardcoded secret in env var "${key}"`,
          server: name,
          client: clientName,
          file: configPath,
        });
        status = 'critical';
      }
    }

    // Check: secrets in args
    for (const arg of args) {
      if (looksLikeSecret(arg)) {
        findings.push({
          severity: 'critical',
          type: 'secret-in-args',
          title: 'Secret in command args',
          description: `Server "${name}" has a secret-like value in command arguments`,
          server: name,
          client: clientName,
          file: configPath,
        });
        status = 'critical';
      }
    }

    servers.push({
      name,
      command,
      args,
      env,
      client: clientName,
      configFile: configPath,
      status,
    });
  }

  return { servers, findings };
}

export function looksLikeSecret(value: string): boolean {
  if (value.length < 10) return false;
  return (
    /^(sk-|ghp_|gho_|AKIA|xox[bpsra]-|glpat-|Bearer\s)/.test(value) ||
    (value.length > 30 && /^[a-zA-Z0-9+/=_-]+$/.test(value) && !value.includes('/'))
  );
}
