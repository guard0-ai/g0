import * as fs from 'node:fs';
import * as path from 'node:path';

// ── Types ──────────────────────────────────────────────────────────────────

export interface IOCMatch {
  type: 'ip' | 'domain' | 'hash' | 'name' | 'artifact' | 'prereq';
  indicator: string;
  matched: string;
  description: string;
  severity: 'critical' | 'high' | 'medium';
}

export interface IOCDatabase {
  c2Ips: string[];
  maliciousDomains: Array<{ domain: string; description: string }>;
  maliciousHashes: Array<{ hash: string; name: string }>;
  typosquatPatterns: Array<{ pattern: RegExp; description: string }>;
  infostealerArtifacts: {
    macos: Array<{ path: string; description: string }>;
    linux: Array<{ path: string; description: string }>;
  };
  dangerousPrereqs: Array<{ pattern: RegExp; description: string }>;
}

// ── Built-in IOC Data ──────────────────────────────────────────────────────

const BUILT_IN_IOCS: IOCDatabase = {
  // Known C2 and data exfil endpoints
  c2Ips: [
    '185.220.101.0/24',  // Tor exit nodes (common range)
    '45.33.32.156',       // Known scanner
    '198.51.100.0/24',    // Documentation range (suspicious if contacted)
  ],

  // Malicious or suspicious domains for data exfil
  maliciousDomains: [
    { domain: 'webhook.site', description: 'Common data exfiltration endpoint' },
    { domain: 'requestbin.com', description: 'HTTP request capture service' },
    { domain: 'pipedream.net', description: 'Webhook capture service' },
    { domain: 'ngrok.io', description: 'Tunnel service often used for C2' },
    { domain: 'ngrok-free.app', description: 'Free ngrok tunnel' },
    { domain: 'burpcollaborator.net', description: 'Burp Suite collaborator' },
    { domain: 'interact.sh', description: 'ProjectDiscovery interaction server' },
    { domain: 'oast.fun', description: 'Out-of-band testing endpoint' },
    { domain: 'canarytokens.com', description: 'Canary token service' },
    { domain: 'dnslog.cn', description: 'DNS logging service' },
    { domain: 'bxss.me', description: 'Blind XSS detection' },
    { domain: 'ceye.io', description: 'DNS/HTTP logging' },
    { domain: 'paste.ee', description: 'Anonymous paste service for data exfil' },
    { domain: 'transfer.sh', description: 'File transfer service' },
    { domain: 'file.io', description: 'One-time file sharing' },
    { domain: '0x0.st', description: 'Anonymous file upload' },
  ],

  // Known malicious skill/plugin hashes (from ClawHavoc and similar)
  maliciousHashes: [
    { hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', name: 'empty file (suspicious placeholder)' },
  ],

  // Typosquat patterns for ClawHub skill names
  typosquatPatterns: [
    { pattern: /^clawhub[_-]?(?:official|verified|real|legit)/i, description: 'Fake "official" ClawHub package' },
    { pattern: /^(?:claw-hub|c1awhub|clawhulb|clawh[uo]b|clawhb)/i, description: 'ClawHub typosquat' },
    { pattern: /^(?:opencl[ao]w|0penclaw|openclav|openc1aw)/i, description: 'OpenClaw typosquat' },
    { pattern: /^(?:claude-?(?:hack|exploit|jailbreak|bypass))/i, description: 'Malicious Claude-themed skill' },
    { pattern: /^(?:gpt-?(?:hack|exploit|jailbreak|bypass))/i, description: 'Malicious GPT-themed skill' },
    { pattern: /^(?:admin-?tool|sudo-?skill|root-?access|privilege-?escalat)/i, description: 'Suspicious privilege-related skill name' },
    { pattern: /(?:reverse.?shell|bind.?shell|backdoor|keylog|credential.?steal)/i, description: 'Explicitly malicious skill name' },
  ],

  // Infostealer artifacts to check on host
  infostealerArtifacts: {
    macos: [
      { path: '~/Library/Keychains/login.keychain-db.bak', description: 'AMOS infostealer keychain backup' },
      { path: '/tmp/.com.apple.dt.instruments', description: 'AMOS staging directory' },
      { path: '~/Library/Application Support/Google/Chrome/Default/Login Data.bak', description: 'Chrome credential dump' },
      { path: '/tmp/browser_data.zip', description: 'Browser data archive (potential exfil staging)' },
      { path: '~/.atomic-wallet/backup', description: 'Atomic wallet dump' },
    ],
    linux: [
      { path: '/tmp/.X11-unix/.lock', description: 'Redline/Lumma staging file' },
      { path: '/dev/shm/.malware', description: 'In-memory malware staging' },
      { path: '/tmp/.ICE-unix/cred_dump', description: 'Credential dump staging' },
      { path: '~/.config/chromium/Default/Login Data.bak', description: 'Chromium credential dump' },
      { path: '/var/tmp/.update-cache', description: 'Persistent staging directory' },
    ],
  },

  // Dangerous prerequisite / install patterns
  dangerousPrereqs: [
    { pattern: /curl\s+.*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)/i, description: 'Pipe to shell execution' },
    { pattern: /wget\s+.*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)/i, description: 'Wget pipe to shell' },
    { pattern: /eval\s*\(\s*\$\(curl/i, description: 'Eval with curl subshell' },
    { pattern: /python\s+-c\s+['"]import\s+(?:urllib|requests)/i, description: 'Python download-and-execute' },
    { pattern: /unzip\s+-P\s/i, description: 'Password-protected zip extraction (may hide malware)' },
    { pattern: /base64\s+-d.*\|\s*(?:sh|bash)/i, description: 'Base64 decode to shell' },
    { pattern: /(?:npm|pip|gem)\s+install\s+.*--global.*--force/i, description: 'Forced global package install' },
    { pattern: /chmod\s+[+]?[xs]\s/i, description: 'Making file executable (check source)' },
  ],
};

// ── Public API ─────────────────────────────────────────────────────────────

let _database: IOCDatabase | null = null;

/**
 * Load the IOC database (built-in + optional external data)
 */
export function loadIOCDatabase(externalDataPath?: string): IOCDatabase {
  if (_database && !externalDataPath) return _database;

  let db = { ...BUILT_IN_IOCS };

  // Merge external IOC data if provided
  if (externalDataPath && fs.existsSync(externalDataPath)) {
    try {
      const raw = fs.readFileSync(externalDataPath, 'utf-8');
      const external = JSON.parse(raw);

      if (Array.isArray(external.c2Ips)) {
        db.c2Ips = [...db.c2Ips, ...external.c2Ips];
      }
      if (Array.isArray(external.maliciousDomains)) {
        db.maliciousDomains = [...db.maliciousDomains, ...external.maliciousDomains];
      }
      if (Array.isArray(external.maliciousHashes)) {
        db.maliciousHashes = [...db.maliciousHashes, ...external.maliciousHashes];
      }
    } catch {
      // Non-fatal — use built-in data only
    }
  }

  if (!externalDataPath) _database = db;
  return db;
}

/**
 * Check a target string against all IOCs of a specific type
 */
export function checkAgainstIOCs(
  target: string,
  type: 'ip' | 'domain' | 'hash' | 'name',
  db?: IOCDatabase,
): IOCMatch[] {
  const database = db ?? loadIOCDatabase();
  const matches: IOCMatch[] = [];

  switch (type) {
    case 'ip':
      for (const cidr of database.c2Ips) {
        if (ipMatchesCIDR(target, cidr)) {
          matches.push({
            type: 'ip',
            indicator: cidr,
            matched: target,
            description: `IP matches known C2/malicious range: ${cidr}`,
            severity: 'critical',
          });
        }
      }
      break;

    case 'domain': {
      // Extract hostname from URL if target looks like a URL, otherwise use as-is
      let hostname = target;
      try {
        if (target.startsWith('http://') || target.startsWith('https://')) {
          hostname = new URL(target).hostname;
        }
      } catch {
        // Not a valid URL, use raw target
      }
      for (const entry of database.maliciousDomains) {
        // Exact match or proper subdomain match (e.g., evil.webhook.site matches webhook.site)
        if (hostname === entry.domain || hostname.endsWith('.' + entry.domain)) {
          matches.push({
            type: 'domain',
            indicator: entry.domain,
            matched: target,
            description: entry.description,
            severity: 'high',
          });
        }
      }
      break;
    }

    case 'hash':
      for (const entry of database.maliciousHashes) {
        if (target.toLowerCase() === entry.hash.toLowerCase()) {
          matches.push({
            type: 'hash',
            indicator: entry.hash,
            matched: target,
            description: `Known malicious hash: ${entry.name}`,
            severity: 'critical',
          });
        }
      }
      break;

    case 'name':
      for (const entry of database.typosquatPatterns) {
        if (entry.pattern.test(target)) {
          matches.push({
            type: 'name',
            indicator: entry.pattern.source,
            matched: target,
            description: entry.description,
            severity: 'high',
          });
        }
      }
      break;
  }

  return matches;
}

/**
 * Scan text content for dangerous prerequisite patterns
 */
export function scanForDangerousPrereqs(content: string, db?: IOCDatabase): IOCMatch[] {
  const database = db ?? loadIOCDatabase();
  const matches: IOCMatch[] = [];

  for (const entry of database.dangerousPrereqs) {
    const match = content.match(entry.pattern);
    if (match) {
      matches.push({
        type: 'prereq',
        indicator: entry.pattern.source,
        matched: match[0],
        description: entry.description,
        severity: 'high',
      });
    }
  }

  return matches;
}

/**
 * Check host for infostealer artifacts
 */
export function scanInfostealerArtifacts(platform?: NodeJS.Platform, db?: IOCDatabase): IOCMatch[] {
  const database = db ?? loadIOCDatabase();
  const matches: IOCMatch[] = [];
  const os = platform ?? process.platform;
  const home = require('node:os').homedir();

  const artifacts = os === 'darwin'
    ? database.infostealerArtifacts.macos
    : database.infostealerArtifacts.linux;

  for (const entry of artifacts) {
    const resolved = entry.path.replace(/^~/, home);
    if (fs.existsSync(resolved)) {
      matches.push({
        type: 'artifact',
        indicator: entry.path,
        matched: resolved,
        description: entry.description,
        severity: 'critical',
      });
    }
  }

  return matches;
}

// ── Internal helpers ──────────────────────────────────────────────────────

function ipMatchesCIDR(ip: string, cidr: string): boolean {
  // Handle plain IPs (no CIDR)
  if (!cidr.includes('/')) {
    return ip === cidr;
  }

  const [network, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);

  const ipNum = ipToNumber(ip);
  const netNum = ipToNumber(network);

  if (ipNum === null || netNum === null) return false;

  const mask = (0xFFFFFFFF << (32 - prefix)) >>> 0;
  return (ipNum & mask) === (netNum & mask);
}

function ipToNumber(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;

  let result = 0;
  for (const part of parts) {
    const num = parseInt(part, 10);
    if (isNaN(num) || num < 0 || num > 255) return null;
    result = (result << 8) | num;
  }

  return result >>> 0;
}
