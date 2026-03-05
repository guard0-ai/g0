import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type {
  RemediationStep,
  RemediationResult,
  EndpointScanResult,
} from '../types/endpoint.js';

const HOME = os.homedir();

// ─── Remediation Engine ─────────────────────────────────────────────────────

export function runRemediation(scanResult: EndpointScanResult): RemediationResult {
  const steps: RemediationStep[] = [];

  // 1. Fix file permissions on auth files
  steps.push(...fixFilePermissions(scanResult));

  // 2. Suggest .gitignore additions
  steps.push(...suggestGitignore(scanResult));

  // 3. Key rotation guidance for plaintext credentials
  steps.push(...suggestKeyRotation(scanResult));

  // 4. Suggest binding to localhost for exposed services
  steps.push(...suggestBindLocalhost(scanResult));

  // 5. Suggest enabling auth on unauthenticated services
  steps.push(...suggestEnableAuth(scanResult));

  const applied = steps.filter(s => s.applied).length;
  const failed = steps.filter(s => s.error).length;
  const skipped = steps.length - applied - failed;

  return {
    steps,
    summary: {
      totalSteps: steps.length,
      applied,
      skipped,
      failed,
    },
  };
}

// ─── Fix File Permissions ───────────────────────────────────────────────────

function fixFilePermissions(scanResult: EndpointScanResult): RemediationStep[] {
  const steps: RemediationStep[] = [];

  if (!scanResult.artifacts) return steps;

  for (const cred of scanResult.artifacts.credentials) {
    if (cred.issue !== 'bad-permissions') continue;

    const step: RemediationStep = {
      action: 'fix-permissions',
      target: cred.location,
      description: `Fix permissions on ${shortenPath(cred.location)} from ${cred.filePermissions || '?'} to 600`,
      command: `chmod 600 "${cred.location}"`,
      applied: false,
    };

    // Only auto-fix on macOS/Linux
    if (os.platform() !== 'win32') {
      try {
        fs.chmodSync(cred.location, 0o600);
        step.applied = true;
      } catch (err) {
        step.error = err instanceof Error ? err.message : String(err);
      }
    } else {
      step.error = 'Auto-fix not supported on Windows — run manually';
    }

    steps.push(step);
  }

  return steps;
}

// ─── Suggest .gitignore ─────────────────────────────────────────────────────

const GITIGNORE_ENTRIES = [
  '.env',
  '.env.local',
  '.env.*.local',
  '*.key',
  '*.pem',
  '.claude/',
  '.cursor/',
  '.continue/',
  '.augment/',
  '.g0/auth.json',
];

function suggestGitignore(scanResult: EndpointScanResult): RemediationStep[] {
  const steps: RemediationStep[] = [];

  if (!scanResult.artifacts) return steps;

  // Check if any credential files are in git repos
  const credLocations = scanResult.artifacts.credentials
    .filter(c => c.issue === 'plaintext' || c.issue === 'env-leak')
    .map(c => c.location);

  if (credLocations.length === 0) return steps;

  // Find .gitignore in home directory
  const gitignorePath = path.join(HOME, '.gitignore');
  let existingGitignore = '';
  try {
    existingGitignore = fs.readFileSync(gitignorePath, 'utf-8');
  } catch {
    // No global gitignore
  }

  const missing = GITIGNORE_ENTRIES.filter(entry =>
    !existingGitignore.includes(entry)
  );

  if (missing.length === 0) return steps;

  const additions = missing.join('\n');
  const step: RemediationStep = {
    action: 'add-gitignore',
    target: gitignorePath,
    description: `Add ${missing.length} entries to global .gitignore: ${missing.join(', ')}`,
    command: `echo "${additions}" >> "${gitignorePath}"`,
    applied: false,
  };

  // Auto-apply: append to .gitignore
  try {
    const newContent = existingGitignore
      ? existingGitignore.trimEnd() + '\n\n# g0 security recommendations\n' + additions + '\n'
      : '# g0 security recommendations\n' + additions + '\n';
    fs.writeFileSync(gitignorePath, newContent, 'utf-8');
    step.applied = true;
  } catch (err) {
    step.error = err instanceof Error ? err.message : String(err);
  }

  steps.push(step);

  return steps;
}

// ─── Key Rotation Guidance ──────────────────────────────────────────────────

const ROTATION_URLS: Record<string, string> = {
  anthropic: 'https://console.anthropic.com/settings/keys',
  openai: 'https://platform.openai.com/api-keys',
  google: 'https://aistudio.google.com/apikey',
  aws: 'https://console.aws.amazon.com/iam/home#/security_credentials',
  github: 'https://github.com/settings/tokens',
  azure: 'https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps',
  huggingface: 'https://huggingface.co/settings/tokens',
};

function suggestKeyRotation(scanResult: EndpointScanResult): RemediationStep[] {
  const steps: RemediationStep[] = [];

  if (!scanResult.artifacts) return steps;

  // Deduplicate by keyType — only suggest once per provider
  const seenTypes = new Set<string>();

  for (const cred of scanResult.artifacts.credentials) {
    if (cred.issue !== 'plaintext' && cred.issue !== 'config-embedded') continue;
    if (cred.keyType === 'other') continue;
    if (seenTypes.has(cred.keyType)) continue;
    seenTypes.add(cred.keyType);

    const url = ROTATION_URLS[cred.keyType] || '';
    steps.push({
      action: 'rotate-key',
      target: cred.keyType,
      description: `Rotate ${cred.keyType} API key found in ${shortenPath(cred.location)}. ${url ? `Rotate at: ${url}` : 'Rotate via your provider dashboard.'}`,
      applied: false, // Key rotation is always manual
      error: 'Manual action required — rotate key and use environment variables instead of hardcoding',
    });
  }

  return steps;
}

// ─── Suggest Bind to Localhost ───────────────────────────────────────────────

function suggestBindLocalhost(scanResult: EndpointScanResult): RemediationStep[] {
  const steps: RemediationStep[] = [];

  if (!scanResult.network) return steps;

  for (const svc of scanResult.network.services) {
    if (svc.bindAddress !== '0.0.0.0') continue;

    steps.push({
      action: 'bind-localhost',
      target: `:${svc.port}`,
      description: `${svc.type} on :${svc.port} is bound to 0.0.0.0 — restrict to 127.0.0.1 to prevent network access`,
      applied: false,
      error: `Manual action required — configure ${svc.process || svc.type} to bind to 127.0.0.1 instead of 0.0.0.0`,
    });
  }

  return steps;
}

// ─── Suggest Enable Auth ────────────────────────────────────────────────────

function suggestEnableAuth(scanResult: EndpointScanResult): RemediationStep[] {
  const steps: RemediationStep[] = [];

  if (!scanResult.network) return steps;

  for (const svc of scanResult.network.services) {
    if (svc.authenticated !== false) continue;

    steps.push({
      action: 'enable-auth',
      target: `:${svc.port}`,
      description: `${svc.type} on :${svc.port} has no authentication — enable auth to prevent unauthorized access`,
      applied: false,
      error: `Manual action required — configure authentication for ${svc.process || svc.type} on port ${svc.port}`,
    });
  }

  return steps;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function shortenPath(p: string): string {
  if (p.startsWith(HOME)) return '~' + p.slice(HOME.length);
  return p;
}

// Exported for testing
export {
  fixFilePermissions,
  suggestGitignore,
  suggestKeyRotation,
  suggestBindLocalhost,
  suggestEnableAuth,
  GITIGNORE_ENTRIES,
  ROTATION_URLS,
};
