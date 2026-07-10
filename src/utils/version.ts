import { createRequire } from 'node:module';

// Single source of truth for the tool version — read from package.json so
// runtime version strings (baselines, AI-BOM, attestations, User-Agent) can
// never drift from the published package version. Located two levels deep to
// match the bundle entry points, mirroring src/cli/branding.ts.
let _version: string | undefined;

export function getG0Version(): string {
  if (_version) return _version;
  try {
    const require = createRequire(import.meta.url);
    const pkg = require('../../package.json') as { version?: string };
    _version = pkg.version ?? '0.0.0';
  } catch {
    _version = '0.0.0';
  }
  return _version;
}

export const G0_VERSION = getG0Version();
