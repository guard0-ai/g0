import { createRequire } from 'node:module';
import { getVersionOverride } from './version-override.js';

// Single source of truth for the tool version. In dev/Node this reads
// package.json; in a compiled single-file binary (which cannot require
// package.json) the entry sets a version override first (see version-override.ts).
// Located two levels deep to match the bundle entry points, mirroring
// src/cli/branding.ts.
let _version: string | undefined;

export function getG0Version(): string {
  if (_version) return _version;
  const override = getVersionOverride();
  if (override) {
    _version = override;
    return _version;
  }
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
