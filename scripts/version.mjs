#!/usr/bin/env node

/**
 * Version management script for guard0 monorepo.
 *
 * Usage:
 *   node scripts/version.mjs <new-version>
 *   node scripts/version.mjs patch|minor|major
 *   node scripts/version.mjs --check          # verify all packages are in sync
 *
 * Updates version across:
 *   - package.json           (@guard0/g0 — main package)
 *   - packages/guard0/       (guard0 — wrapper / vanity package)
 *
 * The wrapper's @guard0/g0 dependency is pinned to the exact version (no caret)
 * so `npm install guard0@1.8.0` always resolves to `@guard0/g0@1.8.0`.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');

const PACKAGES = [
  { path: 'package.json', label: '@guard0/g0' },
  { path: 'packages/guard0/package.json', label: 'guard0 (wrapper)' },
];

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function readPkg(rel) {
  const abs = resolve(root, rel);
  return JSON.parse(readFileSync(abs, 'utf-8'));
}

function writePkg(rel, obj) {
  const abs = resolve(root, rel);
  writeFileSync(abs, JSON.stringify(obj, null, 2) + '\n');
}

function bumpVersion(current, level) {
  const [major, minor, patch] = current.split('.').map(Number);
  switch (level) {
    case 'major': return `${major + 1}.0.0`;
    case 'minor': return `${major}.${minor + 1}.0`;
    case 'patch': return `${major}.${minor}.${patch + 1}`;
    default: throw new Error(`Unknown bump level: ${level}`);
  }
}

function isValidSemver(v) {
  return /^\d+\.\d+\.\d+(-[\w.]+)?$/.test(v);
}

// ---------------------------------------------------------------------------
// --check mode
// ---------------------------------------------------------------------------

function checkSync() {
  const mainPkg = readPkg('package.json');
  const wrapperPkg = readPkg('packages/guard0/package.json');
  const mainVersion = mainPkg.version;
  const wrapperVersion = wrapperPkg.version;
  const wrapperDep = wrapperPkg.dependencies?.['@guard0/g0'];

  let ok = true;

  if (wrapperVersion !== mainVersion) {
    console.error(`  MISMATCH  guard0 wrapper is ${wrapperVersion}, main is ${mainVersion}`);
    ok = false;
  }
  if (wrapperDep !== mainVersion) {
    console.error(`  MISMATCH  guard0 wrapper depends on @guard0/g0@${wrapperDep}, main is ${mainVersion}`);
    ok = false;
  }

  if (ok) {
    console.log(`  OK  all packages at v${mainVersion}`);
  } else {
    console.error('\nRun: node scripts/version.mjs <version>  to fix');
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

const arg = process.argv[2];

if (!arg) {
  console.error('Usage: node scripts/version.mjs <version|patch|minor|major|--check>');
  process.exit(1);
}

if (arg === '--check') {
  checkSync();
  process.exit(0);
}

const mainPkg = readPkg('package.json');
const currentVersion = mainPkg.version;

const newVersion = ['patch', 'minor', 'major'].includes(arg)
  ? bumpVersion(currentVersion, arg)
  : arg;

if (!isValidSemver(newVersion)) {
  console.error(`Invalid version: ${newVersion}`);
  process.exit(1);
}

if (newVersion === currentVersion) {
  console.log(`Already at v${currentVersion} — nothing to do`);
  process.exit(0);
}

console.log(`\n  ${currentVersion} → ${newVersion}\n`);

// 1. Main package
mainPkg.version = newVersion;
writePkg('package.json', mainPkg);
console.log(`  updated  @guard0/g0 → ${newVersion}`);

// 2. Wrapper package — version + pinned dependency
const wrapperPkg = readPkg('packages/guard0/package.json');
wrapperPkg.version = newVersion;
wrapperPkg.dependencies['@guard0/g0'] = newVersion;
writePkg('packages/guard0/package.json', wrapperPkg);
console.log(`  updated  guard0 (wrapper) → ${newVersion}`);
console.log(`  pinned   guard0 → @guard0/g0@${newVersion}`);

console.log(`\n  Done. All packages at v${newVersion}\n`);
