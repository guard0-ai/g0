import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { AdaptiveTestCaseResult, AttackCategory } from '../../types/test.js';
import { withLock } from '../../utils/file-lock.js';
import { readEncryptedJson, writeEncryptedJson } from '../../utils/encryption.js';

interface TacticEntry {
  tactic: string;
  category: AttackCategory;
  strategy: string;
  timestamp: string;
}

export interface AttackProfile {
  successfulTactics: TacticEntry[];
  failedTactics: TacticEntry[];
  frameworkWeaknesses: Record<string, string[]>;
  categoryInsights: Record<string, string[]>;
  lastUpdated: string;
}

const MAX_ENTRIES = 100;

function getProfilePath(): string {
  // Project-level first
  const projectPath = path.join(process.cwd(), '.g0', 'attack-profiles.json');
  const projectDir = path.dirname(projectPath);
  if (fs.existsSync(projectDir)) return projectPath;

  // User-level fallback
  const userDir = path.join(os.homedir(), '.g0');
  return path.join(userDir, 'attack-profiles.json');
}

export function loadProfiles(): AttackProfile {
  const profilePath = getProfilePath();
  try {
    if (fs.existsSync(profilePath)) {
      const profile = readEncryptedJson<AttackProfile>(profilePath);
      if (profile) return profile;
    }
  } catch {
    // Ignore parse/decrypt errors
  }
  return {
    successfulTactics: [],
    failedTactics: [],
    frameworkWeaknesses: {},
    categoryInsights: {},
    lastUpdated: new Date().toISOString(),
  };
}

export async function saveProfiles(profile: AttackProfile): Promise<void> {
  const profilePath = getProfilePath();
  try {
    await withLock(profilePath, () => {
      profile.lastUpdated = new Date().toISOString();
      writeEncryptedJson(profilePath, profile);
    });
  } catch {
    // Profile saving is best-effort
  }
}

export function extractLearnings(
  results: AdaptiveTestCaseResult[],
  existing: AttackProfile,
): AttackProfile {
  const profile = { ...existing };
  const now = new Date().toISOString();

  for (const result of results) {
    if (result.verdict === 'vulnerable') {
      // Extract successful tactics from promising tactics
      for (const tactic of result.finalState.promisingTactics) {
        profile.successfulTactics.push({
          tactic,
          category: result.category,
          strategy: result.strategyId,
          timestamp: now,
        });
      }

      // Track category insights
      const catKey = result.category;
      if (!profile.categoryInsights[catKey]) {
        profile.categoryInsights[catKey] = [];
      }
      if (result.evidence) {
        profile.categoryInsights[catKey].push(
          `${result.strategyId} succeeded in ${result.turnsExecuted} turns: ${result.evidence.slice(0, 150)}`
        );
      }
    } else {
      // Extract failed tactics
      for (const tactic of result.finalState.failedTactics) {
        profile.failedTactics.push({
          tactic,
          category: result.category,
          strategy: result.strategyId,
          timestamp: now,
        });
      }
    }
  }

  // Cap entries
  profile.successfulTactics = profile.successfulTactics.slice(-MAX_ENTRIES);
  profile.failedTactics = profile.failedTactics.slice(-MAX_ENTRIES);
  for (const key of Object.keys(profile.categoryInsights)) {
    profile.categoryInsights[key] = profile.categoryInsights[key].slice(-20);
  }

  return profile;
}

export function buildPriorIntelligence(profile: AttackProfile, category?: AttackCategory): string {
  const parts: string[] = [];

  // Filter relevant successful tactics
  const relevant = category
    ? profile.successfulTactics.filter(t => t.category === category)
    : profile.successfulTactics;

  if (relevant.length > 0) {
    parts.push('\nPRIOR INTELLIGENCE (from previous attack runs):');
    parts.push('Successful tactics:');
    for (const t of relevant.slice(-10)) {
      parts.push(`- [${t.strategy}/${t.category}] ${t.tactic}`);
    }
  }

  // Failed tactics to avoid
  const failedRelevant = category
    ? profile.failedTactics.filter(t => t.category === category)
    : profile.failedTactics;

  if (failedRelevant.length > 0) {
    parts.push('Previously failed tactics (avoid repeating):');
    for (const t of failedRelevant.slice(-5)) {
      parts.push(`- [${t.strategy}] ${t.tactic}`);
    }
  }

  // Category insights
  if (category && profile.categoryInsights[category]?.length) {
    parts.push(`Category insights for ${category}:`);
    for (const insight of profile.categoryInsights[category].slice(-5)) {
      parts.push(`- ${insight}`);
    }
  }

  return parts.length > 0 ? '\n' + parts.join('\n') : '';
}
