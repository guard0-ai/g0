import type { G0Config, PresetName } from '../../types/config.js';
import { strictPreset } from './strict.js';
import { balancedPreset } from './balanced.js';
import { permissivePreset } from './permissive.js';

export const PRESETS: Record<PresetName, G0Config> = {
  strict: strictPreset,
  balanced: balancedPreset,
  permissive: permissivePreset,
};

export function resolvePreset(name: PresetName): G0Config {
  const preset = PRESETS[name];
  if (!preset) {
    throw new Error(`Unknown preset: ${name}. Available: ${Object.keys(PRESETS).join(', ')}`);
  }
  return structuredClone(preset);
}
