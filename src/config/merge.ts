import type { G0Config } from '../types/config.js';

function deepMergeObjects(base: Record<string, unknown>, override: Record<string, unknown>): Record<string, unknown> {
  const result = { ...base };
  for (const key of Object.keys(override)) {
    const ov = override[key];
    const bv = result[key];
    if (ov === undefined) continue;
    if (Array.isArray(ov)) {
      result[key] = ov;
    } else if (ov !== null && typeof ov === 'object' && bv !== null && typeof bv === 'object' && !Array.isArray(bv)) {
      result[key] = deepMergeObjects(bv as Record<string, unknown>, ov as Record<string, unknown>);
    } else {
      result[key] = ov;
    }
  }
  return result;
}

/**
 * Deep-merge two config objects. Objects merge recursively; arrays replace.
 * `override` takes priority over `base` for scalar values.
 */
export function deepMergeConfig(base: G0Config, override: G0Config): G0Config {
  const result = { ...base };

  for (const key of Object.keys(override) as (keyof G0Config)[]) {
    const overrideVal = override[key];
    if (overrideVal === undefined) continue;

    const baseVal = result[key];

    if (Array.isArray(overrideVal)) {
      // Arrays replace entirely
      (result as Record<string, unknown>)[key] = overrideVal;
    } else if (
      overrideVal !== null &&
      typeof overrideVal === 'object' &&
      baseVal !== null &&
      typeof baseVal === 'object' &&
      !Array.isArray(baseVal)
    ) {
      // Objects merge recursively
      (result as Record<string, unknown>)[key] = deepMergeObjects(baseVal as Record<string, unknown>, overrideVal as Record<string, unknown>);
    } else {
      // Scalars replace
      (result as Record<string, unknown>)[key] = overrideVal;
    }
  }

  return result;
}
