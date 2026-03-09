import type { G0Config } from '../types/config.js';

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
      (result as any)[key] = overrideVal;
    } else if (
      overrideVal !== null &&
      typeof overrideVal === 'object' &&
      baseVal !== null &&
      typeof baseVal === 'object' &&
      !Array.isArray(baseVal)
    ) {
      // Objects merge recursively
      (result as any)[key] = { ...baseVal, ...overrideVal };
    } else {
      // Scalars replace
      (result as any)[key] = overrideVal;
    }
  }

  return result;
}
