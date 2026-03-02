import type { AdaptiveStrategyId } from '../../types/test.js';
import type { AdaptiveAttackStrategy } from './strategy.js';
import { GoatStrategy } from './goat.js';
import { CrescendoStrategy } from './crescendo.js';
import { ReconProbeStrategy } from './recon-probe.js';
import { HydraStrategy } from './hydra.js';
import { SimbaStrategy } from './simba.js';

const strategies: Record<AdaptiveStrategyId, () => AdaptiveAttackStrategy> = {
  goat: () => new GoatStrategy(),
  crescendo: () => new CrescendoStrategy(),
  'recon-probe': () => new ReconProbeStrategy(),
  hydra: () => new HydraStrategy(),
  simba: () => new SimbaStrategy(),
};

export function getAdaptiveStrategy(id: AdaptiveStrategyId): AdaptiveAttackStrategy {
  const factory = strategies[id];
  if (!factory) {
    throw new Error(`Unknown adaptive strategy: ${id}. Available: ${getAllAdaptiveStrategyIds().join(', ')}`);
  }
  return factory();
}

export function getAllAdaptiveStrategyIds(): AdaptiveStrategyId[] {
  return Object.keys(strategies) as AdaptiveStrategyId[];
}

export type { AdaptiveAttackStrategy } from './strategy.js';
export { generateObjectives } from './objectives.js';
