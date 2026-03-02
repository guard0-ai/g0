import type { AIProvider } from '../../ai/provider.js';
import type { AttackState, AdaptiveAttackConfig, TurnDecision } from '../../types/test.js';

export interface AdaptiveAttackStrategy {
  id: string;
  name: string;
  initState(config: AdaptiveAttackConfig): AttackState;
  nextTurn(state: AttackState, config: AdaptiveAttackConfig, aiProvider: AIProvider): Promise<TurnDecision>;
  buildRedTeamPrompt(config: AdaptiveAttackConfig, state: AttackState): string;
}
