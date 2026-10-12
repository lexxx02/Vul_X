import { RuleEngine } from './RuleEngine.js';
import { EvalUsageRule } from './definitions/EvalUsageRule.js';
import { DomXssRule } from './definitions/DomXssRule.js';

export { SecurityRule } from './SecurityRule.js';
export type { Vulnerability, AnalysisContext } from './SecurityRule.js';
export { RuleEngine } from './RuleEngine.js';
export { EvalUsageRule } from './definitions/EvalUsageRule.js';
export { DomXssRule } from './definitions/DomXssRule.js';

/**
 * Crea e inicializa una instancia de RuleEngine con todas las reglas por defecto registradas.
 */
export function createDefaultRuleEngine(): RuleEngine {
  const engine = new RuleEngine();
  engine.registerRules([
    new EvalUsageRule(),
    new DomXssRule(),
  ]);
  return engine;
}
