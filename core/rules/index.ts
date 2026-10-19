import { RuleEngine } from './RuleEngine.js';
import { EvalUsageRule } from './definitions/EvalUsageRule.js';
import { DomXssRule } from './definitions/DomXssRule.js';
import { SQLiRule } from './definitions/SQLiRule.js';
import { SecretRule } from './definitions/SecretRule.js';
import { CommandInjectionRule } from './definitions/CommandInjectionRule.js';
import { PathTraversalRule } from './definitions/PathTraversalRule.js';

export { SecurityRule } from './SecurityRule.js';
export type { Vulnerability, AnalysisContext, Remediation, ReplacementRange } from './SecurityRule.js';
export { RuleEngine } from './RuleEngine.js';

// ─── Reglas de detección ───
export { EvalUsageRule } from './definitions/EvalUsageRule.js';
export { DomXssRule } from './definitions/DomXssRule.js';
export { SQLiRule } from './definitions/SQLiRule.js';
export { SecretRule } from './definitions/SecretRule.js';
export { CommandInjectionRule } from './definitions/CommandInjectionRule.js';
export { PathTraversalRule } from './definitions/PathTraversalRule.js';

/**
 * Crea e inicializa una instancia de RuleEngine con todas las reglas por defecto registradas:
 * - EvalUsageRule (Uso peligroso de eval)
 * - DomXssRule (Manipulación insegura del DOM / XSS - VULX-02)
 * - SQLiRule (Inyección SQL - VULX-01)
 * - SecretRule (Secretos Hardcodeados - VULX-03)
 * - CommandInjectionRule (Inyección de Comandos del SO - VULX-04 / CWE-78)
 * - PathTraversalRule (Recorrido de Rutas Arbitrario - VULX-05 / CWE-22)
 */
export function createDefaultRuleEngine(): RuleEngine {
  const engine = new RuleEngine();
  engine.registerRules([
    new EvalUsageRule(),
    new DomXssRule(),
    new SQLiRule(),
    new SecretRule(),
    new CommandInjectionRule(),
    new PathTraversalRule(),
  ]);
  return engine;
}

