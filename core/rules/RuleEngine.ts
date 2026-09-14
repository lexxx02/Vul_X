import { SecurityRule } from './SecurityRule.js';
import type { AnalysisContext, Vulnerability } from './SecurityRule.js';

/**
 * RuleEngine — El despachador central de reglas de seguridad.
 *
 * Es el componente que coordina la ejecución de todas las reglas
 * registradas en el sistema. Cuando la API recibe código para analizar,
 * el RuleEngine se encarga de:
 *
 * 1. Filtrar qué reglas aplican para el lenguaje del archivo.
 * 2. Ejecutar cada regla aplicable contra el código.
 * 3. Recopilar y devolver todas las vulnerabilidades encontradas.
 *
 * Para agregar una nueva regla al sistema, basta con crear una clase
 * que herede de SecurityRule y registrarla con `registerRule()`.
 */
export class RuleEngine {
  /** Registro interno de todas las reglas de seguridad disponibles */
  private rules: SecurityRule[] = [];

  /**
   * Registra una nueva regla de seguridad en el motor.
   *
   * @param rule - Instancia de una clase que hereda de SecurityRule
   */
  registerRule(rule: SecurityRule): void {
    // Evitar registrar la misma regla dos veces
    const alreadyExists = this.rules.some((r) => r.id === rule.id);
    if (alreadyExists) {
      console.warn(`⚠️  La regla "${rule.id}" ya está registrada. Se omite el duplicado.`);
      return;
    }

    this.rules.push(rule);
    console.log(`✅ Regla registrada: [${rule.id}] ${rule.name}`);
  }

  /**
   * Registra múltiples reglas de una sola vez.
   *
   * @param rules - Arreglo de instancias de SecurityRule
   */
  registerRules(rules: SecurityRule[]): void {
    for (const rule of rules) {
      this.registerRule(rule);
    }
  }

  /**
   * Ejecuta todas las reglas aplicables contra el código proporcionado.
   *
   * Filtra las reglas que soportan el lenguaje del archivo,
   * las ejecuta una por una y recopila todas las vulnerabilidades.
   *
   * @param context - Contexto del análisis (código, AST, lenguaje)
   * @returns Lista consolidada de todas las vulnerabilidades encontradas
   */
  analyze(context: AnalysisContext): Vulnerability[] {
    const applicableRules = this.rules.filter((rule) =>
      rule.supportsLanguage(context.language)
    );

    if (applicableRules.length === 0) {
      console.warn(
        `⚠️  No hay reglas registradas para el lenguaje "${context.language}".`
      );
      return [];
    }

    console.log(
      `🔍 Ejecutando ${applicableRules.length} regla(s) para lenguaje "${context.language}"...`
    );

    const allVulnerabilities: Vulnerability[] = [];

    for (const rule of applicableRules) {
      try {
        const findings = rule.evaluate(context);
        allVulnerabilities.push(...findings);

        if (findings.length > 0) {
          console.log(`   🚨 [${rule.id}] encontró ${findings.length} problema(s)`);
        }
      } catch (error) {
        console.error(`   ❌ Error ejecutando regla [${rule.id}]:`, error);
      }
    }

    console.log(`📋 Total de vulnerabilidades encontradas: ${allVulnerabilities.length}`);
    return allVulnerabilities;
  }

  /**
   * Devuelve la lista de todas las reglas registradas.
   * Útil para endpoints de información o documentación.
   */
  getRegisteredRules(): { id: string; name: string; severity: string; languages: string[] }[] {
    return this.rules.map((rule) => ({
      id: rule.id,
      name: rule.name,
      severity: rule.severity,
      languages: rule.supportedLanguages,
    }));
  }

  /**
   * Devuelve cuántas reglas están registradas actualmente.
   */
  getRuleCount(): number {
    return this.rules.length;
  }
}
