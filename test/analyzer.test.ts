/**
 * test/analyzer.test.ts
 *
 * Suite de pruebas de integración y regresión para el Analyzer de VulX.
 *
 * Evalúa el flujo completo del pipeline:
 *   Parser (Tree-sitter) → RuleEngine (reglas AST) → AIService (Remediación/Diff) → AnalysisResult
 *
 * Cobertura:
 *   - Análisis completo en JavaScript y TypeScript (language y detección por filePath).
 *   - Consistencia del objeto summary (total, critical, high, medium, low, durationMs).
 *   - Estructura completa de los objetos Vulnerability.
 *   - Generación de parches de remediación estructurados (diff, fixedSnippet, replacementRange)
 *     cuando includeRemediation es true (usando mock de inferencia para pruebas herméticas y veloces).
 *   - Prueba de rendimiento RNF01: análisis AST en menos de 250 ms por archivo.
 *   - Regresión de registro de reglas y severidades.
 *
 * Compatible con:
 *   - tsx --test (node:test y node:assert/strict)
 *   - TypeScript strict mode con noUncheckedIndexedAccess
 *   - ECMAScript Modules (ESM)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { Analyzer } from '../core/Analyzer.js';
import { createDefaultRuleEngine } from '../core/rules/index.js';
import { AIService } from '../src/services/AIService.js';
import type { AnalysisResult } from '../core/Analyzer.js';

// ─────────────────────────────────────────────────────────────
//  Fixtures: snippets de código con vulnerabilidades conocidas
// ─────────────────────────────────────────────────────────────

/** Código JavaScript con múltiples vulnerabilidades (True Positives conocidos). */
const VULNERABLE_JS = `
const password = "SuperSecretPass99!";
const query = "SELECT * FROM users WHERE id = " + userId;
container.innerHTML = userInput;
exec("ping " + host);
fs.readFileSync("/data/" + file);
eval(formula);
`;

/** Código JavaScript completamente seguro (no debe generar alertas). */
const SAFE_JS = `
const apiKey = process.env.API_KEY;
db.query("SELECT * FROM users WHERE id = ?", [userId]);
container.textContent = userInput;
const data = JSON.parse(jsonString);
fs.readFileSync("./config.json");
`;

/** Código TypeScript con vulnerabilidades para verificar compatibilidad TS. */
const VULNERABLE_TS = `
const secret: string = "AKIAIOSFODNN7EXAMPLE";
const q: string = "SELECT * FROM users WHERE id = " + id;
(el as HTMLElement).innerHTML = payload;
`;

// ─────────────────────────────────────────────────────────────
//  Factory: Analyzer aislado del servicio de IA externo
// ─────────────────────────────────────────────────────────────

/**
 * Crea un Analyzer con el RuleEngine real y AIService configurado sin llamadas de red.
 */
function createTestAnalyzer(): Analyzer {
  const ruleEngine = createDefaultRuleEngine();
  return new Analyzer(ruleEngine);
}

// ═════════════════════════════════════════════════════════════
//  1. Análisis completo en JavaScript
// ═════════════════════════════════════════════════════════════

describe('Analyzer — Pipeline completo en JavaScript', () => {
  const analyzer = createTestAnalyzer();

  it('detecta multiples vulnerabilidades en codigo inseguro JS', async () => {
    const result: AnalysisResult = await analyzer.analyze({
      code: VULNERABLE_JS,
      language: 'javascript',
      includeRemediation: false,
    });

    assert.ok(
      result.vulnerabilities.length >= 5,
      `Esperadas al menos 5 vulnerabilidades, encontradas: ${result.vulnerabilities.length}`
    );

    const ids = result.vulnerabilities.map((v) => v.id);
    assert.ok(ids.includes('SQL_INJECTION'), 'Debe incluir SQL_INJECTION');
    assert.ok(ids.includes('DOM_XSS'), 'Debe incluir DOM_XSS');
    assert.ok(ids.includes('COMMAND_INJECTION'), 'Debe incluir COMMAND_INJECTION');
    assert.ok(ids.includes('PATH_TRAVERSAL'), 'Debe incluir PATH_TRAVERSAL');
    assert.ok(ids.includes('EVAL_USAGE'), 'Debe incluir EVAL_USAGE');
  });

  it('NO genera alertas en codigo seguro JS (False Positives = 0)', async () => {
    const result: AnalysisResult = await analyzer.analyze({
      code: SAFE_JS,
      language: 'javascript',
      includeRemediation: false,
    });

    assert.equal(
      result.vulnerabilities.length,
      0,
      `Codigo seguro no debe generar alertas. Encontradas: ${result.vulnerabilities.length}`
    );
  });
});

// ═════════════════════════════════════════════════════════════
//  2. Análisis completo en TypeScript
// ═════════════════════════════════════════════════════════════

describe('Analyzer — Pipeline completo en TypeScript', () => {
  const analyzer = createTestAnalyzer();

  it('detecta vulnerabilidades en codigo TypeScript', async () => {
    const result: AnalysisResult = await analyzer.analyze({
      code: VULNERABLE_TS,
      language: 'typescript',
      includeRemediation: false,
    });

    assert.ok(
      result.vulnerabilities.length >= 2,
      `Esperadas al menos 2 vulnerabilidades TS, encontradas: ${result.vulnerabilities.length}`
    );

    const ids = result.vulnerabilities.map((v) => v.id);
    assert.ok(ids.includes('HARDCODED_SECRET'), 'Debe detectar AWS Key en TS');
    assert.ok(ids.includes('SQL_INJECTION'), 'Debe detectar SQLi en TS');
  });

  it('infiere lenguaje TypeScript desde filePath', async () => {
    const result: AnalysisResult = await analyzer.analyze({
      code: VULNERABLE_TS,
      filePath: 'src/controller.ts',
      includeRemediation: false,
    });

    assert.ok(
      result.vulnerabilities.length >= 2,
      'Debe detectar vulnerabilidades al inferir TS por extension .ts'
    );
  });
});

// ═════════════════════════════════════════════════════════════
//  3. Consistencia del objeto summary
// ═════════════════════════════════════════════════════════════

describe('Analyzer — Consistencia de AnalysisSummary', () => {
  const analyzer = createTestAnalyzer();

  it('summary refleja conteos correctos por severidad', async () => {
    const result: AnalysisResult = await analyzer.analyze({
      code: VULNERABLE_JS,
      language: 'javascript',
      includeRemediation: false,
    });

    const { summary } = result;

    assert.equal(typeof summary.total, 'number', 'summary.total debe ser number');
    assert.equal(typeof summary.critical, 'number', 'summary.critical debe ser number');
    assert.equal(typeof summary.high, 'number', 'summary.high debe ser number');
    assert.equal(typeof summary.medium, 'number', 'summary.medium debe ser number');
    assert.equal(typeof summary.low, 'number', 'summary.low debe ser number');
    assert.equal(typeof summary.durationMs, 'number', 'summary.durationMs debe ser number');

    const severitySum = summary.critical + summary.high + summary.medium + summary.low;
    assert.equal(
      severitySum,
      summary.total,
      `Suma de severidades (${severitySum}) debe igualar total (${summary.total})`
    );

    assert.equal(
      summary.total,
      result.vulnerabilities.length,
      'summary.total debe coincidir con vulnerabilities.length'
    );
  });

  it('summary de codigo seguro tiene todos los conteos en cero', async () => {
    const result: AnalysisResult = await analyzer.analyze({
      code: SAFE_JS,
      language: 'javascript',
      includeRemediation: false,
    });

    const { summary } = result;
    assert.equal(summary.total, 0);
    assert.equal(summary.critical, 0);
    assert.equal(summary.high, 0);
    assert.equal(summary.medium, 0);
    assert.equal(summary.low, 0);
  });

  it('summary.durationMs es un numero no negativo', async () => {
    const result: AnalysisResult = await analyzer.analyze({
      code: VULNERABLE_JS,
      language: 'javascript',
      includeRemediation: false,
    });

    assert.ok(
      result.summary.durationMs >= 0,
      `durationMs debe ser >= 0, obtenido: ${result.summary.durationMs}`
    );
  });
});

// ═════════════════════════════════════════════════════════════
//  4. Estructura de los objetos Vulnerability
// ═════════════════════════════════════════════════════════════

describe('Analyzer — Estructura de los objetos Vulnerability', () => {
  const analyzer = createTestAnalyzer();

  it('cada vulnerabilidad contiene los campos obligatorios del contrato', async () => {
    const result: AnalysisResult = await analyzer.analyze({
      code: VULNERABLE_JS,
      language: 'javascript',
      includeRemediation: false,
    });

    for (const v of result.vulnerabilities) {
      assert.equal(typeof v.id, 'string', 'id debe ser string');
      assert.equal(typeof v.name, 'string', 'name debe ser string');
      assert.equal(typeof v.description, 'string', 'description debe ser string');
      assert.ok(
        ['low', 'medium', 'high', 'critical'].includes(v.severity),
        `severity invalida: ${v.severity}`
      );
      assert.equal(typeof v.line, 'number', 'line debe ser number');
      assert.ok(v.line > 0, `line debe ser > 0, obtenido: ${v.line}`);
      assert.equal(typeof v.column, 'number', 'column debe ser number');
      assert.equal(typeof v.codeSnippet, 'string', 'codeSnippet debe ser string');
      assert.equal(typeof v.recommendation, 'string', 'recommendation debe ser string');
    }
  });
});

// ═════════════════════════════════════════════════════════════
//  5. Remediación estructurada (includeRemediation)
// ═════════════════════════════════════════════════════════════

describe('Analyzer — Parches de Remediacion Estructurados', () => {
  it('hallazgos sin IA (includeRemediation: false) no incluyen remediation', async () => {
    const analyzer = createTestAnalyzer();
    const result: AnalysisResult = await analyzer.analyze({
      code: VULNERABLE_JS,
      language: 'javascript',
      includeRemediation: false,
    });

    for (const v of result.vulnerabilities) {
      assert.equal(
        v.remediation,
        undefined,
        `Vulnerabilidad ${v.id} no debe tener remediation cuando includeRemediation: false`
      );
    }
  });

  it('genera remediation.diff y fixedSnippet estructurados cuando includeRemediation: true', async () => {
    // Proveedor mock que simula la respuesta estructurada de la IA sin dependencia externa
    const mockAiService = new AIService({
      inferenceProvider: async () =>
        JSON.stringify({
          fixedSnippet: 'container.textContent = userInput;',
          explanation: 'Se sustituyo innerHTML por textContent para mitigar XSS.',
        }),
    });
    const analyzer = new Analyzer(createDefaultRuleEngine(), mockAiService);

    const result = await analyzer.analyze({
      code: 'container.innerHTML = userInput;',
      language: 'javascript',
      includeRemediation: true,
    });

    assert.ok(result.vulnerabilities.length > 0, 'Debe detectar la vulnerabilidad');
    const first = result.vulnerabilities[0];
    assert.ok(first, 'La vulnerabilidad debe existir');
    assert.ok(first.remediation, 'Debe incluir el objeto remediation');

    // Validar propiedades del parche de remediacion
    const remediation = first.remediation;
    assert.equal(typeof remediation.explanation, 'string', 'explanation debe ser string');
    assert.equal(typeof remediation.fixedSnippet, 'string', 'fixedSnippet debe ser string');
    assert.equal(typeof remediation.diff, 'string', 'diff debe ser string');
    assert.ok(remediation.fixedSnippet.includes('textContent'), 'fixedSnippet debe contener el codigo corregido');

    // Validar formato del diff estilo git
    assert.ok(remediation.diff.startsWith('@@'), 'diff debe incluir cabecera de rango unificada estilo git');
    assert.ok(remediation.diff.includes('- container.innerHTML'), 'diff debe mostrar linea eliminada');
    assert.ok(remediation.diff.includes('+ container.textContent'), 'diff debe mostrar linea agregada');

    // Validar coordenadas de reemplazo para QuickFix en el IDE
    assert.equal(typeof remediation.replacementRange.startLine, 'number');
    assert.equal(typeof remediation.replacementRange.endLine, 'number');
    assert.equal(typeof remediation.replacementRange.startColumn, 'number');
    assert.equal(typeof remediation.replacementRange.endColumn, 'number');
  });
});

// ═════════════════════════════════════════════════════════════
//  6. Rendimiento — RNF01 (< 250 ms por archivo)
// ═════════════════════════════════════════════════════════════

describe('Analyzer — Rendimiento RNF01', () => {
  const analyzer = createTestAnalyzer();

  it('analisis AST se ejecuta en menos de 250 ms', async () => {
    const start = performance.now();

    await analyzer.analyze({
      code: VULNERABLE_JS,
      language: 'javascript',
      includeRemediation: false,
    });

    const elapsed = performance.now() - start;

    assert.ok(
      elapsed < 250,
      `El analisis tomo ${elapsed.toFixed(1)} ms, excede el limite de 250 ms (RNF01)`
    );
  });

  it('analisis AST de archivo de 200 lineas se ejecuta en menos de 250 ms', async () => {
    const lines: string[] = [];
    for (let i = 0; i < 50; i++) {
      lines.push(`const val${i} = "some value ${i}";`);
      lines.push(`console.log(val${i});`);
      lines.push(`const result${i} = JSON.parse(data${i});`);
      lines.push(`db.query("SELECT 1 WHERE id = ?", [id${i}]);`);
    }
    const largeCode = lines.join('\n');

    const start = performance.now();

    await analyzer.analyze({
      code: largeCode,
      language: 'javascript',
      includeRemediation: false,
    });

    const elapsed = performance.now() - start;

    assert.ok(
      elapsed < 250,
      `Archivo grande tomo ${elapsed.toFixed(1)} ms, excede el limite de 250 ms (RNF01)`
    );
  });
});

// ═════════════════════════════════════════════════════════════
//  7. Regresión — Registro y severidades del motor
// ═════════════════════════════════════════════════════════════

describe('Analyzer — Regresion del motor de reglas', () => {
  const analyzer = createTestAnalyzer();

  it('las 6 reglas deterministas estan registradas', () => {
    const rules = analyzer.getRuleEngine().getRegisteredRules();
    const ruleIds = rules.map((r) => r.id);

    assert.ok(ruleIds.includes('EVAL_USAGE'), 'Falta EvalUsageRule');
    assert.ok(ruleIds.includes('DOM_XSS'), 'Falta DomXssRule');
    assert.ok(ruleIds.includes('SQL_INJECTION'), 'Falta SQLiRule');
    assert.ok(ruleIds.includes('HARDCODED_SECRET'), 'Falta SecretRule');
    assert.ok(ruleIds.includes('COMMAND_INJECTION'), 'Falta CommandInjectionRule');
    assert.ok(ruleIds.includes('PATH_TRAVERSAL'), 'Falta PathTraversalRule');
    assert.equal(rules.length, 6, 'Deben estar registradas exactamente 6 reglas');
  });

  it('severidades asignadas correctamente por regla', () => {
    const rules = analyzer.getRuleEngine().getRegisteredRules();
    const severityMap = new Map(rules.map((r) => [r.id, r.severity]));

    assert.equal(severityMap.get('EVAL_USAGE'), 'critical');
    assert.equal(severityMap.get('SQL_INJECTION'), 'critical');
    assert.equal(severityMap.get('COMMAND_INJECTION'), 'critical');
    assert.equal(severityMap.get('DOM_XSS'), 'high');
    assert.equal(severityMap.get('HARDCODED_SECRET'), 'high');
    assert.equal(severityMap.get('PATH_TRAVERSAL'), 'high');
  });
});
