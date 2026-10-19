import { createAnalysisContext } from './parser.js';
import { createDefaultRuleEngine, type RuleEngine } from './rules/index.js';
import type { Vulnerability } from './rules/SecurityRule.js';
import { AIService, type AIServiceOptions } from '../src/services/AIService.js';

// ────────────────────────────────────────────────────────────
//  Tipos públicos del Analyzer
// ────────────────────────────────────────────────────────────

/**
 * Opciones que recibe el método `analyze()`.
 */
export interface AnalyzeRequest {
  /** Código fuente a analizar */
  code: string;
  /** Lenguaje del archivo (js, ts, javascript, typescript). Se auto-detecta si se omite. */
  language?: string;
  /** Ruta del archivo original (ayuda a inferir el lenguaje) */
  filePath?: string;
  /**
   * Si es `true` (por defecto), cada hallazgo se enriquece con la remediación de la IA.
   * Si es `false`, se devuelven solo los hallazgos crudos del RuleEngine.
   */
  includeRemediation?: boolean;
}

/** Conteo de vulnerabilidades por severidad */
export interface AnalysisSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  /** Milisegundos que tomó el análisis completo */
  durationMs: number;
}

/** Resultado final que entrega el Analyzer */
export interface AnalysisResult {
  vulnerabilities: Vulnerability[];
  summary: AnalysisSummary;
}

// ────────────────────────────────────────────────────────────
//  Analyzer — Orquestador de Fusión AST + IA
// ────────────────────────────────────────────────────────────

/**
 * Analyzer — Orquestador principal de VulX.
 *
 * Fusiona dos capas de análisis en un pipeline secuencial:
 *
 * ```
 * Código fuente
 *   │
 *   ▼
 * ┌─────────────────────────────────┐
 * │  1. Tree-sitter Parser          │  → AST (AnalysisContext)
 * └─────────────────────────────────┘
 *   │
 *   ▼
 * ┌─────────────────────────────────┐
 * │  2. RuleEngine (reglas AST)     │  → Vulnerability[] crudos
 * └─────────────────────────────────┘
 *   │
 *   ▼
 * ┌─────────────────────────────────┐
 * │  3. AIService (Ollama/Qwen)     │  → Vulnerability[] enriquecidos
 * │     con remediación + diff      │     (fallback heurístico si IA falla)
 * └─────────────────────────────────┘
 *   │
 *   ▼
 * AnalysisResult { vulnerabilities, summary }
 * ```
 *
 * Principios de diseño:
 * - **Inyección de dependencias**: Recibe RuleEngine y AIService por constructor
 *   para facilitar testing con mocks.
 * - **Resiliencia**: Si la IA no responde, el fallback heurístico del AIService
 *   garantiza que siempre se devuelva una remediación válida.
 * - **Procesamiento secuencial de IA**: Las llamadas a Ollama se procesan de
 *   forma secuencial para no saturar un modelo 7B local con múltiples requests
 *   concurrentes. El RuleEngine (síncrono) sigue siendo rápido.
 */
export class Analyzer {
  private readonly ruleEngine: RuleEngine;
  private readonly aiService: AIService;

  constructor(ruleEngine?: RuleEngine, aiService?: AIService) {
    this.ruleEngine = ruleEngine ?? createDefaultRuleEngine();
    this.aiService = aiService ?? new AIService();
  }

  /**
   * Ejecuta el pipeline completo de análisis: Parseo → Detección AST → Remediación IA.
   *
   * @param request - Código fuente y opciones de análisis
   * @returns Resultado con vulnerabilidades enriquecidas y resumen estadístico
   */
  async analyze(request: AnalyzeRequest): Promise<AnalysisResult> {
    const startTime = performance.now();
    const { code, language, filePath } = request;
    const shouldRemediate = request.includeRemediation !== false;

    // ── Paso 1: Parsear código con Tree-sitter y construir AnalysisContext ──
    const context = createAnalysisContext(code, language, filePath);

    // ── Paso 2: Ejecutar reglas estáticas del RuleEngine sobre el AST ──
    const rawFindings = this.ruleEngine.analyze(context);

    // ── Paso 3: Enriquecer con IA (si hay hallazgos y se solicitó remediación) ──
    let enrichedFindings: Vulnerability[];

    if (shouldRemediate && rawFindings.length > 0) {
      enrichedFindings = await this.enrichWithAI(rawFindings, code);
    } else {
      enrichedFindings = rawFindings;
    }

    // ── Paso 4: Construir resumen estadístico ──
    const durationMs = Math.round(performance.now() - startTime);
    const summary = this.buildSummary(enrichedFindings, durationMs);

    return {
      vulnerabilities: enrichedFindings,
      summary,
    };
  }

  /**
   * Enriquece cada hallazgo con la remediación de la IA de forma secuencial.
   *
   * Se procesan uno por uno para no saturar el modelo local de Ollama.
   * Si una remediación individual falla, el AIService ya aplica
   * su fallback heurístico interno, así que este nivel no necesita
   * try/catch adicional.
   */
  private async enrichWithAI(
    findings: Vulnerability[],
    sourceCode: string
  ): Promise<Vulnerability[]> {
    const enriched: Vulnerability[] = [];

    for (const finding of findings) {
      const remediated = await this.aiService.remediate(finding, sourceCode);
      enriched.push(remediated);
    }

    return enriched;
  }

  /**
   * Genera el resumen estadístico de severidades a partir de los hallazgos.
   */
  private buildSummary(
    vulnerabilities: Vulnerability[],
    durationMs: number
  ): AnalysisSummary {
    return {
      total: vulnerabilities.length,
      critical: vulnerabilities.filter((v) => v.severity === 'critical').length,
      high: vulnerabilities.filter((v) => v.severity === 'high').length,
      medium: vulnerabilities.filter((v) => v.severity === 'medium').length,
      low: vulnerabilities.filter((v) => v.severity === 'low').length,
      durationMs,
    };
  }

  // ── Accesores para inspección/testing ──

  /** Devuelve la instancia interna del RuleEngine */
  getRuleEngine(): RuleEngine {
    return this.ruleEngine;
  }

  /** Devuelve la instancia interna del AIService */
  getAIService(): AIService {
    return this.aiService;
  }
}

// ────────────────────────────────────────────────────────────
//  Factory function (análoga a createDefaultRuleEngine)
// ────────────────────────────────────────────────────────────

/**
 * Crea una instancia de Analyzer lista para usar con la configuración por defecto:
 * - RuleEngine con todas las reglas registradas (Eval, XSS, SQLi, Secrets)
 * - AIService apuntando a Ollama local (qwen2.5-coder:7b)
 *
 * @param aiOptions - Opciones opcionales para personalizar el AIService
 */
export function createAnalyzer(aiOptions?: AIServiceOptions): Analyzer {
  const ruleEngine = createDefaultRuleEngine();
  const aiService = new AIService(aiOptions);
  return new Analyzer(ruleEngine, aiService);
}
