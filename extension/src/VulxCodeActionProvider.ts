import * as vscode from 'vscode';

// ────────────────────────────────────────────────────────────
//  Interfaces — Forma del payload de remediación de la API
// ────────────────────────────────────────────────────────────

/**
 * Coordenadas de reemplazo precisas enviadas por el backend de VulX.
 * Permiten al IDE saber exactamente qué rango de texto debe reemplazarse
 * para aplicar el parche generado por la IA con precisión de línea y columna.
 *
 * Las coordenadas son 1-indexed (igual que en el código fuente), y se
 * convierten a 0-indexed internamente para la API de VS Code.
 */
export interface ReplacementRange {
  startLine: number;
  endLine: number;
  startColumn: number;
  endColumn: number;
}

/**
 * Payload de remediación enriquecido por la IA local (Ollama/Qwen).
 * Contiene el código corregido, la explicación técnica, el diff unificado
 * y las coordenadas exactas para el Quick Fix en el editor.
 */
export interface RemediationPayload {
  explanation: string;
  fixedSnippet: string;
  diff: string;
  replacementRange?: ReplacementRange;
}

/**
 * Representa una vulnerabilidad detectada por el pipeline VulX (RuleEngine + IA).
 * Incluye toda la información necesaria para crear diagnósticos, decoraciones
 * y acciones de corrección rápida (Code Actions / Quick Fixes) en el IDE.
 */
export interface VulnerabilityResponse {
  id: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  line: number;
  column: number;
  codeSnippet: string;
  recommendation: string;
  remediation?: RemediationPayload;
}

// ────────────────────────────────────────────────────────────
//  VulxCodeActionProvider — CodeActionProvider con QuickFix
// ────────────────────────────────────────────────────────────

/**
 * Proveedor de acciones de código (Code Actions) para la extensión VulX.
 *
 * Implementa la interfaz `vscode.CodeActionProvider` para ofrecer correcciones
 * rápidas (Quick Fixes) sobre los diagnósticos de seguridad generados por VulX.
 * Cada Quick Fix aplica el parche generado por la IA en un solo clic, reemplazando
 * el código vulnerable por la versión segura sugerida.
 *
 * Estrategia de resolución de rango (prioridad descendente):
 *
 * 1. **replacementRange** — Si el backend devuelve coordenadas precisas de
 *    reemplazo (generadas por el AIService), se usan directamente para construir
 *    el rango de edición con precisión de línea y columna. Este es el mecanismo
 *    más fiable ya que la IA conoce el contexto completo del código.
 *
 * 2. **Secretos hardcodeados (HARDCODED_SECRET)** — Caso especial donde solo
 *    se reemplaza el valor literal del secreto (entre comillas), preservando la
 *    estructura del código circundante.
 *
 * 3. **Coincidencia inline del snippet** — Si el fragmento de código vulnerable
 *    (`codeSnippet`) se encuentra exactamente dentro de la línea del diagnóstico
 *    y la corrección es de una sola línea, se reemplaza solo ese fragmento.
 *
 * 4. **Reemplazo de línea completa (fallback)** — Si ninguna de las estrategias
 *    anteriores aplica, se reemplaza la línea completa del diagnóstico con el
 *    código corregido, preservando la indentación original.
 *
 * Requisito Funcional: RF05 — Remediación Asistida de Código.
 * Entregable: Reemplazo asistido de código funcional en un solo clic.
 */
export class VulxCodeActionProvider implements vscode.CodeActionProvider {
  /**
   * Metadatos que declaran qué tipos de acciones de código provee esta clase.
   * VS Code usa este campo para decidir cuándo invocar al proveedor (solo cuando
   * se soliciten QuickFixes, no para refactorizaciones u otras categorías).
   */
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
  ];

  /**
   * Almacén de vulnerabilidades por documento.
   * Se inyecta desde extension.ts para mantener la fuente de verdad centralizada.
   * La clave es `document.uri.toString()` y el valor es el array de hallazgos
   * enriquecidos devueltos por la API `/analyze`.
   */
  private readonly documentVulnerabilities: Map<string, VulnerabilityResponse[]>;

  /**
   * Canal de salida para logging diagnóstico del proveedor de Quick Fixes.
   */
  private readonly outputChannel: vscode.OutputChannel;

  constructor(
    documentVulnerabilities: Map<string, VulnerabilityResponse[]>,
    outputChannel: vscode.OutputChannel
  ) {
    this.documentVulnerabilities = documentVulnerabilities;
    this.outputChannel = outputChannel;
  }

  /**
   * Método principal invocado por VS Code cuando el usuario abre el menú de
   * Quick Fix (bombilla 💡) o presiona Ctrl+. sobre un diagnóstico de VulX.
   *
   * Filtra únicamente los diagnósticos con `source === 'VulX'`, busca la
   * vulnerabilidad correspondiente en el almacén en memoria y genera una
   * CodeAction con el WorkspaceEdit necesario para aplicar el parche.
   *
   * @param document - Documento activo donde se solicitan las acciones
   * @param _range - Rango seleccionado o posición del cursor (no se usa directamente)
   * @param context - Contexto que incluye los diagnósticos visibles en el rango
   * @param _token - Token de cancelación (no se usa)
   * @returns Array de CodeActions con Quick Fixes disponibles
   */
  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    _token: vscode.CancellationToken
  ): vscode.CodeAction[] {
    // Filtrar solo diagnósticos de VulX que tengan un código (id de vulnerabilidad)
    const vulxDiagnostics = context.diagnostics.filter(
      (d) => d.source === 'VulX' && d.code
    );

    if (vulxDiagnostics.length === 0) {
      return [];
    }

    const vulns = this.documentVulnerabilities.get(document.uri.toString()) || [];
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of vulxDiagnostics) {
      const action = this.createQuickFixForDiagnostic(document, diagnostic, vulns);
      if (action) {
        actions.push(action);
      }
    }

    this.outputChannel.appendLine(
      `[${new Date().toLocaleTimeString()}] [QuickFix] Generadas ${actions.length} acción(es) de corrección para ${document.fileName}`
    );

    return actions;
  }

  /**
   * Crea una CodeAction de tipo QuickFix para un diagnóstico específico.
   *
   * Busca la vulnerabilidad correspondiente al diagnóstico por su `id` y
   * proximidad de línea, y construye el WorkspaceEdit aplicando la estrategia
   * de resolución de rango adecuada.
   *
   * @param document - Documento donde aplicar la corrección
   * @param diagnostic - Diagnóstico de VulX asociado
   * @param vulns - Lista de vulnerabilidades del documento
   * @returns CodeAction con el parche, o null si no hay corrección disponible
   */
  private createQuickFixForDiagnostic(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    vulns: VulnerabilityResponse[]
  ): vscode.CodeAction | null {
    // Buscar la vulnerabilidad que corresponde a este diagnóstico
    const matchingVuln = this.findMatchingVulnerability(diagnostic, vulns);

    if (!matchingVuln || !matchingVuln.remediation?.fixedSnippet) {
      return null;
    }

    const remediation = matchingVuln.remediation;
    const fix = new vscode.CodeAction(
      `💡 VulX Fix: ${remediation.explanation}`,
      vscode.CodeActionKind.QuickFix
    );
    fix.diagnostics = [diagnostic];
    fix.isPreferred = true;

    const edit = new vscode.WorkspaceEdit();

    // ── Estrategia 1: Usar replacementRange del backend (coordenadas precisas de la IA) ──
    if (remediation.replacementRange) {
      const resolved = this.resolveFromReplacementRange(
        document,
        remediation.replacementRange,
        remediation.fixedSnippet
      );
      if (resolved) {
        edit.replace(document.uri, resolved.range, resolved.text);
        fix.edit = edit;
        this.logFixApplied(matchingVuln, 'replacementRange');
        return fix;
      }
    }

    // ── Estrategia 2: Caso especial para secretos hardcodeados ──
    if (matchingVuln.id === 'HARDCODED_SECRET') {
      const secretFix = this.resolveHardcodedSecretFix(
        document,
        diagnostic,
        remediation.fixedSnippet
      );
      if (secretFix) {
        edit.replace(document.uri, secretFix.range, secretFix.text);
        fix.edit = edit;
        this.logFixApplied(matchingVuln, 'hardcoded-secret');
        return fix;
      }
    }

    // ── Estrategia 3: Coincidencia inline del snippet vulnerable ──
    const inlineFix = this.resolveInlineSnippetFix(
      document,
      diagnostic,
      matchingVuln.codeSnippet,
      remediation.fixedSnippet
    );
    if (inlineFix) {
      edit.replace(document.uri, inlineFix.range, inlineFix.text);
      fix.edit = edit;
      this.logFixApplied(matchingVuln, 'inline-snippet');
      return fix;
    }

    // ── Estrategia 4: Reemplazo de línea completa (fallback) ──
    const fullLineFix = this.resolveFullLineReplacement(
      document,
      diagnostic,
      remediation.fixedSnippet
    );
    edit.replace(document.uri, fullLineFix.range, fullLineFix.text);
    fix.edit = edit;
    this.logFixApplied(matchingVuln, 'full-line');
    return fix;
  }

  // ────────────────────────────────────────────────────────────
  //  Estrategias de resolución de rango
  // ────────────────────────────────────────────────────────────

  /**
   * Estrategia 1 — Usa las coordenadas precisas del backend (`replacementRange`).
   *
   * Convierte las coordenadas 1-indexed del backend a 0-indexed para VS Code.
   * Valida que el rango esté dentro de los límites del documento.
   *
   * @param document - Documento activo
   * @param rr - Coordenadas de reemplazo del backend (1-indexed)
   * @param fixedSnippet - Código corregido a insertar
   * @returns Objeto con rango y texto, o null si las coordenadas están fuera de rango
   */
  private resolveFromReplacementRange(
    document: vscode.TextDocument,
    rr: ReplacementRange,
    fixedSnippet: string
  ): { range: vscode.Range; text: string } | null {
    // Convertir de 1-indexed (backend) a 0-indexed (VS Code)
    const startLine = rr.startLine - 1;
    const endLine = rr.endLine - 1;

    // Validar que las líneas están dentro del documento
    if (
      startLine < 0 ||
      endLine < 0 ||
      startLine >= document.lineCount ||
      endLine >= document.lineCount
    ) {
      this.outputChannel.appendLine(
        `[${new Date().toLocaleTimeString()}] [QuickFix] replacementRange fuera de rango: ` +
        `L${rr.startLine}-${rr.endLine} (documento tiene ${document.lineCount} líneas)`
      );
      return null;
    }

    const startCol = Math.max(0, rr.startColumn);
    const endCol = Math.max(0, rr.endColumn);

    const range = new vscode.Range(
      new vscode.Position(startLine, startCol),
      new vscode.Position(endLine, endCol)
    );

    // Preservar indentación de la primera línea del rango
    const originalLine = document.lineAt(startLine);
    const indent = originalLine.text.match(/^\s*/)?.[0] || '';
    const indentedSnippet = this.applyIndentation(fixedSnippet, indent);

    return { range, text: indentedSnippet };
  }

  /**
   * Estrategia 2 — Reemplazo de secreto hardcodeado.
   *
   * Busca el valor literal del secreto (cadena larga entre comillas) dentro
   * de la línea del diagnóstico y reemplaza solo esa porción, preservando
   * la asignación y el resto de la estructura del código.
   *
   * @param document - Documento activo
   * @param diagnostic - Diagnóstico asociado al secreto
   * @param fixedSnippet - Snippet de reemplazo (ej: `process.env.API_KEY`)
   * @returns Objeto con rango y texto, o null si no se encontró el literal
   */
  private resolveHardcodedSecretFix(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    fixedSnippet: string
  ): { range: vscode.Range; text: string } | null {
    const targetLine = document.lineAt(diagnostic.range.start.line);
    const lineText = targetLine.text;

    // Buscar una cadena literal larga (≥8 caracteres entre comillas)
    const quoteMatch = lineText.match(/(['"])(?:(?!\1).){8,}\1/);
    if (!quoteMatch || typeof quoteMatch.index !== 'number') {
      return null;
    }

    const range = new vscode.Range(
      new vscode.Position(diagnostic.range.start.line, quoteMatch.index),
      new vscode.Position(
        diagnostic.range.start.line,
        quoteMatch.index + quoteMatch[0].length
      )
    );

    return { range, text: fixedSnippet };
  }

  /**
   * Estrategia 3 — Coincidencia inline del fragmento de código vulnerable.
   *
   * Si el `codeSnippet` original se encuentra textualmente dentro de la línea
   * del diagnóstico y el snippet de corrección es de una sola línea, se reemplaza
   * solo la porción exacta del código vulnerable.
   *
   * @param document - Documento activo
   * @param diagnostic - Diagnóstico asociado
   * @param codeSnippet - Fragmento de código vulnerable original
   * @param fixedSnippet - Código corregido
   * @returns Objeto con rango y texto, o null si no hay coincidencia inline
   */
  private resolveInlineSnippetFix(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    codeSnippet: string,
    fixedSnippet: string
  ): { range: vscode.Range; text: string } | null {
    const targetLine = document.lineAt(diagnostic.range.start.line);
    const lineText = targetLine.text;

    const snippetIdx = lineText.indexOf(codeSnippet);
    if (snippetIdx === -1 || fixedSnippet.includes('\n')) {
      return null;
    }

    const range = new vscode.Range(
      new vscode.Position(diagnostic.range.start.line, snippetIdx),
      new vscode.Position(
        diagnostic.range.start.line,
        snippetIdx + codeSnippet.length
      )
    );

    return { range, text: fixedSnippet };
  }

  /**
   * Estrategia 4 (fallback) — Reemplazo de la línea completa.
   *
   * Cuando ninguna estrategia más precisa aplica, reemplaza la línea completa
   * del diagnóstico con el código corregido, preservando la indentación
   * original de la línea.
   *
   * @param document - Documento activo
   * @param diagnostic - Diagnóstico asociado
   * @param fixedSnippet - Código corregido
   * @returns Objeto con rango y texto (siempre devuelve un resultado válido)
   */
  private resolveFullLineReplacement(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
    fixedSnippet: string
  ): { range: vscode.Range; text: string } {
    const targetLine = document.lineAt(diagnostic.range.start.line);
    const indent = targetLine.text.match(/^\s*/)?.[0] || '';
    const indentedText = this.applyIndentation(fixedSnippet, indent);

    return { range: targetLine.range, text: indentedText };
  }

  // ────────────────────────────────────────────────────────────
  //  Métodos auxiliares
  // ────────────────────────────────────────────────────────────

  /**
   * Busca la vulnerabilidad que corresponde a un diagnóstico específico.
   *
   * La correspondencia se establece por:
   * - Coincidencia exacta del `id` de la vulnerabilidad con el `code` del diagnóstico
   * - Proximidad de línea (tolerancia de ±1 línea para absorber diferencias de indexación)
   *
   * @param diagnostic - Diagnóstico de VS Code
   * @param vulns - Lista de vulnerabilidades del documento
   * @returns La vulnerabilidad correspondiente, o undefined si no se encuentra
   */
  private findMatchingVulnerability(
    diagnostic: vscode.Diagnostic,
    vulns: VulnerabilityResponse[]
  ): VulnerabilityResponse | undefined {
    return vulns.find(
      (v) =>
        v.id === diagnostic.code &&
        Math.abs(v.line - 1 - diagnostic.range.start.line) <= 1
    );
  }

  /**
   * Aplica indentación a un snippet multilínea, preservando líneas vacías.
   *
   * @param snippet - Código a indentar
   * @param indent - Cadena de indentación (espacios/tabs de la línea original)
   * @returns Código indentado correctamente
   */
  private applyIndentation(snippet: string, indent: string): string {
    return snippet
      .split(/\r?\n/)
      .map((line) => (line.trim().length > 0 ? `${indent}${line.trim()}` : ''))
      .join('\n');
  }

  /**
   * Registra en el canal de salida cuándo y cómo se aplicó un Quick Fix.
   *
   * @param vuln - Vulnerabilidad corregida
   * @param strategy - Nombre de la estrategia de resolución utilizada
   */
  private logFixApplied(vuln: VulnerabilityResponse, strategy: string): void {
    this.outputChannel.appendLine(
      `[${new Date().toLocaleTimeString()}] [QuickFix] Fix preparado para ${vuln.id} ` +
      `en L${vuln.line} (estrategia: ${strategy})`
    );
  }
}

