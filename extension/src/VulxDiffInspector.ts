import * as vscode from 'vscode';
import type { VulnerabilityResponse } from './VulxCodeActionProvider';

/**
 * Proveedor de contenido para documentos virtuales de previsualización de diffs (VulX).
 *
 * Utiliza el esquema de URI `vulx-diff:` para alimentar el editor comparativo
 * nativo de VS Code (`vscode.diff`) sin necesidad de escribir archivos temporales en el disco.
 */
export class VulxDiffContentProvider implements vscode.TextDocumentContentProvider {
  public static readonly scheme = 'vulx-diff';

  private readonly onDidChangeEmitter = new vscode.EventEmitter<vscode.Uri>();
  public readonly onDidChange = this.onDidChangeEmitter.event;

  /** Mapa en memoria de contenido virtual: uriString -> contenido */
  private readonly virtualContents = new Map<string, string>();

  provideTextDocumentContent(uri: vscode.Uri): string {
    return this.virtualContents.get(uri.toString()) ?? '';
  }

  /**
   * Actualiza o registra el contenido de una URI virtual y notifica al editor para refrescar la vista.
   */
  public setContent(uri: vscode.Uri, content: string): void {
    this.virtualContents.set(uri.toString(), content);
    this.onDidChangeEmitter.fire(uri);
  }

  /**
   * Limpia el contenido asociado a una URI para liberar memoria.
   */
  public deleteContent(uri: vscode.Uri): void {
    this.virtualContents.delete(uri.toString());
  }
}

/**
 * Orquestador del Inspector de Diffs de VulX.
 *
 * Permite previsualizar de forma interactiva y lado a lado (`Side-by-Side Diff`)
 * el código fuente original versus el código corregido por el modelo de IA antes de aplicar el parche.
 */
export class VulxDiffInspector {
  private readonly contentProvider: VulxDiffContentProvider;
  private readonly documentVulnerabilities: Map<string, VulnerabilityResponse[]>;
  private readonly outputChannel: vscode.OutputChannel;

  constructor(
    contentProvider: VulxDiffContentProvider,
    documentVulnerabilities: Map<string, VulnerabilityResponse[]>,
    outputChannel: vscode.OutputChannel
  ) {
    this.contentProvider = contentProvider;
    this.documentVulnerabilities = documentVulnerabilities;
    this.outputChannel = outputChannel;
  }

  /**
   * Abre el visor comparativo nativo de VS Code para una vulnerabilidad específica
   * o despliega un selector (QuickPick) si no se pasa un id.
   */
  public async previewDiff(vulnId?: string, lineNumber?: number): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage('VulX Diff Inspector: No hay un archivo activo para comparar.');
      return;
    }

    const document = editor.document;
    const docUriStr = document.uri.toString();
    const vulns = this.documentVulnerabilities.get(docUriStr) || [];

    if (vulns.length === 0) {
      vscode.window.showInformationMessage('VulX: No hay vulnerabilidades detectadas en este archivo.');
      return;
    }

    // Filtrar aquellas vulnerabilidades que tengan parche disponible
    const fixableVulns = vulns.filter((v) => v.remediation?.fixedSnippet);
    if (fixableVulns.length === 0) {
      vscode.window.showInformationMessage('VulX: Ninguna vulnerabilidad cuenta con parche de remediación disponible.');
      return;
    }

    let targetVuln: VulnerabilityResponse | undefined;

    if (vulnId && lineNumber !== undefined) {
      targetVuln = fixableVulns.find((v) => v.id === vulnId && Math.abs(v.line - lineNumber) <= 1);
    }

    // Si no se especificó o no se encontró, mostrar menú QuickPick
    if (!targetVuln) {
      const selected = await vscode.window.showQuickPick(
        fixableVulns.map((v) => ({
          label: `$(diff) ${v.name}`,
          description: `Línea ${v.line} [${v.severity.toUpperCase()}]`,
          detail: v.remediation?.explanation ?? v.recommendation,
          vuln: v,
        })),
        {
          title: '🛡️ VulX Diff Inspector — Seleccionar vulnerabilidad para previsualizar parche',
          placeHolder: 'Elige la vulnerabilidad para inspeccionar el cambio lado a lado',
        }
      );

      if (!selected) {
        return;
      }
      targetVuln = selected.vuln;
    }

    if (!targetVuln.remediation?.fixedSnippet) {
      return;
    }

    // Generar el código completo simulado con el parche aplicado
    const originalText = document.getText();
    const patchedText = this.buildPatchedDocument(document, targetVuln);

    // Construir URIs virtuales para el visualizador diff
    const originalUri = document.uri;
    const patchedVirtualUri = vscode.Uri.parse(
      `${VulxDiffContentProvider.scheme}:/${encodeURIComponent(document.fileName)} [VulX Parche Seguro].${document.languageId}`
    );

    // Cargar contenido en el provider virtual
    this.contentProvider.setContent(patchedVirtualUri, patchedText);

    const title = `VulX Diff: ${targetVuln.id} (Línea ${targetVuln.line}) ↔ Original vs. Parche IA`;

    this.outputChannel.appendLine(
      `[${new Date().toLocaleTimeString()}] [DiffInspector] Abriendo vista comparativa para ${targetVuln.id} en línea ${targetVuln.line}`
    );

    // Lanzar el visor nativo de diff de VS Code
    await vscode.commands.executeCommand('vscode.diff', originalUri, patchedVirtualUri, title, {
      preview: true,
      viewColumn: vscode.ViewColumn.Beside,
    });
  }

  /**
   * Genera el texto completo del documento aplicando la corrección sugerida
   * respetando la estrategia de resolución de VulX.
   */
  public buildPatchedDocument(document: vscode.TextDocument, vuln: VulnerabilityResponse): string {
    const remediation = vuln.remediation;
    if (!remediation) {
      return document.getText();
    }

    const rr = remediation.replacementRange;

    // Caso 1: replacementRange del backend (1-indexed -> 0-indexed)
    if (
      rr &&
      rr.startLine - 1 >= 0 &&
      rr.endLine - 1 < document.lineCount &&
      rr.startLine <= rr.endLine
    ) {
      const startLine = rr.startLine - 1;
      const endLine = rr.endLine - 1;
      const originalLine = document.lineAt(startLine);
      const indent = originalLine.text.match(/^\s*/)?.[0] || '';
      const indented = this.applyIndentation(remediation.fixedSnippet, indent);

      const range = new vscode.Range(
        new vscode.Position(startLine, Math.max(0, rr.startColumn)),
        new vscode.Position(endLine, Math.max(0, rr.endColumn))
      );

      return this.replaceRangeInString(document.getText(), document.offsetAt(range.start), document.offsetAt(range.end), indented);
    }

    // Caso 2: Secreto hardcodeado
    const lineIndex = Math.min(Math.max(0, vuln.line - 1), document.lineCount - 1);
    const targetLine = document.lineAt(lineIndex);
    const lineText = targetLine.text;

    if (vuln.id === 'HARDCODED_SECRET') {
      const quoteMatch = lineText.match(/(['"])(?:(?!\1).){8,}\1/);
      if (quoteMatch && typeof quoteMatch.index === 'number') {
        const startOffset = document.offsetAt(new vscode.Position(lineIndex, quoteMatch.index));
        const endOffset = startOffset + quoteMatch[0].length;
        return this.replaceRangeInString(document.getText(), startOffset, endOffset, remediation.fixedSnippet);
      }
    }

    // Caso 3: Inline snippet match
    const snippetIdx = lineText.indexOf(vuln.codeSnippet);
    if (snippetIdx !== -1 && !remediation.fixedSnippet.includes('\n')) {
      const startOffset = document.offsetAt(new vscode.Position(lineIndex, snippetIdx));
      const endOffset = startOffset + vuln.codeSnippet.length;
      return this.replaceRangeInString(document.getText(), startOffset, endOffset, remediation.fixedSnippet);
    }

    // Caso 4: Reemplazo de línea completa con indentación
    const indent = lineText.match(/^\s*/)?.[0] || '';
    const indented = this.applyIndentation(remediation.fixedSnippet, indent);
    const startOffset = document.offsetAt(targetLine.range.start);
    const endOffset = document.offsetAt(targetLine.range.end);
    return this.replaceRangeInString(document.getText(), startOffset, endOffset, indented);
  }

  private applyIndentation(snippet: string, indent: string): string {
    return snippet
      .split(/\r?\n/)
      .map((line) => (line.trim().length > 0 ? `${indent}${line.trim()}` : ''))
      .join('\n');
  }

  private replaceRangeInString(source: string, startOffset: number, endOffset: number, replacement: string): string {
    return source.substring(0, startOffset) + replacement + source.substring(endOffset);
  }
}
