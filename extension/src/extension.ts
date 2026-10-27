import * as vscode from 'vscode';

// Canal de salida dedicado para los logs de VulX en la consola del IDE
let outputChannel: vscode.OutputChannel;
let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;

// Decoration types para resaltado visual de líneas vulnerables (line highlights por severidad)
let criticalLineDecoration: vscode.TextEditorDecorationType;
let highLineDecoration: vscode.TextEditorDecorationType;
let mediumLineDecoration: vscode.TextEditorDecorationType;
let lowLineDecoration: vscode.TextEditorDecorationType;

// URL base del backend de análisis VulX
const VULX_API_URL = process.env.VULX_API_URL || 'http://127.0.0.1:3000';
const VULX_FETCH_TIMEOUT_MS = 30_000; // Timeout máximo para la respuesta de la API (30s)

interface RemediationPayload {
  explanation: string;
  fixedSnippet: string;
  diff: string;
  replacementRange?: {
    startLine: number;
    endLine: number;
    startColumn: number;
    endColumn: number;
  };
}

interface VulnerabilityResponse {
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

// Almacenamiento en memoria de hallazgos por documento para Quick Fixes
const documentVulnerabilities = new Map<string, VulnerabilityResponse[]>();

/**
 * Función de activación: se ejecuta cuando la extensión se inicia
 * según los activationEvents definidos en package.json o al invocar un comando.
 */
export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel('VulX Security');
  diagnosticCollection = vscode.languages.createDiagnosticCollection('vulx');

  // ── Inicializar decoration types para resaltado de líneas vulnerables (line highlights) ──
  // Cada severidad recibe un color de borde izquierdo, fondo translúcido y marcador en el overview ruler
  criticalLineDecoration = vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(220, 38, 38, 0.10)',
    isWholeLine: true,
    overviewRulerColor: '#dc2626',
    overviewRulerLane: vscode.OverviewRulerLane.Left,
    borderWidth: '0 0 0 3px',
    borderStyle: 'solid',
    borderColor: '#dc2626',
  });
  highLineDecoration = vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(234, 88, 12, 0.10)',
    isWholeLine: true,
    overviewRulerColor: '#ea580c',
    overviewRulerLane: vscode.OverviewRulerLane.Left,
    borderWidth: '0 0 0 3px',
    borderStyle: 'solid',
    borderColor: '#ea580c',
  });
  mediumLineDecoration = vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(202, 138, 4, 0.10)',
    isWholeLine: true,
    overviewRulerColor: '#ca8a04',
    overviewRulerLane: vscode.OverviewRulerLane.Left,
    borderWidth: '0 0 0 3px',
    borderStyle: 'solid',
    borderColor: '#ca8a04',
  });
  lowLineDecoration = vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(37, 99, 235, 0.08)',
    isWholeLine: true,
    overviewRulerColor: '#2563eb',
    overviewRulerLane: vscode.OverviewRulerLane.Left,
    borderWidth: '0 0 0 3px',
    borderStyle: 'solid',
    borderColor: '#2563eb',
  });

  // ── Status bar item: indica estado de VulX y permite lanzar escaneo con un clic ──
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.text = '$(shield) VulX';
  statusBarItem.tooltip = 'VulX Security Analyzer — Listo para escanear';
  statusBarItem.command = 'vulx.analyzeCurrentFile';
  statusBarItem.show();

  outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [VulX] Extensión activada con éxito.`);

  const supportedLanguages = ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'];

  // 1. Comando de prueba del ciclo de vida
  const helloWorldCmd = vscode.commands.registerCommand('vulx.helloWorld', () => {
    const msg = '¡VulX está activo y listo para analizar vulnerabilidades!';
    outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [Comando] vulx.helloWorld ejecutado.`);
    vscode.window.showInformationMessage(msg);
  });

  // 2. Comando para leer el buffer del editor activo
  const readBufferCmd = vscode.commands.registerCommand('vulx.readBuffer', () => {
    const editor = vscode.window.activeTextEditor;

    if (!editor) {
      const warnMsg = 'VulX: No hay ningún editor de texto activo para leer.';
      vscode.window.showWarningMessage(warnMsg);
      outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [Advertencia] Se intentó leer el buffer sin editor activo.`);
      return;
    }

    const document = editor.document;
    const text = document.getText();
    const fileName = document.fileName;
    const languageId = document.languageId;
    const lineCount = document.lineCount;
    const charCount = text.length;

    outputChannel.appendLine('========================================');
    outputChannel.appendLine(`[VulX - Lectura de Buffer] ${new Date().toLocaleTimeString()}`);
    outputChannel.appendLine(`- Archivo: ${fileName}`);
    outputChannel.appendLine(`- Lenguaje: ${languageId}`);
    outputChannel.appendLine(`- Líneas: ${lineCount}`);
    outputChannel.appendLine(`- Caracteres: ${charCount}`);
    outputChannel.appendLine('---------------- Contenido ----------------');
    outputChannel.appendLine(text);
    outputChannel.appendLine('========================================');

    vscode.window.showInformationMessage(
      `VulX: Buffer leído correctamente (${lineCount} líneas, ${charCount} caracteres, ${languageId}).`,
      'Ver en consola VulX'
    ).then((selection) => {
      if (selection === 'Ver en consola VulX') {
        outputChannel.show(true);
      }
    });
  });

  // 3. Comando para analizar activamente el archivo actual conectando a la API (RF04)
  const analyzeCurrentFileCmd = vscode.commands.registerCommand('vulx.analyzeCurrentFile', async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage('VulX: Abre un archivo para escanear.');
      return;
    }
    // Indicador de progreso visible en la barra de notificaciones durante el escaneo
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: '🛡️ VulX: Analizando vulnerabilidades…',
        cancellable: false,
      },
      () => analyzeDocument(editor.document)
    );
  });

  // 4. Comando para limpiar diagnósticos y decoraciones
  const clearDiagnosticsCmd = vscode.commands.registerCommand('vulx.clearDiagnostics', () => {
    diagnosticCollection.clear();
    documentVulnerabilities.clear();
    // Limpiar decoraciones de resaltado de línea en el editor activo
    const activeEditor = vscode.window.activeTextEditor;
    if (activeEditor) {
      clearLineHighlights(activeEditor);
    }
    if (statusBarItem) {
      statusBarItem.text = '$(shield) VulX';
      statusBarItem.tooltip = 'VulX Security Analyzer — Diagnósticos limpiados';
    }
    vscode.window.showInformationMessage('VulX: Diagnósticos de seguridad limpiados.');
  });

  // 5. Ciclo de vida: Listener de guardado de documentos (Auto-intercepción y análisis en tiempo real - RF01 + RF04)
  const onSaveListener = vscode.workspace.onDidSaveTextDocument(async (document) => {
    if (supportedLanguages.includes(document.languageId)) {
      outputChannel.appendLine(
        `[${new Date().toLocaleTimeString()}] [Auto-Intercepción] Archivo guardado: ${document.fileName} (${document.languageId}). Analizando con VulX...`
      );
      await analyzeDocument(document);
    }
  });

  // 6. Limpiar diagnósticos al cerrar un archivo
  const onCloseListener = vscode.workspace.onDidCloseTextDocument((document) => {
    diagnosticCollection.delete(document.uri);
    documentVulnerabilities.delete(document.uri.toString());
  });

  // 7. Proveedor de Quick Fix (Remediación Asistida - RF05)
  const codeActionProvider = vscode.languages.registerCodeActionsProvider(
    supportedLanguages.map((lang) => ({ language: lang })),
    {
      provideCodeActions(document, range, context) {
        const vulxDiagnostics = context.diagnostics.filter(
          (d) => d.source === 'VulX' && d.code
        );

        if (vulxDiagnostics.length === 0) {
          return [];
        }

        const vulns = documentVulnerabilities.get(document.uri.toString()) || [];
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of vulxDiagnostics) {
          const matchingVuln = vulns.find(
            (v) =>
              v.id === diagnostic.code &&
              Math.abs(v.line - 1 - diagnostic.range.start.line) <= 1
          );

          if (matchingVuln && matchingVuln.remediation?.fixedSnippet) {
            const fix = new vscode.CodeAction(
              `💡 Aplicar corrección de VulX: ${matchingVuln.remediation.explanation}`,
              vscode.CodeActionKind.QuickFix
            );
            fix.diagnostics = [diagnostic];
            fix.isPreferred = true;

            const edit = new vscode.WorkspaceEdit();

            const targetLine = document.lineAt(diagnostic.range.start.line);
            const lineText = targetLine.text;
            const indent = lineText.match(/^\s*/)?.[0] || '';

            // Caso especial para secretos hardcodeados (el snippet viene enmascarado con asteriscos)
            if (matchingVuln.id === 'HARDCODED_SECRET') {
              const quoteMatch = lineText.match(/(['"])(?:(?!\1).){8,}\1/);
              if (quoteMatch && typeof quoteMatch.index === 'number') {
                const quoteRange = new vscode.Range(
                  new vscode.Position(diagnostic.range.start.line, quoteMatch.index),
                  new vscode.Position(diagnostic.range.start.line, quoteMatch.index + quoteMatch[0].length)
                );
                edit.replace(document.uri, quoteRange, matchingVuln.remediation.fixedSnippet);
                fix.edit = edit;
                actions.push(fix);
                continue;
              }
            }

            // 1. Si el fragmento vulnerable exacto existe dentro de la línea y el reemplazo es de una sola línea:
            const snippetIdx = lineText.indexOf(matchingVuln.codeSnippet);
            if (
              snippetIdx !== -1 &&
              !matchingVuln.remediation.fixedSnippet.includes('\n')
            ) {
              const snippetRange = new vscode.Range(
                new vscode.Position(diagnostic.range.start.line, snippetIdx),
                new vscode.Position(
                  diagnostic.range.start.line,
                  snippetIdx + matchingVuln.codeSnippet.length
                )
              );
              edit.replace(
                document.uri,
                snippetRange,
                matchingVuln.remediation.fixedSnippet
              );
            } else {
              // 2. Si reemplaza la línea completa, respetar la indentación original
              const indented = matchingVuln.remediation.fixedSnippet
                .split(/\r?\n/)
                .map((l) => (l.trim().length > 0 ? `${indent}${l.trim()}` : ''))
                .join('\n');
              edit.replace(document.uri, targetLine.range, indented);
            }

            fix.edit = edit;
            actions.push(fix);
          }
        }

        return actions;
      },
    },
    {
      providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
    }
  );

  // 8. Re-aplicar decoraciones de línea al cambiar de editor activo
  const onEditorChangeListener = vscode.window.onDidChangeActiveTextEditor((editor) => {
    if (editor) {
      applyLineHighlights(editor);
    }
  });

  // Registrar todos los disposables
  context.subscriptions.push(
    outputChannel,
    diagnosticCollection,
    statusBarItem,
    criticalLineDecoration,
    highLineDecoration,
    mediumLineDecoration,
    lowLineDecoration,
    helloWorldCmd,
    readBufferCmd,
    analyzeCurrentFileCmd,
    clearDiagnosticsCmd,
    onSaveListener,
    onCloseListener,
    onEditorChangeListener,
    codeActionProvider
  );
}

/**
 * Envía el contenido del documento a la API /analyze y renderiza los diagnósticos (squiggles)
 * junto con decoraciones de resaltado de línea (line highlights) por severidad.
 *
 * Flujo completo del cliente HTTP:
 *   1. Construir payload con código, lenguaje y ruta
 *   2. Enviar POST a /analyze con timeout via AbortController
 *   3. Parsear respuesta JSON con lista de vulnerabilidades
 *   4. Crear DiagnosticCollection con rangos, severidades y mensajes
 *   5. Aplicar decoraciones de línea (line highlights) al editor activo
 *   6. Actualizar status bar con resumen de hallazgos
 */
async function analyzeDocument(document: vscode.TextDocument): Promise<void> {
  const supportedLanguages = ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'];
  if (!supportedLanguages.includes(document.languageId)) {
    return;
  }

  const code = document.getText();
  if (!code || code.trim().length === 0) {
    diagnosticCollection.delete(document.uri);
    return;
  }

  outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [Escaneo] Enviando ${document.fileName} a ${VULX_API_URL}/analyze...`);

  // Actualizar status bar para indicar escaneo en progreso
  if (statusBarItem) {
    statusBarItem.text = '$(loading~spin) VulX: Escaneando…';
    statusBarItem.tooltip = `Analizando: ${document.fileName}`;
  }

  try {
    // Cliente HTTP con AbortController para timeout configurable (evita bloqueos por Ollama lento)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), VULX_FETCH_TIMEOUT_MS);

    const response = await fetch(`${VULX_API_URL}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        code,
        language: document.languageId.includes('typescript') ? 'typescript' : 'javascript',
        filePath: document.fileName,
        includeRemediation: true,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errText = await response.text();
      outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [Error HTTP ${response.status}] ${errText}`);
      return;
    }

    const data = (await response.json()) as {
      status: string;
      analysis?: {
        vulnerabilities: VulnerabilityResponse[];
        summary: {
          total: number;
          critical: number;
          high: number;
          medium: number;
          low: number;
          durationMs: number;
        };
      };
    };

    const vulnerabilities = data.analysis?.vulnerabilities || [];
    documentVulnerabilities.set(document.uri.toString(), vulnerabilities);

    // ── Construir diagnósticos: mapear posiciones VulX (1-indexed) → VS Code (0-indexed) ──
    const diagnostics: vscode.Diagnostic[] = [];

    for (const vuln of vulnerabilities) {
      // Líneas en VS Code son 0-indexed, en VulX son 1-indexed
      const lineIndex = Math.min(Math.max(0, vuln.line - 1), Math.max(0, document.lineCount - 1));
      const docLine = document.lineCount > lineIndex ? document.lineAt(lineIndex) : null;

      const lineEnd = docLine ? docLine.range.end.character : 100;
      const startCol = Math.max(0, Math.min(vuln.column >= 0 ? vuln.column : 0, lineEnd));
      const endCol = Math.max(startCol + 1, lineEnd);

      const range = new vscode.Range(
        new vscode.Position(lineIndex, startCol),
        new vscode.Position(lineIndex, endCol)
      );

      // Mapeo de severidad VulX → DiagnosticSeverity de VS Code
      let severity = vscode.DiagnosticSeverity.Error;
      if (vuln.severity === 'medium') {
        severity = vscode.DiagnosticSeverity.Warning;
      } else if (vuln.severity === 'low') {
        severity = vscode.DiagnosticSeverity.Information;
      }

      const diagnostic = new vscode.Diagnostic(
        range,
        `[VulX] ${vuln.name}: ${vuln.description}\n\n💡 Recomendación: ${vuln.recommendation}`,
        severity
      );

      diagnostic.code = vuln.id;
      diagnostic.source = 'VulX';

      diagnostics.push(diagnostic);
    }

    // Publicar diagnósticos en la colección (renderiza squiggles + panel de Problemas)
    diagnosticCollection.set(document.uri, diagnostics);

    // ── Aplicar resaltado visual de líneas (line highlights) en el editor activo ──
    const activeEditor = vscode.window.activeTextEditor;
    if (activeEditor && activeEditor.document.uri.toString() === document.uri.toString()) {
      applyLineHighlights(activeEditor);
    }

    // ── Actualizar status bar con resumen de hallazgos ──
    if (statusBarItem) {
      if (vulnerabilities.length > 0) {
        statusBarItem.text = `$(warning) VulX: ${vulnerabilities.length} hallazgo(s)`;
        statusBarItem.tooltip = `Último escaneo: ${vulnerabilities.length} vulnerabilidad(es) en ${data.analysis?.summary.durationMs ?? 0}ms`;
      } else {
        statusBarItem.text = '$(shield) VulX: Seguro';
        statusBarItem.tooltip = 'Último escaneo: Sin vulnerabilidades detectadas';
      }
    }

    outputChannel.appendLine(
      `[${new Date().toLocaleTimeString()}] [Escaneo Completado] ${vulnerabilities.length} vulnerabilidad(es) detectada(s) en ${data.analysis?.summary.durationMs ?? 0}ms.`
    );

    if (vulnerabilities.length > 0) {
      vscode.window.showWarningMessage(
        `🛡️ VulX detectó ${vulnerabilities.length} vulnerabilidad(es) de seguridad en el archivo. Revisa el panel de Problemas (Ctrl+Shift+M).`
      );
    } else {
      vscode.window.showInformationMessage('🛡️ VulX: No se detectaron vulnerabilidades en el archivo analizado.');
    }
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    const isTimeout = err instanceof Error && err.name === 'AbortError';

    outputChannel.appendLine(
      `[${new Date().toLocaleTimeString()}] [Error ${isTimeout ? 'Timeout' : 'Conexión'} API] ${errorMsg}`
    );

    if (isTimeout) {
      vscode.window.showErrorMessage(
        `VulX: El análisis excedió el tiempo límite de ${VULX_FETCH_TIMEOUT_MS / 1000}s. Verifica que el servidor de análisis y Ollama estén respondiendo.`
      );
    } else {
      vscode.window.showErrorMessage(
        'VulX: No se pudo conectar con el servidor local en http://127.0.0.1:3000. Asegúrate de ejecutar "npm run dev" en la terminal de Vul_X.'
      );
    }

    // Restaurar status bar al estado inicial tras error
    if (statusBarItem) {
      statusBarItem.text = '$(shield) VulX';
      statusBarItem.tooltip = 'VulX Security Analyzer — Error en último escaneo';
    }
  }
}

/**
 * Aplica decoraciones de resaltado de línea (line highlights) en el editor,
 * agrupando las vulnerabilidades almacenadas por severidad para ofrecer
 * retroalimentación visual inmediata sobre las líneas afectadas.
 *
 * Cada severidad utiliza un color diferente:
 *   - Critical: rojo (#dc2626)
 *   - High:     naranja (#ea580c)
 *   - Medium:   amarillo (#ca8a04)
 *   - Low:      azul (#2563eb)
 */
function applyLineHighlights(editor: vscode.TextEditor): void {
  const vulns = documentVulnerabilities.get(editor.document.uri.toString()) || [];

  const criticalRanges: vscode.DecorationOptions[] = [];
  const highRanges: vscode.DecorationOptions[] = [];
  const mediumRanges: vscode.DecorationOptions[] = [];
  const lowRanges: vscode.DecorationOptions[] = [];

  for (const vuln of vulns) {
    const lineIndex = Math.min(Math.max(0, vuln.line - 1), Math.max(0, editor.document.lineCount - 1));
    const line = editor.document.lineAt(lineIndex);
    const decoration: vscode.DecorationOptions = {
      range: line.range,
      hoverMessage: new vscode.MarkdownString(
        `**🛡️ VulX — ${vuln.name}** (\`${vuln.severity.toUpperCase()}\`)\n\n${vuln.description}\n\n💡 *${vuln.recommendation}*`
      ),
    };

    switch (vuln.severity) {
      case 'critical':
        criticalRanges.push(decoration);
        break;
      case 'high':
        highRanges.push(decoration);
        break;
      case 'medium':
        mediumRanges.push(decoration);
        break;
      case 'low':
        lowRanges.push(decoration);
        break;
    }
  }

  editor.setDecorations(criticalLineDecoration, criticalRanges);
  editor.setDecorations(highLineDecoration, highRanges);
  editor.setDecorations(mediumLineDecoration, mediumRanges);
  editor.setDecorations(lowLineDecoration, lowRanges);
}

/**
 * Limpia todas las decoraciones de resaltado de línea del editor dado.
 */
function clearLineHighlights(editor: vscode.TextEditor): void {
  editor.setDecorations(criticalLineDecoration, []);
  editor.setDecorations(highLineDecoration, []);
  editor.setDecorations(mediumLineDecoration, []);
  editor.setDecorations(lowLineDecoration, []);
}

/**
 * Función de desactivación: se ejecuta al cerrar o deshabilitar la extensión
 */
export function deactivate() {
  if (outputChannel) {
    outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [VulX] Extensión desactivada.`);
    outputChannel.dispose();
  }
  if (diagnosticCollection) {
    diagnosticCollection.clear();
    diagnosticCollection.dispose();
  }
  // Limpiar decoraciones de línea y status bar
  criticalLineDecoration?.dispose();
  highLineDecoration?.dispose();
  mediumLineDecoration?.dispose();
  lowLineDecoration?.dispose();
  statusBarItem?.dispose();
}
