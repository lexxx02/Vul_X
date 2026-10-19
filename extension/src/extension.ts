import * as vscode from 'vscode';

// Canal de salida dedicado para los logs de VulX en la consola del IDE
let outputChannel: vscode.OutputChannel;
let diagnosticCollection: vscode.DiagnosticCollection;

// URL base del backend de análisis VulX
const VULX_API_URL = process.env.VULX_API_URL || 'http://127.0.0.1:3000';

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

  // 3. Comando para analizar activamente el archivo actual conectando a la API
  const analyzeCurrentFileCmd = vscode.commands.registerCommand('vulx.analyzeCurrentFile', async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage('VulX: Abre un archivo para escanear.');
      return;
    }
    await analyzeDocument(editor.document);
  });

  // 4. Comando para limpiar diagnósticos
  const clearDiagnosticsCmd = vscode.commands.registerCommand('vulx.clearDiagnostics', () => {
    diagnosticCollection.clear();
    documentVulnerabilities.clear();
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

            // Rango exacto a reemplazar: si la línea coincide, reemplazar la línea o el snippet
            const targetLine = document.lineAt(diagnostic.range.start.line);
            edit.replace(document.uri, targetLine.range, matchingVuln.remediation.fixedSnippet);

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

  // Registrar todos los disposables
  context.subscriptions.push(
    outputChannel,
    diagnosticCollection,
    helloWorldCmd,
    readBufferCmd,
    analyzeCurrentFileCmd,
    clearDiagnosticsCmd,
    onSaveListener,
    onCloseListener,
    codeActionProvider
  );
}

/**
 * Envía el contenido del documento a la API /analyze y renderiza los diagnósticos (squiggles)
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

  try {
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
    });

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

    const diagnostics: vscode.Diagnostic[] = [];

    for (const vuln of vulnerabilities) {
      // Líneas en VS Code son 0-indexed, en VulX son 1-indexed
      const lineIndex = Math.max(0, vuln.line - 1);
      const docLine = document.lineCount > lineIndex ? document.lineAt(lineIndex) : null;

      const startCol = vuln.column >= 0 ? vuln.column : 0;
      const endCol = docLine ? docLine.range.end.character : startCol + (vuln.codeSnippet.length || 10);

      const range = new vscode.Range(
        new vscode.Position(lineIndex, startCol),
        new vscode.Position(lineIndex, endCol)
      );

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

    diagnosticCollection.set(document.uri, diagnostics);

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
    outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [Error Conexión API] ${errorMsg}`);
    vscode.window.showErrorMessage(
      'VulX: No se pudo conectar con el servidor local en http://127.0.0.1:3000. Asegúrate de ejecutar "npm run dev" en la terminal de Vul_X.'
    );
  }
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
}
