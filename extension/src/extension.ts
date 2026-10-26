import * as vscode from 'vscode';

// Canal de salida dedicado para los logs de VulX en la consola del IDE
let outputChannel: vscode.OutputChannel;
let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;

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

interface VulxConfig {
  apiUrl: string;
  enableOnSave: boolean;
  analysisTrigger: 'both' | 'onSave' | 'onDemand';
  deepScan: boolean;
  showNotifications: boolean;
}

/**
 * Obtiene la configuración activa de VulX desde los ajustes de VS Code / Antigravity
 */
function getVulxConfig(): VulxConfig {
  const config = vscode.workspace.getConfiguration('vulx');
  return {
    apiUrl: config.get<string>('apiUrl') || process.env.VULX_API_URL || 'http://127.0.0.1:3000',
    enableOnSave: config.get<boolean>('enableOnSave', true),
    analysisTrigger: config.get<'both' | 'onSave' | 'onDemand'>('analysisTrigger', 'both'),
    deepScan: config.get<boolean>('deepScan', false),
    showNotifications: config.get<boolean>('showNotifications', true),
  };
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

  // Inicializar elemento en la barra de estado (Status Bar Item)
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = 'vulx.analyzeCurrentFile';
  statusBarItem.text = '$(shield) VulX: Listo';
  statusBarItem.tooltip = 'VulX Security: Clic para analizar archivo activo bajo demanda (Ctrl+Alt+A / Alt+Shift+V)';
  statusBarItem.show();

  outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [VulX] Extensión activada con éxito en el editor.`);
  outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [Triggers] onSave: ${getVulxConfig().enableOnSave ? 'habilitado' : 'deshabilitado'} | Modo: ${getVulxConfig().analysisTrigger}`);

  const supportedLanguages = ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'];

  // 1. Comando de prueba del ciclo de vida
  const helloWorldCmd = vscode.commands.registerCommand('vulx.helloWorld', () => {
    const msg = '¡VulX está activo y listo para analizar vulnerabilidades!';
    outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [Comando] vulx.helloWorld ejecutado.`);
    vscode.window.showInformationMessage(msg);
  });

  // 2. Comando para alternar trigger onSave (On / Off bajo demanda)
  const toggleOnSaveCmd = vscode.commands.registerCommand('vulx.toggleOnSave', async () => {
    const config = vscode.workspace.getConfiguration('vulx');
    const current = config.get<boolean>('enableOnSave', true);
    await config.update('enableOnSave', !current, vscode.ConfigurationTarget.Global);
    const estado = !current ? 'ACTIVADO' : 'DESACTIVADO';
    const msg = `🛡️ VulX: Análisis automático al guardar ${estado}.`;
    outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [Config] ${msg}`);
    vscode.window.showInformationMessage(msg);
  });

  // 3. Comando para leer el buffer del editor activo
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

  // 4. Comando para analizar activamente el archivo actual (Trigger Bajo Demanda)
  const analyzeCurrentFileCmd = vscode.commands.registerCommand('vulx.analyzeCurrentFile', async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage('VulX: Abre un archivo JavaScript o TypeScript para analizarlo bajo demanda.');
      return;
    }
    outputChannel.appendLine(
      `[${new Date().toLocaleTimeString()}] [Trigger onDemand] Solicitud de escaneo manual iniciada para ${editor.document.fileName}`
    );
    await analyzeDocument(editor.document, 'onDemand');
  });

  // 5. Comando para limpiar diagnósticos y resetear status bar
  const clearDiagnosticsCmd = vscode.commands.registerCommand('vulx.clearDiagnostics', () => {
    diagnosticCollection.clear();
    documentVulnerabilities.clear();
    if (statusBarItem) {
      statusBarItem.text = '$(shield) VulX: Listo';
      statusBarItem.tooltip = 'VulX Security: Clic para analizar archivo activo bajo demanda (Ctrl+Alt+A / Alt+Shift+V)';
    }
    vscode.window.showInformationMessage('VulX: Diagnósticos de seguridad limpiados.');
  });

  // 6. Ciclo de vida: Listener de guardado de documentos (Trigger al guardar archivo - onSave)
  const onSaveListener = vscode.workspace.onDidSaveTextDocument(async (document) => {
    if (supportedLanguages.includes(document.languageId)) {
      const { enableOnSave, analysisTrigger } = getVulxConfig();
      if (!enableOnSave || analysisTrigger === 'onDemand') {
        outputChannel.appendLine(
          `[${new Date().toLocaleTimeString()}] [Auto-Intercepción] Archivo guardado: ${document.fileName}. Análisis omitido (trigger onSave desactivado en configuración).`
        );
        return;
      }

      outputChannel.appendLine(
        `[${new Date().toLocaleTimeString()}] [Trigger onSave] Archivo guardado: ${document.fileName} (${document.languageId}). Analizando con VulX...`
      );
      await analyzeDocument(document, 'onSave');
    }
  });

  // 7. Limpiar diagnósticos al cerrar un archivo
  const onCloseListener = vscode.workspace.onDidCloseTextDocument((document) => {
    diagnosticCollection.delete(document.uri);
    documentVulnerabilities.delete(document.uri.toString());
  });

  // 8. Proveedor de Quick Fix (Remediación Asistida - RF05)
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
              const quoteMatch = lineText.match(/(["'])(?:(?!\1).){8,}\1/);
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

  // Registrar todos los disposables
  context.subscriptions.push(
    outputChannel,
    diagnosticCollection,
    statusBarItem,
    helloWorldCmd,
    toggleOnSaveCmd,
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
 * Soporta ejecución tanto automática (trigger onSave) como manual (trigger onDemand).
 */
async function analyzeDocument(
  document: vscode.TextDocument,
  triggerSource: 'onSave' | 'onDemand' = 'onDemand'
): Promise<void> {
  const supportedLanguages = ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'];
  if (!supportedLanguages.includes(document.languageId)) {
    return;
  }

  const code = document.getText();
  if (!code || code.trim().length === 0) {
    diagnosticCollection.delete(document.uri);
    if (statusBarItem) {
      statusBarItem.text = '$(shield) VulX: Listo';
    }
    return;
  }

  const config = getVulxConfig();

  if (statusBarItem) {
    statusBarItem.text = '$(sync~spin) VulX: Analizando...';
    statusBarItem.tooltip = `VulX: Analizando ${document.fileName} (${triggerSource})...`;
  }

  outputChannel.appendLine(
    `[${new Date().toLocaleTimeString()}] [${triggerSource.toUpperCase()}] Enviando ${document.fileName} a ${config.apiUrl}/analyze (DeepScan: ${config.deepScan})...`
  );

  try {
    const response = await fetch(`${config.apiUrl}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        code,
        language: document.languageId.includes('typescript') ? 'typescript' : 'javascript',
        filePath: document.fileName,
        deepScan: config.deepScan,
        includeRemediation: true,
      }),
    });

    if (!response.ok) {
      const errText = await response.text();
      outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [Error HTTP ${response.status}] ${errText}`);
      if (statusBarItem) {
        statusBarItem.text = '$(error) VulX: Error HTTP';
      }
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
      const lineIndex = Math.min(Math.max(0, vuln.line - 1), Math.max(0, document.lineCount - 1));
      const docLine = document.lineCount > lineIndex ? document.lineAt(lineIndex) : null;

      const lineEnd = docLine ? docLine.range.end.character : 100;
      const startCol = Math.max(0, Math.min(vuln.column >= 0 ? vuln.column : 0, lineEnd));
      const endCol = Math.max(startCol + 1, lineEnd);

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
      `[${new Date().toLocaleTimeString()}] [${triggerSource.toUpperCase()} Completado] ${vulnerabilities.length} vulnerabilidad(es) detectada(s) en ${data.analysis?.summary.durationMs ?? 0}ms.`
    );

    // Actualizar elemento en la barra de estado
    if (statusBarItem) {
      if (vulnerabilities.length > 0) {
        statusBarItem.text = `$(alert) VulX: ${vulnerabilities.length} alerta(s)`;
        statusBarItem.tooltip = `VulX: ${vulnerabilities.length} vulnerabilidad(es) en ${document.fileName} (Trigger: ${triggerSource}). Clic para re-analizar.`;
      } else {
        statusBarItem.text = '$(check) VulX: Seguro';
        statusBarItem.tooltip = `VulX: Sin vulnerabilidades en ${document.fileName} (Trigger: ${triggerSource}). Clic para re-analizar.`;
      }
    }

    if (config.showNotifications) {
      if (vulnerabilities.length > 0) {
        vscode.window.showWarningMessage(
          `🛡️ VulX detectó ${vulnerabilities.length} vulnerabilidad(es) de seguridad [${triggerSource}]. Revisa el panel de Problemas (Ctrl+Shift+M).`
        );
      } else if (triggerSource === 'onDemand') {
        vscode.window.showInformationMessage('🛡️ VulX: No se detectaron vulnerabilidades en el archivo analizado.');
      }
    }
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [Error Conexión API] ${errorMsg}`);
    if (statusBarItem) {
      statusBarItem.text = '$(error) VulX: Sin conexión';
      statusBarItem.tooltip = `VulX: No se pudo conectar con el servidor en ${config.apiUrl}`;
    }
    vscode.window.showErrorMessage(
      `VulX: No se pudo conectar con el servidor local en ${config.apiUrl}. Asegúrate de ejecutar "npm run dev" en la terminal de Vul_X.`
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
  if (statusBarItem) {
    statusBarItem.dispose();
  }
}
