import * as vscode from 'vscode';
import {
  VulxCodeActionProvider,
  type VulnerabilityResponse,
} from './VulxCodeActionProvider';
import {
  VulxDiffContentProvider,
  VulxDiffInspector,
} from './VulxDiffInspector';

// Canal de salida dedicado para los logs de VulX en la consola del IDE
let outputChannel: vscode.OutputChannel;
let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;

// Decoration types para resaltado visual de líneas vulnerables (line highlights por severidad)
let criticalLineDecoration: vscode.TextEditorDecorationType;
let highLineDecoration: vscode.TextEditorDecorationType;
let mediumLineDecoration: vscode.TextEditorDecorationType;
let lowLineDecoration: vscode.TextEditorDecorationType;

// Timeout máximo para la respuesta de la API (30s)
const VULX_FETCH_TIMEOUT_MS = 30_000;

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

// Almacenamiento en memoria de hallazgos por documento para Quick Fixes y Hover
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

  // Inicializar elemento en la barra de estado (Status Bar Item)
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = 'vulx.analyzeCurrentFile';
  statusBarItem.text = '$(shield) VulX: Listo';
  statusBarItem.tooltip = 'VulX Security: Clic para analizar archivo activo bajo demanda (Ctrl+Alt+A / Alt+Shift+V)';
  statusBarItem.show();

  outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [VulX] Extensión activada con éxito en el editor.`);
  outputChannel.appendLine(
    `[${new Date().toLocaleTimeString()}] [Triggers] onSave: ${getVulxConfig().enableOnSave ? 'habilitado' : 'deshabilitado'} | Modo: ${getVulxConfig().analysisTrigger}`
  );

  const supportedLanguages = ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'];

  // 1. Comando de prueba del ciclo de vida
  const helloWorldCmd = vscode.commands.registerCommand('vulx.helloWorld', () => {
    const msg = 'VulX está activo y listo para analizar vulnerabilidades.';
    outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [Comando] vulx.helloWorld ejecutado.`);
    vscode.window.showInformationMessage(msg);
  });

  // 2. Comando para alternar trigger onSave (On / Off bajo demanda)
  const toggleOnSaveCmd = vscode.commands.registerCommand('vulx.toggleOnSave', async () => {
    const config = vscode.workspace.getConfiguration('vulx');
    const current = config.get<boolean>('enableOnSave', true);
    await config.update('enableOnSave', !current, vscode.ConfigurationTarget.Global);
    const estado = !current ? 'ACTIVADO' : 'DESACTIVADO';
    const msg = `VulX: Análisis automático al guardar ${estado}.`;
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
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: 'VulX: Analizando vulnerabilidades…',
        cancellable: false,
      },
      () => analyzeDocument(editor.document, 'onDemand')
    );
  });

  // 5. Comando para limpiar diagnósticos y decoraciones
  const clearDiagnosticsCmd = vscode.commands.registerCommand('vulx.clearDiagnostics', () => {
    diagnosticCollection.clear();
    documentVulnerabilities.clear();
    // Limpiar decoraciones de resaltado de línea en el editor activo
    const activeEditor = vscode.window.activeTextEditor;
    if (activeEditor) {
      clearLineHighlights(activeEditor);
    }
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
  // Instanciar la clase VulxCodeActionProvider dedicada con inyección de dependencias
  const vulxCodeActionProvider = new VulxCodeActionProvider(
    documentVulnerabilities,
    outputChannel
  );

  const codeActionProvider = vscode.languages.registerCodeActionsProvider(
    supportedLanguages.map((lang) => ({ language: lang })),
    vulxCodeActionProvider,
    {
      providedCodeActionKinds: VulxCodeActionProvider.providedCodeActionKinds,
    }
  );

  // 8b. Comando programático para aplicar el parche de una vulnerabilidad específica
  //     Uso: vscode.commands.executeCommand('vulx.applyFix', vulnId, lineNumber)
  const applyFixCmd = vscode.commands.registerCommand(
    'vulx.applyFix',
    async (vulnId?: string, lineNumber?: number) => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage('VulX: No hay editor activo para aplicar la corrección.');
        return;
      }

      const docUri = editor.document.uri.toString();
      const vulns = documentVulnerabilities.get(docUri) || [];

      if (vulns.length === 0) {
        vscode.window.showInformationMessage('VulX: No hay vulnerabilidades detectadas en este archivo.');
        return;
      }

      // Si se proporcionan vulnId y lineNumber, buscar la vulnerabilidad específica
      let targetVuln: VulnerabilityResponse | undefined;
      if (vulnId && lineNumber !== undefined) {
        targetVuln = vulns.find(
          (v) => v.id === vulnId && Math.abs(v.line - lineNumber) <= 1
        );
      }

      // Si no se encontró por parámetros, mostrar QuickPick para selección manual
      if (!targetVuln) {
        const fixableVulns = vulns.filter((v) => v.remediation?.fixedSnippet);
        if (fixableVulns.length === 0) {
          vscode.window.showInformationMessage(
            'VulX: Ninguna vulnerabilidad tiene parche de remediación disponible.'
          );
          return;
        }

        const selected = await vscode.window.showQuickPick(
          fixableVulns.map((v) => ({
            label: `$(alert) ${v.name}`,
            description: `Línea ${v.line} — ${v.severity.toUpperCase()}`,
            detail: v.remediation?.explanation || v.recommendation,
            vuln: v,
          })),
          {
            placeHolder: 'Selecciona la vulnerabilidad a corregir',
            title: '🛡️ VulX: Aplicar corrección de seguridad',
          }
        );

        if (!selected) {
          return;
        }
        targetVuln = selected.vuln;
      }

      if (!targetVuln?.remediation?.fixedSnippet) {
        vscode.window.showWarningMessage(
          `VulX: No hay parche disponible para ${targetVuln?.name || vulnId}.`
        );
        return;
      }

      // Buscar el diagnóstico asociado para disparar el Quick Fix
      const diagnostics = diagnosticCollection.get(editor.document.uri) || [];
      const matchDiag = diagnostics.find(
        (d) =>
          d.code === targetVuln!.id &&
          Math.abs((targetVuln!.line - 1) - d.range.start.line) <= 1
      );

      if (!matchDiag) {
        vscode.window.showWarningMessage(
          'VulX: No se encontró el diagnóstico asociado para aplicar la corrección.'
        );
        return;
      }

      // Construir y aplicar el WorkspaceEdit a través del provider
      const fakeContext: vscode.CodeActionContext = {
        diagnostics: [matchDiag],
        triggerKind: vscode.CodeActionTriggerKind.Invoke,
        only: vscode.CodeActionKind.QuickFix,
      };

      const actions = vulxCodeActionProvider.provideCodeActions(
        editor.document,
        matchDiag.range,
        fakeContext,
        new vscode.CancellationTokenSource().token
      );

      if (actions.length > 0 && actions[0].edit) {
        const applied = await vscode.workspace.applyEdit(actions[0].edit);
        if (applied) {
          outputChannel.appendLine(
            `[${new Date().toLocaleTimeString()}] [ApplyFix] Corrección aplicada: ${targetVuln.id} en L${targetVuln.line}`
          );
          vscode.window.showInformationMessage(
            `🛡️ VulX: Corrección aplicada para "${targetVuln.name}" en línea ${targetVuln.line}.`
          );
        } else {
          vscode.window.showErrorMessage('VulX: No se pudo aplicar la corrección.');

        }
      }
    }
  );

  // 8c. Inspector de Diffs: Previsualización lado a lado antes de aplicar parche (Side-by-side diff)
  const diffContentProvider = new VulxDiffContentProvider();
  const diffRegistration = vscode.workspace.registerTextDocumentContentProvider(
    VulxDiffContentProvider.scheme,
    diffContentProvider
  );
  const diffInspector = new VulxDiffInspector(
    diffContentProvider,
    documentVulnerabilities,
    outputChannel
  );

  const previewDiffCmd = vscode.commands.registerCommand(
    'vulx.previewDiff',
    async (vulnId?: string, lineNumber?: number) => {
      await diffInspector.previewDiff(vulnId, lineNumber);
    }
  );

  // 9. Re-aplicar decoraciones de línea al cambiar de editor activo
  const onEditorChangeListener = vscode.window.onDidChangeActiveTextEditor((editor) => {
    if (editor) {
      applyLineHighlights(editor);
    }
  });

  // ── 10. HoverProvider enriquecido: tooltip con detalles de vulnerabilidad en Markdown (Semana 8 - Leo) ──
  // Formato técnico y sobrio estándar industrial (estilo SonarLint / Snyk)
  const hoverProvider = vscode.languages.registerHoverProvider(
    supportedLanguages.map((lang) => ({ language: lang })),
    {
      provideHover(document, position, _token) {
        const vulns = documentVulnerabilities.get(document.uri.toString());
        if (!vulns || vulns.length === 0) {
          return null;
        }

        // Buscar vulnerabilidades cuya línea (1-indexed) coincida con la posición del cursor (0-indexed)
        const hoveredLine = position.line + 1;
        const matchingVulns = vulns.filter((v) => v.line === hoveredLine);

        if (matchingVulns.length === 0) {
          return null;
        }

        // Construir contenido Markdown enriquecido para todas las vulnerabilidades en esa línea
        const markdown = new vscode.MarkdownString();
        markdown.isTrusted = true;
        markdown.supportHtml = true;

        for (let i = 0; i < matchingVulns.length; i++) {
          const vuln = matchingVulns[i];

          // Separador visual entre múltiples vulnerabilidades en la misma línea
          if (i > 0) {
            markdown.appendMarkdown('\n\n---\n\n');
          }

          // Construir el contenido enriquecido del tooltip
          markdown.appendMarkdown(buildVulnerabilityHoverContent(vuln, document.languageId));
        }

        // Asociar el hover al rango completo de la línea vulnerable
        const lineIndex = Math.min(Math.max(0, hoveredLine - 1), Math.max(0, document.lineCount - 1));
        const line = document.lineAt(lineIndex);

        return new vscode.Hover(markdown, line.range);
      },
    }
  );

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
    toggleOnSaveCmd,
    readBufferCmd,
    analyzeCurrentFileCmd,
    clearDiagnosticsCmd,
    applyFixCmd,
    previewDiffCmd,
    diffRegistration,
    onSaveListener,
    onCloseListener,
    onEditorChangeListener,
    codeActionProvider,
    hoverProvider
  );
}

/**
 * Envía el contenido del documento a la API /analyze y renderiza los diagnósticos (squiggles)
 * junto con decoraciones de resaltado de línea (line highlights) por severidad.
 * Soporta ejecución tanto automática (trigger onSave) como manual (trigger onDemand).
 *
 * Flujo completo del cliente HTTP:
 *   1. Construir payload con código, lenguaje y ruta (incluyendo deepScan configurable)
 *   2. Enviar POST a /analyze con timeout via AbortController
 *   3. Parsear respuesta JSON con lista de vulnerabilidades
 *   4. Crear DiagnosticCollection con rangos, severidades y mensajes
 *   5. Aplicar decoraciones de línea (line highlights) al editor activo
 *   6. Actualizar status bar con resumen de hallazgos
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

  // Cliente HTTP con AbortController para timeout configurable (evita bloqueos por Ollama lento)
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), VULX_FETCH_TIMEOUT_MS);

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
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

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

      // Mensaje técnico limpio para el panel de problemas y hover nativo sin emojis
      const diagnostic = new vscode.Diagnostic(
        range,
        `[VulX] ${vuln.name}: ${vuln.description} | Recomendación: ${vuln.recommendation}`,
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
          `VulX detectó ${vulnerabilities.length} vulnerabilidad(es) de seguridad [${triggerSource}]. Revisa el panel de Problemas (Ctrl+Shift+M).`
        );
      } else if (triggerSource === 'onDemand') {
        vscode.window.showInformationMessage('VulX: No se detectaron vulnerabilidades en el archivo analizado.');
      }
    }
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    const isTimeout = err instanceof Error && err.name === 'AbortError';

    outputChannel.appendLine(
      `[${new Date().toLocaleTimeString()}] [Error ${isTimeout ? 'Timeout' : 'Conexión'} API] ${errorMsg}`
    );

    if (statusBarItem) {
      statusBarItem.text = `$(error) VulX: ${isTimeout ? 'Timeout' : 'Sin conexión'}`;
      statusBarItem.tooltip = `VulX: ${isTimeout ? 'Excedió tiempo de espera (30s)' : 'No se pudo conectar con el servidor en ' + config.apiUrl}`;
    }

    if (isTimeout) {
      vscode.window.showErrorMessage(
        `VulX: El análisis excedió el tiempo límite de ${VULX_FETCH_TIMEOUT_MS / 1000}s. Verifica que el servidor de análisis y Ollama estén respondiendo.`
      );
    } else {
      vscode.window.showErrorMessage(
        `VulX: No se pudo conectar con el servidor local en ${config.apiUrl}. Asegúrate de ejecutar "npm run dev" en la terminal de Vul_X.`
      );
    }
  }
}

/**
 * Construye el contenido Markdown sobrio y estructurado para el tooltip de hover de una vulnerabilidad,
 * siguiendo el estándar visual corporativo de linters profesionales (estilo SonarLint / Snyk / CodeQL).
 */
function buildVulnerabilityHoverContent(vuln: VulnerabilityResponse, languageId: string): string {
  const lines: string[] = [];
  const severityUpper = vuln.severity.toUpperCase();

  // ── 1. Encabezado en español técnico ──
  lines.push(`### VulX Seguridad: ${vuln.name}`);

  // ── 2. Insignias con recuadro de fondo contrastado (<kbd>) ──
  lines.push(
    `<kbd>Regla: ${vuln.id}</kbd> &nbsp; <kbd>Severidad: ${severityUpper}</kbd> &nbsp; <kbd>Motor: VulX AST</kbd>`
  );
  lines.push('');

  // ── 3. Caja de Análisis con borde y fondo sombreado (Blockquote) ──
  lines.push('> **Análisis de Vulnerabilidad**');
  lines.push('>');
  for (const paragraph of vuln.description.split(/\r?\n/)) {
    if (paragraph.trim().length > 0) {
      lines.push(`> ${paragraph}`);
    }
  }
  lines.push('');

  // ── 4. Bloque de código detectado ──
  if (vuln.codeSnippet) {
    lines.push('**Código detectado:**');
    const lang = languageId.includes('typescript') ? 'typescript' : 'javascript';
    lines.push('```' + lang);
    lines.push(vuln.codeSnippet);
    lines.push('```');
    lines.push('');
  }

  // ── 5. Caja de Remediación con borde y fondo sombreado (Blockquote) ──
  lines.push('> **Guía de Remediación**');
  lines.push('>');
  for (const paragraph of vuln.recommendation.split(/\r?\n/)) {
    if (paragraph.trim().length > 0) {
      lines.push(`> ${paragraph}`);
    }
  }
  lines.push('');

  // ── 6. Previsualización de Código Corregido (si la API devuelve remediación) ──
  if (vuln.remediation) {
    lines.push('**Corrección sugerida:**');
    if (vuln.remediation.explanation) {
      lines.push(`*${vuln.remediation.explanation}*`);
      lines.push('');
    }

    if (vuln.remediation.diff) {
      lines.push('```diff');
      lines.push(vuln.remediation.diff);
      lines.push('```');
    } else if (vuln.remediation.fixedSnippet) {
      const lang = languageId.includes('typescript') ? 'typescript' : 'javascript';
      lines.push('```' + lang);
      lines.push(vuln.remediation.fixedSnippet);
      lines.push('```');
    }
    lines.push('');
  }

  // ── 7. Pie de Acción Rápida en español ──
  lines.push('---');
  lines.push('*Corrección rápida: Presiona `Ctrl+.` para aplicar la solución sugerida.*');

  return lines.join('\n');
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
        `**VulX Seguridad: ${vuln.name}** (\`${vuln.severity.toUpperCase()}\`)\n\n${vuln.description}\n\n*Recomendación: ${vuln.recommendation}*`
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
  if (statusBarItem) {
    statusBarItem.dispose();
  }
}
