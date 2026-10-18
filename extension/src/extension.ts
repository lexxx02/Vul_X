import * as vscode from 'vscode';

// Canal de salida dedicado para los logs de VulX en la consola del IDE
let outputChannel: vscode.OutputChannel;

/**
 * Función de activación: se ejecuta cuando la extensión se inicia
 * según los activationEvents definidos en package.json o al invocar un comando.
 */
export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel('VulX Security');
  outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [VulX] Extensión activada con éxito.`);

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

  // 3. Comando para preparar y estructurar el payload de escaneo (preparado para /analyze)
  const scanCurrentFileCmd = vscode.commands.registerCommand('vulx.scanCurrentFile', () => {
    const editor = vscode.window.activeTextEditor;

    if (!editor) {
      vscode.window.showWarningMessage('VulX: Abre un archivo para escanear.');
      return;
    }

    const document = editor.document;
    const payload = {
      code: document.getText(),
      language: document.languageId,
      filePath: document.fileName
    };

    outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [Escaneo] Payload preparado para análisis:`);
    outputChannel.appendLine(JSON.stringify({ ...payload, code: `${payload.code.substring(0, 100)}... (truncado)` }, null, 2));

    vscode.window.showInformationMessage(
      `VulX: Payload preparado para ${document.fileName.split(/[\\/]/).pop()} (${payload.code.length} bytes). Listo para conectar con la API /analyze.`
    );
  });

  // 4. Ciclo de vida: Listener de guardado de documentos (Base para RF01)
  const onSaveListener = vscode.workspace.onDidSaveTextDocument((document) => {
    const supportedLanguages = ['javascript', 'typescript', 'javascriptreact', 'typescriptreact'];
    if (supportedLanguages.includes(document.languageId)) {
      outputChannel.appendLine(
        `[${new Date().toLocaleTimeString()}] [Auto-Intercepción] Archivo guardado: ${document.fileName} (${document.languageId}). Buffer listo para análisis.`
      );
    }
  });

  // Registrar todos los disposables en las suscripciones del contexto
  context.subscriptions.push(
    outputChannel,
    helloWorldCmd,
    readBufferCmd,
    scanCurrentFileCmd,
    onSaveListener
  );
}

/**
 * Función de desactivación: se ejecuta al cerrar o deshabilitar la extensión
 */
export function deactivate() {
  if (outputChannel) {
    outputChannel.appendLine(`[${new Date().toLocaleTimeString()}] [VulX] Extensión desactivada.`);
    outputChannel.dispose();
  }
}
