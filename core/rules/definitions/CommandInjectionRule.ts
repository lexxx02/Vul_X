import type { SyntaxNode } from 'tree-sitter';
import { SecurityRule } from '../SecurityRule.js';
import type { AnalysisContext, Vulnerability } from '../SecurityRule.js';

/**
 * Regla: Inyección de Comandos del Sistema Operativo (OS Command Injection)
 *
 * Analiza llamadas a APIs de ejecución de procesos del sistema operativo en Node.js
 * (módulo `child_process`) para detectar concatenaciones de cadenas o template literals
 * no sanitizados que permitan la ejecución de comandos arbitrarios.
 *
 * Funciones auditadas:
 * - child_process.exec() / execSync()
 * - child_process.spawn() / spawnSync() (con shell: true o comandos dinámicos)
 * - child_process.execFile() / execFileSync()
 *
 * Referencia:
 * - VULX-04 (Matriz de Vulnerabilidades VulX)
 * - CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
 */
export class CommandInjectionRule extends SecurityRule {
  readonly id = 'COMMAND_INJECTION';
  readonly name = 'Inyección de comandos del sistema operativo (OS Command Injection)';
  readonly description =
    'Detecta llamadas a funciones de ejecución de procesos (child_process.exec, spawn, etc.) ' +
    'que utilizan comandos construidos dinámicamente con concatenación o variables no sanitizadas.';
  readonly severity = 'critical' as const;
  readonly supportedLanguages = ['javascript', 'typescript'];

  /**
   * Métodos típicos de ejecución de procesos en Node.js
   */
  private readonly EXEC_FUNCTION_PATTERN = /^(exec|execSync|spawn|spawnSync|execFile|execFileSync)$/;

  evaluate(context: AnalysisContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    this.walkTree(context.rootNode, (node: SyntaxNode) => {
      if (node.type === 'call_expression') {
        this.checkProcessExecutionCall(node, vulnerabilities);
      }
    });

    return vulnerabilities;
  }

  /**
   * Inspecciona una llamada a función para verificar si invoca una API de child_process
   * con argumentos construidos de forma insegura.
   */
  private checkProcessExecutionCall(
    node: SyntaxNode,
    vulnerabilities: Vulnerability[]
  ): void {
    const functionNode = node.childForFieldName('function');
    if (!functionNode) return;

    let functionName = '';

    if (functionNode.type === 'member_expression') {
      const property = functionNode.childForFieldName('property');
      if (property) {
        functionName = property.text;
      }
    } else if (functionNode.type === 'identifier') {
      functionName = functionNode.text;
    }

    if (!this.EXEC_FUNCTION_PATTERN.test(functionName)) return;

    const args = node.childForFieldName('arguments');
    if (!args || args.namedChildren.length === 0) return;

    const commandArg = args.namedChildren[0];
    if (!commandArg) return;

    // Caso 1: String literal puro y estático -> SEGURO
    if (commandArg.type === 'string') return;

    // Caso 2: Template string sin sustituciones (${}) -> SEGURO
    if (
      commandArg.type === 'template_string' &&
      !commandArg.children.some((c) => c.type === 'template_substitution')
    ) {
      return;
    }

    // Caso 3: Concatenación con operador '+' (ej: exec('ping ' + host))
    if (commandArg.type === 'binary_expression') {
      const operator = commandArg.childForFieldName('operator');
      if (operator && operator.text === '+') {
        vulnerabilities.push(
          this.createVulnerability(
            node,
            `Se detectó concatenación de cadenas mediante el operador "+" en la llamada a "${functionName}()". ` +
              'Si las variables concatenadas provienen de entradas no confiables del usuario, un atacante ' +
              'puede encadenar comandos maliciosos mediante caracteres como ";", "&&", "|" o backticks.'
          )
        );
        return;
      }
    }

    // Caso 4: Template literal con interpolación `${...}` (ej: exec(`ping ${host}`))
    if (commandArg.type === 'template_string') {
      const hasSubstitutions = commandArg.children.some(
        (c) => c.type === 'template_substitution'
      );
      if (hasSubstitutions) {
        vulnerabilities.push(
          this.createVulnerability(
            node,
            `Se detectó interpolación de variables en template literal para el comando de "${functionName}()". ` +
              'La interpolación con ${} no escapa caracteres especiales de shell, lo que permite la inyección ' +
              'de comandos arbitrarios del sistema operativo (CWE-78).'
          )
        );
        return;
      }
    }

    // Caso 5: Argumento dinámico (variable, llamada o expresión no literal)
    // (ej: exec(userInput) o execSync(buildCommand(param)))
    if (this.isNonLiteralNode(commandArg)) {
      vulnerabilities.push(
        this.createVulnerability(
          node,
          `Se detectó un argumento dinámico en la llamada a "${functionName}()". ` +
            'Ejecutar comandos generados a partir de variables dinámicas sin validación estricta ' +
            'permite a un atacante ejecutar código arbitrario en el servidor.'
        )
      );
    }
  }

  private createVulnerability(
    node: SyntaxNode,
    description: string
  ): Vulnerability {
    return {
      id: this.id,
      name: this.name,
      description,
      severity: this.severity,
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
      codeSnippet: node.text,
      recommendation:
        'Evita concatenar comandos de shell con entradas dinámicas. Utiliza "child_process.execFile()" o ' +
        '"child_process.spawn()" pasando los argumentos en un arreglo separado (ej: execFile("ping", ["-c", "1", host])) ' +
        'y asegúrate de no habilitar la opción { shell: true }.',
    };
  }

  /**
   * Determina si un nodo sintáctico representa un valor no literal.
   */
  private isNonLiteralNode(node: SyntaxNode): boolean {
    const nonLiteralTypes = [
      'identifier',
      'member_expression',
      'call_expression',
      'subscript_expression',
      'binary_expression',
      'await_expression',
    ];
    return nonLiteralTypes.includes(node.type);
  }

  /**
   * Recorrido recursivo en profundidad del AST.
   */
  private walkTree(
    node: SyntaxNode,
    callback: (node: SyntaxNode) => void
  ): void {
    callback(node);
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child) {
        this.walkTree(child, callback);
      }
    }
  }
}
