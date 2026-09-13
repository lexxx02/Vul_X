import type { SyntaxNode } from 'tree-sitter';
import { SecurityRule } from '../SecurityRule.js';
import type { AnalysisContext, Vulnerability } from '../SecurityRule.js';

/**
 * Regla: Uso peligroso de eval()
 *
 * Detecta llamadas a eval() en código JavaScript/TypeScript.
 * eval() ejecuta cadenas de texto como código, lo que puede permitir
 * la ejecución de código malicioso si la cadena proviene de entrada
 * del usuario (ataques de inyección de código).
 *
 * Referencia: CWE-95 (Improper Neutralization of Directives in
 * Dynamically Evaluated Code - 'Eval Injection')
 */
export class EvalUsageRule extends SecurityRule {
  readonly id = 'EVAL_USAGE';
  readonly name = 'Uso peligroso de eval()';
  readonly description =
    'Detecta llamadas a eval() que pueden permitir inyección de código arbitrario.';
  readonly severity = 'critical' as const;
  readonly supportedLanguages = ['javascript', 'typescript'];

  evaluate(context: AnalysisContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    // Recorrer el AST buscando llamadas a funciones
    this.walkTree(context.rootNode, (node: SyntaxNode) => {
      if (node.type === 'call_expression') {
        const functionNode = node.childForFieldName('function');

        if (functionNode && functionNode.text === 'eval') {
          vulnerabilities.push({
            id: this.id,
            name: this.name,
            description:
              'La función eval() ejecuta código arbitrario a partir de una cadena de texto. ' +
              'Si la cadena proviene de entrada del usuario, un atacante podría ejecutar ' +
              'código malicioso en el sistema.',
            severity: this.severity,
            line: node.startPosition.row + 1,
            column: node.startPosition.column,
            codeSnippet: node.text,
            recommendation:
              'Elimina el uso de eval(). Usa alternativas seguras como JSON.parse() ' +
              'para parsear datos, o new Function() con validación estricta si es absolutamente necesario.',
          });
        }
      }
    });

    return vulnerabilities;
  }

  /**
   * Recorre recursivamente todos los nodos del AST y ejecuta
   * el callback en cada uno.
   */
  private walkTree(node: SyntaxNode, callback: (node: SyntaxNode) => void): void {
    callback(node);
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child) {
        this.walkTree(child, callback);
      }
    }
  }
}
