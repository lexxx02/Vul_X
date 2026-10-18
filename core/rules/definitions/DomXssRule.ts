import type { SyntaxNode } from 'tree-sitter';
import { SecurityRule } from '../SecurityRule.js';
import type { AnalysisContext, Vulnerability } from '../SecurityRule.js';

/**
 * Regla: Manipulación insegura del DOM (XSS)
 *
 * Detecta patrones de manipulación del DOM vulnerables a Cross-Site Scripting (DOM-based XSS):
 * 1. Asignaciones directas a propiedades peligrosas como innerHTML y outerHTML.
 * 2. Invocaciones a métodos inseguros del DOM como document.write(), document.writeln()
 *    e insertAdjacentHTML().
 *
 * Si los datos asignados o insertados contienen entrada de usuario sin sanitizar,
 * un atacante puede inyectar y ejecutar código HTML/JavaScript malicioso en el contexto
 * del navegador de la víctima.
 *
 * Referencias:
 * - VULX-02 (Matriz de Vulnerabilidades VulX)
 * - CWE-79 (Improper Neutralization of Input During Web Page Generation - 'Cross-site Scripting')
 */
export class DomXssRule extends SecurityRule {
  readonly id = 'DOM_XSS';
  readonly name = 'Manipulación insegura del DOM (XSS)';
  readonly description =
    'Detecta asignaciones directas a innerHTML/outerHTML o llamadas a document.write() e insertAdjacentHTML() que pueden provocar vulnerabilidades de Cross-Site Scripting (XSS).';
  readonly severity = 'high' as const;
  readonly supportedLanguages = ['javascript', 'typescript'];

  evaluate(context: AnalysisContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    this.walkTree(context.rootNode, (node: SyntaxNode) => {
      // 1. Detección de asignaciones a innerHTML u outerHTML (= y +=)
      if (node.type === 'assignment_expression' || node.type === 'augmented_assignment_expression') {
        const assignmentFinding = this.checkInsecureAssignment(node);
        if (assignmentFinding) {
          vulnerabilities.push(assignmentFinding);
          return;
        }
      }

      // 2. Detección de llamadas a document.write(), document.writeln(), insertAdjacentHTML()
      if (node.type === 'call_expression') {
        const callFinding = this.checkInsecureCall(node);
        if (callFinding) {
          vulnerabilities.push(callFinding);
          return;
        }
      }
    });

    return vulnerabilities;
  }

  /**
   * Verifica si una expresión de asignación apunta a innerHTML u outerHTML.
   */
  private checkInsecureAssignment(node: SyntaxNode): Vulnerability | null {
    const left = node.childForFieldName('left');
    if (!left) return null;

    let targetProperty: string | null = null;

    // Caso A: member_expression (ej: element.innerHTML = userInput)
    if (left.type === 'member_expression') {
      const property = left.childForFieldName('property');
      if (property && (property.text === 'innerHTML' || property.text === 'outerHTML')) {
        targetProperty = property.text;
      }
    }

    // Caso B: subscript_expression (ej: element['innerHTML'] = userInput)
    if (left.type === 'subscript_expression') {
      const index = left.childForFieldName('index');
      if (index) {
        const cleanText = index.text.replace(/['"`]/g, '').trim();
        if (cleanText === 'innerHTML' || cleanText === 'outerHTML') {
          targetProperty = cleanText;
        }
      }
    }

    if (!targetProperty) return null;

    return {
      id: this.id,
      name: this.name,
      description:
        `Asignación directa a "${targetProperty}" detectada. La manipulación insegura ` +
        `del DOM mediante ${targetProperty} interpreta cadenas de texto como HTML ejecutable. ` +
        `Si los datos provienen de una fuente no confiable o entrada de usuario, un atacante ` +
        `puede ejecutar scripts maliciosos (Cross-Site Scripting - XSS) en el navegador del usuario.`,
      severity: this.severity,
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
      codeSnippet: node.text,
      recommendation:
        `Evita asignar directamente a ${targetProperty}. Utiliza propiedades seguras como ` +
        `"textContent" o "innerText" para insertar texto sin procesar HTML. Si requieres ` +
        `renderizar contenido HTML enriquecido, sanitiza la entrada previamente con una ` +
        `biblioteca como DOMPurify antes de insertarla en el DOM.`
    };
  }

  /**
   * Verifica si una llamada de función utiliza métodos inseguros del DOM
   * como document.write, document.writeln o insertAdjacentHTML.
   */
  private checkInsecureCall(node: SyntaxNode): Vulnerability | null {
    const fn = node.childForFieldName('function');
    if (!fn) return null;

    // Caso A: member_expression (ej: document.write(payload) o el.insertAdjacentHTML(...))
    if (fn.type === 'member_expression') {
      const object = fn.childForFieldName('object');
      const property = fn.childForFieldName('property');

      if (property) {
        const propName = property.text;
        const objName = object?.text || '';

        // document.write o document.writeln (incluyendo window.document.write)
        if (
          (propName === 'write' || propName === 'writeln') &&
          (objName === 'document' || objName === 'window.document')
        ) {
          return {
            id: this.id,
            name: this.name,
            description:
              `Invocación insegura a document.${propName}() detectada. Este método escribe ` +
              `directamente sobre el flujo del documento HTML y puede permitir inyección de scripts ` +
              `maliciosos (XSS) si el contenido no se encuentra debidamente validado o sanitizado.`,
            severity: this.severity,
            line: node.startPosition.row + 1,
            column: node.startPosition.column,
            codeSnippet: node.text,
            recommendation:
              `Evita document.${propName}(). Emplea métodos seguros y modernos del DOM ` +
              `como document.createElement() y parentNode.appendChild(), o manipula contenido con textContent.`
          };
        }

        // insertAdjacentHTML
        if (propName === 'insertAdjacentHTML') {
          return {
            id: this.id,
            name: this.name,
            description:
              `Uso inseguro de insertAdjacentHTML() detectado. Insertar fragmentos HTML directamente ` +
              `en el DOM sin sanitización previa permite ataques de Cross-Site Scripting (XSS).`,
            severity: this.severity,
            line: node.startPosition.row + 1,
            column: node.startPosition.column,
            codeSnippet: node.text,
            recommendation:
              `Sanitiza el fragmento HTML con DOMPurify antes de pasarlo a insertAdjacentHTML(), ` +
              `o crea elementos de forma programática mediante document.createElement() y textContent.`
          };
        }
      }
    }

    // Caso B: subscript_expression (ej: document['write'](payload))
    if (fn.type === 'subscript_expression') {
      const object = fn.childForFieldName('object');
      const index = fn.childForFieldName('index');

      if (object && index) {
        const objName = object.text;
        const cleanIndex = index.text.replace(/['"`]/g, '').trim();

        if (
          (cleanIndex === 'write' || cleanIndex === 'writeln') &&
          (objName === 'document' || objName === 'window.document')
        ) {
          return {
            id: this.id,
            name: this.name,
            description:
              `Invocación insegura a document['${cleanIndex}']() detectada. Escribir directamente ` +
              `en el documento abre vectores de ataque de Cross-Site Scripting (XSS).`,
            severity: this.severity,
            line: node.startPosition.row + 1,
            column: node.startPosition.column,
            codeSnippet: node.text,
            recommendation:
              `Evita invocar document['${cleanIndex}'](). Utiliza la API estándar del DOM ` +
              `como createElement() o asignaciones a textContent.`
          };
        }

        if (cleanIndex === 'insertAdjacentHTML') {
          return {
            id: this.id,
            name: this.name,
            description:
              `Uso inseguro de insertAdjacentHTML() detectado mediante acceso por corchetes. ` +
              `Permite vectores de ataque Cross-Site Scripting (XSS).`,
            severity: this.severity,
            line: node.startPosition.row + 1,
            column: node.startPosition.column,
            codeSnippet: node.text,
            recommendation:
              `Sanitiza el contenido con DOMPurify antes de llamar a insertAdjacentHTML() ` +
              `o construye elementos con createElement().`
          };
        }
      }
    }

    return null;
  }

  /**
   * Recorre recursivamente el árbol de sintaxis abstracta (AST).
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
