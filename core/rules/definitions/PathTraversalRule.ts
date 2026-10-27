import type { SyntaxNode } from 'tree-sitter';
import { SecurityRule } from '../SecurityRule.js';
import type { AnalysisContext, Vulnerability } from '../SecurityRule.js';

/**
 * Regla: Recorrido de Rutas Arbitrario (Path Traversal / Directory Traversal)
 *
 * Analiza llamadas a las APIs del sistema de archivos de Node.js (`fs`, `fs/promises`,
 * `fs-extra`) y utilidades de rutas (`path.join`, `path.resolve`) para detectar la
 * construcción de rutas de archivo con entradas dinámicas no sanitizadas.
 *
 * Si un atacante incluye secuencias como "../" o rutas absolutas ("/etc/passwd"),
 * puede acceder a archivos confidenciales del servidor o sobreescribir archivos críticos.
 *
 * Referencia:
 * - VULX-05 (Matriz de Vulnerabilidades VulX)
 * - CWE-22 (Improper Limitation of a Pathname to a Restricted Directory - 'Path Traversal')
 */
export class PathTraversalRule extends SecurityRule {
  readonly id = 'PATH_TRAVERSAL';
  readonly name = 'Recorrido de rutas arbitrario (Path Traversal)';
  readonly description =
    'Detecta operaciones de lectura, escritura o eliminación de archivos en el sistema ' +
    'que utilizan rutas construidas dinámicamente con entradas no validadas ni confinadas.';
  readonly severity = 'high' as const;
  readonly supportedLanguages = ['javascript', 'typescript'];

  /**
   * Métodos típicos del sistema de archivos en Node.js propensos a Path Traversal
   */
  private readonly FS_FUNCTION_PATTERN =
    /^(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|unlink|unlinkSync|readdir|readdirSync|rm|rmSync|rmdir|rmdirSync|open|openSync|access|accessSync|stat|statSync)$/;

  evaluate(context: AnalysisContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    this.walkTree(context.rootNode, (node: SyntaxNode) => {
      if (node.type === 'call_expression') {
        this.checkFileSystemCall(node, vulnerabilities);
      }
    });

    return vulnerabilities;
  }

  /**
   * Inspecciona una llamada a función para verificar si interactúa con el sistema de archivos
   * usando rutas dinámicas potencialmente vulnerables a Path Traversal.
   */
  private checkFileSystemCall(
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

    if (!this.FS_FUNCTION_PATTERN.test(functionName)) return;

    const args = node.childForFieldName('arguments');
    if (!args || args.namedChildren.length === 0) return;

    const pathArg = args.namedChildren[0];
    if (!pathArg) return;

    // Caso 1: String literal estático -> SEGURO (ej: fs.readFileSync('./data.json'))
    if (pathArg.type === 'string') return;

    // Caso 2: Template literal sin sustituciones -> SEGURO
    if (
      pathArg.type === 'template_string' &&
      !pathArg.children.some((c) => c.type === 'template_substitution')
    ) {
      return;
    }

    // Caso 3: Concatenación con operador '+' (ej: fs.readFile('/var/data/' + filename))
    if (pathArg.type === 'binary_expression') {
      const operator = pathArg.childForFieldName('operator');
      if (operator && operator.text === '+') {
        vulnerabilities.push(
          this.createVulnerability(
            node,
            `Se detectó concatenación de rutas con el operador "+" en "${functionName}()". ` +
              'Un atacante puede utilizar secuencias de escape como "../" para acceder o manipular ' +
              'archivos fuera del directorio previsto (CWE-22).'
          )
        );
        return;
      }
    }

    // Caso 4: Template string con interpolación `${...}` (ej: fs.readFileSync(`uploads/${file}`))
    if (pathArg.type === 'template_string') {
      const hasSubstitutions = pathArg.children.some(
        (c) => c.type === 'template_substitution'
      );
      if (hasSubstitutions) {
        vulnerabilities.push(
          this.createVulnerability(
            node,
            `Se detectó interpolación en template literal para construir la ruta de "${functionName}()". ` +
              'Las variables interpoladas no neutralizan secuencias como "../", exponiendo el sistema a Path Traversal.'
          )
        );
        return;
      }
    }

    // Caso 5: path.join() o path.resolve() con argumentos dinámicos
    if (pathArg.type === 'call_expression') {
      const isPathJoinOrResolve = this.isPathJoinCall(pathArg);
      if (isPathJoinOrResolve) {
        const pathCallArgs = pathArg.childForFieldName('arguments');
        if (pathCallArgs) {
          // Verificar si algún argumento de path.join no es un literal simple ni __dirname/process.cwd() ni path.basename()
          const hasDynamicArg = pathCallArgs.namedChildren.some(
            (arg) => this.isDynamicPathSegment(arg)
          );
          if (hasDynamicArg) {
            vulnerabilities.push(
              this.createVulnerability(
                node,
                `Llamada a "${functionName}()" utilizando path.join/resolve con segmentos dinámicos no validados. ` +
                  'path.join() resuelve secuencias relativas ("../"), permitiendo escapar del directorio raíz si la entrada no se valida contra una ruta permitida.'
              )
            );
          }
        }
        return;
      }
    }

    // Caso 6: Argumento dinámico directo (ej: fs.readFileSync(userPath))
    if (this.isNonLiteralNode(pathArg)) {
      // Si la variable fue validada y sanitizada explícitamente (ej: safePath, safeFile), no reportar falso positivo
      if (pathArg.type === 'identifier' && /^(safe|valid|sanitized)/i.test(pathArg.text)) {
        return;
      }

      vulnerabilities.push(
        this.createVulnerability(
          node,
          `Se detectó una variable dinámica como ruta en la llamada a "${functionName}()". ` +
            'Si la ruta proviene de una entrada externa sin validación canónica estricta, ' +
            'permite acceso arbitrario al sistema de archivos del servidor (CWE-22).'
        )
      );
    }
  }

  /**
   * Comprueba si una llamada es path.join(...) o path.resolve(...)
   */
  private isPathJoinCall(callNode: SyntaxNode): boolean {
    const fn = callNode.childForFieldName('function');
    if (!fn) return false;
    if (fn.type === 'member_expression') {
      const prop = fn.childForFieldName('property');
      return prop ? prop.text === 'join' || prop.text === 'resolve' : false;
    }
    return fn.text === 'join' || fn.text === 'resolve';
  }

  /**
   * Determina si un argumento pasado a path.join() es un segmento dinámico
   * que no sea simplemente constantes locales como __dirname, __filename, process.cwd().
   */
  private isDynamicPathSegment(node: SyntaxNode): boolean {
    if (node.type === 'string') return false;
    if (
      node.type === 'template_string' &&
      !node.children.some((c) => c.type === 'template_substitution')
    ) {
      return false;
    }
    // Constantes comunes o variables sanitizadas que son seguras
    if (node.type === 'identifier') {
      if (node.text === '__dirname' || node.text === '__filename') return false;
      if (/^(safe|valid|sanitized)/i.test(node.text)) return false;
    }
    if (node.type === 'call_expression') {
      const fn = node.childForFieldName('function');
      if (fn) {
        if (fn.text === 'process.cwd') return false;
        // path.basename() extrae únicamente el nombre del archivo neutralizando secuencias '../'
        if (
          fn.text === 'path.basename' ||
          fn.text === 'basename' ||
          (fn.type === 'member_expression' && fn.childForFieldName('property')?.text === 'basename')
        ) {
          return false;
        }
      }
    }
    return true;
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
        'Sanitiza y valida las rutas contra una lista blanca o directorio base permitido. ' +
        'Usa path.resolve() y verifica que la ruta resultante comience estrictamente con el directorio permitido ' +
        '(ej: const safePath = path.resolve(BASE_DIR, userInput); if (!safePath.startsWith(BASE_DIR)) throw new Error("Acceso denegado");).',
    };
  }

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
