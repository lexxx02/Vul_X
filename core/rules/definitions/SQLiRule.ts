import type { SyntaxNode } from 'tree-sitter';
import { SecurityRule } from '../SecurityRule.js';
import type { AnalysisContext, Vulnerability } from '../SecurityRule.js';

/**
 * Regla: Detector de Inyección SQL (SQLi)
 *
 * Analiza el AST de Tree-sitter para detectar patrones peligrosos donde
 * se construyen sentencias SQL mediante concatenación de strings o template
 * literals no sanitizados.
 *
 * Patrones detectados:
 * 1. Concatenación con operador +: "SELECT * FROM users WHERE id = " + userId
 * 2. Template literals inseguros: `SELECT * FROM users WHERE id = ${userId}`
 * 3. Uso de .query(), .execute(), .raw() con argumentos dinámicos
 *
 * Referencia: CWE-89 (Improper Neutralization of Special Elements used in
 * an SQL Command — 'SQL Injection')
 */
export class SQLiRule extends SecurityRule {
  readonly id = 'SQL_INJECTION';
  readonly name = 'Posible Inyección SQL';
  readonly description =
    'Detecta construcción insegura de sentencias SQL mediante concatenación de cadenas ' +
    'o template literals no sanitizados, lo que puede permitir inyección SQL.';
  readonly severity = 'critical' as const;
  readonly supportedLanguages = ['javascript', 'typescript'];

  /**
   * Expresión regular para identificar funciones que ejecutan SQL.
   *
   * Coincide con nombres de métodos comunes de librerías de bases de datos:
   *   - query    → método estándar en pg, mysql, mysql2, etc.
   *   - execute  → método usado en mysql2, sequelize
   *   - exec     → variante abreviada en algunos ORMs
   *   - raw      → método de Sequelize/Knex para queries crudos
   *   - prepare  → sentencias preparadas (peligroso si se concatena)
   *   - run      → usado en better-sqlite3
   *
   * El patrón busca estas palabras como identificadores completos
   * (no como parte de otro nombre) gracias a los límites de palabra \b.
   */
  private readonly SQL_FUNCTION_PATTERN = /\b(query|execute|exec|raw|prepare|run)\b/;

  /**
   * Expresión regular para detectar palabras clave SQL en strings.
   *
   * Coincide con las sentencias SQL más comunes:
   *   - SELECT ... FROM  → lectura de datos
   *   - INSERT INTO      → inserción de datos
   *   - UPDATE ... SET   → actualización de datos
   *   - DELETE FROM      → eliminación de datos
   *   - DROP TABLE       → eliminación de tablas
   *   - ALTER TABLE      → modificación de estructura
   *   - CREATE TABLE     → creación de tablas
   *   - UNION SELECT     → posible exfiltración de datos
   *   - WHERE            → cláusula de filtrado (indica query dinámica)
   *
   * Flag 'i' para case-insensitive ya que SQL no distingue mayúsculas.
   */
  private readonly SQL_KEYWORD_PATTERN =
    /\b(SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+.+\s+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+TABLE|UNION\s+SELECT|WHERE)\b/i;

  evaluate(context: AnalysisContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    this.walkTree(context.rootNode, (node: SyntaxNode) => {
      // ─── Caso 1: Concatenación con operador + ───
      // Busca expresiones binarias con '+' donde al menos un operando
      // contiene palabras clave SQL.
      if (node.type === 'binary_expression') {
        this.checkBinaryConcatenation(node, vulnerabilities);
      }

      // ─── Caso 2: Template Literals con interpolación ───
      // Busca template strings (`...${expr}...`) que contengan SQL.
      if (node.type === 'template_string') {
        this.checkTemplateLiteral(node, vulnerabilities);
      }

      // ─── Caso 3: Llamadas a funciones SQL con argumentos dinámicos ───
      // Busca db.query(variable), connection.execute(expr), etc.
      if (node.type === 'call_expression') {
        this.checkSQLFunctionCall(node, vulnerabilities);
      }
    });

    return vulnerabilities;
  }

  /**
   * Verifica si una expresión binaria (+) está construyendo un string SQL
   * de forma insegura al concatenar con variables o expresiones.
   *
   * Ejemplo detectado:
   *   const q = "SELECT * FROM users WHERE id = " + userId;
   */
  private checkBinaryConcatenation(
    node: SyntaxNode,
    vulnerabilities: Vulnerability[]
  ): void {
    const operator = node.childForFieldName('operator');
    // Solo nos interesan concatenaciones con '+'
    if (!operator || operator.text !== '+') return;

    const left = node.childForFieldName('left');
    const right = node.childForFieldName('right');

    if (!left || !right) return;

    // Verificar si alguno de los operandos contiene palabras clave SQL
    const fullText = node.text;
    if (!this.SQL_KEYWORD_PATTERN.test(fullText)) return;

    // Verificar que hay al menos un operando no-literal (una variable,
    // llamada a función, etc.) — eso es lo que lo hace peligroso.
    const hasNonLiteral =
      this.isNonLiteralNode(left) || this.isNonLiteralNode(right);

    if (hasNonLiteral) {
      vulnerabilities.push({
        id: this.id,
        name: this.name,
        description:
          'Se detectó concatenación de cadenas para construir una sentencia SQL. ' +
          'Un atacante podría manipular la entrada para inyectar SQL arbitrario. ' +
          'Esto puede derivar en robo de datos, modificación o eliminación de registros.',
        severity: this.severity,
        line: node.startPosition.row + 1,
        column: node.startPosition.column,
        codeSnippet: node.text,
        recommendation:
          'Usa consultas parametrizadas (prepared statements) en lugar de concatenar variables. ' +
          'Ejemplo: db.query("SELECT * FROM users WHERE id = $1", [userId])',
      });
    }
  }

  /**
   * Verifica si un template literal contiene SQL con interpolaciones
   * (expresiones ${...}) que podrían ser manipuladas por un atacante.
   *
   * Ejemplo detectado:
   *   const q = `SELECT * FROM users WHERE id = ${req.params.id}`;
   */
  private checkTemplateLiteral(
    node: SyntaxNode,
    vulnerabilities: Vulnerability[]
  ): void {
    // Un template_string seguro no tiene template_substitution hijos.
    // Solo nos preocupan los que interpolan variables.
    const hasSubstitutions = node.children.some(
      (child) => child.type === 'template_substitution'
    );

    if (!hasSubstitutions) return;

    // Verificar que el contenido del template contiene SQL
    if (!this.SQL_KEYWORD_PATTERN.test(node.text)) return;

    vulnerabilities.push({
      id: this.id,
      name: this.name,
      description:
        'Se detectó un template literal con interpolación usado para construir una sentencia SQL. ' +
        'Las variables interpoladas con ${} no son sanitizadas automáticamente, ' +
        'lo que permite inyección SQL si la entrada proviene del usuario.',
      severity: this.severity,
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
      codeSnippet: node.text,
      recommendation:
        'Usa consultas parametrizadas en lugar de template literals. ' +
        'Ejemplo: db.query("SELECT * FROM users WHERE id = ?", [userId])',
    });
  }

  /**
   * Verifica si una llamada a función SQL (query, execute, etc.)
   * recibe como argumento una expresión dinámica en lugar de un
   * string literal estático.
   *
   * Ejemplo detectado:
   *   db.query(userInput)
   *   connection.execute(buildQuery(name))
   */
  private checkSQLFunctionCall(
    node: SyntaxNode,
    vulnerabilities: Vulnerability[]
  ): void {
    const functionNode = node.childForFieldName('function');
    if (!functionNode) return;

    // Verificar si el nombre de la función coincide con funciones SQL
    // Manejar tanto llamadas directas como member expressions (db.query)
    let functionName = '';
    if (functionNode.type === 'member_expression') {
      const property = functionNode.childForFieldName('property');
      if (property) {
        functionName = property.text;
      }
    } else if (functionNode.type === 'identifier') {
      functionName = functionNode.text;
    }

    if (!this.SQL_FUNCTION_PATTERN.test(functionName)) return;

    // Verificar los argumentos: si el primer argumento NO es un string
    // literal, podría ser una query construida dinámicamente.
    const args = node.childForFieldName('arguments');
    if (!args || args.namedChildren.length === 0) return;

    const firstArg = args.namedChildren[0];
    if (!firstArg) return;

    // Si el argumento es un string literal simple, no hay riesgo de
    // inyección (a menos que contenga concatenación, ya detectada arriba).
    if (firstArg.type === 'string') return;

    // Si es un template sin sustituciones, es seguro.
    if (
      firstArg.type === 'template_string' &&
      !firstArg.children.some((c) => c.type === 'template_substitution')
    ) {
      return;
    }

    // El argumento es dinámico (variable, expresión, template con interpolación)
    vulnerabilities.push({
      id: this.id,
      name: this.name,
      description:
        `La función "${functionName}()" recibe un argumento dinámico en lugar de una query ` +
        'parametrizada. Si el argumento contiene entrada del usuario sin sanitizar, ' +
        'un atacante podría inyectar SQL malicioso.',
      severity: this.severity,
      line: node.startPosition.row + 1,
      column: node.startPosition.column,
      codeSnippet: node.text,
      recommendation:
        'Pasa la query como un string estático y los valores como parámetros separados. ' +
        `Ejemplo: ${functionName}("SELECT * FROM users WHERE id = $1", [userId])`,
    });
  }

  /**
   * Determina si un nodo del AST NO es un literal (string, número, etc.).
   * Un nodo no-literal indica una variable, llamada a función u otra
   * expresión dinámica que podría ser controlada por un atacante.
   */
  private isNonLiteralNode(node: SyntaxNode): boolean {
    const literalTypes = [
      'string',           // "texto"
      'number',           // 42
      'template_string',  // se evalúa aparte por sustituciones
      'true',             // booleanos
      'false',
      'null',
      'undefined',
    ];
    return !literalTypes.includes(node.type);
  }

  /**
   * Recorre recursivamente todos los nodos del AST y ejecuta
   * el callback en cada uno (depth-first traversal).
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
