import type { SyntaxNode } from 'tree-sitter';

/**
 * Representa una vulnerabilidad detectada por una regla de seguridad.
 *
 * Cada vez que un evaluador encuentra un problema en el código,
 * genera un objeto con esta forma para que la API pueda
 * informarle al usuario exactamente qué está mal y cómo arreglarlo.
 */
export interface Vulnerability {
  /** Identificador único de la regla que detectó el problema (ej: "SQL_INJECTION") */
  id: string;

  /** Nombre corto y legible de la vulnerabilidad */
  name: string;

  /** Explicación clara de por qué este código es inseguro */
  description: string;

  /** Nivel de peligrosidad */
  severity: 'low' | 'medium' | 'high' | 'critical';

  /** Número de línea donde se encontró el problema (1-indexed) */
  line: number;

  /** Columna donde empieza el código vulnerable */
  column: number;

  /** Fragmento exacto del código fuente que disparó la alerta */
  codeSnippet: string;

  /** Sugerencia de corrección generada por la regla o por la IA */
  recommendation: string;
}

/**
 * Contexto que recibe cada regla al momento de evaluar.
 *
 * Contiene toda la información que una regla necesita para
 * inspeccionar el código: el texto original, el árbol sintáctico
 * generado por Tree-sitter y el lenguaje del archivo.
 */
export interface AnalysisContext {
  /** Código fuente completo del archivo */
  sourceCode: string;

  /** Nodo raíz del AST generado por Tree-sitter */
  rootNode: SyntaxNode;

  /** Lenguaje del archivo (ej: "javascript", "typescript") */
  language: string;

  /** Ruta del archivo analizado (opcional) */
  filePath?: string;
}

/**
 * Clase abstracta SecurityRule — El contrato que toda regla debe cumplir.
 *
 * Cada evaluador de seguridad (inyección SQL, XSS, eval inseguro, etc.)
 * hereda de esta clase e implementa su propia lógica de detección
 * en el método `evaluate()`.
 *
 * Esto permite agregar nuevas reglas sin tocar el código existente
 * (principio Open/Closed de SOLID).
 */
export abstract class SecurityRule {
  /** Identificador único de la regla (ej: "EVAL_USAGE") */
  abstract readonly id: string;

  /** Nombre legible (ej: "Uso peligroso de eval()") */
  abstract readonly name: string;

  /** Descripción de qué busca esta regla */
  abstract readonly description: string;

  /** Severidad por defecto de las vulnerabilidades que detecta */
  abstract readonly severity: 'low' | 'medium' | 'high' | 'critical';

  /** Lenguajes compatibles con esta regla (ej: ["javascript", "typescript"]) */
  abstract readonly supportedLanguages: string[];

  /**
   * Determina si esta regla aplica para el lenguaje del archivo.
   */
  supportsLanguage(language: string): boolean {
    return this.supportedLanguages.includes(language.toLowerCase());
  }

  /**
   * Método principal de evaluación.
   *
   * Cada regla concreta implementa aquí su lógica de detección.
   * Recibe el contexto completo (código + AST + lenguaje) y
   * devuelve un arreglo de vulnerabilidades encontradas.
   *
   * @param context - Contexto del análisis (código fuente, AST, lenguaje)
   * @returns Lista de vulnerabilidades detectadas (vacía si no hay problemas)
   */
  abstract evaluate(context: AnalysisContext): Vulnerability[];
}
