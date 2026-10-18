import Parser, { type Tree, type SyntaxNode } from 'tree-sitter';
import JavaScript from 'tree-sitter-javascript';
import tsModule from 'tree-sitter-typescript';
import type { AnalysisContext } from './rules/SecurityRule.js';

/**
 * Normaliza el identificador de lenguaje a partir del nombre o la extensión del archivo.
 */
export function normalizeLanguage(language?: string, filePath?: string): string {
  if (language) {
    const lang = language.toLowerCase().trim();
    if (lang === 'ts' || lang === 'typescript' || lang === 'tsx') return 'typescript';
    if (lang === 'js' || lang === 'javascript' || lang === 'jsx') return 'javascript';
    return lang;
  }
  if (filePath) {
    const lower = filePath.toLowerCase();
    if (lower.endsWith('.ts') || lower.endsWith('.tsx')) return 'typescript';
    if (
      lower.endsWith('.js') ||
      lower.endsWith('.jsx') ||
      lower.endsWith('.mjs') ||
      lower.endsWith('.cjs')
    ) {
      return 'javascript';
    }
  }
  return 'javascript';
}

/**
 * Parsea un fragmento o archivo de código fuente con Tree-sitter.
 */
export function parseSourceCode(
  sourceCode: string,
  language = 'javascript'
): { tree: Tree; rootNode: SyntaxNode; language: string } {
  const normLang = normalizeLanguage(language);
  const parser = new Parser();

  if (normLang === 'typescript') {
    const tsLang = tsModule.typescript || tsModule;
    parser.setLanguage(tsLang);
  } else {
    parser.setLanguage(JavaScript);
  }

  const tree = parser.parse(sourceCode);
  return {
    tree,
    rootNode: tree.rootNode,
    language: normLang
  };
}

/**
 * Construye un AnalysisContext listo para ser evaluado por el RuleEngine.
 */
export function createAnalysisContext(
  sourceCode: string,
  language?: string,
  filePath?: string
): AnalysisContext {
  const normLang = normalizeLanguage(language, filePath);
  const { rootNode } = parseSourceCode(sourceCode, normLang);

  const context: AnalysisContext = {
    sourceCode,
    rootNode,
    language: normLang
  };

  if (filePath) {
    context.filePath = filePath;
  }

  return context;
}

// Compatibilidad con ejecución directa de demostración: npx tsx core/parser.ts
const isMainScript =
  process.argv[1] &&
  (process.argv[1].endsWith('parser.ts') || process.argv[1].endsWith('parser.js'));

if (isMainScript) {
  const sourceCode = 'const saludo = "Hola VulX"; console.log(saludo);';
  const { rootNode } = parseSourceCode(sourceCode, 'javascript');

  console.log('✅ AST generado con éxito.');
  console.log('Tipo de nodo raíz:', rootNode.type);
  console.log('Cantidad de nodos hijos:', rootNode.childCount);
}