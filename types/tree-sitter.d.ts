/**
 * Declaraciones de tipo para tree-sitter y tree-sitter-javascript.
 *
 * tree-sitter es una librería nativa (escrita en C) que no incluye
 * sus propias definiciones de TypeScript. Este archivo le dice
 * al compilador de TypeScript cómo son las clases y métodos
 * que expone tree-sitter.
 */

declare module 'tree-sitter' {
  export interface SyntaxNode {
    type: string;
    text: string;
    startPosition: { row: number; column: number };
    endPosition: { row: number; column: number };
    childCount: number;
    children: SyntaxNode[];
    parent: SyntaxNode | null;
    child(index: number): SyntaxNode | null;
    childForFieldName(fieldName: string): SyntaxNode | null;
    namedChildren: SyntaxNode[];
    namedChild(index: number): SyntaxNode | null;
    descendantsOfType(type: string): SyntaxNode[];
  }

  export interface Tree {
    rootNode: SyntaxNode;
  }

  export interface Language {}

  export default class Parser {
    setLanguage(language: Language): void;
    parse(input: string): Tree;
  }
}

declare module 'tree-sitter-javascript' {
  import type { Language } from 'tree-sitter';
  const language: Language;
  export default language;
}

declare module 'tree-sitter-typescript' {
  import type { Language } from 'tree-sitter';
  const typescript: Language;
  const tsx: Language;
  export { typescript, tsx };
}
