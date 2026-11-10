import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Tests unitarios para VulxDiffInspector y VulxDiffContentProvider.
 *
 * Valida la lógica de construcción de documentos corregidos virtuales
 * respetando las 4 estrategias de resolución de VulX (replacementRange,
 * secretos hardcodeados, inline snippet, y reemplazo de línea completa con indentación).
 */

class MockPosition {
  constructor(public readonly line: number, public readonly character: number) {}
}

class MockRange {
  public readonly start: MockPosition;
  public readonly end: MockPosition;
  constructor(start: MockPosition, end: MockPosition) {
    this.start = start;
    this.end = end;
  }
}

interface MockLine {
  text: string;
  range: MockRange;
}

interface MockTextDocument {
  getText(): string;
  lineCount: number;
  lineAt(line: number): MockLine;
  offsetAt(position: MockPosition): number;
}

function createMockTextDocument(content: string): MockTextDocument {
  const lines = content.split(/\r?\n/);
  return {
    getText(): string {
      return content;
    },
    lineCount: lines.length,
    lineAt(lineIndex: number): MockLine {
      const lineText = lines[lineIndex] ?? '';
      return {
        text: lineText,
        range: new MockRange(
          new MockPosition(lineIndex, 0),
          new MockPosition(lineIndex, lineText.length)
        ),
      };
    },
    offsetAt(position: MockPosition): number {
      let offset = 0;
      for (let i = 0; i < position.line; i++) {
        offset += (lines[i]?.length ?? 0) + 1; // +1 por newline (\n)
      }
      return offset + position.character;
    },
  };
}

// Implementación de referencia aislada de buildPatchedDocument
function buildPatchedDocument(
  doc: MockTextDocument,
  vuln: {
    id: string;
    line: number;
    codeSnippet: string;
    remediation?: {
      explanation: string;
      fixedSnippet: string;
      diff: string;
      replacementRange?: {
        startLine: number;
        endLine: number;
        startColumn: number;
        endColumn: number;
      };
    };
  }
): string {
  const remediation = vuln.remediation;
  if (!remediation) {
    return doc.getText();
  }

  const rr = remediation.replacementRange;

  // Caso 1: replacementRange
  if (
    rr &&
    rr.startLine - 1 >= 0 &&
    rr.endLine - 1 < doc.lineCount &&
    rr.startLine <= rr.endLine
  ) {
    const startLine = rr.startLine - 1;
    const endLine = rr.endLine - 1;
    const originalLine = doc.lineAt(startLine);
    const indent = originalLine.text.match(/^\s*/)?.[0] || '';
    const indented = remediation.fixedSnippet
      .split(/\r?\n/)
      .map((l) => (l.trim().length > 0 ? `${indent}${l.trim()}` : ''))
      .join('\n');

    const startOffset = doc.offsetAt(new MockPosition(startLine, Math.max(0, rr.startColumn)));
    const endOffset = doc.offsetAt(new MockPosition(endLine, Math.max(0, rr.endColumn)));

    return doc.getText().substring(0, startOffset) + indented + doc.getText().substring(endOffset);
  }

  // Caso 2: Secreto hardcodeado
  const lineIndex = Math.min(Math.max(0, vuln.line - 1), doc.lineCount - 1);
  const targetLine = doc.lineAt(lineIndex);
  const lineText = targetLine.text;

  if (vuln.id === 'HARDCODED_SECRET') {
    const quoteMatch = lineText.match(/(['"])(?:(?!\1).){8,}\1/);
    if (quoteMatch && typeof quoteMatch.index === 'number') {
      const startOffset = doc.offsetAt(new MockPosition(lineIndex, quoteMatch.index));
      const endOffset = startOffset + quoteMatch[0].length;
      return doc.getText().substring(0, startOffset) + remediation.fixedSnippet + doc.getText().substring(endOffset);
    }
  }

  // Caso 3: Inline snippet match
  const snippetIdx = lineText.indexOf(vuln.codeSnippet);
  if (snippetIdx !== -1 && !remediation.fixedSnippet.includes('\n')) {
    const startOffset = doc.offsetAt(new MockPosition(lineIndex, snippetIdx));
    const endOffset = startOffset + vuln.codeSnippet.length;
    return doc.getText().substring(0, startOffset) + remediation.fixedSnippet + doc.getText().substring(endOffset);
  }

  // Caso 4: Reemplazo de línea completa
  const indent = lineText.match(/^\s*/)?.[0] || '';
  const indented = remediation.fixedSnippet
    .split(/\r?\n/)
    .map((l) => (l.trim().length > 0 ? `${indent}${l.trim()}` : ''))
    .join('\n');
  const startOffset = doc.offsetAt(targetLine.range.start);
  const endOffset = doc.offsetAt(targetLine.range.end);
  return doc.getText().substring(0, startOffset) + indented + doc.getText().substring(endOffset);
}

describe('VulxDiffInspector — Generación de documento corregido virtual', () => {
  it('debe generar documento con reemplazo de DOM XSS usando replacementRange', () => {
    const source = 'function render(bio) {\n  container.innerHTML = bio;\n}';
    const doc = createMockTextDocument(source);

    const patched = buildPatchedDocument(doc, {
      id: 'DOM_XSS',
      line: 2,
      codeSnippet: 'container.innerHTML = bio;',
      remediation: {
        explanation: 'Reemplazar innerHTML por textContent',
        fixedSnippet: 'container.textContent = bio;',
        diff: '- container.innerHTML = bio;\n+ container.textContent = bio;',
        replacementRange: {
          startLine: 2,
          endLine: 2,
          startColumn: 2,
          endColumn: 28,
        },
      },
    });

    assert.ok(patched.includes('container.textContent = bio;'));
    assert.ok(!patched.includes('container.innerHTML'));
  });

  it('debe reemplazar únicamente el secreto literal manteniendo la variable', () => {
    const source = 'const API_KEY = "AKIA1234567890ABCDEF";';
    const doc = createMockTextDocument(source);

    const patched = buildPatchedDocument(doc, {
      id: 'HARDCODED_SECRET',
      line: 1,
      codeSnippet: 'const API_KEY = "AKIA1234567890ABCDEF";',
      remediation: {
        explanation: 'Extraer a variable de entorno',
        fixedSnippet: 'process.env.AWS_ACCESS_KEY',
        diff: '- "AKIA1234567890ABCDEF"\n+ process.env.AWS_ACCESS_KEY',
      },
    });

    assert.equal(patched, 'const API_KEY = process.env.AWS_ACCESS_KEY;');
  });

  it('debe reemplazar inline snippet de eval por JSON.parse', () => {
    const source = 'function calc(formula) {\n  return eval(formula);\n}';
    const doc = createMockTextDocument(source);

    const patched = buildPatchedDocument(doc, {
      id: 'EVAL_USAGE',
      line: 2,
      codeSnippet: 'eval(formula)',
      remediation: {
        explanation: 'Reemplazar eval por JSON.parse',
        fixedSnippet: 'JSON.parse(formula)',
        diff: '- eval(formula)\n+ JSON.parse(formula)',
      },
    });

    assert.ok(patched.includes('return JSON.parse(formula);'));
  });

  it('debe retornar el texto original si no hay objeto remediation', () => {
    const source = 'console.log("hola mundo");';
    const doc = createMockTextDocument(source);

    const patched = buildPatchedDocument(doc, {
      id: 'UNKNOWN',
      line: 1,
      codeSnippet: 'console.log',
    });

    assert.equal(patched, source);
  });
});
