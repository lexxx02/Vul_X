import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Tests unitarios para VulxCodeActionProvider.
 *
 * Dado que el proveedor depende de la API de VS Code (vscode.Range, vscode.CodeAction,
 * etc.), estos tests validan la LÓGICA de resolución de rango de forma aislada
 * mediante mocks ligeros que simulan las interfaces necesarias.
 *
 * Cubre las 4 estrategias de resolución de Quick Fix:
 *   1. replacementRange — coordenadas precisas del backend
 *   2. Hardcoded secrets — reemplazo de literales entre comillas
 *   3. Inline snippet — coincidencia textual dentro de la línea
 *   4. Full-line fallback — reemplazo de línea completa con indentación
 *
 * Requisito: RF05 — Remediación Asistida de Código.
 */

// ────────────────────────────────────────────────────────────
//  Mocks ligeros para tipos de VS Code
// ────────────────────────────────────────────────────────────

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

interface MockDocument {
  uri: { toString(): string };
  lineCount: number;
  lineAt(index: number): MockLine;
}

interface MockVulnerability {
  id: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  line: number;
  column: number;
  codeSnippet: string;
  recommendation: string;
  remediation?: {
    explanation: string;
    fixedSnippet: string;
    diff: string;
    replacementRange?: {
      startLine: number;
      endLine: number;
      startColumn: number;
      endColumn: number;
    } | undefined;
  } | undefined;
}

// ────────────────────────────────────────────────────────────
//  Funciones de resolución (extraídas de la lógica del provider)
//  para poder testarlas sin dependencia directa de vscode.*
// ────────────────────────────────────────────────────────────

/**
 * Replica la lógica de findMatchingVulnerability del provider.
 */
function findMatchingVulnerability(
  diagnosticCode: string,
  diagnosticStartLine: number,
  vulns: MockVulnerability[]
): MockVulnerability | undefined {
  return vulns.find(
    (v) =>
      v.id === diagnosticCode &&
      Math.abs(v.line - 1 - diagnosticStartLine) <= 1
  );
}

/**
 * Replica la lógica de resolveFromReplacementRange.
 */
function resolveFromReplacementRange(
  doc: MockDocument,
  rr: { startLine: number; endLine: number; startColumn: number; endColumn: number },
  fixedSnippet: string
): { startLine: number; startCol: number; endLine: number; endCol: number; text: string } | null {
  const startLine = rr.startLine - 1;
  const endLine = rr.endLine - 1;

  if (startLine < 0 || endLine < 0 || startLine >= doc.lineCount || endLine >= doc.lineCount) {
    return null;
  }

  const startCol = Math.max(0, rr.startColumn);
  const endCol = Math.max(0, rr.endColumn);

  const originalLine = doc.lineAt(startLine);
  const indent = originalLine.text.match(/^\s*/)?.[0] || '';
  const indentedSnippet = applyIndentation(fixedSnippet, indent);

  return { startLine, startCol, endLine, endCol, text: indentedSnippet };
}

/**
 * Replica la lógica de resolveHardcodedSecretFix.
 */
function resolveHardcodedSecretFix(
  lineText: string,
  fixedSnippet: string
): { startCol: number; endCol: number; text: string } | null {
  const quoteMatch = lineText.match(/(['"])(?:(?!\1).){8,}\1/);
  if (!quoteMatch || typeof quoteMatch.index !== 'number') {
    return null;
  }

  return {
    startCol: quoteMatch.index,
    endCol: quoteMatch.index + quoteMatch[0].length,
    text: fixedSnippet,
  };
}

/**
 * Replica la lógica de resolveInlineSnippetFix.
 */
function resolveInlineSnippetFix(
  lineText: string,
  codeSnippet: string,
  fixedSnippet: string
): { startCol: number; endCol: number; text: string } | null {
  const snippetIdx = lineText.indexOf(codeSnippet);
  if (snippetIdx === -1 || fixedSnippet.includes('\n')) {
    return null;
  }

  return {
    startCol: snippetIdx,
    endCol: snippetIdx + codeSnippet.length,
    text: fixedSnippet,
  };
}

/**
 * Replica la lógica de applyIndentation.
 */
function applyIndentation(snippet: string, indent: string): string {
  return snippet
    .split(/\r?\n/)
    .map((line) => (line.trim().length > 0 ? `${indent}${line.trim()}` : ''))
    .join('\n');
}

// ────────────────────────────────────────────────────────────
//  Fábricas de datos de prueba
// ────────────────────────────────────────────────────────────

function createMockDocument(lines: string[]): MockDocument {
  return {
    uri: { toString: () => 'file:///test/mock.ts' },
    lineCount: lines.length,
    lineAt(index: number): MockLine {
      const text = lines[index] || '';
      return {
        text,
        range: new MockRange(
          new MockPosition(index, 0),
          new MockPosition(index, text.length)
        ),
      };
    },
  };
}

function createXssVulnerability(overrides: Partial<MockVulnerability> = {}): MockVulnerability {
  return {
    id: 'DOM_XSS',
    name: 'Manipulación insegura del DOM (XSS)',
    description: 'Asignación directa a innerHTML detectada.',
    severity: 'high',
    line: 3,
    column: 10,
    codeSnippet: 'container.innerHTML = userInput',
    recommendation: 'Usa textContent en lugar de innerHTML.',
    remediation: {
      explanation: 'Reemplazar innerHTML por textContent para evitar XSS',
      fixedSnippet: 'container.textContent = userInput',
      diff: '- container.innerHTML = userInput\n+ container.textContent = userInput',
      replacementRange: {
        startLine: 3,
        endLine: 3,
        startColumn: 10,
        endColumn: 40,
      },
    },
    ...overrides,
  };
}

function createSecretVulnerability(): MockVulnerability {
  return {
    id: 'HARDCODED_SECRET',
    name: 'Secreto hardcodeado',
    description: 'Se detectó un secreto hardcodeado en el código.',
    severity: 'critical',
    line: 2,
    column: 0,
    codeSnippet: 'const apiKey = "sk-abc123456789def0"',
    recommendation: 'Usa variables de entorno.',
    remediation: {
      explanation: 'Mover secreto a variable de entorno',
      fixedSnippet: 'process.env.API_KEY',
      diff: '- const apiKey = "sk-abc123456789def0"\n+ const apiKey = process.env.API_KEY',
    },
  };
}

function createEvalVulnerability(): MockVulnerability {
  return {
    id: 'EVAL_USAGE',
    name: 'Uso peligroso de eval()',
    description: 'eval() ejecuta código arbitrario.',
    severity: 'critical',
    line: 5,
    column: 4,
    codeSnippet: 'eval(userCode)',
    recommendation: 'Reemplaza eval() por JSON.parse() u otra alternativa segura.',
    remediation: {
      explanation: 'Reemplazar eval por JSON.parse',
      fixedSnippet: 'JSON.parse(userCode)',
      diff: '- eval(userCode)\n+ JSON.parse(userCode)',
    },
  };
}

function createMultilineVulnerability(): MockVulnerability {
  return {
    id: 'DOM_XSS',
    name: 'Manipulación insegura del DOM (XSS)',
    description: 'document.write() inyecta HTML arbitrario.',
    severity: 'high',
    line: 4,
    column: 4,
    codeSnippet: 'document.write("<p>" + data + "</p>")',
    recommendation: 'Usar createElement y textContent.',
    remediation: {
      explanation: 'Reemplazar document.write por createElement',
      fixedSnippet: 'const el = document.createElement("p");\nel.textContent = data;\ndocument.body.appendChild(el);',
      diff: '- document.write("<p>" + data + "</p>")\n+ const el = document.createElement("p");\n+ el.textContent = data;\n+ document.body.appendChild(el);',
      replacementRange: {
        startLine: 4,
        endLine: 4,
        startColumn: 4,
        endColumn: 40,
      },
    },
  };
}

// ────────────────────────────────────────────────────────────
//  Tests
// ────────────────────────────────────────────────────────────

describe('VulxCodeActionProvider — Resolución de Quick Fixes', () => {

  // ── findMatchingVulnerability ──

  describe('findMatchingVulnerability', () => {
    it('debe encontrar la vulnerabilidad por id y línea exacta', () => {
      const vuln = createXssVulnerability();
      const result = findMatchingVulnerability('DOM_XSS', 2, [vuln]);
      assert.ok(result);
      assert.equal(result!.id, 'DOM_XSS');
    });

    it('debe encontrar la vulnerabilidad con tolerancia de ±1 línea', () => {
      const vuln = createXssVulnerability({ line: 4 });
      // diagnosticStartLine = 2 → vuln.line - 1 = 3, diff = 1 → dentro de tolerancia
      const result = findMatchingVulnerability('DOM_XSS', 2, [vuln]);
      assert.ok(result);
    });

    it('debe retornar undefined si el id no coincide', () => {
      const vuln = createXssVulnerability();
      const result = findMatchingVulnerability('SQL_INJECTION', 2, [vuln]);
      assert.equal(result, undefined);
    });

    it('debe retornar undefined si la línea está fuera de tolerancia', () => {
      const vuln = createXssVulnerability({ line: 10 });
      const result = findMatchingVulnerability('DOM_XSS', 2, [vuln]);
      assert.equal(result, undefined);
    });

    it('debe manejar array vacío de vulnerabilidades', () => {
      const result = findMatchingVulnerability('DOM_XSS', 2, []);
      assert.equal(result, undefined);
    });
  });

  // ── Estrategia 1: replacementRange ──

  describe('resolveFromReplacementRange', () => {
    it('debe crear el rango correcto con coordenadas válidas (1-indexed → 0-indexed)', () => {
      const doc = createMockDocument([
        'function render(input) {',
        '  const container = document.getElementById("app");',
        '  container.innerHTML = input;',
        '}',
      ]);

      const result = resolveFromReplacementRange(
        doc,
        { startLine: 3, endLine: 3, startColumn: 2, endColumn: 30 },
        'container.textContent = input;'
      );

      assert.ok(result);
      assert.equal(result!.startLine, 2); // 0-indexed
      assert.equal(result!.endLine, 2);
      assert.equal(result!.startCol, 2);
      assert.equal(result!.endCol, 30);
      assert.ok(result!.text.includes('container.textContent'));
    });

    it('debe retornar null si startLine está fuera del documento', () => {
      const doc = createMockDocument(['línea 0', 'línea 1']);

      const result = resolveFromReplacementRange(
        doc,
        { startLine: 10, endLine: 10, startColumn: 0, endColumn: 5 },
        'fix'
      );

      assert.equal(result, null);
    });

    it('debe retornar null si endLine está fuera del documento', () => {
      const doc = createMockDocument(['línea 0', 'línea 1']);

      const result = resolveFromReplacementRange(
        doc,
        { startLine: 1, endLine: 100, startColumn: 0, endColumn: 5 },
        'fix'
      );

      assert.equal(result, null);
    });

    it('debe preservar la indentación de la línea original', () => {
      const doc = createMockDocument([
        'function f() {',
        '    container.innerHTML = input;',
        '}',
      ]);

      const result = resolveFromReplacementRange(
        doc,
        { startLine: 2, endLine: 2, startColumn: 4, endColumn: 34 },
        'container.textContent = input;'
      );

      assert.ok(result);
      assert.ok(result!.text.startsWith('    ')); // 4 espacios de indentación
    });

    it('debe manejar snippet multilínea con indentación', () => {
      const doc = createMockDocument([
        'function f() {',
        '  document.write(data);',
        '}',
      ]);

      const result = resolveFromReplacementRange(
        doc,
        { startLine: 2, endLine: 2, startColumn: 2, endColumn: 23 },
        'const el = document.createElement("p");\nel.textContent = data;\ndocument.body.appendChild(el);'
      );

      assert.ok(result);
      const lines = result!.text.split('\n');
      assert.equal(lines.length, 3);
      // Todas las líneas deben tener 2 espacios de indentación
      for (const line of lines) {
        if (line.trim().length > 0) {
          assert.ok(line.startsWith('  '), `Línea "${line}" debería iniciar con 2 espacios`);
        }
      }
    });
  });

  // ── Estrategia 2: Secretos hardcodeados ──

  describe('resolveHardcodedSecretFix', () => {
    it('debe localizar el literal de secreto entre comillas dobles', () => {
      const lineText = 'const apiKey = "sk-abc123456789def0";';
      const result = resolveHardcodedSecretFix(lineText, 'process.env.API_KEY');

      assert.ok(result);
      assert.equal(result!.startCol, 15); // posición de la comilla de apertura
      assert.equal(result!.endCol, 36); // posición después de la comilla de cierre
      assert.equal(result!.text, 'process.env.API_KEY');
    });

    it('debe localizar el literal de secreto entre comillas simples', () => {
      const lineText = "const token = 'ghp_xxxxxxxxxxxxxxxxxxxx';";
      const result = resolveHardcodedSecretFix(lineText, 'process.env.GH_TOKEN');

      assert.ok(result);
      assert.equal(result!.text, 'process.env.GH_TOKEN');
    });

    it('debe retornar null si no hay cadena larga entre comillas', () => {
      const lineText = 'const x = "short";';
      const result = resolveHardcodedSecretFix(lineText, 'process.env.X');

      assert.equal(result, null);
    });

    it('debe retornar null si la línea no tiene comillas', () => {
      const lineText = 'const x = 42;';
      const result = resolveHardcodedSecretFix(lineText, 'process.env.X');

      assert.equal(result, null);
    });
  });

  // ── Estrategia 3: Inline snippet ──

  describe('resolveInlineSnippetFix', () => {
    it('debe encontrar y reemplazar el snippet exacto en la línea', () => {
      const lineText = '  container.innerHTML = userInput;';
      const result = resolveInlineSnippetFix(
        lineText,
        'container.innerHTML = userInput',
        'container.textContent = userInput'
      );

      assert.ok(result);
      assert.equal(result!.startCol, 2);
      assert.equal(result!.endCol, 33); // 2 + 31 (longitud de 'container.innerHTML = userInput')
      assert.equal(result!.text, 'container.textContent = userInput');
    });

    it('debe retornar null si el snippet no está en la línea', () => {
      const lineText = '  el.textContent = safeData;';
      const result = resolveInlineSnippetFix(
        lineText,
        'container.innerHTML = userInput',
        'container.textContent = userInput'
      );

      assert.equal(result, null);
    });

    it('debe retornar null si el fixedSnippet es multilínea', () => {
      const lineText = '  document.write(data);';
      const result = resolveInlineSnippetFix(
        lineText,
        'document.write(data)',
        'const el = document.createElement("p");\nel.textContent = data;'
      );

      assert.equal(result, null);
    });

    it('debe funcionar con eval → JSON.parse', () => {
      const lineText = '    const result = eval(userCode);';
      const result = resolveInlineSnippetFix(
        lineText,
        'eval(userCode)',
        'JSON.parse(userCode)'
      );

      assert.ok(result);
      assert.equal(result!.text, 'JSON.parse(userCode)');
      assert.equal(result!.startCol, 19);
      assert.equal(result!.endCol, 33); // 19 + 14
    });
  });

  // ── Estrategia 4: Full-line fallback ──

  describe('applyIndentation', () => {
    it('debe aplicar indentación con espacios a snippet de una línea', () => {
      const result = applyIndentation('container.textContent = input;', '    ');
      assert.equal(result, '    container.textContent = input;');
    });

    it('debe aplicar indentación a snippet multilínea', () => {
      const snippet = 'const el = document.createElement("p");\nel.textContent = data;\ndocument.body.appendChild(el);';
      const result = applyIndentation(snippet, '  ');
      const lines = result.split('\n');

      assert.equal(lines.length, 3);
      assert.equal(lines[0], '  const el = document.createElement("p");');
      assert.equal(lines[1], '  el.textContent = data;');
      assert.equal(lines[2], '  document.body.appendChild(el);');
    });

    it('debe preservar líneas vacías sin indentar', () => {
      const snippet = 'línea 1\n\nlínea 3';
      const result = applyIndentation(snippet, '  ');
      const lines = result.split('\n');

      assert.equal(lines.length, 3);
      assert.equal(lines[0], '  línea 1');
      assert.equal(lines[1], '');
      assert.equal(lines[2], '  línea 3');
    });

    it('debe manejar indentación con tabs', () => {
      const result = applyIndentation('textContent = x;', '\t\t');
      assert.equal(result, '\t\ttextContent = x;');
    });

    it('debe manejar snippet sin indentación (cadena vacía)', () => {
      const result = applyIndentation('x = 1;', '');
      assert.equal(result, 'x = 1;');
    });
  });

  // ── Flujo completo de selección de estrategia ──

  describe('Selección de estrategia de resolución', () => {
    it('debe priorizar replacementRange sobre inline snippet', () => {
      const vuln = createXssVulnerability();
      const doc = createMockDocument([
        'function render(userInput) {',
        '  const container = document.getElementById("app");',
        '  container.innerHTML = userInput;',
        '}',
      ]);

      // Tiene replacementRange → debe usarla (Estrategia 1)
      assert.ok(vuln.remediation?.replacementRange);
      const rrResult = resolveFromReplacementRange(
        doc,
        vuln.remediation!.replacementRange!,
        vuln.remediation!.fixedSnippet
      );
      assert.ok(rrResult, 'replacementRange debe resolver correctamente');

      // Verificar que inline snippet TAMBIÉN funcionaría si no existiera replacementRange
      const inlineResult = resolveInlineSnippetFix(
        doc.lineAt(2).text,
        vuln.codeSnippet,
        vuln.remediation!.fixedSnippet
      );
      assert.ok(inlineResult, 'Inline snippet también coincide');

      // Pero replacementRange tiene prioridad → el texto resuelto puede diferir en indentación
      assert.ok(rrResult!.text.includes('textContent'));
    });

    it('debe usar inline snippet si no hay replacementRange', () => {
      const vuln = createEvalVulnerability();
      const doc = createMockDocument([
        'function run(code) {',
        '  // preparar código',
        '  const x = 1;',
        '  const y = 2;',
        '    eval(userCode);',
        '}',
      ]);

      // Sin replacementRange
      assert.equal(vuln.remediation?.replacementRange, undefined);

      // Inline snippet debe funcionar
      const inlineResult = resolveInlineSnippetFix(
        doc.lineAt(4).text,
        vuln.codeSnippet,
        vuln.remediation!.fixedSnippet
      );
      assert.ok(inlineResult);
      assert.equal(inlineResult!.text, 'JSON.parse(userCode)');
    });

    it('debe usar full-line fallback para snippets multilínea sin replacementRange', () => {
      const vuln = createMultilineVulnerability();
      // Quitar replacementRange para forzar fallback
      delete (vuln.remediation as Record<string, unknown>).replacementRange;

      const doc = createMockDocument([
        'function render(data) {',
        '  // inicio',
        '  // procesamiento',
        '    document.write("<p>" + data + "</p>")',
        '}',
      ]);

      // Sin replacementRange
      assert.equal(vuln.remediation?.replacementRange, undefined);

      // Inline snippet retorna null porque fixedSnippet es multilínea
      const inlineResult = resolveInlineSnippetFix(
        doc.lineAt(3).text,
        vuln.codeSnippet,
        vuln.remediation!.fixedSnippet
      );
      assert.equal(inlineResult, null);

      // Full-line fallback debe funcionar
      const indent = doc.lineAt(3).text.match(/^\s*/)?.[0] || '';
      const indented = applyIndentation(vuln.remediation!.fixedSnippet, indent);
      const lines = indented.split('\n');
      assert.equal(lines.length, 3);
      assert.ok(lines[0] !== undefined && lines[0].startsWith('    ')); // 4 espacios de indentación original
    });

    it('debe manejar secreto hardcodeado correctamente', () => {
      const vuln = createSecretVulnerability();
      const lineText = 'const apiKey = "sk-abc123456789def0";';

      const secretResult = resolveHardcodedSecretFix(
        lineText,
        vuln.remediation!.fixedSnippet
      );
      assert.ok(secretResult);
      assert.equal(secretResult!.text, 'process.env.API_KEY');
    });
  });

  // ── Casos edge ──

  describe('Casos edge y robustez', () => {
    it('debe manejar vulnerabilidad sin remediación (sin fixedSnippet)', () => {
      const vuln = createXssVulnerability({ remediation: undefined });
      assert.equal(vuln.remediation?.fixedSnippet, undefined);

      // findMatchingVulnerability debe encontrarla, pero no debe crear Quick Fix
      const result = findMatchingVulnerability('DOM_XSS', 2, [vuln]);
      assert.ok(result);
      assert.equal(result!.remediation, undefined);
    });

    it('debe manejar documento con una sola línea', () => {
      const doc = createMockDocument(['eval(x);']);

      const result = resolveFromReplacementRange(
        doc,
        { startLine: 1, endLine: 1, startColumn: 0, endColumn: 8 },
        'JSON.parse(x)'
      );

      assert.ok(result);
      assert.equal(result!.startLine, 0);
      assert.equal(result!.endLine, 0);
    });

    it('debe manejar replacementRange con startLine negativo', () => {
      const doc = createMockDocument(['línea 0', 'línea 1']);

      const result = resolveFromReplacementRange(
        doc,
        { startLine: 0, endLine: 1, startColumn: 0, endColumn: 5 },
        'fix'
      );

      // startLine 0 → 0-indexed = -1 → debe retornar null
      assert.equal(result, null);
    });

    it('debe manejar múltiples vulnerabilidades en el mismo archivo', () => {
      const vulns = [
        createXssVulnerability({ line: 3 }),
        createEvalVulnerability(),
        createSecretVulnerability(),
      ];

      const xss = findMatchingVulnerability('DOM_XSS', 2, vulns);
      const evalV = findMatchingVulnerability('EVAL_USAGE', 4, vulns);
      const secret = findMatchingVulnerability('HARDCODED_SECRET', 1, vulns);

      assert.ok(xss);
      assert.ok(evalV);
      assert.ok(secret);
      assert.equal(xss!.id, 'DOM_XSS');
      assert.equal(evalV!.id, 'EVAL_USAGE');
      assert.equal(secret!.id, 'HARDCODED_SECRET');
    });

    it('debe manejar snippet con caracteres especiales de regex', () => {
      const lineText = '  el.innerHTML = data.replace(/</g, "&lt;");';
      // El snippet contiene paréntesis y barras — indexOf funciona bien, no usa regex
      const codeSnippet = 'data.replace(/</g, "&lt;")';

      const result = resolveInlineSnippetFix(
        lineText,
        codeSnippet,
        'DOMPurify.sanitize(data)'
      );

      assert.ok(result);
      assert.equal(result!.text, 'DOMPurify.sanitize(data)');
    });
  });
});
