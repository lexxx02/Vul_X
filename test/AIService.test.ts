import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { AIService } from '../src/services/AIService.js';
import type { Vulnerability } from '../core/rules/SecurityRule.js';

// Configurar entorno de pruebas antes de importar el servidor (usa timeout reducido para Ollama)
process.env.NODE_ENV = 'test';

import { server } from '../src/server.js';

describe('AIService — Remediación y Generación de Diffs', () => {
  const dummyVuln: Vulnerability = {
    id: 'DOM_XSS',
    name: 'Manipulación Insegura del DOM',
    description: 'Asignación directa a innerHTML',
    severity: 'high',
    line: 5,
    column: 4,
    codeSnippet: 'container.innerHTML = userInput;',
    recommendation: 'Usar textContent'
  };

  const dummySource = `
function render(userInput) {
  const container = document.getElementById("content");
  if (container) {
    container.innerHTML = userInput;
  }
}
  `;

  it('generatePrompt debe incluir los metadatos de la vulnerabilidad y formato JSON', () => {
    const service = new AIService();
    const prompt = service.generatePrompt(dummyVuln, dummySource);

    // Datos de la vulnerabilidad presentes en el prompt de usuario
    assert.ok(prompt.includes('DOM_XSS'), 'Debe incluir el ID de la regla');
    assert.ok(prompt.includes('container.innerHTML = userInput;'), 'Debe incluir el snippet vulnerable');
    assert.ok(prompt.includes('Usar textContent'), 'Debe incluir la recomendación de la regla');
    assert.ok(prompt.includes('Corrige la vulnerabilidad'), 'Debe incluir la instrucción de cierre');
  });

  it('calculateReplacementRange debe calcular coordenadas precisas para snippets de una línea', () => {
    const service = new AIService();
    const range = service.calculateReplacementRange(dummyVuln, dummySource);

    assert.equal(range.startLine, 5);
    assert.equal(range.endLine, 5);
    assert.equal(range.startColumn, 4);
    assert.equal(range.endColumn, 4 + dummyVuln.codeSnippet.length);
  });

  it('calculateReplacementRange debe calcular coordenadas para snippets multilínea', () => {
    const service = new AIService();
    const multiLineVuln: Vulnerability = {
      ...dummyVuln,
      line: 10,
      column: 2,
      codeSnippet: 'const q = "SELECT * FROM users " +\n  "WHERE id = " + id;'
    };

    const range = service.calculateReplacementRange(multiLineVuln, dummySource);
    assert.equal(range.startLine, 10);
    assert.equal(range.endLine, 11);
    assert.equal(range.startColumn, 2);
    assert.equal(range.endColumn, '  "WHERE id = " + id;'.length);
  });

  it('generateDiff debe generar un diff unificado estilo Git con marcas - y +', () => {
    const service = new AIService();
    const original = 'container.innerHTML = userInput;';
    const fixed = 'container.textContent = userInput;';

    const diff = service.generateDiff(original, fixed, 5);

    assert.ok(diff.includes('@@ -5,1 +5,1 @@'));
    assert.ok(diff.includes('- container.innerHTML = userInput;'));
    assert.ok(diff.includes('+ container.textContent = userInput;'));
  });

  it('parseAIResponse debe parsear respuestas JSON estrictas', () => {
    const service = new AIService();
    const raw = JSON.stringify({
      fixedSnippet: 'container.textContent = userInput;',
      explanation: 'Uso seguro de textContent'
    });

    const parsed = service.parseAIResponse(raw, dummyVuln);
    assert.equal(parsed.fixedSnippet, 'container.textContent = userInput;');
    assert.equal(parsed.explanation, 'Uso seguro de textContent');
  });

  it('parseAIResponse debe extraer JSON envuelto en bloques markdown ```json ... ```', () => {
    const service = new AIService();
    const raw = `
Aquí está la solución recomendada:
\`\`\`json
{
  "fixedSnippet": "container.textContent = userInput;",
  "explanation": "Elimina el riesgo de XSS reemplazando innerHTML"
}
\`\`\`
Espero que ayude.
    `;

    const parsed = service.parseAIResponse(raw, dummyVuln);
    assert.equal(parsed.fixedSnippet, 'container.textContent = userInput;');
    assert.ok(parsed.explanation.includes('Elimina el riesgo de XSS'));
  });

  it('getHeuristicRemediation debe proveer remediación determinística para cada tipo de vulnerabilidad', () => {
    const service = new AIService();

    // DOM_XSS con innerHTML
    const xssRemediation = service.getHeuristicRemediation(dummyVuln);
    assert.equal(xssRemediation.fixedSnippet, 'container.textContent = userInput;');

    // SQL_INJECTION
    const sqliVuln: Vulnerability = {
      ...dummyVuln,
      id: 'SQL_INJECTION',
      codeSnippet: 'client.query("SELECT * FROM t WHERE id = " + id);'
    };
    const sqliRemediation = service.getHeuristicRemediation(sqliVuln);
    assert.ok(sqliRemediation.fixedSnippet.includes('parametrizada'));

    // HARDCODED_SECRET
    const secretVuln: Vulnerability = {
      ...dummyVuln,
      id: 'HARDCODED_SECRET',
      codeSnippet: 'const token = "AKIAIOSFODNN7EXAMPLE";'
    };
    const secretRemediation = service.getHeuristicRemediation(secretVuln);
    assert.ok(secretRemediation.fixedSnippet.includes('process.env.SECRET_TOKEN'));

    // EVAL_USAGE
    const evalVuln: Vulnerability = {
      ...dummyVuln,
      id: 'EVAL_USAGE',
      codeSnippet: 'eval(userInput)'
    };
    const evalRemediation = service.getHeuristicRemediation(evalVuln);
    assert.ok(evalRemediation.fixedSnippet.includes('JSON.parse(userInput)'));
  });

  it('remediate debe retornar la vulnerabilidad enriquecida con el objeto remediation completo', async () => {
    // Simulamos un proveedor de inferencia que responde con un JSON válido
    const mockInference = async (_prompt: string) => {
      return JSON.stringify({
        fixedSnippet: 'container.textContent = sanitize(userInput);',
        explanation: 'Sanitización estricta antes de renderizar'
      });
    };

    const service = new AIService({ inferenceProvider: mockInference });
    const result = await service.remediate(dummyVuln, dummySource);

    assert.ok(result.remediation);
    assert.equal(result.remediation.fixedSnippet, 'container.textContent = sanitize(userInput);');
    assert.equal(result.remediation.explanation, 'Sanitización estricta antes de renderizar');
    assert.ok(result.remediation.diff.includes('- container.innerHTML = userInput;'));
    assert.ok(result.remediation.diff.includes('+ container.textContent = sanitize(userInput);'));
    assert.equal(result.remediation.replacementRange.startLine, 5);
  });

  it('remediateAll debe procesar múltiples vulnerabilidades y tolerar caídas de IA con fallback', async () => {
    // Proveedor que falla para probar el fallback resiliente
    const failingInference = async () => {
      throw new Error('Connection refused to Ollama');
    };

    const service = new AIService({ inferenceProvider: failingInference });
    const list = [
      dummyVuln,
      { ...dummyVuln, id: 'EVAL_USAGE', codeSnippet: 'eval(code);' }
    ];

    const results = await service.remediateAll(list, dummySource);

    assert.equal(results.length, 2);
    assert.ok(results[0]?.remediation);
    assert.ok(results[1]?.remediation);
    assert.ok(results[0].remediation.fixedSnippet.includes('textContent'));
    assert.ok(results[1].remediation.fixedSnippet.includes('JSON.parse'));
  });

  it('POST /analyze debe incluir remediaciones completas en el payload de respuesta', async () => {
    const payload = {
      code: `
        function update(input) {
          const el = document.getElementById("demo");
          el.innerHTML = input;
        }
      `,
      language: 'javascript'
    };

    const response = await server.inject({
      method: 'POST',
      url: '/analyze',
      payload
    });

    assert.equal(response.statusCode, 200);
    const body = JSON.parse(response.body);

    assert.equal(body.status, 'success');
    assert.ok(body.analysis.vulnerabilities.length > 0);

    const vuln = body.analysis.vulnerabilities[0];
    assert.ok(vuln.remediation, 'Debe incluir el objeto remediation');
    assert.ok(typeof vuln.remediation.explanation === 'string');
    assert.ok(typeof vuln.remediation.fixedSnippet === 'string');
    assert.ok(typeof vuln.remediation.diff === 'string');
    assert.ok(vuln.remediation.replacementRange);
    assert.equal(typeof vuln.remediation.replacementRange.startLine, 'number');
    assert.equal(typeof vuln.remediation.replacementRange.endLine, 'number');
  });

  it('POST /analyze con includeRemediation: false debe omitir la remediación', async () => {
    const payload = {
      code: `document.body.innerHTML = malicious;`,
      language: 'javascript',
      includeRemediation: false
    };

    const response = await server.inject({
      method: 'POST',
      url: '/analyze',
      payload
    });

    assert.equal(response.statusCode, 200);
    const body = JSON.parse(response.body);
    const vuln = body.analysis.vulnerabilities[0];
    assert.equal(vuln.remediation, undefined);
  });
});
