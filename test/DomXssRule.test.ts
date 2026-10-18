import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { DomXssRule } from '../core/rules/definitions/DomXssRule.js';
import { createAnalysisContext } from '../core/parser.js';

describe('DomXssRule - Detección de Manipulación Insegura del DOM (XSS)', () => {
  const rule = new DomXssRule();

  it('debe tener las propiedades base de la regla correctamente configuradas', () => {
    assert.equal(rule.id, 'DOM_XSS');
    assert.equal(rule.severity, 'high');
    assert.ok(rule.supportedLanguages.includes('javascript'));
    assert.ok(rule.supportedLanguages.includes('typescript'));
  });

  it('debe detectar asignación directa a innerHTML', () => {
    const code = `
      const target = document.getElementById('target');
      target.innerHTML = userInput;
    `;
    const context = createAnalysisContext(code, 'javascript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.id, 'DOM_XSS');
    assert.equal(findings[0]?.severity, 'high');
    assert.equal(findings[0]?.line, 3);
    assert.ok(findings[0]?.codeSnippet.includes('target.innerHTML = userInput'));
    assert.ok(findings[0]?.recommendation.includes('textContent'));
  });

  it('debe detectar asignación acumulativa (+=) a innerHTML', () => {
    const code = `
      element.innerHTML += '<p>' + dynamicData + '</p>';
    `;
    const context = createAnalysisContext(code, 'javascript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.line, 2);
    assert.ok(findings[0]?.codeSnippet.includes('element.innerHTML +='));
  });

  it('debe detectar asignación a outerHTML', () => {
    const code = `
      document.querySelector('.card').outerHTML = payload;
    `;
    const context = createAnalysisContext(code, 'javascript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 1);
    assert.ok(findings[0]?.description.includes('outerHTML'));
  });

  it('debe detectar acceso a innerHTML mediante notación de corchetes', () => {
    const code = `
      const el = document.body;
      el['innerHTML'] = untrustedData;
    `;
    const context = createAnalysisContext(code, 'javascript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 1);
    assert.ok(findings[0]?.codeSnippet.includes("el['innerHTML'] = untrustedData"));
  });

  it('debe detectar invocación a document.write()', () => {
    const code = `
      document.write(untrustedHtml);
    `;
    const context = createAnalysisContext(code, 'javascript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.line, 2);
    assert.ok(findings[0]?.description.includes('document.write()'));
  });

  it('debe detectar invocación a document.writeln() y window.document.write()', () => {
    const code = `
      document.writeln(data1);
      window.document.write(data2);
    `;
    const context = createAnalysisContext(code, 'javascript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 2);
  });

  it('debe detectar uso inseguro de insertAdjacentHTML()', () => {
    const code = `
      container.insertAdjacentHTML('beforeend', userComment);
    `;
    const context = createAnalysisContext(code, 'javascript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 1);
    assert.ok(findings[0]?.description.includes('insertAdjacentHTML'));
  });

  it('debe funcionar con código TypeScript con tipado estricto', () => {
    const tsCode = `
      const container: HTMLElement = document.getElementById('app')!;
      const userInput: string = window.location.hash;
      container.innerHTML = userInput;
    `;
    const context = createAnalysisContext(tsCode, 'typescript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.line, 4);
  });

  it('NO debe reportar falsos positivos en operaciones seguras del DOM', () => {
    const safeCode = `
      const el = document.getElementById('msg');
      el.textContent = userInput;
      el.innerText = safeText;
      console.log(el.innerHTML);
      const currentContent = el.innerHTML;
    `;
    const context = createAnalysisContext(safeCode, 'javascript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 0);
  });
});
