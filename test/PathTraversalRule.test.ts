import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PathTraversalRule } from '../core/rules/definitions/PathTraversalRule.js';
import { createAnalysisContext } from '../core/parser.js';

describe('PathTraversalRule - Detección de Path Traversal (CWE-22)', () => {
  const rule = new PathTraversalRule();

  it('debe tener las propiedades base de la regla correctamente configuradas', () => {
    assert.equal(rule.id, 'PATH_TRAVERSAL');
    assert.equal(rule.severity, 'high');
    assert.ok(rule.supportedLanguages.includes('javascript'));
    assert.ok(rule.supportedLanguages.includes('typescript'));
  });

  it('debe detectar concatenación con operador + en fs.readFile()', () => {
    const code = `
      const fs = require('fs');
      function getFile(userPath) {
        fs.readFile('/var/www/uploads/' + userPath, 'utf8', (err, data) => {
          console.log(data);
        });
      }
    `;
    const context = createAnalysisContext(code, 'javascript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.id, 'PATH_TRAVERSAL');
    assert.equal(findings[0]?.severity, 'high');
    assert.equal(findings[0]?.line, 4);
    assert.ok(findings[0]?.description.includes('operador "+"'));
    assert.ok(findings[0]?.recommendation.includes('path.resolve'));
  });

  it('debe detectar template literals con interpolación en fs.readFileSync()', () => {
    const code = `
      import fs from 'fs';
      function readProfile(username: string) {
        return fs.readFileSync(\`profiles/\${username}.json\`, 'utf-8');
      }
    `;
    const context = createAnalysisContext(code, 'typescript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.id, 'PATH_TRAVERSAL');
    assert.equal(findings[0]?.line, 4);
    assert.ok(findings[0]?.description.includes('template literal'));
  });

  it('debe detectar path.join() con segmentos dinámicos no validados', () => {
    const code = `
      const fs = require('fs');
      const path = require('path');
      function loadReport(reportName) {
        const fullPath = path.join(__dirname, 'reports', reportName);
        fs.createReadStream(fullPath);
      }
    `;
    const context = createAnalysisContext(code, 'javascript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.id, 'PATH_TRAVERSAL');
    assert.equal(findings[0]?.line, 6);
  });

  it('NO debe reportar lecturas de archivos estáticas seguras', () => {
    const code = `
      const fs = require('fs');
      const data = fs.readFileSync('./package.json', 'utf8');
      fs.readFileSync(\`config.json\`);
    `;
    const context = createAnalysisContext(code, 'javascript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 0);
  });
});
