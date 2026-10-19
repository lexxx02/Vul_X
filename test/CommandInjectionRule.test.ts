import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { CommandInjectionRule } from '../core/rules/definitions/CommandInjectionRule.js';
import { createAnalysisContext } from '../core/parser.js';

describe('CommandInjectionRule - Detección de Inyección de Comandos (CWE-78)', () => {
  const rule = new CommandInjectionRule();

  it('debe tener las propiedades base de la regla correctamente configuradas', () => {
    assert.equal(rule.id, 'COMMAND_INJECTION');
    assert.equal(rule.severity, 'critical');
    assert.ok(rule.supportedLanguages.includes('javascript'));
    assert.ok(rule.supportedLanguages.includes('typescript'));
  });

  it('debe detectar concatenación con operador + en exec()', () => {
    const code = `
      const { exec } = require('child_process');
      function pingHost(host) {
        exec("ping -c 1 " + host, (err, stdout) => {
          console.log(stdout);
        });
      }
    `;
    const context = createAnalysisContext(code, 'javascript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.id, 'COMMAND_INJECTION');
    assert.equal(findings[0]?.severity, 'critical');
    assert.equal(findings[0]?.line, 4);
    assert.ok(findings[0]?.codeSnippet.includes('exec('));
    assert.ok(findings[0]?.description.includes('operador "+"'));
    assert.ok(findings[0]?.recommendation.includes('execFile'));
  });

  it('debe detectar template literals con interpolación en execSync()', () => {
    const code = `
      import { execSync } from 'child_process';
      function backup(folderName) {
        execSync(\`tar -czf backup.tar.gz \${folderName}\`);
      }
    `;
    const context = createAnalysisContext(code, 'typescript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.id, 'COMMAND_INJECTION');
    assert.equal(findings[0]?.severity, 'critical');
    assert.equal(findings[0]?.line, 4);
    assert.ok(findings[0]?.description.includes('template literal'));
  });

  it('debe detectar paso de variable dinámica directamente a exec()', () => {
    const code = `
      const cp = require('child_process');
      function runUserScript(userCommand) {
        cp.exec(userCommand);
      }
    `;
    const context = createAnalysisContext(code, 'javascript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.line, 4);
    assert.ok(findings[0]?.description.includes('argumento dinámico'));
  });

  it('NO debe reportar comandos estáticos literales seguros', () => {
    const code = `
      const { exec } = require('child_process');
      exec("ls -la");
      exec('git status');
      exec(\`whoami\`);
    `;
    const context = createAnalysisContext(code, 'javascript');
    const findings = rule.evaluate(context);

    assert.equal(findings.length, 0);
  });
});
