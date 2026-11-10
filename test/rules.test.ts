/**
 * test/rules.test.ts
 *
 * Suite de pruebas unitarias para las 6 reglas determinísticas del motor AST de VulX.
 *
 * Cada regla se evalúa de forma aislada con snippets mínimos de código para verificar:
 *   - True Positives:  el código vulnerable es detectado con id, severity y línea correctos.
 *   - False Positives: el código seguro equivalente NO genera alertas (vulnerabilities.length === 0).
 *
 * Compatible con:
 *   - tsx --test (node:test y node:assert/strict)
 *   - TypeScript strict mode con noUncheckedIndexedAccess
 *   - ECMAScript Modules (ESM)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { createAnalysisContext } from '../core/parser.js';
import { SQLiRule } from '../core/rules/definitions/SQLiRule.js';
import { DomXssRule } from '../core/rules/definitions/DomXssRule.js';
import { SecretRule } from '../core/rules/definitions/SecretRule.js';
import { CommandInjectionRule } from '../core/rules/definitions/CommandInjectionRule.js';
import { PathTraversalRule } from '../core/rules/definitions/PathTraversalRule.js';
import { EvalUsageRule } from '../core/rules/definitions/EvalUsageRule.js';

// ─────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────

/** Construye un AnalysisContext a partir de un snippet JS para evaluar una regla. */
function ctxJS(code: string) {
  return createAnalysisContext(code, 'javascript');
}

/** Construye un AnalysisContext a partir de un snippet TS para evaluar una regla. */
function ctxTS(code: string) {
  return createAnalysisContext(code, 'typescript');
}

// ═════════════════════════════════════════════════════════════
//  1. SQLiRule  (CWE-89 - Inyección SQL) — severity: critical
// ═════════════════════════════════════════════════════════════

describe('SQLiRule (CWE-89)', () => {
  const rule = new SQLiRule();

  // ── True Positives (Casos Positivos) ──

  it('detecta concatenacion con operador + en sentencia SQL', () => {
    const code = `const q = "SELECT * FROM users WHERE id = " + userId;`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar al menos una vulnerabilidad');
    const first = vulns[0];
    assert.ok(first, 'La primera vulnerabilidad debe existir');
    assert.equal(first.id, 'SQL_INJECTION');
    assert.equal(first.severity, 'critical');
    assert.equal(first.line, 1);
  });

  it('detecta template literal con interpolacion SQL', () => {
    const code = 'const q = `SELECT * FROM users WHERE name = ${userName}`;';
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar template literal inseguro');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'SQL_INJECTION');
    assert.equal(first.severity, 'critical');
  });

  it('detecta db.query() con argumento dinamico', () => {
    const code = `db.query(userQuery);`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar argumento dinamico en query()');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'SQL_INJECTION');
    assert.equal(first.severity, 'critical');
  });

  // ── False Positives (Control de Negativos) ──

  it('NO alerta con consulta parametrizada (placeholder ?)', () => {
    const code = `db.query("SELECT * FROM users WHERE id = ?", [userId]);`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.equal(vulns.length, 0, 'Consulta parametrizada no debe generar alerta');
  });

  it('NO alerta con string literal estatico en query()', () => {
    const code = `db.query("SELECT 1");`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.equal(vulns.length, 0, 'Query con string estatico no debe alertar');
  });
});

// ═════════════════════════════════════════════════════════════
//  2. DomXssRule  (CWE-79 - DOM XSS) — severity: high
// ═════════════════════════════════════════════════════════════

describe('DomXssRule (CWE-79)', () => {
  const rule = new DomXssRule();

  // ── True Positives (Casos Positivos) ──

  it('detecta asignacion a innerHTML', () => {
    const code = `container.innerHTML = userInput;`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar innerHTML inseguro');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'DOM_XSS');
    assert.equal(first.severity, 'high');
    assert.equal(first.line, 1);
  });

  it('detecta asignacion a outerHTML', () => {
    const code = `element.outerHTML = payload;`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar outerHTML inseguro');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'DOM_XSS');
    assert.equal(first.severity, 'high');
  });

  it('detecta document.write()', () => {
    const code = `document.write(userContent);`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar document.write()');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'DOM_XSS');
    assert.equal(first.severity, 'high');
  });

  it('detecta insertAdjacentHTML()', () => {
    const code = `element.insertAdjacentHTML('beforeend', htmlString);`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar insertAdjacentHTML()');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'DOM_XSS');
    assert.equal(first.severity, 'high');
  });

  // ── False Positives (Control de Negativos) ──

  it('NO alerta con textContent (seguro)', () => {
    const code = `container.textContent = userInput;`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.equal(vulns.length, 0, 'textContent es seguro, no debe alertar');
  });

  it('NO alerta con innerText (seguro)', () => {
    const code = `element.innerText = data;`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.equal(vulns.length, 0, 'innerText es seguro, no debe alertar');
  });
});

// ═════════════════════════════════════════════════════════════
//  3. SecretRule  (CWE-798 - Secretos Hardcodeados)
// ═════════════════════════════════════════════════════════════

describe('SecretRule (CWE-798)', () => {
  const rule = new SecretRule();

  // ── True Positives (Casos Positivos) ──

  it('detecta AWS Access Key ID (patron AKIA...)', () => {
    const code = `const awsKey = "AKIAIOSFODNN7EXAMPLE";`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar AWS Access Key');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'HARDCODED_SECRET');
    assert.equal(first.severity, 'high');
  });

  it('detecta JWT hardcodeado (patron eyJ...)', () => {
    const code = `const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar JWT');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'HARDCODED_SECRET');
  });

  it('detecta Stripe secret key (patron sk_test_...)', () => {
    // Se construye dinámicamente para no disparar GitHub Secret Push Protection
    const dummyStripe = ['sk', 'test', 'abcdefghijklmnopqrstuvwx'].join('_');
    const code = `const stripe = "${dummyStripe}";`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar Stripe key');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'HARDCODED_SECRET');
  });

  it('detecta variable con nombre sospechoso (password)', () => {
    const code = `const password = "SuperSecret123!";`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar password hardcodeada');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'HARDCODED_SECRET');
  });

  // ── False Positives (Control de Negativos) ──

  it('NO alerta con variable de entorno process.env', () => {
    const code = `const apiKey = process.env.API_KEY;`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.equal(vulns.length, 0, 'process.env no debe generar alerta');
  });

  it('NO alerta con placeholder "your-api-key-here"', () => {
    const code = `const token = "your-api-key-here";`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.equal(vulns.length, 0, 'Placeholder no debe generar alerta');
  });
});

// ═════════════════════════════════════════════════════════════
//  4. CommandInjectionRule  (CWE-78 - Inyección de Comandos)
// ═════════════════════════════════════════════════════════════

describe('CommandInjectionRule (CWE-78)', () => {
  const rule = new CommandInjectionRule();

  // ── True Positives (Casos Positivos) ──

  it('detecta exec() con concatenacion de cadenas', () => {
    const code = `exec("ping " + host);`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar concatenacion en exec()');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'COMMAND_INJECTION');
    assert.equal(first.severity, 'critical');
    assert.equal(first.line, 1);
  });

  it('detecta execSync() con template literal interpolado', () => {
    const code = 'execSync(`ls ${directory}`);';
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar template literal en execSync()');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'COMMAND_INJECTION');
    assert.equal(first.severity, 'critical');
  });

  it('detecta spawn() con argumento dinamico', () => {
    const code = `spawn(userCommand);`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar argumento dinamico en spawn()');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'COMMAND_INJECTION');
    assert.equal(first.severity, 'critical');
  });

  // ── False Positives (Control de Negativos) ──

  it('NO alerta con exec() y string literal estatico', () => {
    const code = `exec("ls -la");`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.equal(vulns.length, 0, 'Comando estatico no debe alertar');
  });

  it('NO alerta con template literal sin interpolacion', () => {
    const code = 'exec(`echo hello`);';
    const vulns = rule.evaluate(ctxJS(code));

    assert.equal(vulns.length, 0, 'Template sin interpolacion no debe alertar');
  });
});

// ═════════════════════════════════════════════════════════════
//  5. PathTraversalRule  (CWE-22 - Path Traversal)
// ═════════════════════════════════════════════════════════════

describe('PathTraversalRule (CWE-22)', () => {
  const rule = new PathTraversalRule();

  // ── True Positives (Casos Positivos) ──

  it('detecta fs.readFileSync() con concatenacion de ruta', () => {
    const code = `fs.readFileSync("/var/data/" + userInput);`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar concatenacion en readFileSync()');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'PATH_TRAVERSAL');
    assert.equal(first.severity, 'high');
    assert.equal(first.line, 1);
  });

  it('detecta fs.readFile() con variable dinamica directa', () => {
    const code = `fs.readFile(filePath, callback);`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar variable dinamica en readFile()');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'PATH_TRAVERSAL');
    assert.equal(first.severity, 'high');
  });

  it('detecta writeFile() con template literal interpolado', () => {
    const code = 'fs.writeFile(`uploads/${fileName}`, data);';
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar template literal en writeFile()');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'PATH_TRAVERSAL');
    assert.equal(first.severity, 'high');
  });

  // ── False Positives (Control de Negativos) ──

  it('NO alerta con ruta estatica literal', () => {
    const code = `fs.readFileSync("./config.json");`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.equal(vulns.length, 0, 'Ruta estatica no debe alertar');
  });

  it('NO alerta con template literal sin interpolacion', () => {
    const code = 'fs.readFileSync(`data/file.txt`);';
    const vulns = rule.evaluate(ctxJS(code));

    assert.equal(vulns.length, 0, 'Template sin interpolacion no debe alertar');
  });
});

// ═════════════════════════════════════════════════════════════
//  6. EvalUsageRule  (CWE-95 - Uso peligroso de eval)
// ═════════════════════════════════════════════════════════════

describe('EvalUsageRule (CWE-95)', () => {
  const rule = new EvalUsageRule();

  // ── True Positives (Casos Positivos) ──

  it('detecta eval() con variable', () => {
    const code = `eval(userInput);`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'Debe detectar eval()');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'EVAL_USAGE');
    assert.equal(first.severity, 'critical');
    assert.equal(first.line, 1);
  });

  it('detecta eval() con string literal (aun es peligroso)', () => {
    const code = `eval("console.log('hacked')");`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.ok(vulns.length > 0, 'eval() con literal tambien debe alertar');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'EVAL_USAGE');
    assert.equal(first.severity, 'critical');
  });

  it('detecta eval() en TypeScript', () => {
    const code = `const result: string = eval(formula);`;
    const vulns = rule.evaluate(ctxTS(code));

    assert.ok(vulns.length > 0, 'Debe detectar eval() en TypeScript');
    const first = vulns[0];
    assert.ok(first);
    assert.equal(first.id, 'EVAL_USAGE');
    assert.equal(first.severity, 'critical');
  });

  // ── False Positives (Control de Negativos) ──

  it('NO alerta con JSON.parse() (alternativa segura)', () => {
    const code = `const data = JSON.parse(jsonString);`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.equal(vulns.length, 0, 'JSON.parse() no debe alertar');
  });

  it('NO alerta con parseInt() (alternativa segura)', () => {
    const code = `const num = parseInt(value, 10);`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.equal(vulns.length, 0, 'parseInt() no debe alertar');
  });

  it('NO alerta con funciones que contienen "eval" en su nombre', () => {
    const code = `evaluate(expression);`;
    const vulns = rule.evaluate(ctxJS(code));

    assert.equal(vulns.length, 0, 'evaluate() no es eval(), no debe alertar');
  });
});

// ═════════════════════════════════════════════════════════════
//  7. Pruebas transversales — Compatibilidad de lenguaje
// ═════════════════════════════════════════════════════════════

describe('Compatibilidad de lenguaje (JS y TS)', () => {
  it('SQLiRule detecta vulnerabilidades en TypeScript', () => {
    const rule = new SQLiRule();
    const code = `const q: string = "SELECT * FROM users WHERE id = " + id;`;
    const vulns = rule.evaluate(ctxTS(code));

    assert.ok(vulns.length > 0, 'SQLiRule debe funcionar en TypeScript');
  });

  it('DomXssRule detecta innerHTML en TypeScript', () => {
    const rule = new DomXssRule();
    const code = `(el as HTMLElement).innerHTML = payload;`;
    const vulns = rule.evaluate(ctxTS(code));

    assert.ok(vulns.length > 0, 'DomXssRule debe funcionar en TypeScript');
  });

  it('CommandInjectionRule detecta exec en TypeScript', () => {
    const rule = new CommandInjectionRule();
    const code = `exec("ping " + host);`;
    const vulns = rule.evaluate(ctxTS(code));

    assert.ok(vulns.length > 0, 'CommandInjectionRule debe funcionar en TypeScript');
  });
});
