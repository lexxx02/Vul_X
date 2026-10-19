import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Configurar entorno de pruebas para evitar iniciar el listener de red
process.env.NODE_ENV = 'test';

import { server } from '../src/server.js';

describe('Server & Endpoints - Conexión de RuleEngine con /analyze', () => {
  it('GET /health debe retornar estado ok', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/health'
    });

    assert.equal(response.statusCode, 200);
    const body = JSON.parse(response.body);
    assert.equal(body.status, 'ok');
    assert.ok(body.timestamp);
  });

  it('GET /rules debe listar las reglas activas (EVAL_USAGE y DOM_XSS)', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/rules'
    });

    assert.equal(response.statusCode, 200);
    const body = JSON.parse(response.body);
    assert.equal(body.status, 'success');
    assert.ok(body.count >= 2);
    const ruleIds = body.rules.map((r: { id: string }) => r.id);
    assert.ok(ruleIds.includes('DOM_XSS'));
    assert.ok(ruleIds.includes('EVAL_USAGE'));
  });

  it('POST /analyze debe detectar vulnerabilidades de manipulación insegura del DOM (XSS)', async () => {
    const payload = {
      code: `
        function render(userInput) {
          const container = document.getElementById("content");
          container.innerHTML = userInput;
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

    const xssFinding = body.analysis.vulnerabilities[0];
    assert.equal(xssFinding.id, 'DOM_XSS');
    assert.equal(xssFinding.severity, 'high');
    assert.equal(xssFinding.line, 4);
    assert.ok(xssFinding.codeSnippet.includes('container.innerHTML = userInput'));
    assert.ok(xssFinding.recommendation.length > 0);

    assert.equal(body.analysis.summary.total, 1);
    assert.equal(body.analysis.summary.high, 1);
  });

  it('POST /analyze debe detectar múltiples vulnerabilidades combinadas (DOM XSS + eval)', async () => {
    const payload = {
      code: `
        eval("2 + 2");
        document.write("<p>" + user + "</p>");
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
    assert.equal(body.analysis.vulnerabilities.length, 2);

    const ids = body.analysis.vulnerabilities.map((v: { id: string }) => v.id);
    assert.ok(ids.includes('EVAL_USAGE'));
    assert.ok(ids.includes('DOM_XSS'));

    assert.equal(body.analysis.summary.total, 2);
    assert.equal(body.analysis.summary.critical, 1);
    assert.equal(body.analysis.summary.high, 1);
  });

  it('POST /analyze debe retornar 0 vulnerabilidades para código seguro', async () => {
    const payload = {
      code: `
        function displaySafe(text) {
          const el = document.getElementById("label");
          el.textContent = text;
          console.log(text);
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
    assert.equal(body.analysis.vulnerabilities.length, 0);
    assert.equal(body.analysis.summary.total, 0);
  });

  it('POST /api/v1/analyze debe funcionar idénticamente por compatibilidad de ruta', async () => {
    const payload = {
      code: 'document.body.outerHTML = evilPayload;',
      language: 'javascript'
    };

    const response = await server.inject({
      method: 'POST',
      url: '/api/v1/analyze',
      payload
    });

    assert.equal(response.statusCode, 200);
    const body = JSON.parse(response.body);

    assert.equal(body.status, 'success');
    assert.equal(body.analysis.vulnerabilities.length, 1);
    assert.equal(body.analysis.vulnerabilities[0].id, 'DOM_XSS');
  });

  it('POST /analyze debe soportar archivos TypeScript mediante filePath', async () => {
    const payload = {
      code: `
        interface Props { html: string; }
        const update = (p: Props): void => {
          document.getElementById('view')!.innerHTML = p.html;
        };
      `,
      filePath: 'src/components/View.ts'
    };

    const response = await server.inject({
      method: 'POST',
      url: '/analyze',
      payload
    });

    assert.equal(response.statusCode, 200);
    const body = JSON.parse(response.body);

    assert.equal(body.status, 'success');
    assert.equal(body.analysis.vulnerabilities.length, 1);
    assert.equal(body.analysis.vulnerabilities[0].id, 'DOM_XSS');
  });

  it('POST /analyze debe fallar con 400 si falta el campo obligatorio "code"', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/analyze',
      payload: {
        language: 'javascript'
      }
    });

    assert.equal(response.statusCode, 400);
  });

  it('POST /analyze debe detectar vulnerabilidades de Command Injection', async () => {
    const payload = {
      code: `
        const { exec } = require('child_process');
        function run(userCmd) {
          exec("ping -c 1 " + userCmd);
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
    assert.ok(body.analysis.vulnerabilities.some((v: { id: string }) => v.id === 'COMMAND_INJECTION'));
    assert.equal(body.analysis.summary.critical, 1);
  });

  it('POST /analyze debe detectar vulnerabilidades de Path Traversal', async () => {
    const payload = {
      code: `
        const fs = require('fs');
        function serveFile(name) {
          return fs.readFileSync('/var/data/' + name, 'utf8');
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
    assert.ok(body.analysis.vulnerabilities.some((v: { id: string }) => v.id === 'PATH_TRAVERSAL'));
    assert.equal(body.analysis.summary.high, 1);
  });

  it('POST /analyze con deepScan: true debe responder 200 y procesar el pipeline sin errores', async () => {
    const payload = {
      code: `
        const a = 1;
        const b = 2;
        console.log(a + b);
      `,
      language: 'javascript',
      deepScan: true
    };

    const response = await server.inject({
      method: 'POST',
      url: '/analyze',
      payload
    });

    assert.equal(response.statusCode, 200);
    const body = JSON.parse(response.body);
    assert.equal(body.status, 'success');
    assert.ok(body.analysis);
    assert.ok(Array.isArray(body.analysis.vulnerabilities));
  });
});

