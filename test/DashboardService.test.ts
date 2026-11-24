import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

process.env.NODE_ENV = 'test';

import { server } from '../src/server.js';

describe('DashboardService — VulX Live Security Dashboard & HTML Reports', () => {
  it('GET /dashboard debe retornar la interfaz web interactiva con HTTP 200 y Content-Type text/html', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/dashboard'
    });

    assert.equal(response.statusCode, 200);
    assert.ok(response.headers['content-type']?.includes('html'), 'Content-Type debe incluir html');
    assert.ok(response.body.includes('VulX'), 'Body debe contener VulX');
    assert.ok(response.body.includes('Security Audit Dashboard') || response.body.includes('Live Security'), 'Body debe contener el título del dashboard');
    assert.ok(response.body.includes('runLiveScan'), 'Body debe contener la función de análisis en vivo');
    assert.ok(response.body.includes('SQL Injection') || response.body.includes('sqli'), 'Body debe contener escenarios de demostración');
  });

  it('GET /report debe redirigir a /dashboard (código 302)', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/report'
    });

    assert.equal(response.statusCode, 302);
    assert.equal(response.headers['location'], '/dashboard');
  });

  it('POST /report/html debe generar un reporte ejecutivo autónomo con código vulnerable', async () => {
    const payload = {
      code: `
        function queryUser(userId) {
          const sql = "SELECT * FROM users WHERE id = " + userId;
          db.query(sql);
        }
      `,
      language: 'javascript',
      filePath: 'src/userRepository.js'
    };

    const response = await server.inject({
      method: 'POST',
      url: '/report/html',
      payload
    });

    assert.equal(response.statusCode, 200);
    assert.ok(response.headers['content-type']?.includes('text/html'));
    assert.ok(response.headers['content-disposition']?.includes('vulx-audit-report.html'));
    assert.ok(response.body.includes('Informe de Seguridad SAST'));
    assert.ok(response.body.includes('src/userRepository.js'));
    assert.ok(response.body.includes('Detalle de Hallazgos'));
    assert.ok(response.body.includes('SQL_INJECTION') || response.body.includes('Inyección SQL'));
  });

  it('POST /report/html debe retornar 400 Bad Request si no se proporciona el código', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/report/html',
      payload: {
        language: 'javascript'
      }
    });

    assert.equal(response.statusCode, 400);
    const body = JSON.parse(response.body);
    assert.equal(body.error, 'Bad Request');
  });
});
