import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

process.env.NODE_ENV = 'test';

import { server } from '../src/server.js';

describe('SwaggerService — Documentación Interactiva OpenAPI en Vivo', () => {
  it('GET /docs/openapi.yaml debe retornar la especificación YAML con content-type correcto', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/docs/openapi.yaml',
    });

    assert.equal(response.statusCode, 200);
    assert.ok(response.headers['content-type']?.includes('yaml'));
    assert.ok(response.body.includes('openapi: 3.0.3'));
    assert.ok(response.body.includes('title: VulX Security Analysis API'));
    assert.ok(response.body.includes('/analyze:'));
  });

  it('GET /documentation debe servir la interfaz HTML de Swagger UI', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/documentation',
    });

    assert.equal(response.statusCode, 200);
    assert.ok(response.headers['content-type']?.includes('html'));
    assert.ok(response.body.includes('SwaggerUIBundle'));
    assert.ok(response.body.includes('/docs/openapi.yaml'));
    assert.ok(response.body.includes('VulX Security API'));
  });

  it('GET /docs debe responder de forma idéntica a /documentation como alias directo', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/docs',
    });

    assert.equal(response.statusCode, 200);
    assert.ok(response.headers['content-type']?.includes('html'));
    assert.ok(response.body.includes('id="swagger-ui"'));
  });

  it('GET /docs/scalar debe servir la interfaz interactiva de Scalar Reference', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/docs/scalar',
    });

    assert.equal(response.statusCode, 200);
    assert.ok(response.headers['content-type']?.includes('html'));
    assert.ok(response.body.includes('@scalar/api-reference'));
    assert.ok(response.body.includes('data-url="/docs/openapi.yaml"'));
  });
});

