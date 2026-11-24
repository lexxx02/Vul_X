import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Registra la interfaz interactiva de Swagger UI y Scalar para la API REST de VulX.
 *
 * Características:
 * 1. `GET /docs/openapi.yaml` - Sirve el archivo formal OpenAPI 3.0.3 en formato YAML crudo.
 * 2. `GET /docs` o `GET /documentation` - Renderiza la interfaz interactiva de Swagger UI con soporte "Try it out" en vivo.
 * 3. `GET /docs/scalar` - Renderiza la moderna interfaz interactiva de Scalar API Reference.
 *
 * Funciona de manera 100% nativa sin requerir plugins pesados adicionales en Fastify,
 * leyendo directamente la especificación centralizada en `Docs/api-spec.yaml`.
 */
export function registerSwaggerDocumentation(server: FastifyInstance): void {
  const specPath = path.resolve(__dirname, '../../Docs/api-spec.yaml');

  // Cargar especificación YAML una sola vez en memoria
  let yamlContent = '';
  try {
    if (fs.existsSync(specPath)) {
      yamlContent = fs.readFileSync(specPath, 'utf8');
    }
  } catch (err) {
    server.log.warn({ err }, 'No se pudo leer Docs/api-spec.yaml en el inicio');
  }

  // 1. Endpoint para servir el archivo YAML crudo
  server.get('/docs/openapi.yaml', async (_request: FastifyRequest, reply: FastifyReply) => {
    if (!yamlContent) {
      if (fs.existsSync(specPath)) {
        yamlContent = fs.readFileSync(specPath, 'utf8');
      } else {
        return reply.code(404).send({ error: 'Especificación api-spec.yaml no encontrada' });
      }
    }

    return reply
      .header('Content-Type', 'text/yaml; charset=utf-8')
      .header('Access-Control-Allow-Origin', '*')
      .send(yamlContent);
  });

  // 2. Endpoint Swagger UI Interactivo (HTML oficial standalone con CDN y soporte offline)
  const renderSwaggerUI = (_request: FastifyRequest, reply: FastifyReply) => {
    const html = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>VulX Security API — Swagger UI Interactivo</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.18.2/swagger-ui.css" />
  <link rel="icon" type="image/png" href="https://unpkg.com/swagger-ui-dist@5.18.2/favicon-32x32.png" sizes="32x32" />
  <style>
    html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin: 0; background: #fafafa; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    .topbar { background-color: #0f172a !important; padding: 10px 0; border-bottom: 2px solid #3b82f6; }
    .topbar .wrapper .topbar-wrapper { display: flex; align-items: center; justify-content: space-between; }
    .topbar-wrapper img { display: none; }
    .vulx-brand { color: #fff; font-size: 1.25rem; font-weight: 700; text-decoration: none; display: flex; align-items: center; gap: 8px; }
    .vulx-badge { background: #2563eb; color: #fff; font-size: 0.75rem; padding: 2px 8px; border-radius: 9999px; }
    .vulx-links { display: flex; gap: 12px; }
    .vulx-link { color: #93c5fd; text-decoration: none; font-size: 0.875rem; font-weight: 500; }
    .vulx-link:hover { color: #ffffff; text-decoration: underline; }
    .swagger-ui .info .title { font-size: 2rem; color: #0f172a; }
  </style>
</head>
<body>
  <div class="topbar">
    <div class="wrapper">
      <div class="topbar-wrapper">
        <a class="vulx-brand" href="/documentation">
          <span>🛡️ VulX Security API</span>
          <span class="vulx-badge">OpenAPI 3.0.3</span>
        </a>
        <div class="vulx-links">
          <a class="vulx-link" href="/dashboard" style="color: #60a5fa; font-weight: 700;">⚡ Live Dashboard</a>
          <a class="vulx-link" href="/docs/scalar">Vista Scalar Reference</a>
          <a class="vulx-link" href="/docs/openapi.yaml" target="_blank">Descargar YAML</a>
          <a class="vulx-link" href="/health" target="_blank">Health Check</a>
        </div>
      </div>
    </div>
  </div>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.18.2/swagger-ui-bundle.js" charset="UTF-8"></script>
  <script src="https://unpkg.com/swagger-ui-dist@5.18.2/swagger-ui-standalone-preset.js" charset="UTF-8"></script>
  <script>
    window.onload = function() {
      window.ui = SwaggerUIBundle({
        url: "/docs/openapi.yaml",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "BaseLayout",
        displayRequestDuration: true,
        docExpansion: "list",
        filter: true,
        showExtensions: true,
        showCommonExtensions: true,
        defaultModelsExpandDepth: 2,
        defaultModelExpandDepth: 2,
      });
    };
  </script>
</body>
</html>`;

    return reply
      .header('Content-Type', 'text/html; charset=utf-8')
      .send(html);
  };

  server.get('/documentation', renderSwaggerUI);
  server.get('/docs', renderSwaggerUI);

  // 3. Endpoint Scalar API Reference (Visualizador moderno de última generación)
  server.get('/docs/scalar', async (_request: FastifyRequest, reply: FastifyReply) => {
    const html = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>VulX Security API — Scalar Reference</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
  <script
    id="api-reference"
    data-url="/docs/openapi.yaml"
    data-proxy-url="https://proxy.scalar.com"
  ></script>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>`;

    return reply
      .header('Content-Type', 'text/html; charset=utf-8')
      .send(html);
  });
}

