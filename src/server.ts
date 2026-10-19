import Fastify, {
  type FastifyInstance,
  type FastifyRequest,
  type FastifyReply
} from 'fastify';
import { createAnalyzer, Analyzer } from '../core/Analyzer.js';


export const server: FastifyInstance = Fastify({
  logger: process.env.NODE_ENV === 'test' ? false : true
});

export const analyzer: Analyzer = createAnalyzer(
  process.env.NODE_ENV === 'test' ? { timeoutMs: 3_000 } : undefined
);

// Accesores de compatibilidad (usados por /rules y tests existentes)
export const ruleEngine = analyzer.getRuleEngine();
export const aiService = analyzer.getAIService();

// GET /health
server.get('/health', async (request: FastifyRequest, reply: FastifyReply) => {
  return { status: 'ok', timestamp: new Date().toISOString() };
});

// GET /rules - Lista las reglas de seguridad registradas en el RuleEngine
server.get('/rules', async (request: FastifyRequest, reply: FastifyReply) => {
  return {
    status: 'success',
    count: ruleEngine.getRuleCount(),
    rules: ruleEngine.getRegisteredRules()
  };
});

// Schema formal para POST /analyze y /api/v1/analyze
const analyzeBodySchema = {
  type: 'object',
  required: ['code'],
  properties: {
    code: { type: 'string', minLength: 1 },
    language: { type: 'string' },
    filePath: { type: 'string' },
    includeRemediation: { type: 'boolean', default: true },
    deepScan: { type: 'boolean', default: false }
  }
};


const analyzeResponseSchema = {
  200: {
    type: 'object',
    properties: {
      status: { type: 'string' },
      message: { type: 'string' },
      analysis: {
        type: 'object',
        properties: {
          vulnerabilities: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: { type: 'string' },
                name: { type: 'string' },
                description: { type: 'string' },
                severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
                line: { type: 'number' },
                column: { type: 'number' },
                codeSnippet: { type: 'string' },
                recommendation: { type: 'string' },
                remediation: {
                  type: 'object',
                  properties: {
                    explanation: { type: 'string' },
                    fixedSnippet: { type: 'string' },
                    diff: { type: 'string' },
                    replacementRange: {
                      type: 'object',
                      properties: {
                        startLine: { type: 'number' },
                        endLine: { type: 'number' },
                        startColumn: { type: 'number' },
                        endColumn: { type: 'number' }
                      }
                    }
                  }
                }
              }
            }
          },
          summary: {
            type: 'object',
            properties: {
              total: { type: 'number' },
              critical: { type: 'number' },
              high: { type: 'number' },
              medium: { type: 'number' },
              low: { type: 'number' },
              durationMs: { type: 'number' }
            }
          }
        }
      }
    }
  }
};

interface AnalyzeBody {
  code: string;
  language?: string;
  filePath?: string;
  includeRemediation?: boolean;
  deepScan?: boolean;
}

const analyzeHandler = async (
  request: FastifyRequest<{ Body: AnalyzeBody }>,
  reply: FastifyReply
) => {
  const { code, language, filePath, includeRemediation, deepScan } = request.body;

  server.log.info(
    { language: language || 'auto', filePath, deepScan: !!deepScan },
    'Ejecutando análisis híbrido (AST + IA) con Analyzer'
  );

  // Delegar el pipeline completo al Analyzer (Parser → RuleEngine → AIService)
  const result = await analyzer.analyze({
    code,
    language,
    filePath,
    includeRemediation,
    deepScan,
  });


  server.log.info(
    { total: result.summary.total, durationMs: result.summary.durationMs },
    'Análisis completado'
  );

  return reply.code(200).send({
    status: 'success',
    message:
      result.vulnerabilities.length > 0
        ? `Análisis completado: se detectaron ${result.vulnerabilities.length} vulnerabilidad(es)`
        : 'Análisis completado: no se detectaron vulnerabilidades',
    analysis: result,
  });
};

const analyzeRouteConfig = {
  schema: {
    body: analyzeBodySchema,
    response: analyzeResponseSchema
  }
};

// Endpoint principal especificado en arquitectura y requerimientos (/analyze)
server.post<{ Body: AnalyzeBody }>('/analyze', analyzeRouteConfig, analyzeHandler);

// Endpoint versionado (/api/v1/analyze)
server.post<{ Body: AnalyzeBody }>('/api/v1/analyze', analyzeRouteConfig, analyzeHandler);

// Iniciar servidor
export const start = async () => {
  try {
    const port = process.env.PORT ? parseInt(process.env.PORT) : 3000;
    await server.listen({ port, host: '0.0.0.0' });
    console.log(`Servidor de VulX escuchando en http://localhost:${port}`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
};

import { fileURLToPath } from 'node:url';

// Iniciar servidor únicamente si este archivo se ejecuta directamente (no cuando se importa en pruebas)
const isDirectRun =
  process.argv[1] &&
  fileURLToPath(import.meta.url).replace(/\\/g, '/').toLowerCase() ===
    process.argv[1].replace(/\\/g, '/').toLowerCase();

if (isDirectRun) {
  start();
}

