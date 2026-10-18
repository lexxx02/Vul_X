import Fastify, {
  type FastifyInstance,
  type FastifyRequest,
  type FastifyReply
} from 'fastify';
import { createDefaultRuleEngine, type RuleEngine } from '../core/rules/index.js';
import { createAnalysisContext } from '../core/parser.js';
import { AIService } from './services/AIService.js';


export const server: FastifyInstance = Fastify({
  logger: process.env.NODE_ENV === 'test' ? false : true
});

export const ruleEngine: RuleEngine = createDefaultRuleEngine();
export const aiService: AIService = new AIService();

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
    includeRemediation: { type: 'boolean', default: true }
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
              low: { type: 'number' }
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
}

const analyzeHandler = async (
  request: FastifyRequest<{ Body: AnalyzeBody }>,
  reply: FastifyReply
) => {
  const { code, language, filePath, includeRemediation } = request.body;

  server.log.info(
    { language: language || 'auto', filePath },
    'Ejecutando análisis determinístico con RuleEngine y remediación con AIService'
  );

  // 1. Parsear el código con Tree-sitter y construir el AnalysisContext
  const context = createAnalysisContext(code, language, filePath);

  // 2. Ejecutar el RuleEngine con las reglas AST registradas
  const rawVulnerabilities = ruleEngine.analyze(context);

  // 3. Generar respuestas de remediación completas con AIService si está activo
  const shouldRemediate = includeRemediation !== false;
  const vulnerabilities = shouldRemediate && rawVulnerabilities.length > 0
    ? await aiService.remediateAll(rawVulnerabilities, code)
    : rawVulnerabilities;

  const summary = {
    total: vulnerabilities.length,
    critical: vulnerabilities.filter((v) => v.severity === 'critical').length,
    high: vulnerabilities.filter((v) => v.severity === 'high').length,
    medium: vulnerabilities.filter((v) => v.severity === 'medium').length,
    low: vulnerabilities.filter((v) => v.severity === 'low').length
  };

  return reply.code(200).send({
    status: 'success',
    message:
      vulnerabilities.length > 0
        ? `Análisis completado: se detectaron ${vulnerabilities.length} vulnerabilidad(es)`
        : 'Análisis completado: no se detectaron vulnerabilidades',
    analysis: {
      vulnerabilities,
      summary
    }
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

