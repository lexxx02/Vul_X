import Fastify, { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

const server: FastifyInstance = Fastify({
  logger: true
});

// GET /health
server.get('/health', async (request: FastifyRequest, reply: FastifyReply) => {
  return { status: 'ok', timestamp: new Date().toISOString() };
});

// Schema formal para POST /api/v1/analyze
const analyzeBodySchema = {
  type: 'object',
  required: ['code'],
  properties: {
    code: { type: 'string', minLength: 1 },
    language: { type: 'string' },
    filePath: { type: 'string' }
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
                description: { type: 'string' },
                severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
                line: { type: 'number' }
              }
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
}

// POST /api/v1/analyze
server.post<{ Body: AnalyzeBody }>(
  '/api/v1/analyze',
  {
    schema: {
      body: analyzeBodySchema,
      response: analyzeResponseSchema
    }
  },
  async (request, reply) => {
    const { code, language, filePath } = request.body;

    // Aquí irá la lógica de integración con Tree-sitter y Ollama
    server.log.info(`Analizando código en lenguaje: ${language || 'desconocido'}`);

    // Respuesta mock para el contrato
    return {
      status: 'success',
      message: 'Análisis completado (Mock)',
      analysis: {
        vulnerabilities: []
      }
    };
  }
);

// Iniciar servidor
const start = async () => {
  try {
    const port = process.env.PORT ? parseInt(process.env.PORT) : 3000;
    await server.listen({ port, host: '0.0.0.0' });
    console.log(`Servidor de VulX escuchando en http://localhost:${port}`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
};

start();
