import type { Vulnerability, Remediation, ReplacementRange } from '../../core/rules/SecurityRule.js';

/**
 * Opciones de configuración para inicializar AIService
 */
export interface AIServiceOptions {
  /** URL base de la API de Ollama (por defecto: http://127.0.0.1:11434) */
  ollamaUrl?: string;
  /** Nombre del modelo de IA local (por defecto: qwen2.5-coder:7b) */
  model?: string;
  /** Tiempo límite en ms para la llamada a la IA antes de usar fallback (por defecto: 60000ms) */
  timeoutMs?: number;
  /** Proveedor personalizado de inferencia (útil para inyección de mocks en pruebas) */
  inferenceProvider?: (prompt: string) => Promise<string>;
}

/**
 * Respuesta estructurada esperada de la IA para una remediación
 */
export interface AIRemediationPayload {
  fixedSnippet: string;
  explanation: string;
}

/**
 * AIService — Servicio de Inteligencia Artificial y Remediación de Código.
 *
 * Responsabilidades:
 * 1. Generar prompts especializados para remediación segura.
 * 2. Consultar al motor de inferencia local (Ollama / Qwen 2.5 Coder 7B) con respuestas en JSON estricto.
 * 3. Limpiar y validar el código devuelto por la IA.
 * 4. Calcular el diff unificado estilo Git (- y +).
 * 5. Determinar las coordenadas exactas de reemplazo (ReplacementRange) para acciones de Quick Fix en el IDE.
 * 6. Proveer mecanismos de fallback heurísticos de alta velocidad cuando Ollama no esté disponible.
 */
export class AIService {
  private readonly ollamaUrl: string;
  private readonly model: string;
  private readonly timeoutMs: number;
  private readonly inferenceProvider?: ((prompt: string) => Promise<string>) | undefined;

  constructor(options: AIServiceOptions = {}) {
    this.ollamaUrl = options.ollamaUrl || process.env.OLLAMA_URL || 'http://127.0.0.1:11434';
    this.model = options.model || process.env.OLLAMA_MODEL || 'qwen2.5-coder:7b';
    this.timeoutMs = options.timeoutMs ?? 60_000;
    this.inferenceProvider = options.inferenceProvider;
  }

  /**
   * System prompt estricto enviado a Ollama en el campo `system`.
   * Obliga al modelo a responder ÚNICAMENTE con JSON válido.
   */
  private readonly SYSTEM_PROMPT = [
    'Eres un asistente experto en seguridad de código para la herramienta SAST "VulX".',
    'Tu ÚNICA función es analizar fragmentos de código vulnerables y devolver la corrección.',
    '',
    'REGLAS INQUEBRANTABLES:',
    '1. Responde EXCLUSIVAMENTE con un objeto JSON válido. SIN texto antes ni después del JSON.',
    '2. NO uses bloques markdown (```), NO escribas explicaciones fuera del JSON, NO saludes.',
    '3. El JSON debe tener EXACTAMENTE dos campos:',
    '   - "fixedSnippet": string → El fragmento de código corregido que reemplaza al vulnerable.',
    '   - "explanation": string → Explicación técnica breve de la corrección aplicada.',
    '4. El "fixedSnippet" debe ser un reemplazo drop-in exacto del fragmento vulnerable.',
    '5. Aplica las mejores prácticas de seguridad (OWASP, CWE) para la corrección.',
    '',
    'Ejemplo de respuesta CORRECTA:',
    '{"fixedSnippet": "elemento.textContent = userInput;", "explanation": "Se reemplazó innerHTML por textContent para prevenir XSS (CWE-79)."}',
    '',
    'Ejemplo de respuesta INCORRECTA (NUNCA hagas esto):',
    'Aquí tienes la corrección: ```json {"fixedSnippet": ...} ```',
  ].join('\n');

  /**
   * System prompt para auditoría semántica de código completo (AI Deep Scan).
   */
  private readonly AUDIT_SYSTEM_PROMPT = [
    'Eres un auditor de seguridad de código de élite para la herramienta SAST "VulX".',
    'Tu tarea es analizar el código fuente suministrado e identificar vulnerabilidades de seguridad reales (OWASP Top 10, CWE).',
    'Debes buscar problemas como: Inyección de Comandos, SSRF, Path Traversal, Insecure Deserialization, Prototype Pollution, Broken Access Control, Weak Cryptography, Open Redirect, etc.',
    '',
    'REGLAS OBLIGATORIAS:',
    '1. Responde ÚNICAMENTE con un arreglo JSON de objetos: [{"id": string, "name": string, "description": string, "severity": "critical"|"high"|"medium"|"low", "line": number, "column": number, "codeSnippet": string, "recommendation": string, "fixedSnippet": string, "explanation": string}].',
    '2. Si el código no presenta vulnerabilidades, responde exactamente: []',
    '3. NO incluyas markdown (```), NO escribas texto fuera del arreglo JSON.',
    '4. La línea debe corresponder al número de línea aproximado en el código fuente (1-indexed).',
    '5. "fixedSnippet" debe ser la corrección segura del "codeSnippet".',
  ].join('\n');


  /**
   * Construye el prompt de usuario con los datos de la vulnerabilidad.
   * Las instrucciones de formato van en el system prompt, aquí solo van los datos.
   */
  public generatePrompt(vulnerability: Vulnerability, sourceCode: string): string {
    return [
      `Vulnerabilidad detectada:`,
      `- Regla ID: ${vulnerability.id}`,
      `- Nombre: ${vulnerability.name}`,
      `- Severidad: ${vulnerability.severity}`,
      `- Línea: ${vulnerability.line}`,
      `- Descripción: ${vulnerability.description}`,
      `- Recomendación de la regla: ${vulnerability.recommendation}`,
      ``,
      `Fragmento de código vulnerable:`,
      vulnerability.codeSnippet,
      ``,
      `Contexto del archivo (primeros 1500 caracteres):`,
      sourceCode.substring(0, 1500),
      ``,
      `Corrige la vulnerabilidad y responde con el JSON.`,
    ].join('\n');
  }

  /**
   * Calcula las coordenadas de reemplazo (ReplacementRange) en base al inicio del hallazgo y su fragmento.
   */
  public calculateReplacementRange(
    vulnerability: Vulnerability,
    _sourceCode?: string
  ): ReplacementRange {
    const lines = vulnerability.codeSnippet.split(/\r?\n/);
    const startLine = vulnerability.line;
    const startColumn = vulnerability.column;

    if (lines.length <= 1) {
      return {
        startLine,
        endLine: startLine,
        startColumn,
        endColumn: startColumn + vulnerability.codeSnippet.length
      };
    }

    const endLine = startLine + lines.length - 1;
    const lastLine = lines[lines.length - 1] ?? '';
    const endColumn = lastLine.length;

    return {
      startLine,
      endLine,
      startColumn,
      endColumn
    };
  }

  /**
   * Genera un diff unificado estilo Git entre el código original y el corregido.
   */
  public generateDiff(
    originalSnippet: string,
    fixedSnippet: string,
    startLine = 1
  ): string {
    const origLines = originalSnippet.trimEnd().split(/\r?\n/);
    const fixedLines = fixedSnippet.trimEnd().split(/\r?\n/);

    const origCount = origLines.length;
    const fixedCount = fixedLines.length;

    const diffRows: string[] = [
      `@@ -${startLine},${origCount} +${startLine},${fixedCount} @@`
    ];

    for (const line of origLines) {
      diffRows.push(`- ${line}`);
    }

    for (const line of fixedLines) {
      diffRows.push(`+ ${line}`);
    }

    return diffRows.join('\n');
  }

  /**
   * Limpia y extrae el JSON o fragmento de código de la respuesta textual de la IA.
   */
  public parseAIResponse(
    rawResponse: string,
    vulnerability: Vulnerability
  ): AIRemediationPayload {
    try {
      // 1. Intentar parsear directamente como JSON
      const parsed = JSON.parse(rawResponse.trim());
      if (parsed && typeof parsed.fixedSnippet === 'string') {
        return {
          fixedSnippet: this.sanitizeCodeSnippet(parsed.fixedSnippet),
          explanation: parsed.explanation || vulnerability.recommendation
        };
      }
    } catch {
      // Continuar al intento de extracción mediante expresiones regulares
    }

    // 2. Extraer bloque JSON si viene envuelto en markdown ```json ... ```
    const jsonMatch = rawResponse.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
    if (jsonMatch && jsonMatch[1]) {
      try {
        const parsed = JSON.parse(jsonMatch[1].trim());
        if (parsed && typeof parsed.fixedSnippet === 'string') {
          return {
            fixedSnippet: this.sanitizeCodeSnippet(parsed.fixedSnippet),
            explanation: parsed.explanation || vulnerability.recommendation
          };
        }
      } catch {
        // Ignorar y pasar a fallback
      }
    }

    // 3. Si la IA devolvió solo un bloque de código como markdown: ```js ... ```
    const codeBlockMatch = rawResponse.match(/```(?:javascript|typescript|js|ts)?\s*([\s\S]*?)\s*```/i);
    if (codeBlockMatch && codeBlockMatch[1]) {
      return {
        fixedSnippet: this.sanitizeCodeSnippet(codeBlockMatch[1]),
        explanation: vulnerability.recommendation
      };
    }

    // 4. Si falló el parseo, recurrir a la remediación heurística
    return this.getHeuristicRemediation(vulnerability);
  }

  /**
   * Elimina artefactos o backticks innecesarios de un snippet de código.
   */
  private sanitizeCodeSnippet(snippet: string): string {
    let cleaned = snippet.trim();
    if (cleaned.startsWith('```') && cleaned.endsWith('```')) {
      cleaned = cleaned.replace(/^```[a-zA-Z]*\n?/, '').replace(/\n?```$/, '');
    }
    return cleaned.trim();
  }

  /**
   * Proporciona una remediación heurística determinística según la regla de seguridad.
   * Garantiza que el backend siempre entregue una respuesta válida de remediación incluso
   * cuando el servicio de IA local esté desconectado o en pruebas.
   */
  public getHeuristicRemediation(vulnerability: Vulnerability): AIRemediationPayload {
    const { id, codeSnippet } = vulnerability;

    switch (id) {
      case 'DOM_XSS': {
        if (codeSnippet.includes('.innerHTML')) {
          const fixed = codeSnippet.replace(/\.innerHTML\s*=/, '.textContent =');
          return {
            fixedSnippet: fixed,
            explanation: 'Se sustituyó .innerHTML por .textContent para prevenir la ejecución no controlada de scripts en el DOM.'
          };
        }
        if (codeSnippet.includes('.outerHTML')) {
          const fixed = codeSnippet.replace(/\.outerHTML\s*=/, '.textContent =');
          return {
            fixedSnippet: fixed,
            explanation: 'Se sustituyó .outerHTML por asignación segura de texto para mitigar riesgo de DOM XSS.'
          };
        }
        if (codeSnippet.includes('document.write')) {
          return {
            fixedSnippet: '// TODO: Reemplazar document.write por document.createElement() y appendChild() seguro\n' +
              codeSnippet.replace(/document\.write\((.*)\);?/, '/* document.write deprecado */ console.warn("Evitar document.write");'),
            explanation: 'document.write sobreescribe el flujo HTML y es inseguro. Usa manipulación estructurada del DOM.'
          };
        }
        return {
          fixedSnippet: `// Sanitizar entrada antes de renderizar\n${codeSnippet}`,
          explanation: vulnerability.recommendation || 'Sanitiza cualquier entrada del usuario antes de insertarla en el DOM.'
        };
      }

      case 'SQL_INJECTION': {
        return {
          fixedSnippet: '// Utilizar consulta parametrizada con placeholders (ej: $1, ?, :val)\n' +
            codeSnippet.replace(/\+[^;]+/, '/* pasar como parámetro en array de valores */'),
          explanation: 'Reemplaza la concatenación dinámica por consultas parametrizadas o sentencias preparadas.'
        };
      }

      case 'HARDCODED_SECRET': {
        return {
          fixedSnippet: codeSnippet.replace(/["'][A-Za-z0-9_\-\.\/\+=]{8,}["']/, 'process.env.SECRET_TOKEN!'),
          explanation: 'Extrae la credencial codificada hacia una variable de entorno (.env) para evitar filtraciones en el repositorio.'
        };
      }

      case 'EVAL_USAGE': {
        return {
          fixedSnippet: codeSnippet.replace(/\beval\((.*)\)/, 'JSON.parse($1)'),
          explanation: 'Evita el uso de eval(). Emplea JSON.parse() o deserializadores seguros según el caso de uso.'
        };
      }

      case 'COMMAND_INJECTION': {
        return {
          fixedSnippet: '// Usar child_process.execFile o spawn con arreglo de argumentos sin shell: true\n' +
            codeSnippet.replace(/\bexec\((.*)\)/, 'execFile("comando", [/* args seguros */])'),
          explanation: 'Usa execFile() o spawn() con argumentos separados en un arreglo para evitar la inyección en la shell del sistema operativo (CWE-78).'
        };
      }

      case 'PATH_TRAVERSAL': {
        return {
          fixedSnippet: '// Validar ruta canónica contra directorio base permitido antes de acceder\n' +
            'const safePath = path.resolve(BASE_DIRECTORY, userInput);\n' +
            'if (!safePath.startsWith(BASE_DIRECTORY)) throw new Error("Acceso denegado");\n' +
            codeSnippet,
          explanation: 'Confinar la ruta usando path.resolve() y verificando que empiece por el directorio base permitido (CWE-22).'
        };
      }


      default:
        return {
          fixedSnippet: `/* Corrección sugerida */\n${codeSnippet}`,
          explanation: vulnerability.recommendation || 'Aplica la recomendación de seguridad para mitigar el riesgo reportado.'
        };
    }
  }

  /**
   * Invoca el motor de inferencia local de Ollama con un timeout seguro.
   * Envía el system prompt separado del prompt de usuario para máxima adherencia al formato JSON.
   */
  private async queryInferenceEngine(
    prompt: string,
    customSystemPrompt?: string
  ): Promise<string> {
    // Si hay un proveedor de inferencia personalizado (tests/mocks), usarlo directamente
    if (this.inferenceProvider) {
      return this.inferenceProvider(prompt);
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(`${this.ollamaUrl}/api/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: this.model,
          system: customSystemPrompt || this.SYSTEM_PROMPT,
          prompt,
          stream: false,
          format: 'json',
          options: {
            temperature: 0.2,
            num_predict: 1024,
          },
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const body = await response.text().catch(() => '(no body)');
        throw new Error(
          `Ollama respondió con HTTP ${response.status}: ${body.substring(0, 200)}`
        );
      }

      const data = (await response.json()) as { response?: string };
      if (!data.response || data.response.trim().length === 0) {
        throw new Error('Respuesta vacía recibida de Ollama');
      }

      return data.response;
    } catch (err) {
      // Re-lanzar para que el caller (remediate) active el fallback heurístico
      const message = err instanceof Error ? err.message : String(err);
      if (controller.signal.aborted) {
        throw new Error(
          `Ollama timeout tras ${this.timeoutMs}ms. ¿El modelo ${this.model} está cargado?`
        );
      }
      throw new Error(`Error conectando con Ollama (${this.ollamaUrl}): ${message}`);
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Ensambla el objeto de remediación completo con código corregido, diff y coordenadas.
   */
  public formatRemediation(
    vulnerability: Vulnerability,
    fixedSnippet: string,
    explanation: string,
    sourceCode?: string
  ): Remediation {
    const replacementRange = this.calculateReplacementRange(vulnerability, sourceCode);
    const diff = this.generateDiff(
      vulnerability.codeSnippet,
      fixedSnippet,
      vulnerability.line
    );

    return {
      explanation,
      fixedSnippet,
      diff,
      replacementRange
    };
  }

  /**
   * Genera la remediación para una vulnerabilidad específica.
   */
  public async remediate(
    vulnerability: Vulnerability,
    sourceCode: string
  ): Promise<Vulnerability> {
    let payload: AIRemediationPayload;

    try {
      const prompt = this.generatePrompt(vulnerability, sourceCode);
      const rawResponse = await this.queryInferenceEngine(prompt);
      payload = this.parseAIResponse(rawResponse, vulnerability);
    } catch (err) {
      // Si la IA no está disponible o da timeout, aplicar remediación heurística determinística
      const reason = err instanceof Error ? err.message : String(err);
      console.warn(
        `[VulX/AIService] Fallback heurístico activado para ${vulnerability.id}: ${reason}`
      );
      payload = this.getHeuristicRemediation(vulnerability);
    }

    const remediation = this.formatRemediation(
      vulnerability,
      payload.fixedSnippet,
      payload.explanation,
      sourceCode
    );

    return {
      ...vulnerability,
      remediation
    };
  }

  /**
   * Genera remediaciones completas para todas las vulnerabilidades encontradas.
   */
  public async remediateAll(
    vulnerabilities: Vulnerability[],
    sourceCode: string
  ): Promise<Vulnerability[]> {
    if (!vulnerabilities || vulnerabilities.length === 0) {
      return [];
    }

    // Ejecutar en paralelo la generación de remediaciones
    const remediatedPromises = vulnerabilities.map((vuln) =>
      this.remediate(vuln, sourceCode)
    );

    return Promise.all(remediatedPromises);
  }

  /**
   * Realiza una auditoría semántica de seguridad directamente con la IA (AI Deep Scan).
   * Identifica vulnerabilidades complejas o lógicas (SSRF, Insecure Deserialization,
   * Prototype Pollution, Broken Access Control, Weak Cryptography, Open Redirect, etc.)
   * que no están cubiertas por las reglas sintácticas del AST.
   */
  public async auditCodeWithAI(
    sourceCode: string,
    language: string = 'javascript'
  ): Promise<Vulnerability[]> {
    const prompt = [
      `Audita el siguiente código fuente en lenguaje "${language}" en busca de vulnerabilidades de seguridad:`,
      '```' + language,
      sourceCode,
      '```',
      'Responde EXCLUSIVAMENTE con el arreglo JSON según las instrucciones del sistema.'
    ].join('\n');

    try {
      const rawResponse = await this.queryInferenceEngine(
        prompt,
        this.AUDIT_SYSTEM_PROMPT
      );
      return this.parseAuditResponse(rawResponse, sourceCode);
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      console.warn(`[VulX/AIService] AI Deep Scan omitido o no disponible: ${reason}`);
      return [];
    }
  }

  /**
   * Parsea la respuesta del AI Deep Scan y la convierte en objetos Vulnerability estandarizados.
   */
  public parseAuditResponse(
    rawResponse: string,
    sourceCode: string
  ): Vulnerability[] {
    let cleanJson = rawResponse.trim();

    // Extraer bloque JSON si vino envuelto en ```json ... ```
    const match = cleanJson.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
    if (match && match[1]) {
      cleanJson = match[1].trim();
    }

    // Buscar el primer '[' y último ']'
    const startIdx = cleanJson.indexOf('[');
    const endIdx = cleanJson.lastIndexOf(']');
    if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
      cleanJson = cleanJson.substring(startIdx, endIdx + 1);
    }

    try {
      const parsed = JSON.parse(cleanJson);
      if (!Array.isArray(parsed)) {
        return [];
      }

      const findings: Vulnerability[] = [];
      for (const item of parsed) {
        if (!item || typeof item !== 'object') continue;

        const id =
          typeof item.id === 'string' && item.id.length > 0
            ? item.id
            : 'AI_DETECTED_VULNERABILITY';
        const name =
          typeof item.name === 'string' && item.name.length > 0
            ? item.name
            : 'Vulnerabilidad detectada por IA';
        const description =
          typeof item.description === 'string'
            ? item.description
            : 'Problema de seguridad identificado por modelo de IA.';
        const severity: 'low' | 'medium' | 'high' | 'critical' = [
          'low',
          'medium',
          'high',
          'critical',
        ].includes(item.severity)
          ? item.severity
          : 'medium';
        const line =
          typeof item.line === 'number' && item.line > 0 ? item.line : 1;
        const column =
          typeof item.column === 'number' && item.column >= 0
            ? item.column
            : 0;
        const codeSnippet =
          typeof item.codeSnippet === 'string' ? item.codeSnippet : '';
        const recommendation =
          typeof item.recommendation === 'string'
            ? item.recommendation
            : 'Revisa el código para corregir el fallo reportado.';

        const vuln: Vulnerability = {
          id,
          name,
          description,
          severity,
          line,
          column,
          codeSnippet,
          recommendation,
        };

        if (
          typeof item.fixedSnippet === 'string' &&
          item.fixedSnippet.length > 0
        ) {
          vuln.remediation = this.formatRemediation(
            vuln,
            this.sanitizeCodeSnippet(item.fixedSnippet),
            item.explanation || recommendation,
            sourceCode
          );
        }

        findings.push(vuln);
      }

      return findings;
    } catch (parseErr) {
      console.warn(
        '[VulX/AIService] Error parseando respuesta de AI Deep Scan:',
        parseErr
      );
      return [];
    }
  }
}

