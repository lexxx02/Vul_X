import type { SyntaxNode } from 'tree-sitter';
import { SecurityRule } from '../SecurityRule.js';
import type { AnalysisContext, Vulnerability } from '../SecurityRule.js';

/**
 * Regla: Detector de Secretos Codificados (Hardcoded Secrets)
 *
 * Analiza literales de texto en el AST usando dos técnicas complementarias:
 *
 * 1. **Detección por patrones (Regex):** Busca formatos conocidos de
 *    credenciales como API keys de AWS, tokens de Stripe, JWTs,
 *    contraseñas en variables con nombres sospechosos, etc.
 *
 * 2. **Detección por entropía (Shannon Entropy):** Identifica strings
 *    con alta aleatoriedad que probablemente son secretos generados
 *    automáticamente (tokens, hashes, claves aleatorias).
 *
 * Referencia: CWE-798 (Use of Hard-coded Credentials)
 * Referencia: CWE-259 (Use of Hard-coded Password)
 */
export class SecretRule extends SecurityRule {
  readonly id = 'HARDCODED_SECRET';
  readonly name = 'Secreto codificado en el código';
  readonly description =
    'Detecta credenciales, tokens, claves API y contraseñas escritas directamente ' +
    'en el código fuente, lo que representa un riesgo crítico si el código se expone.';
  readonly severity = 'high' as const;
  readonly supportedLanguages = ['javascript', 'typescript'];

  /**
   * Umbral mínimo de entropía Shannon para considerar un string como
   * un posible secreto. Los strings aleatorios típicos (tokens, hashes)
   * tienen entropía entre 4.0 y 6.0 bits por carácter.
   *
   * Un umbral de 4.5 minimiza falsos positivos por strings cortos
   * o texto natural (inglés: ~4.0, código: ~3.5).
   */
  private readonly ENTROPY_THRESHOLD = 4.5;

  /**
   * Longitud mínima de un string para que sea evaluado por entropía.
   * Strings muy cortos pueden tener alta entropía sin ser secretos
   * (ej: "xyz" tiene entropía alta pero claramente no es un token).
   */
  private readonly MIN_SECRET_LENGTH = 16;

  /**
   * Patrones de credenciales conocidas.
   *
   * Cada entrada contiene:
   * - name:        Nombre descriptivo del tipo de secreto
   * - pattern:     Expresión regular para detectarlo
   * - description: Explicación de qué se detectó y por qué es peligroso
   */
  private readonly SECRET_PATTERNS: {
    name: string;
    pattern: RegExp;
    description: string;
  }[] = [
    {
      name: 'AWS Access Key ID',
      /**
       * Patrón: AKIA seguido de exactamente 16 caracteres alfanuméricos en mayúsculas.
       *
       * Las Access Key ID de AWS siempre comienzan con "AKIA" (para claves activas)
       * seguido de 16 caracteres de [A-Z0-9]. Total: 20 caracteres.
       *
       * Ejemplo: AKIAIOSFODNN7EXAMPLE
       * Ref: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
       */
      pattern: /AKIA[0-9A-Z]{16}/,
      description:
        'Se detectó una AWS Access Key ID. Si se expone junto con la Secret Key, ' +
        'un atacante puede acceder a todos los recursos de AWS de la cuenta.',
    },
    {
      name: 'AWS Secret Access Key',
      /**
       * Patrón: Exactamente 40 caracteres alfanuméricos incluyendo + y /.
       *
       * Las Secret Access Keys de AWS son strings de 40 caracteres en Base64
       * (letras, dígitos, +, /). Este patrón busca la clave precedida por
       * un nombre de variable o clave JSON típica como "aws_secret", etc.
       *
       * Nota: se usa un lookahead contextual para reducir falsos positivos.
       */
      pattern: /(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*['"]([A-Za-z0-9/+=]{40})['"]/i,
      description:
        'Se detectó una posible AWS Secret Access Key. Esta clave otorga acceso ' +
        'programático completo a los servicios de AWS.',
    },
    {
      name: 'Stripe API Key',
      /**
       * Patrón: "sk_live_" o "sk_test_" seguido de 24+ caracteres alfanuméricos.
       *
       * Las claves secretas de Stripe comienzan con "sk_live_" (producción)
       * o "sk_test_" (pruebas). Ambas deben protegerse ya que sk_live_
       * permite realizar cargos reales.
       *
       * Ejemplo: sk_live_abc123def456ghi789jkl012
       * Ref: https://stripe.com/docs/keys
       */
      pattern: /sk_(live|test)_[A-Za-z0-9]{24,}/,
      description:
        'Se detectó una API key de Stripe. Las claves sk_live_ permiten realizar ' +
        'transacciones financieras reales si se exponen.',
    },
    {
      name: 'Stripe Publishable Key',
      /**
       * Patrón: "pk_live_" o "pk_test_" seguido de 24+ caracteres.
       *
       * Aunque las publishable keys son menos sensibles que las secret keys,
       * su presencia hardcodeada indica mala práctica que podría acompañar
       * secret keys en el mismo archivo.
       */
      pattern: /pk_(live|test)_[A-Za-z0-9]{24,}/,
      description:
        'Se detectó una publishable key de Stripe codificada en el código. ' +
        'Aunque es menos sensible, indica que podría haber secret keys cerca.',
    },
    {
      name: 'JSON Web Token (JWT)',
      /**
       * Patrón: Tres segmentos Base64URL separados por puntos.
       *
       * Un JWT tiene la forma: header.payload.signature
       * - Header:    segmento Base64URL (mínimo ~20 chars)
       * - Payload:   segmento Base64URL (mínimo ~20 chars)
       * - Signature: segmento Base64URL (mínimo ~20 chars)
       *
       * El prefijo "eyJ" es constante porque el header siempre comienza con
       * '{"' en JSON, que en Base64 se codifica como "eyJ".
       *
       * Ejemplo: eyJhbGciOiJIUzI1NiIs...
       */
      pattern: /eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/,
      description:
        'Se detectó un JSON Web Token (JWT) codificado en el código. ' +
        'Los JWT contienen información de autenticación/autorización que puede ' +
        'ser decodificada y reutilizada por un atacante.',
    },
    {
      name: 'GitHub Personal Access Token',
      /**
       * Patrón: "ghp_" seguido de 36 caracteres alfanuméricos.
       *
       * Los PAT de GitHub (formato fine-grained y classic) usan el prefijo
       * "ghp_" seguido de exactamente 36 caracteres.
       *
       * Ejemplo: ghp_ABCDEFghijklmnopqrstuvwxyz0123456789
       * Ref: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github
       */
      pattern: /ghp_[A-Za-z0-9]{36}/,
      description:
        'Se detectó un Personal Access Token de GitHub. Con este token, un ' +
        'atacante puede acceder a repositorios privados y realizar acciones en nombre del usuario.',
    },
    {
      name: 'GitHub OAuth Access Token',
      /**
       * Patrón: "gho_" seguido de 36 caracteres alfanuméricos.
       *
       * Tokens OAuth de GitHub para apps que autentican usuarios.
       */
      pattern: /gho_[A-Za-z0-9]{36}/,
      description:
        'Se detectó un token OAuth de GitHub codificado en el código.',
    },
    {
      name: 'Slack Token',
      /**
       * Patrón: "xoxb-" o "xoxp-" seguido de números y guiones.
       *
       * Los tokens de Slack para bots (xoxb) y usuarios (xoxp) siguen
       * un formato de grupos numéricos separados por guiones.
       *
       * Ejemplo: xoxb-123456789012-1234567890123-ABCdefGHIjklMNOpqrSTUvwx
       */
      pattern: /xox[bp]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}/,
      description:
        'Se detectó un token de Slack. Con acceso a este token, un atacante ' +
        'puede leer mensajes, enviar comunicaciones o acceder a archivos del workspace.',
    },
    {
      name: 'Google API Key',
      /**
       * Patrón: "AIza" seguido de exactamente 35 caracteres alfanuméricos y guiones.
       *
       * Las API keys de Google Cloud/Firebase siempre comienzan con "AIza"
       * seguido de 35 caracteres de [A-Za-z0-9_-].
       *
       * Ejemplo: AIzaSyA1bcDefGhiJklMnoPqrStUvWxYz12345
       */
      pattern: /AIza[A-Za-z0-9_-]{35}/,
      description:
        'Se detectó una API key de Google. Dependiendo de los permisos configurados, ' +
        'un atacante podría consumir servicios de Google Cloud con cargos a la cuenta del propietario.',
    },
    {
      name: 'Contraseña en variable',
      /**
       * Patrón: Variable con nombre que contiene "password", "passwd", "pwd",
       * "secret", "token", "api_key", "apikey" o "credentials" seguida de
       * una asignación con un valor literal de string.
       *
       * Busca patrones como:
       *   password = "mi_clave_123"
       *   const DB_PASSWORD = 'supersecret'
       *   let api_key = "abc123"
       *
       * Flag 'i' para case-insensitive (PASSWORD, Password, password).
       */
      pattern: /(?:password|passwd|pwd|secret|token|api_key|apikey|credentials|auth_token|access_token)\s*[=:]\s*['"][^'"]{4,}['"]/i,
      description:
        'Se detectó una posible contraseña o credencial asignada directamente en el código. ' +
        'Las credenciales deben almacenarse en variables de entorno o gestores de secretos.',
    },
    {
      name: 'Clave privada (PEM)',
      /**
       * Patrón: Encabezado de clave privada en formato PEM.
       *
       * Las claves privadas RSA/EC/DSA en formato PEM comienzan con
       * "-----BEGIN [TYPE] PRIVATE KEY-----". Este patrón detecta
       * la presencia de este encabezado en strings del código.
       */
      pattern: /-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----/,
      description:
        'Se detectó una clave privada en formato PEM codificada en el código. ' +
        'Las claves privadas nunca deben incluirse en el código fuente.',
    },
    {
      name: 'Cadena de conexión a base de datos',
      /**
       * Patrón: URIs de conexión a bases de datos populares.
       *
       * Detecta strings con formato de URI de conexión que incluyen
       * credenciales embebidas:
       *   - mongodb://user:pass@host
       *   - postgres://user:pass@host
       *   - mysql://user:pass@host
       *   - redis://user:pass@host
       *
       * El patrón busca el esquema seguido de user:password@host.
       */
      pattern: /(?:mongodb|postgres|postgresql|mysql|redis|amqp|mssql):\/\/[^\s'"]{10,}/i,
      description:
        'Se detectó una cadena de conexión a base de datos con posibles credenciales embebidas. ' +
        'Use variables de entorno para almacenar strings de conexión.',
    },
  ];

  evaluate(context: AnalysisContext): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    this.walkTree(context.rootNode, (node: SyntaxNode) => {
      // ─── Detección en string literals ───
      // Analiza nodos de tipo 'string' y 'string_fragment' del AST.
      if (node.type === 'string' || node.type === 'string_fragment') {
        this.checkStringNode(node, vulnerabilities);
      }

      // ─── Detección en template literals ───
      // Analiza template strings que podrían contener secretos.
      if (node.type === 'template_string') {
        this.checkStringContent(
          node.text,
          node,
          vulnerabilities
        );
      }

      // ─── Detección en asignaciones sospechosas ───
      // Busca patrones como: const password = "valor"
      if (node.type === 'variable_declarator' || node.type === 'assignment_expression') {
        this.checkSuspiciousAssignment(node, vulnerabilities);
      }
    });

    return vulnerabilities;
  }

  /**
   * Analiza un nodo de tipo string buscando patrones de secretos
   * y evaluando la entropía del contenido.
   */
  private checkStringNode(
    node: SyntaxNode,
    vulnerabilities: Vulnerability[]
  ): void {
    // Extraer el contenido del string sin las comillas
    const rawText = node.text;
    const content = this.stripQuotes(rawText);

    if (content.length < 4) return; // Ignorar strings muy cortos

    this.checkStringContent(content, node, vulnerabilities);
  }

  /**
   * Verifica el contenido de un string contra todos los patrones
   * de secretos conocidos y evalúa su entropía Shannon.
   */
  private checkStringContent(
    content: string,
    node: SyntaxNode,
    vulnerabilities: Vulnerability[]
  ): void {
    // ─── Fase 1: Detección por patrones conocidos ───
    for (const secretPattern of this.SECRET_PATTERNS) {
      if (secretPattern.pattern.test(content)) {
        // Evitar duplicados: no reportar si ya existe una vulnerabilidad
        // en la misma línea con el mismo patrón.
        const isDuplicate = vulnerabilities.some(
          (v) =>
            v.line === node.startPosition.row + 1 &&
            v.name === `Secreto: ${secretPattern.name}`
        );

        if (!isDuplicate) {
          vulnerabilities.push({
            id: this.id,
            name: `Secreto: ${secretPattern.name}`,
            description: secretPattern.description,
            severity: this.severity,
            line: node.startPosition.row + 1,
            column: node.startPosition.column,
            codeSnippet: this.maskSecret(node.text),
            recommendation:
              'Mueve este secreto a una variable de entorno (.env) o a un gestor de ' +
              'secretos como AWS Secrets Manager, HashiCorp Vault o Azure Key Vault. ' +
              'Nunca incluyas credenciales en el código fuente.',
          });
        }
        return; // Un match por patrón es suficiente para este string
      }
    }

    // ─── Fase 2: Detección por entropía Shannon ───
    // Solo para strings lo suficientemente largos que no fueron detectados
    // por patrones conocidos.
    const cleanContent = this.stripQuotes(content);
    if (cleanContent.length >= this.MIN_SECRET_LENGTH) {
      const entropy = this.calculateShannonEntropy(cleanContent);

      if (entropy >= this.ENTROPY_THRESHOLD) {
        // Verificar que no sea un string común (URL, path, etc.)
        if (!this.isCommonString(cleanContent)) {
          vulnerabilities.push({
            id: this.id,
            name: 'Posible secreto (alta entropía)',
            description:
              `Se detectó un string con entropía Shannon de ${entropy.toFixed(2)} bits/char ` +
              `(umbral: ${this.ENTROPY_THRESHOLD}). Los strings con alta aleatoriedad ` +
              'suelen ser tokens, hashes o claves generadas automáticamente.',
            severity: 'medium',
            line: node.startPosition.row + 1,
            column: node.startPosition.column,
            codeSnippet: this.maskSecret(node.text),
            recommendation:
              'Si este string es un secreto o token, muévelo a una variable de entorno. ' +
              'Si es un valor legítimo (hash, salt, etc.), considera marcarlo con un ' +
              'comentario // nosecret para suprimir esta alerta.',
          });
        }
      }
    }
  }

  /**
   * Analiza asignaciones donde el nombre de la variable sugiere que
   * contiene un secreto (password, apiKey, token, etc.).
   *
   * Inspecciona el lado izquierdo de la asignación para detectar
   * nombres sospechosos y el lado derecho para verificar que se
   * asigna un valor literal.
   */
  private checkSuspiciousAssignment(
    node: SyntaxNode,
    vulnerabilities: Vulnerability[]
  ): void {
    let nameNode: SyntaxNode | null = null;
    let valueNode: SyntaxNode | null = null;

    if (node.type === 'variable_declarator') {
      nameNode = node.childForFieldName('name');
      valueNode = node.childForFieldName('value');
    } else if (node.type === 'assignment_expression') {
      nameNode = node.childForFieldName('left');
      valueNode = node.childForFieldName('right');
    }

    if (!nameNode || !valueNode) return;

    // Solo nos interesan asignaciones con string literal como valor
    if (valueNode.type !== 'string' && valueNode.type !== 'template_string') return;

    const varName = nameNode.text.toLowerCase();
    const valueText = this.stripQuotes(valueNode.text);

    // Ignorar valores vacíos, placeholders o ejemplos
    if (this.isPlaceholderValue(valueText)) return;

    /**
     * Patrón para nombres de variables que sugieren credenciales.
     *
     * Busca variables cuyo nombre contenga:
     *   - password, passwd, pwd → contraseñas
     *   - secret                → secretos genéricos
     *   - token                 → tokens de autenticación
     *   - api_key, apikey       → claves de API
     *   - private_key           → claves privadas
     *   - auth                  → datos de autenticación
     *   - credential            → credenciales genéricas
     *   - access_key            → claves de acceso (AWS, etc.)
     *
     * Flag 'i' implícito porque ya convertimos a lowercase.
     */
    const suspiciousNamePattern =
      /(?:password|passwd|pwd|secret|token|api_?key|private_?key|auth|credential|access_?key)/;

    if (suspiciousNamePattern.test(varName)) {
      // Evitar duplicados
      const isDuplicate = vulnerabilities.some(
        (v) =>
          v.line === node.startPosition.row + 1 &&
          v.id === this.id
      );

      if (!isDuplicate) {
        vulnerabilities.push({
          id: this.id,
          name: 'Credencial en asignación',
          description:
            `La variable "${nameNode.text}" tiene un nombre que sugiere credenciales ` +
            'y se le asigna un valor literal. Las credenciales hardcodeadas son un ' +
            'vector de ataque común cuando el código fuente se expone.',
          severity: this.severity,
          line: node.startPosition.row + 1,
          column: node.startPosition.column,
          codeSnippet: this.maskSecret(node.text),
          recommendation:
            `Usa una variable de entorno: process.env.${nameNode.text.toUpperCase()} ` +
            'en lugar de codificar el valor directamente. Ejemplo: ' +
            `const ${nameNode.text} = process.env.${nameNode.text.toUpperCase()};`,
        });
      }
    }
  }

  /**
   * Calcula la entropía Shannon de un string.
   *
   * La entropía Shannon mide la "aleatoriedad" o "imprevisibilidad" de
   * una cadena de caracteres. Se calcula como:
   *
   *   H = -Σ (p_i × log₂(p_i))
   *
   * donde p_i es la frecuencia relativa de cada carácter único.
   *
   * Valores de referencia:
   *   - Texto en inglés:  ~3.5 - 4.0 bits/char
   *   - Código fuente:    ~3.0 - 4.0 bits/char
   *   - Tokens/hashes:    ~4.5 - 6.0 bits/char
   *   - String aleatorio: ~5.5 - 6.5 bits/char
   *
   * @param str - String a evaluar
   * @returns Entropía en bits por carácter
   */
  private calculateShannonEntropy(str: string): number {
    if (str.length === 0) return 0;

    // Contar la frecuencia de cada carácter
    const charFrequency = new Map<string, number>();
    for (const char of str) {
      charFrequency.set(char, (charFrequency.get(char) ?? 0) + 1);
    }

    // Calcular la entropía
    let entropy = 0;
    const length = str.length;

    for (const count of charFrequency.values()) {
      const probability = count / length;
      if (probability > 0) {
        entropy -= probability * Math.log2(probability);
      }
    }

    return entropy;
  }

  /**
   * Enmascara un secreto para mostrarlo parcialmente en los reportes.
   * Muestra los primeros 4 y últimos 4 caracteres, reemplazando el
   * resto con asteriscos.
   *
   * Ejemplo: "AKIAIOSFODNN7EXAMPLE" → "AKIA************MPLE"
   */
  private maskSecret(text: string): string {
    const content = this.stripQuotes(text);
    if (content.length <= 12) {
      return text.substring(0, 4) + '****' + text.substring(text.length - 2);
    }
    return (
      content.substring(0, 4) +
      '*'.repeat(Math.min(content.length - 8, 20)) +
      content.substring(content.length - 4)
    );
  }

  /**
   * Elimina las comillas (simples, dobles o backticks) que envuelven un string.
   */
  private stripQuotes(text: string): string {
    if (
      (text.startsWith('"') && text.endsWith('"')) ||
      (text.startsWith("'") && text.endsWith("'")) ||
      (text.startsWith('`') && text.endsWith('`'))
    ) {
      return text.slice(1, -1);
    }
    return text;
  }

  /**
   * Determina si un valor es un placeholder o ejemplo obvio que no
   * debería generar una alerta. Esto reduce falsos positivos.
   *
   * Se consideran placeholders:
   *   - Strings vacíos o con solo espacios
   *   - Valores como "TODO", "CHANGE_ME", "your-api-key-here"
   *   - Valores genéricos de ejemplo como "xxxx", "****"
   */
  private isPlaceholderValue(value: string): boolean {
    const trimmed = value.trim().toLowerCase();

    // Valores vacíos o muy cortos
    if (trimmed.length < 4) return true;

    // Placeholders comunes
    const placeholders = [
      'todo',
      'fixme',
      'changeme',
      'change_me',
      'replace_me',
      'your-api-key-here',
      'your-secret-here',
      'your-token-here',
      'insert-your-key',
      'xxxxxxxx',
      '********',
      'placeholder',
      'example',
      'test',
      'dummy',
      'sample',
      'undefined',
      'null',
      'none',
      'n/a',
    ];

    return placeholders.some(
      (p) => trimmed === p || trimmed.includes(p)
    );
  }

  /**
   * Determina si un string es un valor común que no debería
   * disparar alertas por entropía alta, como URLs, paths,
   * selectores CSS, hashes de integridad, etc.
   */
  private isCommonString(text: string): boolean {
    // URLs (incluso con path largo tienen alta entropía)
    if (/^https?:\/\//.test(text)) return true;

    // File paths
    if (/^[.\/\\]/.test(text) || /^[a-zA-Z]:[\\\/]/.test(text)) return true;

    // Selectores CSS / clases de Tailwind
    if (/^[.#]?[a-z][a-z0-9-_\s.#:]+$/i.test(text)) return true;

    // UUIDs (formato estándar con guiones)
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(text)) return true;

    // Hashes de integridad en HTML (sha256-, sha384-, sha512-)
    if (/^sha(256|384|512)-/.test(text)) return true;

    // Mime types
    if (/^(application|text|image|audio|video|font)\//.test(text)) return true;

    // Cadenas que son mayormente texto natural (muchos espacios)
    const spaceRatio = (text.match(/\s/g) ?? []).length / text.length;
    if (spaceRatio > 0.15) return true;

    return false;
  }

  /**
   * Recorre recursivamente todos los nodos del AST y ejecuta
   * el callback en cada uno (depth-first traversal).
   */
  private walkTree(node: SyntaxNode, callback: (node: SyntaxNode) => void): void {
    callback(node);
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child) {
        this.walkTree(child, callback);
      }
    }
  }
}
