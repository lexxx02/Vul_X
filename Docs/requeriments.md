# Especificación de Requerimientos y Alcance del MVP — VulX

## 1. Alcance del MVP (v1.0.0)
VulX se concibe como una herramienta DevSecOps integrada directamente en el entorno de desarrollo. En su primera versión (MVP), el sistema se limitará a:
* **Entornos soportados:** VS Code y Antigravity.
* **Lenguajes soportados:** JavaScript y TypeScript.
* **Arquitectura de análisis:** Híbrida. Uso de análisis de sintaxis abstracta (AST con Tree-sitter) para detección determinística, complementado con IA generativa local (Ollama + Qwen 2.5 Coder 7B) para la contextualización y remediación.
* **Privacidad:** Operación 100% local. El código fuente nunca abandona la máquina del desarrollador.

## 2. Matriz de Vulnerabilidades Iniciales
El MVP se centrará en detectar y explicar tres tipos críticos de vulnerabilidades de seguridad:

| ID | Tipo de Vulnerabilidad | CWE Base | Método de Detección (AST) | Rol de la IA (Ollama) |
| :--- | :--- | :--- | :--- | :--- |
| **VULX-01** | Inyección SQL (SQLi) | CWE-89 | Detección de concatenación de cadenas en métodos de consulta a bases de datos. | Explicar el vector de ataque y sugerir el uso de consultas parametrizadas. |
| **VULX-02** | Cross-Site Scripting (XSS) | CWE-79 | Identificación de asignaciones directas a `innerHTML` o manipulación insegura del DOM. | Demostrar cómo se inyectan los scripts y sugerir sanitización de entradas. |
| **VULX-03** | Secretos Hardcodeados | CWE-798 | Uso de expresiones regulares y cálculo de entropía en asignaciones de variables (tokens, passwords). | Advertir sobre el riesgo de exposición en repositorios y sugerir el uso de variables de entorno (`.env`). |

## 3. Especificación Técnica de Requerimientos

### 3.1. Requerimientos Funcionales (RF)
* **RF01 - Intercepción de Código:** La extensión debe capturar el texto del editor activo y enviarlo a la API local al guardar el archivo.
* **RF02 - Análisis Estructural:** El backend debe utilizar Tree-sitter para generar el AST y aplicar las reglas de seguridad definidas.
* **RF03 - Inferencia de IA:** La API debe estructurar un prompt con el fragmento vulnerable y consultar al servicio local de Ollama esperando una respuesta en formato JSON estricto.
* **RF04 - Diagnósticos Visuales:** La extensión debe renderizar subrayados (squiggles) en las líneas de código afectadas y mostrar los detalles en el panel de Problemas.
* **RF05 - Remediación Asistida:** La interfaz debe proporcionar una acción de código (Quick Fix) que permita al usuario reemplazar el código vulnerable por el parche sugerido por la IA con un solo clic.

### 3.2. Requerimientos No Funcionales (RNF)
* **RNF01 - Latencia de Detección:** El análisis inicial mediante Tree-sitter debe completarse en menos de 100ms para no bloquear la experiencia de usuario.
* **RNF02 - Pila Tecnológica:** El backend y la extensión deben desarrollarse en TypeScript, utilizando Node.js como entorno de ejecución.
* **RNF03 - Desacoplamiento:** La API de análisis debe ser completamente independiente del cliente IDE, permitiendo futuras integraciones sin modificar el core.