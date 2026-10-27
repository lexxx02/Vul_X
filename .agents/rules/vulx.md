---
description: Guía de integración, triggers y uso del analizador de seguridad VulX en Antigravity y VS Code
globs: ["**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx"]
---

# Regla de Integración: VulX Security Analyzer

Esta regla orienta a los desarrolladores y al agente de IA sobre el funcionamiento y los triggers de análisis de **VulX** en el espacio de trabajo.

## 1. Triggers de Análisis Disponibles

VulX cuenta con dos modalidades de disparo de análisis en Antigravity y VS Code:

### A. Trigger al Guardar Archivo (`onSave`)
* **Comportamiento**: Se activa automáticamente al presionar `Ctrl+S` (`Cmd+S` en macOS) en cualquier archivo JavaScript o TypeScript.
* **Flujo**: Intercepta el buffer, envía el código al motor de análisis REST (`http://127.0.0.1:3000/analyze`) y renderiza diagnósticos visuales (*squiggles*) en las líneas afectadas.
* **Control**: Se puede activar o desactivar mediante la configuración `vulx.enableOnSave` en los ajustes del editor o ejecutando el comando `VulX: Alternar análisis automático al guardar`.

### B. Trigger Bajo Demanda (`onDemand`)
Permite al desarrollador auditar el código en cualquier momento sin necesidad de guardar cambios:
1. **Atajo de teclado**: Presionar `Ctrl+Alt+A` o `Alt+Shift+V` en el editor activo.
2. **Menú contextual**: Clic derecho en el código fuente -> Seleccionar `VulX: Analizar archivo activo (Bajo demanda)`.
3. **Barra de título del editor**: Clic en el icono del escudo `$(shield)` ubicado en la esquina superior derecha del editor.
4. **Item en la Barra de Estado**: Clic en el botón `$(shield) VulX` en la esquina inferior derecha. Muestra en tiempo real el conteo de vulnerabilidades o el estado de escaneo.
5. **Paleta de comandos**: `Ctrl+Shift+P` -> Escribir `VulX: Analizar archivo activo`.

## 2. Acciones de Remediación Rápida (Quick Fixes)
Cuando VulX detecta una vulnerabilidad (CWE-89 SQLi, CWE-79 XSS, CWE-798 Secretos, CWE-78 Command Injection, CWE-22 Path Traversal):
* Ubicar el cursor sobre el subrayado y presionar `Ctrl+.` (`Cmd+.`).
* Seleccionar `💡 Aplicar corrección de VulX`. La remediación generada por el motor AST/IA reemplazará el fragmento vulnerable respetando la indentación.

## 3. Comandos de Terminal / Tareas Integradas
* **Iniciar backend**: `npm run dev`
* **Compilar extensión**: `npm run compile:extension`
* **Empaquetar VSIX**: `npm run package:extension`
* **Verificar triggers**: `npm run verify:triggers`
