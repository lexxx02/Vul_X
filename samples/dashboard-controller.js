// ============================================================================
// Panel de Administración y Métricas (dashboard-controller.js)
// Simula el backend y frontend de un dashboard empresarial con KPIs y reportes
// ============================================================================

const fs = require('fs');
const path = require('path');
const { exec, execFile } = require('child_process');


// 1. HARDCODED SECRET (CWE-798)
// Token de integración de pagos o API externa presente en el código fuente

const STRIPE_SECRET_KEY = "sec_mock_stripe_api_key_9876543210xyz";

/**
 * Renderiza el perfil y las métricas del usuario en el DOM del Dashboard
 */
function renderDashboardMetrics(userProfile, recentActivity) {
  const profileContainer = document.getElementById("user-profile");
  const activityList = document.getElementById("recent-activity");

  // --------------------------------------------------------------------------
  // 2. DOM XSS (CWE-79)
  // Inserción de contenido dinámico no sanitizado en el DOM mediante innerHTML
  // --------------------------------------------------------------------------
  profileContainer.innerHTML = userProfile.bio;
  activityList.innerHTML = recentActivity.summary;
}

/**
 * Descarga o lee un reporte generado por el sistema según el nombre indicado
 */
function exportDashboardReport(reportFileName) {
  // --------------------------------------------------------------------------
  // 3. PATH TRAVERSAL (CWE-22)
  // Concatenación de rutas de archivo con entrada sin confinar ni validar
  // --------------------------------------------------------------------------
  return fs.readFileSync("/var/app/reports/" + reportFileName, "utf-8");
}

/**
 * Diagnóstico de conectividad de servidores de la infraestructura
 */
function checkServerConnectivity(serverHost) {
  // --------------------------------------------------------------------------
  // 4. COMMAND INJECTION (CWE-78)
  // Ejecución en la shell del sistema operativo concatenando variables de usuario
  // --------------------------------------------------------------------------
  exec("ping -c 1 " + serverHost, (error, stdout) => {
    console.log("Resultado del diagnóstico: " + stdout);
  });
}

/**
 * Calculadora de KPIs dinámicos definidos por el usuario en el dashboard
 */
function computeCustomKPI(customKpiFormula) {
  // --------------------------------------------------------------------------
  // 5. EVAL USAGE (CWE-95)
  // Evaluación arbitraria de cadenas de código JavaScript
  // --------------------------------------------------------------------------
  return eval(customKpiFormula);
}

module.exports = {
  STRIPE_SECRET_KEY,
  renderDashboardMetrics,
  exportDashboardReport,
  checkServerConnectivity,
  computeCustomKPI
};
