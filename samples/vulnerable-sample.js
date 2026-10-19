// ============================================================================
// VulX Security Scanner — Muestra Oficial de Vulnerabilidades para Demostración
// ============================================================================
const fs = require('fs');
const { exec } = require('child_process');

// 1. VULX-02 (CWE-79): Manipulación Insegura del DOM (Cross-Site Scripting)
function renderProfile(userBio) {
  const container = document.getElementById("bio-container");
  container.innerHTML = userBio;
}

// 2. CWE-95: Uso Peligroso de eval()
function calculateTotal(formula) {
  return eval(formula);
}

// 3. VULX-01 (CWE-89): Inyección SQL por concatenación de variables
function getUserById(userId) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  return query;
}

// 4. VULX-03 (CWE-798): Credencial Hardcodeada (AWS Access Key ID)
const AWS_ACCESS_KEY = "AKIA1234567890ABCDEF";

// 5. VULX-04 (CWE-78): Inyección de Comandos del Sistema Operativo
function pingHost(host) {
  exec("ping -c 1 " + host);
}