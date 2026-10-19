// -------------------------------------------------------------
// Archivo de Demostración para VulX — Muestra de Vulnerabilidades
// -------------------------------------------------------------
const fs = require('fs');
const { exec } = require('child_process');

// 1. VULX-01 (CWE-89): Inyección SQL por concatenación de cadenas
function getUserData(db, userId) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  return db.query(query);
}

// 2. VULX-02 (CWE-79): Manipulación Insegura del DOM (Cross-Site Scripting)
function renderProfile(userBio) {
  const container = document.getElementById("bio-container");
  container.innerHTML = userBio;
}

// 3. VULX-03 (CWE-798): Credencial Hardcodeada (AWS Access Key ID)
const AWS_ACCESS_KEY = "AKIA1234567890ABCDEF";

// 4. VULX-04 (CWE-78): Inyección de Comandos del Sistema Operativo
function pingHost(host) {
  exec("ping -c 1 " + host, (err, stdout) => {
    console.log(stdout);
  });
}

// 5. VULX-05 (CWE-22): Recorrido de Rutas Arbitrario (Path Traversal)
function downloadFile(userFileName) {
  return fs.readFileSync("/var/app/uploads/" + userFileName, "utf-8");
}

// 6. CWE-95: Uso Peligroso de eval()
function executeFormula(mathFormula) {
  return eval(mathFormula);
}
