

// Módulo de Autenticación y Login (login-service.js)
// Simula un servicio real de autenticación de usuarios y renderizado de sesión


const db = require('./database-mock');

// 1. HARDCODED SECRET (CWE-798)
// Clave secreta o token de API sensible quemado directamente en el código

const JWT_SECRET_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

/**
 * Procesa el inicio de sesión del usuario
 */
function handleLogin(email, password) {
  // 2. SQL INJECTION (CWE-89)

  const query = "SELECT id, email, role FROM users WHERE email = '" + email + "' AND password = '" + password + "'";
  return db.query(query);
}

/**
 * Muestra el estado del inicio de sesión en la interfaz web del usuario
 */
function displayLoginFeedback(errorMessage, userDisplayName) {
  const feedbackBox = document.getElementById("login-feedback");
  const welcomeBanner = document.getElementById("welcome-banner");

  if (errorMessage) {
    // ------------------------------------------------------------------------
    // 3. DOM XSS (CWE-79)
    // Asignación directa a innerHTML permitiendo inyección de scripts maliciosos
    // ------------------------------------------------------------------------
    feedbackBox.innerHTML = errorMessage;
  } else if (userDisplayName) {
    welcomeBanner.innerHTML = userDisplayName;
  }
}

module.exports = {
  JWT_SECRET_KEY,
  handleLogin,
  displayLoginFeedback
};
