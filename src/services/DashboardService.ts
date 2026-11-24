import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { Analyzer } from '../../core/Analyzer.js';

/**
 * Servicio encargado de renderizar y gestionar el VulX Live Security Dashboard
 * y la generación de reportes ejecutivos en formato HTML en tiempo real.
 */
export function registerDashboard(server: FastifyInstance, analyzerInstance?: Analyzer): void {
  // 1. Endpoint principal: GET /dashboard
  server.get('/dashboard', async (_request: FastifyRequest, reply: FastifyReply) => {
    return reply
      .header('Content-Type', 'text/html; charset=utf-8')
      .send(getDashboardHtml());
  });

  // 2. Alias de compatibilidad: GET /report
  server.get('/report', async (_request: FastifyRequest, reply: FastifyReply) => {
    return reply.redirect('/dashboard');
  });

  // 3. Endpoint POST /report/html: Genera un reporte HTML autónomo a partir del código enviado
  server.post('/report/html', async (request: FastifyRequest<{
    Body: {
      code: string;
      language?: string;
      filePath?: string;
      includeRemediation?: boolean;
      deepScan?: boolean;
    }
  }>, reply: FastifyReply) => {
    const { code, language, filePath, includeRemediation, deepScan } = request.body || {};

    if (!code || typeof code !== 'string') {
      return reply.code(400).send({
        error: 'Bad Request',
        message: 'El campo "code" es obligatorio y debe ser una cadena de texto.'
      });
    }

    const activeAnalyzer = analyzerInstance || (server as any).analyzer;
    if (!activeAnalyzer) {
      return reply.code(500).send({
        error: 'Internal Server Error',
        message: 'Instancia de Analyzer no disponible en el servidor.'
      });
    }

    const result = await activeAnalyzer.analyze({
      code,
      language: language || 'javascript',
      filePath,
      includeRemediation: includeRemediation !== false,
      deepScan: !!deepScan
    });

    const htmlReport = generateStaticHtmlReport(result, code, filePath || 'input-code.js');
    return reply
      .header('Content-Type', 'text/html; charset=utf-8')
      .header('Content-Disposition', 'inline; filename="vulx-audit-report.html"')
      .send(htmlReport);
  });
}

/**
 * Plantilla HTML del Dashboard Interactivo en Vivo — Estilo Scalar API Reference
 */
export const VULX_LOGO_BASE64 = 'data:image/png;base64,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';

export function getDashboardHtml(): string {
  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VulX — Live Security Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --scalar-bg: #f8fafc;
      --scalar-sidebar: #ffffff;
      --scalar-card: #ffffff;
      --scalar-card-hover: #f1f5f9;
      --scalar-border: #e2e8f0;
      --scalar-border-strong: #cbd5e1;
      --scalar-text: #0f172a;
      --scalar-text-muted: #475569;
      --scalar-text-faint: #64748b;
      --scalar-accent: #4338ca;
      --scalar-accent-hover: #3730a3;
      --scalar-success: #15803d;
      --scalar-warn: #b45309;
      --scalar-high: #c2410c;
      --scalar-danger: #b91c1c;
      --scalar-purple: #6d28d9;
      --scalar-radius: 4px;
      --scalar-radius-lg: 6px;
      --sidebar-width: 250px;
      --header-height: 50px;
    }

    html, body { height: 100%; background: var(--scalar-bg); color: var(--scalar-text); }
    body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 13px; line-height: 1.6; display: flex; flex-direction: column; min-height: 100vh; overflow-x: hidden; }

    /* ─── Scrollbar ─────────────────────────────── */
    ::-webkit-scrollbar { width: 5px; height: 5px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #94a3b8; }

    /* ─── Header (Scalar topbar style) ─────────── */
    .s-header {
      position: sticky; top: 0; z-index: 100;
      height: var(--header-height);
      background: var(--scalar-sidebar);
      border-bottom: 1px solid var(--scalar-border);
      display: flex; align-items: center; justify-content: space-between;
      padding: 0 20px;
      flex-shrink: 0;
    }
    .s-header-logo { display: flex; align-items: center; gap: 10px; text-decoration: none; color: var(--scalar-text); }
        .s-logo-img { width: 28px; height: 28px; border-radius: 6px; object-fit: contain; flex-shrink: 0; }
    @keyframes spin { 100% { transform: rotate(360deg); } }
    .s-logo-icon {
      width: 28px; height: 28px; border-radius: 6px;
      background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
      display: flex; align-items: center; justify-content: center;
      font-size: 15px; flex-shrink: 0;
    }
    .s-logo-name { font-size: 14px; font-weight: 600; letter-spacing: -0.02em; }
    .s-logo-badge {
      font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 600;
      background: #e0e7ff; color: #312e81;
      border: 1px solid #a5b4fc;
      padding: 1px 7px; border-radius: 3px;
    }
    .s-header-nav { display: flex; align-items: center; gap: 6px; }
    .s-nav-link {
      font-size: 12px; font-weight: 500; color: #475569; text-decoration: none;
      padding: 4px 10px; border-radius: var(--scalar-radius);
      border: 1px solid transparent; transition: all 0.15s;
    }
    .s-nav-link:hover { color: #0f172a; background: #f1f5f9; border-color: #cbd5e1; }
    .s-status-pill {
      display: flex; align-items: center; gap: 6px;
      font-size: 11px; font-weight: 600;
      color: #14532d;
      background: #dcfce7;
      border: 1px solid #86efac;
      padding: 2px 8px; border-radius: 3px;
    }
    .s-pulse { width: 6px; height: 6px; border-radius: 50%; background: var(--scalar-success); animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity: 0.4; } }

    /* ─── Layout ─────────────────────────────────── */
    .s-layout { display: flex; flex: 1; min-height: 0; }

    /* ─── Sidebar ────────────────────────────────── */
    .s-sidebar {
      width: var(--sidebar-width);
      background: var(--scalar-sidebar);
      border-right: 1px solid var(--scalar-border);
      flex-shrink: 0;
      display: flex; flex-direction: column;
      overflow-y: auto; overflow-x: hidden;
      position: sticky; top: var(--header-height);
      height: calc(100vh - var(--header-height));
    }
    .s-sidebar-section { padding: 20px 14px 8px; }
    .s-sidebar-label { font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #475569; padding: 0 6px 8px; }
    .s-sidebar-item {
      display: flex; align-items: center; gap: 8px;
      padding: 7px 10px; border-radius: var(--scalar-radius);
      font-size: 12.5px; font-weight: 500; color: #334155;
      cursor: pointer; transition: all 0.12s; border: 1px solid transparent;
      text-decoration: none;
    }
    .s-sidebar-item:hover { background: #f1f5f9; color: #0f172a; }
    .s-sidebar-item.active { background: #e0e7ff; color: #312e81; border-color: #a5b4fc; font-weight: 600; }
    .s-sidebar-item .item-icon { font-size: 14px; width: 20px; text-align: center; flex-shrink: 0; }
    .s-sidebar-divider { height: 1px; background: var(--scalar-border); margin: 8px 14px; }
    .s-sidebar-presets { padding: 4px 14px 16px; }
    .s-preset-label { font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #475569; padding: 0 6px 8px; }
    .s-preset-btn {
      display: flex; align-items: center; gap: 8px;
      width: 100%; padding: 7px 10px; border-radius: var(--scalar-radius);
      font-size: 12px; font-family: 'JetBrains Mono', monospace; font-weight: 500;
      color: #334155; background: transparent;
      border: 1px solid transparent; cursor: pointer; transition: all 0.12s;
      text-align: left;
    }
    .s-preset-btn:hover { background: #f1f5f9; color: #0f172a; border-color: #cbd5e1; }
    .s-preset-btn .p-dot { width: 6px; height: 6px; border-radius: 2px; flex-shrink: 0; }
    .dot-red { background: #dc2626; }
    .dot-orange { background: #ea580c; }
    .dot-purple { background: #7c3aed; }
    .dot-rose { background: #db2777; }
    .dot-amber { background: #eab308; }
    .dot-green { background: #16a34a; }

    /* ─── Main Content ───────────────────────────── */
    .s-main { flex: 1; min-width: 0; overflow-y: auto; padding: 28px 32px; display: flex; flex-direction: column; gap: 24px; }

    /* ─── Page heading ───────────────────────────── */
    .s-page-title { font-size: 20px; font-weight: 700; letter-spacing: -0.03em; color: var(--scalar-text); }
    .s-page-desc { font-size: 12.5px; color: var(--scalar-text-muted); margin-top: 4px; }

    /* ─── Cards ──────────────────────────────────── */
    .s-card {
      background: var(--scalar-card);
      border: 1px solid var(--scalar-border);
      border-radius: var(--scalar-radius-lg);
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .s-card-header {
      padding: 14px 18px; border-bottom: 1px solid var(--scalar-border);
      display: flex; align-items: center; justify-content: space-between;
    }
    .s-card-title { font-size: 12px; font-weight: 600; color: var(--scalar-text); letter-spacing: -0.01em; }
    .s-card-body { padding: 18px; }

    /* ─── Stats Row ──────────────────────────────── */
    .s-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
    .s-stat {
      background: var(--scalar-card); border: 1px solid var(--scalar-border);
      border-radius: var(--scalar-radius-lg); padding: 16px;
      display: flex; flex-direction: column; gap: 4px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .s-stat-label { font-size: 10.5px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--scalar-text-muted); }
    .s-stat-value { font-size: 28px; font-weight: 700; letter-spacing: -0.04em; color: var(--scalar-text); font-family: 'Inter', sans-serif; }

    /* ─── Risk Score ─────────────────────────────── */
    .s-risk-row { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
    .s-risk-num { font-size: 36px; font-weight: 800; letter-spacing: -0.05em; color: var(--scalar-text); }
    .s-risk-num span { font-size: 14px; font-weight: 400; color: var(--scalar-text-muted); }
    .s-risk-bar-wrap { height: 4px; background: #e2e8f0; border-radius: 2px; overflow: hidden; margin-top: 10px; }
    .s-risk-bar { height: 100%; border-radius: 2px; transition: width 0.5s ease; }
    .s-badge {
      font-family: 'JetBrains Mono', monospace; font-size: 10.5px; font-weight: 700;
      padding: 3px 8px; border-radius: 3px; letter-spacing: 0.05em; text-transform: uppercase;
    }
    .s-badge-safe { background: #dcfce7; color: #15803d; border: 1.5px solid #22c55e; }
    .s-badge-low { background: #f0f9ff; color: #0284c7; border: 1.5px solid #38bdf8; }
    .s-badge-medium { background: #fefce8; color: #a16207; border: 1.5px solid #eab308; }
    .s-badge-high { background: #fee2e2; color: #dc2626; border: 1.5px solid #ef4444; }

    /* ─── Code Editor (Scalar "request body" style) ── */
    .s-editor-bar { background: #f1f5f9; border-radius: var(--scalar-radius-lg) var(--scalar-radius-lg) 0 0; padding: 10px 14px; display: flex; align-items: center; justify-content: space-between; border: 1px solid var(--scalar-border); border-bottom: 1px solid var(--scalar-border); }
    .s-editor-dots { display: flex; gap: 5px; }
    .s-editor-dot { width: 10px; height: 10px; border-radius: 50%; }
    .s-editor-fname { font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--scalar-text-muted); }
    .s-editor-select {
      font-family: 'JetBrains Mono', monospace; font-size: 11px;
      background: #ffffff; color: var(--scalar-text);
      border: 1px solid var(--scalar-border); border-radius: 4px;
      padding: 2px 6px; cursor: pointer; outline: none;
    }
    .s-editor-select:focus { border-color: var(--scalar-accent); }
    textarea#codeInput {
      display: block; width: 100%; min-height: 220px; resize: vertical;
      background: #ffffff; color: #0f172a;
      font-family: 'JetBrains Mono', monospace; font-size: 12.5px; line-height: 1.65;
      border: 1px solid var(--scalar-border); border-top: none;
      border-radius: 0 0 var(--scalar-radius-lg) var(--scalar-radius-lg);
      padding: 14px 16px; outline: none; transition: border-color 0.15s;
    }
    textarea#codeInput:focus { border-color: var(--scalar-accent); }

    /* ─── Action bar ─────────────────────────────── */
    .s-action-bar { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
    .s-checkboxes { display: flex; gap: 16px; }
    .s-check-label { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--scalar-text-muted); cursor: pointer; }
    .s-check-label:hover { color: var(--scalar-text); }
    .s-check-label input[type="checkbox"] { accent-color: var(--scalar-accent); width: 13px; height: 13px; }
    .s-actions { display: flex; align-items: center; gap: 8px; }
    .s-btn-ghost {
      font-size: 12px; color: var(--scalar-text); background: #ffffff;
      border: 1px solid var(--scalar-border); border-radius: var(--scalar-radius);
      padding: 6px 12px; cursor: pointer; transition: all 0.12s; font-family: 'Inter', sans-serif;
    }
    .s-btn-ghost:hover { color: var(--scalar-text); background: var(--scalar-card-hover); }
    .s-btn-primary {
      font-size: 12.5px; font-weight: 500; color: #fff;
      background: #4f5bba; border: 1px solid rgba(255,255,255,0.15);
      border-radius: var(--scalar-radius); padding: 7px 16px;
      cursor: pointer; transition: all 0.12s; display: flex; align-items: center; gap: 7px;
      font-family: 'Inter', sans-serif;
    }
    .s-btn-primary:hover { background: #5e6ad2; border-color: rgba(255,255,255,0.25); transform: translateY(-1px); }
    .s-btn-primary:active { transform: translateY(0); }
    .s-btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }

    /* ─── Chart Canvas ───────────────────────────── */
    #severityChart { max-height: 180px; }

    /* ─── Findings ───────────────────────────────── */
    .s-finding {
      border: 1px solid var(--scalar-border);
      border-left: 4px solid #cbd5e1;
      border-radius: var(--scalar-radius-lg);
      overflow: hidden;
      transition: all 0.15s;
      background: #ffffff;
      box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }
    .s-finding:hover { border-color: var(--scalar-border-strong); box-shadow: 0 4px 6px -1px rgba(0,0,0,0.07); }
    .s-finding.f-critical { border-left: 4px solid #dc2626; }
    .s-finding.f-high { border-left: 4px solid #ea580c; }
    .s-finding.f-medium { border-left: 4px solid #eab308; }
    .s-finding.f-low { border-left: 4px solid #0284c7; }
    .s-finding-head {
      padding: 12px 16px; display: flex; align-items: flex-start;
      justify-content: space-between; gap: 10px;
    }
    .s-finding-title { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .s-sev-badge { font-family: 'JetBrains Mono', monospace; font-size: 10.5px; font-weight: 700; padding: 3px 8px; border-radius: 3px; text-transform: uppercase; letter-spacing: 0.04em; }
    .sev-critical { background: #fef2f2; color: #dc2626; border: 1.5px solid #ef4444; }
    .sev-high { background: #fff7ed; color: #ea580c; border: 1.5px solid #f97316; }
    .sev-medium { background: #fefce8; color: #a16207; border: 1.5px solid #eab308; }
    .sev-low { background: #f0f9ff; color: #0284c7; border: 1.5px solid #38bdf8; }
    .s-finding-name { font-size: 13.5px; font-weight: 700; color: #0f172a; }
    .s-finding-id { font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 600; color: #334155; background: #f1f5f9; border: 1px solid #cbd5e1; padding: 1px 6px; border-radius: 4px; }
    .s-finding-loc { font-family: 'JetBrains Mono', monospace; font-size: 11px; font-weight: 600; color: #475569; flex-shrink: 0; }
    .s-finding-body { padding: 0 16px 14px; display: flex; flex-direction: column; gap: 10px; }
    .s-finding-desc { font-size: 13px; color: #334155; line-height: 1.65; }
    .s-code-block {
      background: #f8fafc; border: 1px solid var(--scalar-border);
      border-radius: var(--scalar-radius); padding: 12px 14px;
      font-family: 'JetBrains Mono', monospace; font-size: 11.5px;
      color: #1e293b; overflow-x: auto; white-space: pre; line-height: 1.6;
    }
    .s-code-label { font-size: 11px; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; color: #475569; margin-bottom: 6px; }
    .s-rec { display: flex; gap: 8px; padding: 10px 14px; background: #eff6ff; border: 1px solid #bfdbfe; border-radius: var(--scalar-radius); }
    .s-rec-icon { font-size: 14px; flex-shrink: 0; }
    .s-rec-text { font-size: 12.5px; color: #1e3a8a; line-height: 1.6; }
    .s-remediation { margin-top: 8px; }
    .s-rem-toggle { display: flex; align-items: center; justify-content: space-between; padding: 10px 0 10px; border-top: 1px solid var(--scalar-border); cursor: pointer; }
    .s-rem-title { font-size: 11px; font-weight: 600; letter-spacing: 0.04em; text-transform: uppercase; color: var(--scalar-success); display: flex; align-items: center; gap: 5px; }
    .s-rem-toggle-btn { font-size: 11px; color: var(--scalar-text-muted); background: none; border: none; cursor: pointer; padding: 2px 8px; border-radius: 3px; transition: background 0.1s; }
    .s-rem-toggle-btn:hover { background: rgba(255,255,255,0.05); color: var(--scalar-text); }
    .diff-add { color: #14532d; background: #dcfce7; font-weight: 500; display: inline-block; width: 100%; }
    .diff-rem { color: #7f1d1d; background: #fee2e2; font-weight: 500; display: inline-block; width: 100%; }
    .diff-meta { color: #312e81; font-weight: 600; }

    /* ─── Empty state ────────────────────────────── */
    .s-empty {
      padding: 48px 24px; text-align: center;
      border: 1px dashed var(--scalar-border); border-radius: var(--scalar-radius-lg);
      color: var(--scalar-text-muted);
    }
    .s-empty-icon { font-size: 32px; display: block; margin-bottom: 12px; }
    .s-empty-title { font-size: 14px; font-weight: 500; color: var(--scalar-text); }
    .s-empty-desc { font-size: 12px; margin-top: 4px; }

    /* ─── 2-col grid ─────────────────────────────── */
    .s-grid { display: grid; grid-template-columns: 1fr 320px; gap: 20px; align-items: start; }

    /* ─── Print ──────────────────────────────────── */
    @media print {
      .s-sidebar, .s-header { display: none !important; }
      .s-main { padding: 24px; }
      .s-card { border: 1px solid #ccc !important; }
    }

    /* ─── Mobile ─────────────────────────────────── */
    @media (max-width: 900px) {
      .s-sidebar { display: none; }
      .s-grid { grid-template-columns: 1fr; }
      .s-stats { grid-template-columns: repeat(2, 1fr); }
    }
  </style>
</head>
<body>

  <!-- ═══ HEADER (Scalar topbar) ═══ -->
  <header class="s-header">
    <a class="s-header-logo" href="/dashboard">
      <img src="data:image/png;base64,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" alt="VulX Logo" class="s-logo-img">
      <span class="s-logo-name">VulX</span>
      <span class="s-logo-badge">SAST Live</span>
    </a>
    <nav class="s-header-nav">
      <div class="s-status-pill">
        <span class="s-pulse"></span>AST Online
      </div>
      <a class="s-nav-link" href="/documentation" target="_blank">Swagger UI</a>
      <a class="s-nav-link" href="/docs/scalar" target="_blank">Scalar</a>
      <button class="s-nav-link" style="cursor:pointer;" onclick="window.print()"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:5px;"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>PDF</button>
    </nav>
  </header>


  <!-- ═══ BODY LAYOUT (Scalar: sidebar + main) ═══ -->
  <div class="s-layout">

    <!-- SIDEBAR -->
    <aside class="s-sidebar">

      <div class="s-sidebar-section">
        <div class="s-sidebar-label">Escenarios</div>
        <div class="s-sidebar-presets">
          <button class="s-preset-btn" onclick="loadPreset('sqli')">
            <span class="p-dot dot-red"></span>SQL Injection
          </button>
          <button class="s-preset-btn" onclick="loadPreset('xss')">
            <span class="p-dot dot-orange"></span>DOM XSS
          </button>
          <button class="s-preset-btn" onclick="loadPreset('pathtraversal')">
            <span class="p-dot dot-purple"></span>Path Traversal
          </button>
          <button class="s-preset-btn" onclick="loadPreset('cmdi')">
            <span class="p-dot dot-rose"></span>Command Injection
          </button>
          <button class="s-preset-btn" onclick="loadPreset('secrets')">
            <span class="p-dot dot-amber"></span>Hardcoded Secret
          </button>
          <button class="s-preset-btn" onclick="loadPreset('clean')">
            <span class="p-dot dot-green"></span>Código Limpio
          </button>
        </div>
      </div>

      <div class="s-sidebar-divider"></div>

      <div class="s-sidebar-section">
        <div class="s-sidebar-label">Métricas</div>
        <div style="padding: 0 6px;">
          <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 4px; border-bottom:1px solid var(--scalar-border);">
            <span style="font-size:12px; color:var(--scalar-text-muted);">Total hallazgos</span>
            <span id="sbTotal" style="font-family:'JetBrains Mono',monospace; font-size:13px; font-weight:700; color:var(--scalar-text);">0</span>
          </div>
          <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 4px; border-bottom:1px solid var(--scalar-border);">
            <span style="font-size:12px; font-weight:600; color:#dc2626;">Críticas</span>
            <span id="sbCritical" style="font-family:'JetBrains Mono',monospace; font-size:13px; font-weight:700; color:#dc2626;">0</span>
          </div>
          <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 4px; border-bottom:1px solid var(--scalar-border);">
            <span style="font-size:12px; font-weight:600; color:#ea580c;">Altas</span>
            <span id="sbHigh" style="font-family:'JetBrains Mono',monospace; font-size:13px; font-weight:700; color:#ea580c;">0</span>
          </div>
          <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 4px; border-bottom:1px solid var(--scalar-border);">
            <span style="font-size:12px; font-weight:600; color:#a16207;">Medias</span>
            <span id="sbMedium" style="font-family:'JetBrains Mono',monospace; font-size:13px; font-weight:700; color:#a16207;">0</span>
          </div>
          <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 4px;">
            <span style="font-size:12px; color:var(--scalar-text-muted);">Latencia</span>
            <span id="sbDuration" style="font-family:'JetBrains Mono',monospace; font-size:13px; font-weight:700; color:#0284c7;">0ms</span>
          </div>
        </div>
      </div>

      <div class="s-sidebar-divider"></div>

      <div class="s-sidebar-section">
        <div class="s-sidebar-label">API Docs</div>
        <a href="/documentation" target="_blank" class="s-sidebar-item">
          <span class="item-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path></svg></span> Swagger UI
        </a>
        <a href="/docs/scalar" target="_blank" class="s-sidebar-item active">
          <span class="item-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg></span> Scalar Reference
        </a>
        <a href="/docs/openapi.yaml" target="_blank" class="s-sidebar-item">
          <span class="item-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg></span> OpenAPI YAML
        </a>
        <a href="/health" target="_blank" class="s-sidebar-item">
          <span class="item-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><path d="M22 12h-4l-3 9L9 3l-3 9H2"></path></svg></span> Health Check
        </a>
      </div>

    </aside>

    <!-- MAIN CONTENT -->
    <main class="s-main">

      <!-- Page Heading -->
      <div>
        <h2 class="s-page-title"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:8px;display:inline-block;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>Security Audit Dashboard</h2>
        <p class="s-page-desc">Analizador SAST en tiempo real — AST Engine + Tree-sitter + Remediación Inteligente</p>
      </div>

      <!-- Stats Row -->
      <div class="s-stats">
        <div class="s-stat">
          <span class="s-stat-label">Risk Score</span>
          <span class="s-stat-value" id="riskScoreNum">0.0<span style="font-size:14px; color:var(--scalar-text-muted); font-weight:400;"> / 10</span></span>
        </div>
        <div class="s-stat" style="border-color: #fca5a5; background: #fffdfd;">
          <span class="s-stat-label" style="color:var(--scalar-danger);">Críticas</span>
          <span class="s-stat-value" style="color:var(--scalar-danger);" id="metricCritical">0</span>
        </div>
        <div class="s-stat" style="border-color: #fdba74; background: #fffdfb;">
          <span class="s-stat-label" style="color:var(--scalar-high);">Altas</span>
          <span class="s-stat-value" style="color:var(--scalar-high);" id="metricHigh">0</span>
        </div>
        <div class="s-stat">
          <span class="s-stat-label">Latencia</span>
          <span class="s-stat-value" style="color:var(--scalar-accent);" id="metricDuration">0<span style="font-size:14px; font-weight:400; color:var(--scalar-text-muted);">ms</span></span>
        </div>
      </div>

      <!-- 2-Column Grid: Editor + Risk Panel -->
      <div class="s-grid">

        <!-- Left: Code Editor -->
        <div>
          <!-- Editor Bar -->
          <div class="s-editor-bar">
            <div style="display:flex; align-items:center; gap:10px;">
              <div class="s-editor-dots">
                <span class="s-editor-dot" style="background:#ff5f57;"></span>
                <span class="s-editor-dot" style="background:#febc2e;"></span>
                <span class="s-editor-dot" style="background:#28c840;"></span>
              </div>
              <span class="s-editor-fname" id="currentFileName">vulnerable-code.js</span>
            </div>
            <select id="languageSelect" class="s-editor-select">
              <option value="javascript">JavaScript</option>
              <option value="typescript">TypeScript</option>
            </select>
          </div>
          <textarea id="codeInput" placeholder="// Pega aquí el código fuente a auditar, o selecciona un escenario en el panel izquierdo..."></textarea>

          <!-- Action bar -->
          <div class="s-action-bar" style="margin-top:12px;">
            <div class="s-checkboxes">
              <label class="s-check-label">
                <input type="checkbox" id="remediationCheck" checked>
                Remediación
              </label>
              <label class="s-check-label">
                <input type="checkbox" id="deepScanCheck">
                Deep Scan (IA)
              </label>
            </div>
            <div class="s-actions">
              <button class="s-btn-ghost" onclick="clearEditor()">Limpiar</button>
              <button class="s-btn-primary" id="scanButton" onclick="runLiveScan()">
                <span id="scanBtnIcon"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg></span>
                <span id="scanBtnText">Escanear en Vivo</span>
              </button>
            </div>
          </div>
        </div>

        <!-- Right: Risk Score + Chart -->
        <div style="display:flex; flex-direction:column; gap:16px;">

          <!-- Risk Score Card -->
          <div class="s-card">
            <div class="s-card-header">
              <span class="s-card-title">Índice de Riesgo</span>
              <span class="s-badge s-badge-safe" id="riskBadge">Seguro</span>
            </div>
            <div class="s-card-body">
              <div class="s-risk-row">
                <div class="s-risk-num" id="riskScoreDisplay">0.0<span> / 10</span></div>
              </div>
              <div class="s-risk-bar-wrap">
                <div class="s-risk-bar" id="riskBar" style="width:0%; background:var(--scalar-success);"></div>
              </div>
              <p id="riskDescription" style="font-size:11.5px; color:var(--scalar-text-muted); margin-top:10px; line-height:1.6;">
                Sin análisis. Carga un escenario o escribe código.
              </p>
            </div>
          </div>

          <!-- Severity Chart -->
          <div class="s-card">
            <div class="s-card-header">
              <span class="s-card-title">Distribución por Severidad</span>
              <span id="findingsCountBadge" style="font-family:'JetBrains Mono',monospace; font-size:10px; color:var(--scalar-text-muted); background:var(--scalar-card); border:1px solid var(--scalar-border); padding:2px 8px; border-radius:4px;">0 hallazgos</span>
            </div>
            <div class="s-card-body" style="display:flex; flex-direction:column; align-items:center; gap:14px;">
              <canvas id="severityChart"></canvas>
              <div style="display:flex; gap:14px; flex-wrap:wrap; justify-content:center;">
                <span style="font-size:11.5px; font-weight:700; color:#dc2626; display:flex; align-items:center; gap:5px;"><span style="width:8px;height:8px;border-radius:2px;background:#dc2626;display:inline-block;"></span>Crítico</span>
                <span style="font-size:11.5px; font-weight:700; color:#ea580c; display:flex; align-items:center; gap:5px;"><span style="width:8px;height:8px;border-radius:2px;background:#ea580c;display:inline-block;"></span>Alto</span>
                <span style="font-size:11.5px; font-weight:700; color:#a16207; display:flex; align-items:center; gap:5px;"><span style="width:8px;height:8px;border-radius:2px;background:#eab308;display:inline-block;"></span>Medio</span>
                <span style="font-size:11.5px; font-weight:700; color:#0284c7; display:flex; align-items:center; gap:5px;"><span style="width:8px;height:8px;border-radius:2px;background:#0284c7;display:inline-block;"></span>Bajo</span>
              </div>
            </div>
          </div>

        </div>
      </div>

      <!-- Findings Section -->
      <div>
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:14px;">
          <div>
            <h3 style="font-size:14px; font-weight:600; color:var(--scalar-text); letter-spacing:-0.02em;">Hallazgos de Seguridad</h3>
            <p style="font-size:11.5px; color:var(--scalar-text-muted); margin-top:2px;">Clasificación CWE, fragmentos vulnerables y Quick Fixes automáticos</p>
          </div>
        </div>
        <div id="findingsContainer">
          <div class="s-empty">
            <span class="s-empty-icon"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;opacity:0.5;margin-bottom:8px;"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg></span>
            <p class="s-empty-title">Sin análisis activo</p>
            <p class="s-empty-desc">Selecciona un escenario en el panel izquierdo o escribe código para auditar.</p>
          </div>
        </div>
      </div>

      <!-- Footer -->
      <div style="border-top:1px solid var(--scalar-border); padding-top:16px; display:flex; justify-content:space-between; align-items:center;">
        <span style="font-size:11px; color:var(--scalar-text-faint);">VulX Security Engine v1.0.0 — Fastify REST API + Tree-sitter AST Core</span>
        <span style="font-family:'JetBrains Mono',monospace; font-size:10px; color:var(--scalar-text-faint);">http://127.0.0.1:3000</span>
      </div>

    </main>
  </div>

  <script>
    let severityChartInstance = null;

    const PRESETS = {
      sqli: {
        file: 'authController.js', lang: 'javascript',
        code: \`// Vulnerabilidad: Inyección SQL (CWE-89)
const express = require('express');
const db = require('./database');
const app = express();

app.post('/api/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Concatenación directa de entradas de usuario en consulta SQL
  const query = "SELECT * FROM users WHERE user = '" + username + "' AND pass = '" + password + "'";
  
  db.query(query, (err, results) => {
    if (err) return res.status(500).send("Error");
    res.json(results);
  });
});\`
      },
      xss: {
        file: 'userProfile.js', lang: 'javascript',
        code: \`// Vulnerabilidad: DOM Cross-Site Scripting (CWE-79)
function renderUserProfile(userData) {
  const container = document.getElementById('user-bio');
  
  // Asignación directa e insegura al innerHTML
  container.innerHTML = "<div><h3>" + userData.name + "</h3><p>" + userData.bio + "</p></div>";
}\`
      },
      pathtraversal: {
        file: 'fileServer.js', lang: 'javascript',
        code: \`// Vulnerabilidad: Path Traversal (CWE-22)
const fs = require('fs');
const path = require('path');

function getDocument(req, res) {
  const filename = req.query.file;
  const fullPath = path.join('/var/www/uploads', filename);
  const content = fs.readFileSync(fullPath, 'utf8');
  res.send(content);
}\`
      },
      cmdi: {
        file: 'networkTools.js', lang: 'javascript',
        code: \`// Vulnerabilidad: OS Command Injection (CWE-78)
const { exec } = require('child_process');

function pingHost(req, res) {
  const targetHost = req.body.host;
  exec("ping -c 3 " + targetHost, (err, stdout) => {
    res.send(stdout);
  });
}\`
      },
      secrets: {
        file: 'config.js', lang: 'javascript',
        code: \`// Vulnerabilidad: Hardcoded Secrets (CWE-798)
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const JWT_SECRET = "super_secret_jwt_token_12345";
module.exports = { AWS_ACCESS_KEY, AWS_SECRET_KEY, JWT_SECRET };\`
      },
      clean: {
        file: 'secureAuth.js', lang: 'javascript',
        code: \`// Código Seguro: Buenas prácticas de seguridad
const db = require('./database');

async function authenticateUser(username, passwordHash) {
  const query = "SELECT id, username FROM users WHERE user = ? AND pass_hash = ?";
  const [rows] = await db.execute(query, [username, passwordHash]);
  return rows[0] || null;
}

function renderSafeProfile(container, safeText) {
  container.textContent = safeText;
}\`
      }
    };

    function loadPreset(key) {
      const preset = PRESETS[key];
      if (!preset) return;
      document.getElementById('codeInput').value = preset.code;
      document.getElementById('currentFileName').innerText = preset.file;
      document.getElementById('languageSelect').value = preset.lang;
      runLiveScan();
    }

    function clearEditor() {
      document.getElementById('codeInput').value = '';
      document.getElementById('currentFileName').innerText = 'custom-code.js';
      resetDashboard();
    }

    function resetDashboard() {
      document.getElementById('metricCritical').innerText = '0';
      document.getElementById('metricHigh').innerHTML = '0';
      document.getElementById('metricDuration').innerHTML = '0<span style="font-size:14px; font-weight:400; color:var(--scalar-text-muted);">ms</span>';
      document.getElementById('riskScoreNum').innerHTML = '0.0<span style="font-size:14px; color:var(--scalar-text-muted); font-weight:400;"> / 10</span>';
      document.getElementById('riskScoreDisplay').innerHTML = '0.0<span> / 10</span>';
      document.getElementById('sbTotal').innerText = '0';
      document.getElementById('sbCritical').innerText = '0';
      document.getElementById('sbHigh').innerText = '0';
      document.getElementById('sbMedium').innerText = '0';
      document.getElementById('sbDuration').innerText = '0ms';
      document.getElementById('riskBadge').innerText = 'Seguro';
      document.getElementById('riskBadge').className = 's-badge s-badge-safe';
      document.getElementById('riskBar').style.width = '0%';
      document.getElementById('riskBar').style.background = 'var(--scalar-success)';
      document.getElementById('riskDescription').innerText = 'Sin análisis. Carga un escenario o escribe código.';
      document.getElementById('findingsCountBadge').innerText = '0 hallazgos';
      document.getElementById('findingsContainer').innerHTML = \`
        <div class="s-empty">
          <span class="s-empty-icon"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;opacity:0.5;margin-bottom:8px;"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg></span>
          <p class="s-empty-title">Sin análisis activo</p>
          <p class="s-empty-desc">Selecciona un escenario en el panel izquierdo o escribe código para auditar.</p>
        </div>\`;
      updateChart(0, 0, 0, 0);
    }

    function initChart() {
      const ctx = document.getElementById('severityChart').getContext('2d');
      severityChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ['Crítico', 'Alto', 'Medio', 'Bajo'],
          datasets: [{
            data: [0, 0, 0, 1],
            backgroundColor: ['#f1f5f9','#f1f5f9','#f1f5f9','#f1f5f9'],
            borderWidth: 2,
            borderColor: '#ffffff',
            hoverOffset: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          cutout: '76%'
        }
      });
    }

    function updateChart(critical, high, medium, low) {
      if (!severityChartInstance) return;
      const total = critical + high + medium + low;
      if (total === 0) {
        severityChartInstance.data.datasets[0].data = [0, 0, 0, 1];
        severityChartInstance.data.datasets[0].backgroundColor = ['#f1f5f9','#f1f5f9','#f1f5f9','#f1f5f9'];
      } else {
        severityChartInstance.data.datasets[0].data = [critical, high, medium, low];
        severityChartInstance.data.datasets[0].backgroundColor = ['#dc2626', '#ea580c', '#eab308', '#0284c7'];
      }
      severityChartInstance.update();
    }

    async function runLiveScan() {
      const code = document.getElementById('codeInput').value.trim();
      if (!code) { alert('Ingresa código antes de analizar.'); return; }

      const scanBtn = document.getElementById('scanButton');
      const scanBtnIcon = document.getElementById('scanBtnIcon');
      const scanBtnText = document.getElementById('scanBtnText');
      const language = document.getElementById('languageSelect').value;
      const includeRemediation = document.getElementById('remediationCheck').checked;
      const deepScan = document.getElementById('deepScanCheck').checked;

      scanBtn.disabled = true;
      scanBtnIcon.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="animation:spin 1s linear infinite;vertical-align:middle;"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>';
      scanBtnText.innerText = 'Analizando...';

      const startTime = performance.now();

      try {
        const response = await fetch('/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code, language, includeRemediation, deepScan })
        });
        const data = await response.json();
        const duration = Math.round(performance.now() - startTime);
        if (response.ok && data.status === 'success') {
          renderAnalysisResults(data.analysis, duration);
        } else {
          alert('Error: ' + (data.message || 'Error desconocido'));
        }
      } catch (err) {
        console.error(err);
        alert('No se pudo conectar con el servidor VulX en http://127.0.0.1:3000');
      } finally {
        scanBtn.disabled = false;
        scanBtnIcon.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>';
        scanBtnText.innerText = 'Escanear en Vivo';
      }
    }

    function renderAnalysisResults(analysis, duration) {
      const summary = analysis.summary || { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
      const vulns = analysis.vulnerabilities || [];
      const dur = summary.durationMs || duration;

      // Sidebar metrics
      document.getElementById('sbTotal').innerText = summary.total;
      document.getElementById('sbCritical').innerText = summary.critical;
      document.getElementById('sbHigh').innerText = summary.high;
      document.getElementById('sbMedium').innerText = summary.medium;
      document.getElementById('sbDuration').innerText = dur + 'ms';

      // Top stats
      document.getElementById('metricCritical').innerText = summary.critical;
      document.getElementById('metricHigh').innerHTML = summary.high;
      document.getElementById('metricDuration').innerHTML = dur + '<span style="font-size:14px; font-weight:400; color:var(--scalar-text-muted);">ms</span>';
      document.getElementById('findingsCountBadge').innerText = summary.total + ' hallazgos';

      updateChart(summary.critical, summary.high, summary.medium, summary.low);

      // Risk Score
      const rawScore = (summary.critical * 3.5) + (summary.high * 2.0) + (summary.medium * 1.0) + (summary.low * 0.5);
      const score = Math.min(10, Math.round(rawScore * 10) / 10);
      const pct = Math.min(100, Math.round((score / 10) * 100));

      document.getElementById('riskScoreNum').innerHTML = score.toFixed(1) + '<span style="font-size:14px; color:var(--scalar-text-muted); font-weight:400;"> / 10</span>';
      document.getElementById('riskScoreDisplay').innerHTML = score.toFixed(1) + '<span> / 10</span>';
      document.getElementById('riskBar').style.width = pct + '%';

      const badge = document.getElementById('riskBadge');
      const bar = document.getElementById('riskBar');
      const desc = document.getElementById('riskDescription');

      if (score === 0) {
        badge.innerText = 'Seguro'; badge.className = 's-badge s-badge-safe';
        bar.style.background = 'var(--scalar-success)';
        desc.innerText = 'Código limpio. No se detectaron vulnerabilidades conocidas.';
      } else if (score < 4.0) {
        badge.innerText = 'Riesgo Bajo'; badge.className = 's-badge s-badge-low';
        bar.style.background = '#0284c7';
        desc.innerText = 'Alertas menores detectadas. Revisar antes del despliegue.';
      } else if (score < 7.0) {
        badge.innerText = 'Riesgo Medio'; badge.className = 's-badge s-badge-medium';
        bar.style.background = '#eab308';
        desc.innerText = 'Vulnerabilidades que pueden comprometer la aplicación.';
      } else {
        badge.innerText = 'Riesgo Crítico'; badge.className = 's-badge s-badge-high';
        bar.style.background = '#dc2626';
        desc.innerText = '¡Crítico! Vulnerabilidades severas que requieren remediación inmediata.';
      }

      // Render findings
      const container = document.getElementById('findingsContainer');
      if (vulns.length === 0) {
        container.innerHTML = \`
          <div class="s-empty" style="border-color:#bbf7d0; background:#f0fdf4;">
            <span class="s-empty-icon"><svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;margin-bottom:8px;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg></span>
            <p class="s-empty-title" style="color:#14532d; font-weight:700;">¡Código Libre de Vulnerabilidades!</p>
            <p class="s-empty-desc" style="color:#166534;">El análisis no encontró fallas de inyección, XSS, secretos ni traversal.</p>
          </div>\`;
        return;
      }

      container.innerHTML = vulns.map((v, idx) => {
        const sevClass = { critical:'sev-critical', high:'sev-high', medium:'sev-medium', low:'sev-low' }[v.severity] || 'sev-low';
        const rem = v.remediation;
        return \`
          <div class="s-finding">
            <div class="s-finding-head">
              <div class="s-finding-title">
                <span class="s-sev-badge \${sevClass}">\${v.severity}</span>
                <span class="s-finding-name">\${v.name}</span>
                <span class="s-finding-id">\${v.id}</span>
              </div>
              <span class="s-finding-loc">L\${v.line}:\${v.column}</span>
            </div>
            <div class="s-finding-body">
              <p class="s-finding-desc">\${v.description}</p>

              \${v.codeSnippet ? \`
                <div>
                  <div class="s-code-label" style="color:var(--scalar-danger);">Fragmento vulnerable</div>
                  <div class="s-code-block" style="border-color:rgba(239,68,68,0.15); color:#fca5a5;">\${escapeHtml(v.codeSnippet)}</div>
                </div>
              \` : ''}

              \${v.recommendation ? \`
                <div class="s-rec">
                  <span class="s-rec-icon"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;margin-top:2px;"><path d="M9 18h6"></path><path d="M10 22h4"></path><path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 0 1 8.91 14"></path></svg></span>
                  <span class="s-rec-text"><strong style="color:#1d4ed8;">Recomendación:</strong> \${v.recommendation}</span>
                </div>
              \` : ''}

              \${rem ? \`
                <div class="s-remediation">
                  <div class="s-rem-toggle" onclick="toggleRemediation('rem-\${idx}')">
                    <span class="s-rem-title"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;margin-right:5px;"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>Quick Fix — Remediación automática</span>
                    <button class="s-rem-toggle-btn">alternar ↕</button>
                  </div>
                  <div id="rem-\${idx}" style="display:flex; flex-direction:column; gap:10px;">
                    \${rem.explanation ? \`<p style="font-size:11.5px; color:var(--scalar-text-muted); font-style:italic;">\${rem.explanation}</p>\` : ''}
                    \${rem.fixedSnippet ? \`
                      <div>
                        <div class="s-code-label" style="color:var(--scalar-success);">Código seguro sugerido</div>
                        <div class="s-code-block" style="border-color:rgba(34,197,94,0.15); color:#86efac;">\${escapeHtml(rem.fixedSnippet)}</div>
                      </div>
                    \` : ''}
                    \${rem.diff ? \`
                      <div>
                        <div class="s-code-label">Diff de remediación</div>
                        <div class="s-code-block">\${formatDiff(rem.diff)}</div>
                      </div>
                    \` : ''}
                  </div>
                </div>
              \` : ''}
            </div>
          </div>\`;
      }).join('');
    }

    function toggleRemediation(id) {
      const el = document.getElementById(id);
      if (el) el.style.display = el.style.display === 'none' ? 'flex' : 'none';
    }

    function escapeHtml(str) {
      if (!str) return '';
      return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    function formatDiff(diffText) {
      if (!diffText) return '';
      return escapeHtml(diffText).split('\\n').map(line => {
        if (line.startsWith('+')) return '<span class="diff-add">' + line + '</span>';
        if (line.startsWith('-')) return '<span class="diff-rem">' + line + '</span>';
        if (line.startsWith('@')) return '<span class="diff-meta">' + line + '</span>';
        return line;
      }).join('\\n');
    }

    window.addEventListener('DOMContentLoaded', () => {
      initChart();
      loadPreset('sqli');
    });
  </script>
</body>
</html>`;
}

/**
 * Genera un reporte HTML autónomo e imprimible a partir de un resultado de análisis previo
 */
export function generateStaticHtmlReport(
  analysis: any,
  originalCode: string,
  filePath: string
): string {
  const summary = analysis.summary || { total: 0, critical: 0, high: 0, medium: 0, low: 0, durationMs: 0 };
  const vulns = analysis.vulnerabilities || [];
  const timestamp = new Date().toLocaleString('es-ES', { dateStyle: 'full', timeStyle: 'medium' });

  const rawScore = (summary.critical * 3.5) + (summary.high * 2.0) + (summary.medium * 1.0) + (summary.low * 0.5);
  const score = Math.min(10, Math.round(rawScore * 10) / 10);

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>VulX — Informe Ejecutivo de Auditoría SAST</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }
    .container { max-width: 900px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 32px; border: 1px solid #334155; }
    h1 { margin: 0; font-size: 24px; color: #ffffff; }
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #334155; padding-bottom: 16px; margin-bottom: 24px; }
    .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
    .stat-card { background: #0f172a; padding: 16px; border-radius: 8px; text-align: center; border: 1px solid #334155; }
    .stat-num { font-size: 28px; font-weight: bold; margin-top: 4px; }
    .critical { color: #ef4444; }
    .high { color: #f59e0b; }
    .vuln-item { background: #0f172a; border-radius: 8px; padding: 16px; margin-bottom: 16px; border-left: 4px solid #ef4444; }
    pre { background: #020617; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 13px; color: #e2e8f0; }
    @media print {
      body { background: #fff !important; color: #000 !important; }
      .container { background: #fff !important; border: none !important; padding: 0 !important; color: #000 !important; }
      .vuln-item, .stat-card { background: #f8fafc !important; color: #000 !important; border: 1px solid #cbd5e1 !important; }
      pre { background: #f1f5f9 !important; color: #0f172a !important; border: 1px solid #cbd5e1 !important; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <div style="display:flex; align-items:center; gap:12px;"><img src="data:image/png;base64,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" alt="VulX" style="width:38px;height:38px;border-radius:8px;object-fit:contain;"><h1>VulX — Informe de Seguridad SAST</h1></div>
        <p style="color: #94a3b8; font-size: 13px; margin-top: 4px;">Archivo auditado: <strong>${filePath}</strong></p>
      </div>
      <div style="text-align: right; font-size: 12px; color: #94a3b8;">
        <div>Fecha: ${timestamp}</div>
        <div>Score de Riesgo: <strong style="color: #ef4444; font-size: 16px;">${score}/10</strong></div>
      </div>
    </div>

    <div class="stats">
      <div class="stat-card">
        <div style="font-size: 11px; text-transform: uppercase; color: #94a3b8;">Total Hallazgos</div>
        <div class="stat-num">${summary.total}</div>
      </div>
      <div class="stat-card">
        <div style="font-size: 11px; text-transform: uppercase; color: #ef4444;">Críticas</div>
        <div class="stat-num critical">${summary.critical}</div>
      </div>
      <div class="stat-card">
        <div style="font-size: 11px; text-transform: uppercase; color: #f59e0b;">Altas</div>
        <div class="stat-num high">${summary.high}</div>
      </div>
      <div class="stat-card">
        <div style="font-size: 11px; text-transform: uppercase; color: #38bdf8;">Tiempo</div>
        <div class="stat-num" style="color: #38bdf8;">${summary.durationMs || 0}ms</div>
      </div>
    </div>

    <h2>Detalle de Hallazgos</h2>
    ${vulns.length === 0 ? '<p style="color: #10b981;">No se identificaron vulnerabilidades en el archivo analizado.</p>' : ''}
    ${vulns.map((v: any) => `
      <div class="vuln-item">
        <div style="display: flex; justify-content: space-between;">
          <strong>${v.name} (${v.id})</strong>
          <span style="font-size: 12px; color: #94a3b8;">Línea ${v.line}:${v.column}</span>
        </div>
        <p style="font-size: 13px; margin: 8px 0; color: #cbd5e1;">${v.description}</p>
        ${v.codeSnippet ? `<pre>${v.codeSnippet}</pre>` : ''}
        ${v.recommendation ? `<p style="font-size: 12px; color: #38bdf8;"><strong>Recomendación:</strong> ${v.recommendation}</p>` : ''}
      </div>
    `).join('')}
  </div>
</body>
</html>`;
}
