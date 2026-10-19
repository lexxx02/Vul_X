import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAnalyzer } from '../core/Analyzer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  const samplePath = path.resolve(__dirname, '../samples/vulnerable-sample.js');
  const code = fs.readFileSync(samplePath, 'utf-8');

  console.log('\n================================================================');
  console.log(' 🛡️  VULX SECURITY ANALYZER — DEMOSTRACIÓN EN VIVO (AVANCE 2)');
  console.log('================================================================');
  console.log(`📄 Archivo analizado: ${path.basename(samplePath)}`);
  console.log(`📏 Tamaño: ${code.length} bytes | Lenguaje: javascript\n`);

  const analyzer = createAnalyzer({ timeoutMs: 3000 });
  const result = await analyzer.analyze({
    code,
    language: 'javascript',
    filePath: samplePath,
    includeRemediation: true,
  });

  console.log('────────────────────────────────────────────────────────────────');
  console.log('📊 RESUMEN DE HALLAZGOS:');
  console.log(`   Total de vulnerabilidades: ${result.summary.total}`);
  console.log(`   🚨 Críticas: ${result.summary.critical}`);
  console.log(`   ⚠️  Altas:    ${result.summary.high}`);
  console.log(`   ⚡ Medias:   ${result.summary.medium}`);
  console.log(`   ℹ️  Bajas:    ${result.summary.low}`);
  console.log(`   ⏱️  Tiempo de análisis: ${result.summary.durationMs}ms`);
  console.log('────────────────────────────────────────────────────────────────\n');

  result.vulnerabilities.forEach((vuln, index) => {
    console.log(`[${index + 1}] [${vuln.severity.toUpperCase()}] ${vuln.name} (${vuln.id})`);
    console.log(`    📍 Línea: ${vuln.line}, Columna: ${vuln.column}`);
    console.log(`    🔍 Código detectado: ${vuln.codeSnippet.replace(/\n\s*/g, ' ')}`);
    console.log(`    📝 Descripción: ${vuln.description}`);
    console.log(`    💡 Recomendación: ${vuln.recommendation}`);

    if (vuln.remediation) {
      console.log(`    🛠️  Explicación de parche: ${vuln.remediation.explanation}`);
      console.log('    📄 Diff propuesto:');
      vuln.remediation.diff.split('\n').forEach((line) => {
        if (line.startsWith('+')) console.log(`       \x1b[32m${line}\x1b[0m`);
        else if (line.startsWith('-')) console.log(`       \x1b[31m${line}\x1b[0m`);
        else console.log(`       ${line}`);
      });
    }
    console.log('');
  });

  console.log('================================================================');
  console.log(' ✅ Análisis completado con éxito.');
  console.log('================================================================\n');
}

main().catch(console.error);
