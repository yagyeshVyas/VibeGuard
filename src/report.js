'use strict';

/*
 * Rendering: human report (colored), JSON, SARIF, and the copy-paste fix prompt.
 * No dependencies — colors are raw ANSI, disabled when not a TTY or NO_COLOR set.
 */

const path = require('path');

const useColor =
  process.stdout.isTTY && !process.env.NO_COLOR && process.env.TERM !== 'dumb';

const C = {
  reset: useColor ? '\x1b[0m' : '',
  bold: useColor ? '\x1b[1m' : '',
  dim: useColor ? '\x1b[2m' : '',
  red: useColor ? '\x1b[31m' : '',
  green: useColor ? '\x1b[32m' : '',
  yellow: useColor ? '\x1b[33m' : '',
  blue: useColor ? '\x1b[34m' : '',
  magenta: useColor ? '\x1b[35m' : '',
  cyan: useColor ? '\x1b[36m' : '',
  gray: useColor ? '\x1b[90m' : '',
};

const SEV_STYLE = {
  critical: { color: C.red, label: 'CRITICAL' },
  high: { color: C.magenta, label: 'HIGH' },
  medium: { color: C.yellow, label: 'MEDIUM' },
  low: { color: C.blue, label: 'LOW' },
};

const GRADE_COLOR = {
  A: C.green, B: C.green, C: C.yellow, D: C.yellow, F: C.red,
};

function severityBadge(sev) {
  const s = SEV_STYLE[sev] || { color: C.gray, label: sev.toUpperCase() };
  return `${s.color}${C.bold}${s.label.padEnd(8)}${C.reset}`;
}

// -------- Human report -----------------------------------------------------

function renderHuman(result) {
  const lines = [];
  lines.push('');
  lines.push(`${C.bold}${C.cyan}VibeGuard${C.reset} ${C.dim}security scan${C.reset}`);
  lines.push(`${C.dim}${result.root}${C.reset}`);
  lines.push('');

  if (result.findings.length === 0) {
    lines.push(`${C.green}${C.bold}No issues found across ${result.scannedFiles} files.${C.reset}`);
  } else {
    for (const f of result.findings) {
      const loc = `${f.file}:${f.line}:${f.column}`;
      const conf =
        f.confidence === 'low'
          ? ` ${C.yellow}⚑ review${C.reset}`
          : f.confidence === 'medium'
          ? ` ${C.dim}⚑ likely${C.reset}`
          : '';
      lines.push(
        `${severityBadge(f.severity)} ${C.bold}${loc}${C.reset}${conf} ${C.dim}[${f.ruleId}]${C.reset}`
      );
      lines.push(`  ${f.message}`);
      if (f.snippet) lines.push(`  ${C.gray}${f.snippet}${C.reset}`);
      lines.push(`  ${C.green}fix:${C.reset} ${f.fix}`);
      lines.push('');
    }
  }

  lines.push(renderSummaryLine(result));
  lines.push('');
  lines.push(
    `${C.dim}VibeGuard checks high-frequency, well-defined issues (secrets, injection, misconfig).`
  );
  lines.push(
    `It does not prove an app is safe and cannot catch every logic bug or backdoor.${C.reset}`
  );
  lines.push('');
  return lines.join('\n');
}

function renderSummaryLine(result) {
  const { counts, grade } = result;
  const gc = GRADE_COLOR[grade] || C.gray;
  const parts = [
    `${C.red}${counts.critical} critical${C.reset}`,
    `${C.magenta}${counts.high} high${C.reset}`,
    `${C.yellow}${counts.medium} medium${C.reset}`,
    `${C.blue}${counts.low} low${C.reset}`,
  ];
  return (
    `${C.bold}Grade ${gc}${grade}${C.reset}  ` +
    `${C.dim}(${result.scannedFiles} files)${C.reset}  ` +
    parts.join('  ')
  );
}

// -------- JSON -------------------------------------------------------------

function renderJson(result) {
  return JSON.stringify(
    {
      tool: 'vibeguard',
      version: require('../package.json').version,
      root: result.root,
      generatedAt: result.generatedAt,
      grade: result.grade,
      counts: result.counts,
      scannedFiles: result.scannedFiles,
      depsInfo: result.depsInfo || null,
      externalInfo: result.externalInfo || null,
      findings: result.findings,
    },
    null,
    2
  );
}

// -------- SARIF 2.1.0 ------------------------------------------------------

const SARIF_LEVEL = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
};

function renderSarif(result) {
  const ruleIndex = new Map();
  const rules = [];
  for (const f of result.findings) {
    if (!ruleIndex.has(f.ruleId)) {
      ruleIndex.set(f.ruleId, rules.length);
      rules.push({
        id: f.ruleId,
        name: f.title || f.ruleId,
        shortDescription: { text: f.title || f.ruleId },
        fullDescription: { text: f.message },
        helpUri: 'https://github.com/vibeguard/vibeguard#rules',
        properties: {
          security_severity: f.severity,
          tags: [
            f.cwe ? f.cwe : null,
            f.owasp ? f.owasp : null,
            f.confidence ? 'confidence:' + f.confidence : null,
          ].filter(Boolean),
        },
        defaultConfiguration: { level: SARIF_LEVEL[f.severity] || 'warning' },
      });
    }
  }

  const results = result.findings.map((f) => ({
    ruleId: f.ruleId,
    ruleIndex: ruleIndex.get(f.ruleId),
    level: SARIF_LEVEL[f.severity] || 'warning',
    properties: { severity: f.severity, confidence: f.confidence },
    partialFingerprints: f.fingerprint ? { vibeguard: f.fingerprint } : undefined,
    message: { text: `${f.message} Fix: ${f.fix}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file },
          region: { startLine: f.line, startColumn: f.column },
        },
      },
    ],
  }));

  return JSON.stringify(
    {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'VibeGuard',
              informationUri: 'https://github.com/vibeguard/vibeguard',
              version: require('../package.json').version,
              rules,
            },
          },
          results,
        },
      ],
    },
    null,
    2
  );
}

// -------- Fix prompt (paste back into your AI tool) ------------------------

function renderFixPrompt(result) {
  if (result.findings.length === 0) {
    return 'VibeGuard found no issues — nothing to fix.';
  }
  const lines = [];
  lines.push(
    'You are fixing security issues found by VibeGuard. Apply the minimal, safe change for each item below. Do not change unrelated code. For any leaked secret, also tell me to rotate it.'
  );
  lines.push('');
  lines.push(`Overall grade: ${result.grade}.`);
  lines.push('');

  const actNow = result.findings.filter((f) => f.confidence !== 'low');
  const review = result.findings.filter((f) => f.confidence === 'low');

  let n = 1;
  if (actNow.length) {
    lines.push('APPLY THESE FIXES (high/medium confidence):');
    for (const f of actNow) {
      lines.push(`${n}. [${f.severity.toUpperCase()}] ${f.file}:${f.line} — ${f.message}`);
      lines.push(`   Fix: ${f.fix}`);
      n++;
    }
    lines.push('');
  }
  if (review.length) {
    lines.push(
      'REVIEW THESE — heuristic hints, verify before changing (do NOT blindly rewrite):'
    );
    for (const f of review) {
      lines.push(`${n}. [${f.severity.toUpperCase()}, review] ${f.file}:${f.line} — ${f.message}`);
      lines.push(`   Suggested: ${f.fix}`);
      n++;
    }
    lines.push('');
  }
  lines.push(
    'After applying fixes, I will re-run `vibeguard verify` to confirm each issue is resolved.'
  );
  return lines.join('\n');
}

function renderHtml(result) {
  const c = result.counts;
  const findings = result.findings || [];
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;

  const gradeColor = { A: '#22c55e', B: '#84cc16', C: '#eab308', D: '#f97316', F: '#ef4444' };
  const sevColor = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6' };

  const rows = findings.map(f => `      <tr>
        <td><span class="sev sev-${f.severity}">${f.severity}</span></td>
        <td><code>${esc(f.ruleId)}</code></td>
        <td><code>${esc(f.file)}:${f.line}</code></td>
        <td>${esc(f.message || '')}</td>
        <td>${esc(f.fix || '')}</td>
      </tr>`).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VibeGuard Security Report</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 1100px; margin: 0 auto; padding: 20px; color: #1a1a1a; }
  .grade { font-size: 72px; font-weight: 800; text-align: center; padding: 20px; border-radius: 12px; color: white; width: 120px; height: 120px; line-height: 120px; margin: 0 auto; }
  .summary { display: flex; gap: 16px; justify-content: center; margin: 20px 0; }
  .stat { text-align: center; padding: 12px 24px; border-radius: 8px; background: #f3f4f6; }
  .stat .num { font-size: 28px; font-weight: 700; }
  .stat .label { font-size: 12px; color: #6b7280; text-transform: uppercase; }
  table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 13px; }
  th { text-align: left; padding: 8px 12px; background: #f9fafb; border-bottom: 2px solid #e5e7eb; }
  td { padding: 8px 12px; border-bottom: 1px solid #f3f4f6; }
  .sev { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; color: white; }
  .sev-critical { background: #ef4444; }
  .sev-high { background: #f97316; }
  .sev-medium { background: #eab308; }
  .sev-low { background: #3b82f6; }
  code { background: #f3f4f6; padding: 2px 4px; border-radius: 3px; font-size: 12px; }
  h1 { text-align: center; }
  .meta { text-align: center; color: #6b7280; font-size: 13px; margin-bottom: 20px; }
</style>
</head>
<body>
  <h1>VibeGuard Security Report</h1>
  <div class="meta">${esc(result.root || '')} — ${result.scannedFiles} files scanned — ${result.generatedAt || new Date().toISOString()}</div>
  <div class="grade" style="background:${gradeColor[result.grade] || '#6b7280'}">${result.grade}</div>
  <div class="summary">
    <div class="stat"><div class="num" style="color:#ef4444">${bySeverity.critical}</div><div class="label">Critical</div></div>
    <div class="stat"><div class="num" style="color:#f97316">${bySeverity.high}</div><div class="label">High</div></div>
    <div class="stat"><div class="num" style="color:#eab308">${bySeverity.medium}</div><div class="label">Medium</div></div>
    <div class="stat"><div class="num" style="color:#3b82f6">${bySeverity.low}</div><div class="label">Low</div></div>
  </div>
  ${findings.length > 0 ? `<table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th><th>Fix</th></tr></thead>
    <tbody>
${rows}
    </tbody>
  </table>` : '<p style="text-align:center;color:#22c55e;font-size:18px;">No findings. Clean!</p>'}
</body>
</html>`;
}

function esc(s) { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

module.exports = {
  renderHuman,
  renderJson,
  renderSarif,
  renderHtml,
  renderFixPrompt,
  renderSummaryLine,
  C,
};
