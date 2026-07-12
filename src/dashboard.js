'use strict';

/*
 * VibeGuard Beautiful Terminal Dashboard.
 *
 * Renders a stunning ASCII dashboard with:
 * - Visual grade meter (A-F) with color
 * - Severity bar chart (critical/high/medium/low)
 * - Top findings table with severity colors
 * - Risk score gauge (0-100)
 * - Category breakdown matrix
 * - Auto-fix summary
 * - Compliance posture
 *
 * Zero dependencies. Pure ASCII art with ANSI colors.
 */

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m', underline: '\x1b[4m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', blue: '\x1b[34m',
  magenta: '\x1b[35m', cyan: '\x1b[36m', white: '\x1b[37m',
  bgRed: '\x1b[41m', bgGreen: '\x1b[42m', bgYellow: '\x1b[43m', bgBlue: '\x1b[44m',
  bgMagenta: '\x1b[45m', bgCyan: '\x1b[46m', bgWhite: '\x1b[47m',
  gray: '\x1b[90m', brightRed: '\x1b[91m', brightGreen: '\x1b[92m',
  brightYellow: '\x1b[93m', brightBlue: '\x1b[94m', brightMagenta: '\x1b[95m',
  brightCyan: '\x1b[96m',
};

function severityColor(sev) {
  return { critical: C.red, high: C.yellow, medium: C.cyan, low: C.gray }[sev] || C.white;
}

function gradeColor(grade) {
  if (grade === 'A') return C.green;
  if (grade === 'B') return C.green;
  if (grade === 'C') return C.yellow;
  if (grade === 'D') return C.yellow;
  if (grade === 'F') return C.red;
  return C.white;
}

// Render a visual bar: ████████░░░░  67%
function bar(count, max, width = 20, color = C.red) {
  if (max === 0) max = 1;
  const filled = Math.round((count / max) * width);
  return color + '█'.repeat(filled) + C.gray + '░'.repeat(width - filled) + C.reset;
}

// Render the grade as a large ASCII art meter
function gradeMeter(grade) {
  const g = gradeColor(grade);
  const meter = [
    '┌─────────────────────────────────────────────────────────┐',
    '│                                                         │',
    '│' + g + C.bold + `                    GRADE: ${grade}                    ` + C.reset + '│',
    '│                                                         │',
    '└─────────────────────────────────────────────────────────┘',
  ];
  return meter.join('\n');
}

// Risk score gauge (0-100)
function riskGauge(score, level) {
  const colors = { NONE: C.green, LOW: C.green, MEDIUM: C.yellow, HIGH: C.yellow, CRITICAL: C.red };
  const color = colors[level] || C.white;
  const pct = Math.min(100, score);
  const filled = Math.round((pct / 100) * 30);
  const gauge = color + '▰'.repeat(filled) + C.gray + '▱'.repeat(30 - filled) + C.reset;
  return `${C.bold}Risk Score${C.reset}  ${gauge}  ${color}${C.bold}${score}${C.reset} ${color}(${level})${C.reset}`;
}

// Severity bar chart
function severityBars(counts) {
  const max = Math.max(counts.critical, counts.high, counts.medium, counts.low, 1);
  const lines = [
    `${C.bold}Severity Distribution${C.reset}`,
    '',
    `  ${C.red}Critical ${C.reset} ${bar(counts.critical, max, 25, C.red)}  ${C.red}${C.bold}${counts.critical}${C.reset}`,
    `  ${C.yellow}High     ${C.reset} ${bar(counts.high, max, 25, C.yellow)}  ${C.yellow}${C.bold}${counts.high}${C.reset}`,
    `  ${C.cyan}Medium   ${C.reset} ${bar(counts.medium, max, 25, C.cyan)}  ${C.cyan}${C.bold}${counts.medium}${C.reset}`,
    `  ${C.gray}Low      ${C.reset} ${bar(counts.low, max, 25, C.gray)}  ${C.gray}${C.bold}${counts.low}${C.reset}`,
    '',
  ];
  return lines.join('\n');
}

// Category breakdown matrix
function categoryMatrix(findings) {
  const matrix = {};
  for (const f of findings) {
    const cat = f.ruleId.split('.')[0];
    if (!matrix[cat]) matrix[cat] = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
    matrix[cat][f.severity]++;
    matrix[cat].total++;
  }
  const sorted = Object.entries(matrix).sort((a, b) => b[1].total - a[1].total).slice(0, 12);
  if (sorted.length === 0) return `${C.green}No findings — clean codebase!${C.reset}`;
  const lines = [
    `${C.bold}Category Breakdown${C.reset}`,
    '',
    `  ${C.dim}Category        Total  Crit  High  Med   Low${C.reset}`,
    `  ${C.dim}──────────────  ─────  ────  ────  ────  ───${C.reset}`,
  ];
  for (const [cat, c] of sorted) {
    const catColor = c.critical > 0 ? C.red : c.high > 0 ? C.yellow : c.medium > 0 ? C.cyan : C.gray;
    lines.push(
      `  ${catColor}${cat.padEnd(14)}${C.reset}  ${String(c.total).padStart(5)}  ` +
      `${c.critical > 0 ? C.red + String(c.critical).padStart(4) + C.reset : '   0'}  ` +
      `${c.high > 0 ? C.yellow + String(c.high).padStart(4) + C.reset : '   0'}  ` +
      `${c.medium > 0 ? C.cyan + String(c.medium).padStart(4) + C.reset : '   0'}  ` +
      `${c.low > 0 ? C.gray + String(c.low).padStart(4) + C.reset : '   0'}`
    );
  }
  return lines.join('\n');
}

// Top findings table
function topFindings(findings, limit = 10) {
  if (findings.length === 0) return `${C.green}${C.bold}✓ No security issues found — clean codebase!${C.reset}`;
  const sorted = findings.slice().sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return (order[a.severity] || 4) - (order[b.severity] || 4);
  }).slice(0, limit);
  const lines = [
    `${C.bold}Top Findings${C.reset}`,
    '',
  ];
  for (const f of sorted) {
    const sc = severityColor(f.severity);
    const sevTag = sc + C.bold + `[${f.severity.toUpperCase().padEnd(8)}]` + C.reset;
    lines.push(`  ${sevTag} ${C.brightCyan}${f.ruleId}${C.reset}`);
    lines.push(`           ${C.dim}${f.file}:${f.line}${C.reset} — ${f.message.slice(0, 70)}`);
    if (f.fix) lines.push(`           ${C.green}fix:${C.reset} ${f.fix.slice(0, 70)}`);
    lines.push('');
  }
  if (findings.length > limit) {
    lines.push(`  ${C.dim}... and ${findings.length - limit} more findings${C.reset}`);
  }
  return lines.join('\n');
}

// Auto-fix summary
function autoFixSummary(findings) {
  try {
    const { isAutoFixable } = require('./autofix');
    const fixable = findings.filter(f => isAutoFixable(f.ruleId));
    if (fixable.length === 0) return '';
    const lines = [
      `${C.green}${C.bold}Auto-Fix Available${C.reset}`,
      '',
      `  ${C.green}✓${C.reset} ${fixable.length} of ${findings.length} findings can be auto-fixed`,
      `  ${C.dim}Run: vibeguard fix${C.reset}`,
      '',
    ];
    return lines.join('\n');
  } catch { return ''; }
}

// Compliance posture
function compliancePosture(findings) {
  try {
    const { generateComplianceReport } = require('./compliance');
    const report = generateComplianceReport(findings);
    if (typeof report === 'string') return report;
    const lines = [`${C.bold}Compliance Posture${C.reset}`, ''];
    for (const [framework, data] of Object.entries(report)) {
      const failed = data.failed || data.failures || 0;
      const passed = data.passed || data.pass || 0;
      const status = failed === 0 ? C.green + '✓ PASS' : failed < 3 ? C.yellow + '⚠ REVIEW' : C.red + '✗ FAIL';
      lines.push(`  ${status}${C.reset}  ${framework.padEnd(12)} ${C.dim}${failed} findings${C.reset}`);
    }
    return lines.join('\n');
  } catch { return `${C.dim}Compliance analysis unavailable${C.reset}`; }
}

// Full dashboard render
function renderDashboard(result) {
  const counts = result.counts;
  const weights = { critical: 10, high: 5, medium: 2, low: 1 };
  let score = 0;
  for (const f of result.findings) score += weights[f.severity] || 1;
  const maxScore = result.scannedFiles * 10 || 1;
  const riskPercent = Math.min(100, Math.round((score / maxScore) * 100));
  const riskLevel = score === 0 ? 'NONE' : score < 10 ? 'LOW' : score < 30 ? 'MEDIUM' : score < 60 ? 'HIGH' : 'CRITICAL';

  const W = 60;
  const border = C.cyan + '═'.repeat(W) + C.reset;
  const borderThin = C.dim + '─'.repeat(W) + C.reset;

  const sections = [
    '',
    border,
    C.cyan + C.bold + '  VibeGuard Security Dashboard' + C.reset + C.dim + '  —  ' + new Date().toISOString().slice(0, 19) + C.reset,
    border,
    '',
    gradeMeter(result.grade),
    '',
    riskGauge(score, riskLevel),
    '',
    borderThin,
    '',
    severityBars(counts),
    borderThin,
    '',
    `  ${C.bold}Scan Summary${C.reset}`,
    `  ${C.dim}Files scanned:${C.reset}  ${result.scannedFiles}`,
    `  ${C.dim}Total findings:${C.reset} ${result.findings.length}`,
    `  ${C.dim}Grade:${C.reset}          ${gradeColor(result.grade)}${C.bold}${result.grade}${C.reset}`,
    '',
    borderThin,
    '',
    categoryMatrix(result.findings),
    '',
    borderThin,
    '',
    topFindings(result.findings),
    autoFixSummary(result.findings),
    borderThin,
    '',
    compliancePosture(result.findings),
    '',
    border,
    C.dim + '  Run "vibeguard scan" for full report  |  "vibeguard fix" to auto-fix  |  "vibeguard why <rule>" for details' + C.reset,
    border,
    '',
  ];

  return sections.join('\n');
}

// GitHub PR comment format (markdown)
function renderPRComment(result) {
  const counts = result.counts;
  const gradeEmoji = { A: '🟢', B: '🟢', C: '🟡', D: '🟡', F: '🔴' };
  const emoji = gradeEmoji[result.grade] || '⚪';

  let md = `## ${emoji} VibeGuard Security Report\n\n`;
  md += `| Metric | Value |\n|--------|-------|\n`;
  md += `| Grade | **${result.grade}** |\n`;
  md += `| Files Scanned | ${result.scannedFiles} |\n`;
  md += `| Total Findings | ${result.findings.length} |\n`;
  md += `| Critical | ${counts.critical} |\n`;
  md += `| High | ${counts.high} |\n`;
  md += `| Medium | ${counts.medium} |\n`;
  md += `| Low | ${counts.low} |\n\n`;

  if (result.findings.length > 0) {
    md += `### Top Findings\n\n`;
    md += `| Severity | Rule | File:Line | Message |\n`;
    md += `|----------|------|-----------|--------|\n`;
    const sorted = result.findings.slice().sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order[a.severity] || 4) - (order[b.severity] || 4);
    }).slice(0, 15);
    for (const f of sorted) {
      const sevEmoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '⚪' }[f.severity] || '⚪';
      md += `| ${sevEmoji} ${f.severity} | \`${f.ruleId}\` | \`${f.file}:${f.line}\` | ${f.message.slice(0, 60)} |\n`;
    }
    if (result.findings.length > 15) md += `\n_...and ${result.findings.length - 15} more findings_\n`;
  } else {
    md += `### ✅ No security issues found!\n\nClean codebase. Great job! 🎉\n`;
  }

  // Auto-fix
  try {
    const { isAutoFixable } = require('./autofix');
    const fixable = result.findings.filter(f => isAutoFixable(f.ruleId));
    if (fixable.length > 0) {
      md += `\n### 🔧 Auto-Fix Available\n\n`;
      md += `${fixable.length} findings can be automatically fixed. Run:\n`;
      md += '```\nvibeguard fix\n```\n';
    }
  } catch {}

  md += `\n---\n_VibeGuard — Free, zero-dependency security scanner. [Learn more](https://github.com/vibeguard/vibeguard)_\n`;
  return md;
}

module.exports = { renderDashboard, renderPRComment, gradeMeter, riskGauge, severityBars, categoryMatrix, topFindings, autoFixSummary, compliancePosture };