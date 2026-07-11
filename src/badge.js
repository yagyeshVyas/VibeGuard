'use strict';

/*
 * Shareable badge — awarded ONLY on a genuinely clean scan (no critical AND no
 * high severity findings, using real severities). The wording is deliberately
 * modest: "passed VibeGuard checks as of <date>". It never claims the app is
 * "safe" or "100% secure" — that would be a lie a scanner can't back up.
 */

function isEligible(result) {
  return result.counts.critical === 0 && result.counts.high === 0;
}

function passLabel(dateStr) {
  return `VibeGuard: passed as of ${dateStr}`;
}

// Minimal shields-style SVG (no dependency).
function svg(result, dateStr) {
  const ok = isEligible(result);
  const label = 'VibeGuard';
  const status = ok ? `passed ${dateStr}` : `grade ${result.grade}`;
  const color = ok ? '#3fb950' : '#d29922';
  const lw = 8 + label.length * 6.2;
  const sw = 8 + status.length * 6.2;
  const w = lw + sw;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w.toFixed(0)}" height="20" role="img" aria-label="${label}: ${status}">
  <rect width="${lw.toFixed(0)}" height="20" fill="#555"/>
  <rect x="${lw.toFixed(0)}" width="${sw.toFixed(0)}" height="20" fill="${color}"/>
  <g fill="#fff" font-family="Verdana,Geneva,sans-serif" font-size="11">
    <text x="${(lw / 2).toFixed(0)}" y="14" text-anchor="middle">${label}</text>
    <text x="${(lw + sw / 2).toFixed(0)}" y="14" text-anchor="middle">${status}</text>
  </g>
</svg>`;
}

function markdown(result, dateStr, svgPath) {
  if (!isEligible(result)) return null;
  return `![${passLabel(dateStr)}](${svgPath || './vibeguard-badge.svg'})`;
}

module.exports = { isEligible, svg, markdown, passLabel };
