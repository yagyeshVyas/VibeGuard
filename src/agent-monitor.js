'use strict';

/*
 * src/agent-monitor.js — runtime monitor for autonomous agent activity.
 *
 * Reads the hash-chained audit log the MCP firewall writes and turns it into
 * an operator view: what the agent tried, what was blocked, which servers and
 * tools were involved, whether the log is intact, and whether the sequence of
 * events matches a known hostile pattern (trust building, data gathering
 * before egress, slow exfiltration, repeated blocks, rapid fire, tampering).
 *
 * `--watch` tails the log live. This is monitoring, not prevention: prevention
 * happens in src/mcp-firewall.js, before the call reaches the server.
 *
 * 100% local. Zero network. Zero dependencies.
 */

const fs = require('fs');
const path = require('path');
const { createLogger } = require('./audit-trail');
const { createSession, recordEvent, analyzeSession } = require('./behavior');
const { DEFAULT_AUDIT_FILE } = require('./mcp-firewall');

function eventFor(entry) {
  const detail = entry.detail || {};
  switch (entry.type) {
    case 'mcp_blocked': return { type: 'blocked', detail };
    case 'mcp_tool_poisoned': return { type: 'tamper', detail };
    case 'mcp_prompt_blocked': return { type: 'blocked', detail };
    case 'mcp_warn': return { type: 'network', detail };
    case 'mcp_result_scrubbed': return { type: 'secret_access', detail };
    case 'mcp_result_injection': return { type: 'tamper', detail };
    case 'mcp_call': return { type: 'file_read', detail };
    case 'mcp_tool_pinned': return { type: 'file_read', detail };
    default: return null;
  }
}

function analyzeMonitorLog(file) {
  const resolved = path.resolve(file || DEFAULT_AUDIT_FILE);
  const report = {
    file: resolved,
    exists: false,
    entries: 0,
    allowed: 0,
    blocked: 0,
    warned: 0,
    scrubbed: 0,
    poisoned: 0,
    resultInjections: 0,
    pinned: 0,
    servers: {},
    tools: {},
    blockedTools: {},
    byType: {},
    firstEvent: null,
    lastEvent: null,
    chainValid: true,
    brokenAt: [],
    anomalies: [],
    behavior: null,
    riskScore: 0,
    riskLevel: 'NONE',
    recent: [],
  };

  if (!fs.existsSync(resolved)) return report;
  let logger;
  try { logger = createLogger(resolved); } catch (err) {
    report.error = err.message;
    return report;
  }
  report.exists = true;
  const entries = logger.entries;
  report.entries = entries.length;
  if (entries.length) {
    report.firstEvent = entries[0].timestamp;
    report.lastEvent = entries[entries.length - 1].timestamp;
  }

  const verification = logger.verify();
  report.chainValid = verification.valid;
  report.brokenAt = verification.brokenAt;

  const session = createSession();
  for (const entry of entries) {
    report.byType[entry.type] = (report.byType[entry.type] || 0) + 1;
    const detail = entry.detail || {};
    if (detail.server) report.servers[detail.server] = (report.servers[detail.server] || 0) + 1;
    if (detail.tool) report.tools[detail.tool] = (report.tools[detail.tool] || 0) + 1;

    if (entry.type === 'mcp_call') report.allowed++;
    if (entry.type === 'mcp_warn') report.warned++;
    if (entry.type === 'mcp_blocked') {
      report.blocked++;
      if (detail.tool) report.blockedTools[detail.tool] = (report.blockedTools[detail.tool] || 0) + 1;
    }
    if (entry.type === 'mcp_result_scrubbed') report.scrubbed += Number(detail.redactions || 1);
    if (entry.type === 'mcp_result_injection') report.resultInjections++;
    if (entry.type === 'mcp_tool_poisoned') report.poisoned++;
    if (entry.type === 'mcp_tool_pinned') report.pinned++;

    const mapped = eventFor(entry);
    if (mapped) recordEvent(session, mapped.type, mapped.detail);
  }

  report.behavior = analyzeSession(session);
  report.anomalies = report.behavior.patterns;
  report.riskScore =
    Math.min(30, report.blocked * 6) +
    Math.min(30, report.poisoned * 15) +
    Math.min(20, report.resultInjections * 10) +
    Math.min(10, report.warned) +
    Math.min(10, report.scrubbed * 2) +
    Math.min(20, report.anomalies.reduce((sum, p) => sum + (p.severity === 'critical' ? 20 : p.severity === 'high' ? 10 : 4), 0)) +
    (report.chainValid ? 0 : 15);
  report.riskScore = Math.min(100, report.riskScore);
  report.riskLevel =
    report.riskScore === 0 ? 'NONE' :
    report.riskScore < 20 ? 'LOW' :
    report.riskScore < 45 ? 'MEDIUM' :
    report.riskScore < 70 ? 'HIGH' : 'CRITICAL';

  report.recent = entries.slice(-15).map((entry) => ({
    at: entry.timestamp,
    type: entry.type,
    server: entry.detail && entry.detail.server,
    tool: entry.detail && entry.detail.tool,
    reason: entry.detail && entry.detail.reasons ? entry.detail.reasons[0] : (entry.detail && entry.detail.error) || null,
  }));

  return report;
}

function topEntries(map, n = 5) {
  return Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, n);
}

function renderMonitor(report) {
  const C = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', cyan: '\x1b[36m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  const riskColor = { NONE: C.green, LOW: C.green, MEDIUM: C.yellow, HIGH: C.yellow, CRITICAL: C.red };
  const color = riskColor[report.riskLevel] || C.dim;
  const lines = [
    `${C.bold}VibeGuard Agent Monitor${C.reset}`,
    `${C.dim}${'─'.repeat(64)}${C.reset}`,
    `  Log:          ${report.file}`,
  ];
  if (!report.exists) {
    lines.push(`  ${C.yellow}No audit log yet.${C.reset} Start the firewall first:`);
    lines.push(`    vibeguard mcp-firewall --server <name>`);
    return lines.join('\n');
  }
  lines.push(
    `  Events:       ${report.entries}`,
    `  Runtime risk: ${color}${report.riskScore}/100 (${report.riskLevel})${C.reset}`,
    `  Chain:        ${report.chainValid ? C.green + 'intact' : C.red + 'BROKEN at ' + report.brokenAt.join(', ')}${C.reset}`,
    '',
    `${C.bold}Decisions${C.reset}`,
    `  Allowed:      ${C.green}${report.allowed}${C.reset}`,
    `  Warned:       ${C.yellow}${report.warned}${C.reset}`,
    `  Blocked:      ${C.red}${report.blocked}${C.reset}`,
    `  Redactions:   ${report.scrubbed}`,
    `  Injections:   ${C.red}${report.resultInjections}${C.reset} tool-output injection(s) withheld`,
    `  Poisoned:     ${C.red}${report.poisoned}${C.reset}`,
    `  Tools pinned: ${report.pinned}`,
    ''
  );
  const servers = topEntries(report.servers);
  if (servers.length) {
    lines.push(`${C.bold}Servers${C.reset}`);
    for (const [name, count] of servers) lines.push(`  ${name.padEnd(28)} ${count}`);
    lines.push('');
  }
  const blocked = topEntries(report.blockedTools);
  if (blocked.length) {
    lines.push(`${C.bold}Blocked tools${C.reset}`);
    for (const [name, count] of blocked) lines.push(`  ${C.red}${name.padEnd(28)}${C.reset} ${count}`);
    lines.push('');
  }
  if (report.anomalies.length) {
    lines.push(`${C.bold}Behavior anomalies${C.reset}`);
    for (const a of report.anomalies) {
      const sc = a.severity === 'critical' ? C.red : C.yellow;
      lines.push(`  ${sc}[${a.severity}]${C.reset} ${a.pattern}`);
      lines.push(`    ${a.message}`);
    }
    lines.push('');
  } else {
    lines.push(`${C.green}No behavioral anomalies.${C.reset}`, '');
  }
  if (report.recent.length) {
    lines.push(`${C.bold}Recent events${C.reset}`);
    for (const e of report.recent) {
      const t = new Date(e.at).toISOString().slice(11, 19);
      const sc = e.type === 'mcp_blocked' || e.type === 'mcp_tool_poisoned' ? C.red : e.type === 'mcp_warn' ? C.yellow : C.dim;
      const where = [e.server, e.tool].filter(Boolean).join('/');
      lines.push(`  ${C.dim}${t}${C.reset} ${sc}${e.type.padEnd(20)}${C.reset} ${where}${e.reason ? ' — ' + String(e.reason).slice(0, 80) : ''}`);
    }
  }
  return lines.join('\n');
}

// Tail a JSONL audit log. Calls onEvent for every new complete line.
function watchAudit(file, opts = {}) {
  const resolved = path.resolve(file || DEFAULT_AUDIT_FILE);
  const interval = Math.max(200, Number(opts.interval || 1000));
  let position = 0;
  let carry = '';
  try { position = fs.statSync(resolved).size; } catch { position = 0; }
  let timer = null;
  let stopped = false;

  const tick = () => {
    if (stopped) return;
    let stat;
    try { stat = fs.statSync(resolved); } catch { return; }
    if (stat.size < position) { position = 0; carry = ''; } // log rotated
    if (stat.size === position) return;
    let chunk;
    try {
      const fd = fs.openSync(resolved, 'r');
      const length = stat.size - position;
      const buffer = Buffer.alloc(length);
      fs.readSync(fd, buffer, 0, length, position);
      fs.closeSync(fd);
      position = stat.size;
      chunk = carry + buffer.toString('utf8');
    } catch {
      return;
    }
    const lines = chunk.split(/\r?\n/);
    carry = lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const entry = JSON.parse(line);
        if (opts.onEvent) opts.onEvent(entry);
      } catch { /* ignore partial/corrupt line */ }
    }
  };

  timer = setInterval(tick, interval);
  return {
    stop() {
      stopped = true;
      if (timer) clearInterval(timer);
      timer = null;
    },
    tick,
  };
}

function formatEvent(entry) {
  const C = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', reset: '\x1b[0m' };
  const detail = entry.detail || {};
  const t = new Date(entry.timestamp).toISOString().slice(11, 19);
  const color = entry.type === 'mcp_blocked' || entry.type === 'mcp_tool_poisoned' ? C.red : entry.type === 'mcp_warn' ? C.yellow : C.green;
  const where = [detail.server, detail.tool].filter(Boolean).join('/');
  return `${C.dim}${t}${C.reset} ${color}${entry.type}${C.reset} ${where}${detail.reasons ? ' — ' + String(detail.reasons[0] || detail.reasons).slice(0, 100) : ''}`;
}

module.exports = { analyzeMonitorLog, renderMonitor, watchAudit, formatEvent, eventFor };
