'use strict';

/*
 * VibeGuard Audit Trail.
 *
 * Append-only, hash-chained log of every security decision an agent makes:
 * tool calls allowed or blocked, secrets found, tamper attempts, sandbox runs,
 * firewall verdicts. Each entry commits to the previous entry's hash, so
 * editing or deleting an entry breaks the chain and is detectable.
 *
 * Two ways to use it:
 *   - The module-level API (log / verifyChain / summary / ...) for in-process
 *     logging, exactly as older callers expect.
 *   - createLogger(file) for a self-contained logger backed by a JSONL file.
 *     The MCP firewall, agent monitor and risk engine use this so their audit
 *     trail survives process restarts.
 *
 * 100% local. Zero network. Zero dependencies.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const GENESIS = 'GENESIS';

function hashPayload(entry) {
  // Deterministic: every field that matters is committed to. Object key order
  // is fixed explicitly so a JSON round-trip cannot change the hash.
  const canonical = JSON.stringify({
    id: entry.id,
    type: entry.type,
    detail: entry.detail,
    timestamp: entry.timestamp,
    previousHash: entry.previousHash,
  });
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

function makeEntry(type, detail, previousHash, id, timestamp) {
  const entry = {
    id,
    type,
    detail: detail === undefined ? {} : detail,
    timestamp,
    previousHash,
  };
  entry.hash = hashPayload(entry);
  return entry;
}

function verifyEntries(entries) {
  let prevHash = GENESIS;
  const brokenAt = [];
  for (const entry of entries) {
    let ok = true;
    if (!entry || typeof entry !== 'object') {
      brokenAt.push(entry && entry.id);
      continue;
    }
    if (entry.previousHash !== prevHash) ok = false;
    if (entry.hash !== hashPayload(entry)) ok = false;
    if (!ok) brokenAt.push(entry.id);
    prevHash = entry.hash;
  }
  return { valid: brokenAt.length === 0, brokenAt, total: entries.length };
}

function summarizeEntries(entries) {
  const byType = {};
  for (const e of entries) byType[e.type] = (byType[e.type] || 0) + 1;
  return {
    total: entries.length,
    byType,
    firstEntry: entries.length ? entries[0].timestamp : null,
    lastEntry: entries.length ? entries[entries.length - 1].timestamp : null,
    duration: entries.length > 1 ? entries[entries.length - 1].timestamp - entries[0].timestamp : 0,
  };
}

function readJsonl(filePath) {
  const entries = [];
  let raw;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch {
    return entries;
  }
  for (const line of raw.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line);
      if (parsed && parsed.hash) entries.push(parsed);
    } catch {
      // A malformed line is retained as evidence of tampering: stop and let
      // verification fail rather than silently ignoring it.
      entries.push({ id: entries.length + 1, type: 'corrupt_line', detail: { line: line.slice(0, 120) }, timestamp: 0, previousHash: 'CORRUPT', hash: 'CORRUPT' });
    }
  }
  return entries;
}

function appendJsonl(filePath, entry) {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.appendFileSync(filePath, JSON.stringify(entry) + '\n', 'utf8');
    return true;
  } catch {
    return false;
  }
}

// ─── Self-contained logger (file-backed) ────────────────────────────────────

function createLogger(filePath) {
  const entries = filePath ? readJsonl(filePath) : [];
  let lastHash = entries.length ? entries[entries.length - 1].hash : GENESIS;
  let writeFailures = 0;

  function log(type, detail = {}) {
    const entry = makeEntry(type, detail, lastHash, entries.length + 1, Date.now());
    lastHash = entry.hash;
    entries.push(entry);
    if (filePath && !appendJsonl(filePath, entry)) writeFailures++;
    return entry;
  }

  function verify() {
    return verifyEntries(entries);
  }

  function getEntries(filter = {}) {
    let filtered = entries;
    if (filter.type) filtered = filtered.filter((e) => e.type === filter.type);
    if (filter.since) filtered = filtered.filter((e) => e.timestamp >= filter.since);
    const limit = Number(filter.limit || 0);
    if (limit > 0) filtered = filtered.slice(-limit);
    return filtered;
  }

  function summary() {
    return summarizeEntries(entries);
  }

  function exportLog(outPath) {
    const payload = JSON.stringify({ entries, lastHash, exportedAt: Date.now() }, null, 2);
    if (outPath) {
      fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
      fs.writeFileSync(outPath, payload, 'utf8');
      return { exported: true, path: outPath, entries: entries.length };
    }
    return payload;
  }

  return {
    log,
    verify,
    summary,
    getEntries,
    exportLog,
    file: filePath || null,
    get writeFailures() { return writeFailures; },
    get entries() { return entries.slice(); },
  };
}

// ─── Module-level logger (legacy API, unchanged signatures) ─────────────────

const memory = {
  entries: [],
  lastHash: GENESIS,
  file: null,
};

function log(type, detail = {}) {
  const entry = makeEntry(type, detail, memory.lastHash, memory.entries.length + 1, Date.now());
  memory.lastHash = entry.hash;
  memory.entries.push(entry);
  if (memory.file) appendJsonl(memory.file, entry);
  return entry;
}

function setFile(filePath) {
  memory.file = filePath || null;
  if (filePath) {
    // Resume the existing chain instead of appending a fresh GENESIS after
    // yesterday's entries — otherwise a restart corrupts the audit log.
    const existing = readJsonl(filePath);
    if (existing.length) {
      memory.entries = existing;
      memory.lastHash = existing[existing.length - 1].hash;
    }
  }
  return { file: memory.file, entries: memory.entries.length };
}

function loadFile(filePath) {
  memory.entries = readJsonl(filePath);
  memory.lastHash = memory.entries.length ? memory.entries[memory.entries.length - 1].hash : GENESIS;
  memory.file = filePath;
  return { loaded: true, entries: memory.entries.length, verification: verifyChain() };
}

function verifyChain(entries) {
  return verifyEntries(entries || memory.entries);
}

function getEntries(filter = {}) {
  let filtered = memory.entries;
  if (filter.type) filtered = filtered.filter((e) => e.type === filter.type);
  if (filter.since) filtered = filtered.filter((e) => e.timestamp >= filter.since);
  if (filter.limit) filtered = filtered.slice(-filter.limit);
  return filtered;
}

function summary() {
  return summarizeEntries(memory.entries);
}

function exportLog(filePath) {
  const data = JSON.stringify({ entries: memory.entries, lastHash: memory.lastHash, exportedAt: Date.now() }, null, 2);
  if (filePath) {
    fs.mkdirSync(path.dirname(path.resolve(filePath)), { recursive: true });
    fs.writeFileSync(filePath, data, 'utf8');
    return { exported: true, path: filePath, entries: memory.entries.length };
  }
  return data;
}

function importLog(filePath) {
  const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  memory.entries = data.entries || [];
  memory.lastHash = data.lastHash || GENESIS;
  return { imported: true, entries: memory.entries.length };
}

function clear() {
  memory.entries = [];
  memory.lastHash = GENESIS;
  return { cleared: true };
}

function renderAuditReport(entriesArg) {
  const C = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  const entries = entriesArg || memory.entries;
  const s = summarizeEntries(entries);
  const lines = [
    `${C.bold}VibeGuard Audit Trail${C.reset}`,
    `${C.dim}${'─'.repeat(60)}${C.reset}`,
    '',
    `  Total entries:     ${s.total}`,
    `  First entry:       ${s.firstEntry ? new Date(s.firstEntry).toISOString().slice(0, 19) : 'N/A'}`,
    `  Last entry:        ${s.lastEntry ? new Date(s.lastEntry).toISOString().slice(0, 19) : 'N/A'}`,
    `  Duration:          ${s.duration}ms`,
    '',
    `${C.bold}By Type${C.reset}`,
    '',
  ];

  for (const [type, count] of Object.entries(s.byType).sort((a, b) => b[1] - a[1])) {
    const color = type === 'blocked' || type === 'tamper' || type === 'mcp_blocked' ? C.red : type === 'warning' ? C.yellow : C.dim;
    lines.push(`  ${color}${type.padEnd(22)}${C.reset} ${count}`);
  }

  const verification = verifyEntries(entries);
  lines.push('', `${C.bold}Chain Verification${C.reset}`, '');
  if (verification.valid) {
    lines.push(`  ${C.green}PASS — Chain intact (${verification.total} entries)${C.reset}`);
  } else {
    lines.push(`  ${C.red}FAIL — Chain broken at entries: ${verification.brokenAt.join(', ')}${C.reset}`);
  }

  if (entries.length > 0) {
    lines.push('', `${C.bold}Recent Entries${C.reset}`, '');
    for (const e of entries.slice(-10)) {
      const time = new Date(e.timestamp).toISOString().slice(11, 19);
      const color = e.type === 'blocked' || e.type === 'mcp_blocked' ? C.red : e.type === 'tamper' ? C.red : e.type === 'warning' ? C.yellow : C.dim;
      lines.push(`  ${C.dim}${time}${C.reset} ${color}${e.type}${C.reset} ${JSON.stringify(e.detail).slice(0, 70)}`);
    }
  }

  return lines.join('\n');
}

module.exports = {
  log,
  setFile,
  loadFile,
  createLogger,
  verifyChain,
  verifyEntries,
  getEntries,
  summary,
  exportLog,
  importLog,
  clear,
  renderAuditReport,
  hashPayload,
};
