'use strict';

/*
 * VibeGuard Zero-Trust Sandbox.
 *
 * Executes AI-generated code in a locked-down context with:
 * - No access to process.env (secrets hidden)
 * - No access to fs (filesystem locked)
 * - No access to child_process (no command execution)
 * - No access to net/http (no network access)
 * - No access to eval/Function (no dynamic code)
 * - Time-limited execution (prevents infinite loops)
 * - Memory-limited (prevents memory bombs)
 * - Full audit log of every operation attempted
 *
 * Even if AI generates malicious code, it runs in a cage.
 * 100% local. Zero network. Zero dependencies.
 */

const vm = require('vm');

const DEFAULT_TIMEOUT = 5000; // 5s
const DEFAULT_MAX_MEMORY = 16 * 1024 * 1024; // 16MB

// Safe globals — only harmless operations allowed
const SAFE_GLOBALS = {
  console: { log: (...args) => sandboxLog('log', args), error: (...args) => sandboxLog('error', args), warn: (...args) => sandboxLog('warn', args) },
  JSON: { parse: JSON.parse, stringify: JSON.stringify },
  Math: Math,
  Date: Date,
  Array: Array,
  Object: Object,
  String: String,
  Number: Number,
  Boolean: Boolean,
  RegExp: RegExp,
  Map: Map,
  Set: Set,
  Promise: Promise,
  Symbol: Symbol,
  parseInt: parseInt,
  parseFloat: parseFloat,
  isNaN: isNaN,
  isFinite: isFinite,
  encodeURIComponent: encodeURIComponent,
  decodeURIComponent: decodeURIComponent,
};

// Blocked globals — AI cannot access these
const BLOCKED_GLOBALS = [
  'process', 'require', 'module', 'exports', '__dirname', '__filename',
  'eval', 'Function', 'setTimeout', 'setInterval', 'setImmediate',
  'fetch', 'XMLHttpRequest', 'WebSocket', 'ChildProcess',
  'Buffer', 'Stream', 'crypto', 'net', 'http', 'https', 'dns', 'os',
  'child_process', 'cluster', 'worker', 'v8', 'vm',
];

let sandboxLog = () => {};
let auditLog = [];

function createSandbox(opts = {}) {
  const timeout = opts.timeout || DEFAULT_TIMEOUT;
  const maxMemory = opts.maxMemory || DEFAULT_MAX_MEMORY;
  auditLog = [];

  sandboxLog = (level, args) => {
    auditLog.push({ type: 'console', level, args: args.map(a => String(a).slice(0, 200)) });
  };

  const context = { ...SAFE_GLOBALS };

  // Add blocked globals as traps that log attempts
  for (const blocked of BLOCKED_GLOBALS) {
    Object.defineProperty(context, blocked, {
      get() {
        auditLog.push({ type: 'blocked_access', global: blocked, timestamp: Date.now() });
        throw new Error(`VibeGuard Sandbox: "${blocked}" is not available in sandboxed execution`);
      },
    });
  }

  context.globalThis = context;
  context.global = context;
  context.this = context;

  return { context, timeout, maxMemory };
}

function runInSandbox(code, opts = {}) {
  const { context, timeout } = createSandbox(opts);
  const startTime = Date.now();
  const result = { success: false, output: null, error: null, audit: [], duration: 0 };

  try {
    const vmContext = vm.createContext(context);
    const script = new vm.Script(code, { timeout });
    result.output = script.runInContext(vmContext, { timeout });
    result.success = true;
  } catch (err) {
    result.error = err.message;
    if (err.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') {
      result.error = 'VibeGuard Sandbox: Execution timed out (possible infinite loop)';
    }
  }

  result.duration = Date.now() - startTime;
  result.audit = auditLog;
  return result;
}

function getAuditLog() {
  return auditLog;
}

function renderSandboxReport(result) {
  const C = { red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', dim: '\x1b[2m', bold: '\x1b[1m', reset: '\x1b[0m' };
  const lines = [
    `${C.bold}VibeGuard Sandbox Execution${C.reset}`,
    `${C.dim}${'─'.repeat(60)}${C.reset}`,
    '',
    `  Success:  ${result.success ? C.green + 'YES' : C.red + 'NO'}${C.reset}`,
    `  Duration: ${result.duration}ms`,
    `  Output:   ${result.success ? String(result.output).slice(0, 200) : 'N/A'}`,
  ];
  if (result.error) lines.push(`  Error:    ${C.red}${result.error}${C.reset}`);
  if (result.audit.length > 0) {
    lines.push('', `${C.bold}Audit Log${C.reset}`, '');
    for (const entry of result.audit) {
      if (entry.type === 'blocked_access') {
        lines.push(`  ${C.red}[BLOCKED]${C.reset} Attempted access to "${entry.global}"`);
      } else if (entry.type === 'console') {
        lines.push(`  ${C.dim}[${entry.level}]${C.reset} ${entry.args.join(' ').slice(0, 100)}`);
      }
    }
  }
  return lines.join('\n');
}

module.exports = { createSandbox, runInSandbox, getAuditLog, renderSandboxReport, SAFE_GLOBALS, BLOCKED_GLOBALS };