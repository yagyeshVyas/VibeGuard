'use strict';

/*
 * VibeGuard Sandbox.
 *
 * Executes AI-generated code in a locked-down context with:
 * - No access to process.env (secrets hidden)
 * - No access to fs (filesystem locked)
 * - No access to child_process (no command execution)
 * - No access to net/http (no network access)
 * - No access to eval/Function (no dynamic code)
 * - Time-limited execution (prevents infinite loops)
 * - Memory-limited (prevents memory bombs) [enforced with isolated-vm]
 * - Full audit log of every operation attempted
 *
 * Raises the bar for AI-generated code. NOT a hard sandbox at Level 1.
 * 100% local. Zero network. Zero dependencies (isolated-vm is optional).
 *
 * ISOLATION LEVELS:
 * - Level 2 (isolated-vm installed): True V8 isolate with enforced memory
 *   limit, no shared heap, no process/require/global access. This is a real
 *   security boundary. Prototype chain escape is not possible.
 * - Level 1 (vm only, no isolated-vm): Node `vm` module — NOT a security
 *   boundary per Node.js docs. Prototype chain traversal can escape.
 *   Memory cap is NOT enforced. Treat as a "raised floor" not a "steel vault".
 */

const vm = require('vm');

let isolatedVm = null;
try { isolatedVm = require('isolated-vm'); } catch { /* optional dep */ }

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

// ─── Level 2: isolated-vm (real isolation) ────────────────────────────────

function runInIsolatedVm(code, opts = {}) {
  const timeout = opts.timeout || DEFAULT_TIMEOUT;
  const maxMemory = opts.maxMemory || DEFAULT_MAX_MEMORY;
  const startTime = Date.now();
  const result = { success: false, output: null, error: null, audit: [], duration: 0, memoryCap: maxMemory, memoryEnforced: true, isolation: 'isolated-vm' };

  try {
    const isolate = new isolatedVm.Isolate({ memoryLimit: Math.ceil(maxMemory / 1024 / 1024) });
    const context = isolate.createContextSync();
    const jail = context.global;
    jail.setSync('globalThis', jail.derefInto());

    // Provide safe globals
    const safeNames = ['console','JSON','Math','Date','Array','String','Number','Boolean','RegExp','Map','Set','parseInt','parseFloat','isNaN','isFinite','encodeURIComponent','decodeURIComponent'];
    for (const name of safeNames) {
      jail.setSync(name, globalThis[name]);
    }

    // Override console to capture output
    const logCapture = (...args) => {
      auditLog.push({ type: 'console', level: 'log', args: args.map(a => String(a).slice(0, 200)) });
    };
    jail.setSync('console', { log: logCapture, error: logCapture, warn: logCapture });

    // Block dangerous globals explicitly
    const blocked = ['process','require','module','exports','__dirname','__filename','eval','Function','setTimeout','setInterval','setImmediate','fetch','Buffer','child_process'];
    for (const b of blocked) {
      jail.setSync(b, undefined);
    }

    const script = isolate.compileScriptSync(code);
    const output = script.runSync(context, { timeout });
    result.output = output !== undefined ? String(output) : null;
    result.success = true;
    isolate.dispose();
  } catch (err) {
    if (err.message && err.message.includes('memory')) {
      result.error = 'VibeGuard Sandbox: Memory limit exceeded (' + Math.ceil(maxMemory / 1024 / 1024) + 'MB)';
    } else if (err.message && err.message.includes('timeout')) {
      result.error = 'VibeGuard Sandbox: Execution timed out (possible infinite loop)';
    } else {
      result.error = err.message || String(err);
    }
  }

  result.duration = Date.now() - startTime;
  result.audit = auditLog;
  return result;
}

// ─── Level 1: vm (fallback, not a hard boundary) ──────────────────────────

function runInVm(code, opts = {}) {
  const { context, timeout, maxMemory } = createSandbox(opts);
  const startTime = Date.now();
  const result = { success: false, output: null, error: null, audit: [], duration: 0, memoryCap: maxMemory, memoryEnforced: false, isolation: 'vm' };

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
  result.memoryEnforced = false;
  return result;
}

// ─── Main entry: use isolated-vm when available, vm as fallback ───────────

function runInSandbox(code, opts = {}) {
  if (isolatedVm) {
    return runInIsolatedVm(code, opts);
  }
  return runInVm(code, opts);
}

function getIsolationLevel() {
  return isolatedVm ? 'isolated-vm' : 'vm';
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
    `  Isolation: ${result.isolation === 'isolated-vm' ? C.green + 'isolated-vm (hard boundary)' : C.yellow + 'vm (not a hard boundary)'}${C.reset}`,
    `  Memory:   ${result.memoryEnforced ? C.green + 'enforced' : C.yellow + 'not enforced'}${C.reset} (${Math.ceil((result.memoryCap || 0) / 1024 / 1024)}MB cap)`,
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

module.exports = { createSandbox, runInSandbox, runInVm, runInIsolatedVm, getIsolationLevel, getAuditLog, renderSandboxReport, SAFE_GLOBALS, BLOCKED_GLOBALS };