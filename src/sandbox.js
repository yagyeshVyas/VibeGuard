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
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

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

// ─── Level 3: process isolation with Node's permission model ───────────────
//
// The vm sandbox above is a raised floor, not a security boundary. When the
// runtime supports it (Node 20+), run the code in a *separate process* with
// Node's permission model enabled: filesystem and child_process are denied by
// the runtime, the environment is stripped, memory is capped and a hard
// timeout kills the process. A prelude additionally blocks require() of
// network and process modules and removes fetch/WebSocket globals.
//
// This is the mode an agent should use for untrusted code. It is still not a
// container: the code runs as the same OS user, and the permission model is
// not a kernel boundary. It is a real process boundary with deny-by-default
// capabilities — a large step up from vm.

const HARNESS_SOURCE = `'use strict';
const Module = require('module');
const vm = require('vm');
const fs = require('fs');
const path = require('path');

const userFile = path.join(__dirname, 'user.js');
let userCode = '';
try { userCode = fs.readFileSync(userFile, 'utf8'); }
catch (err) { console.log('__VG_ERROR__' + JSON.stringify('cannot read sandbox program: ' + err.message)); process.exit(0); }

// Deny module loads that can reach the network, the disk or other processes.
// (The Node permission model already denies fs/child_process at runtime; this
// makes the failure explicit and covers runtimes without the model.)
const BLOCKED = new Set([
  'child_process', 'fs', 'fs/promises', 'net', 'http', 'https', 'http2',
  'dgram', 'tls', 'dns', 'worker_threads', 'cluster', 'vm', 'v8',
  'inspector', 'repl', 'module', 'perf_hooks',
]);
const originalLoad = Module._load;
Module._load = function (request, parent, isMain) {
  const name = String(request).replace(/^node:/, '');
  if (BLOCKED.has(name)) {
    console.log('__VG_BLOCKED__' + JSON.stringify(request));
    throw new Error('VibeGuard Sandbox: module "' + request + '" is not available in process-isolated execution');
  }
  return originalLoad.apply(this, arguments);
};

// Remove ambient network globals.
for (const g of ['fetch', 'WebSocket', 'EventSource', 'XMLHttpRequest']) {
  try { delete globalThis[g]; } catch { /* non-configurable */ }
}
try { process.mainModule = undefined; } catch { /* ignore */ }
try { process.binding = function () { throw new Error('VibeGuard Sandbox: process.binding is disabled'); }; } catch { /* ignore */ }
try { process.kill = function () { throw new Error('VibeGuard Sandbox: process.kill is disabled'); }; } catch { /* ignore */ }
try { process.exit = function () { throw new Error('VibeGuard Sandbox: process.exit is disabled'); }; } catch { /* ignore */ }

try {
  // Run the program in a fresh vm context rather than the harness's global.
  // That removes process/require and leaves Node's dynamic import callback
  // unset, so dynamic import("node:net") fails too. Combined with the permission
  // model in the parent this is a real process boundary with a locked context.
  const sandbox = {
    console,
    JSON,
    Math,
    Date,
    Array,
    Object,
    String,
    Number,
    Boolean,
    RegExp,
    Map,
    Set,
    Promise,
    Symbol,
    parseInt,
    parseFloat,
    isNaN,
    isFinite,
    encodeURIComponent,
    decodeURIComponent,
  };
  sandbox.globalThis = sandbox;
  const context = vm.createContext(sandbox);
  const script = new vm.Script(userCode, {
    filename: 'user.js',
    importModuleDynamically() { throw new Error('VibeGuard Sandbox: dynamic import is disabled'); },
  });
  const result = script.runInContext(context);
  const emit = (value) => {
    console.log('__VG_RESULT__' + JSON.stringify({ ok: true, result: value === undefined ? null : String(value) }));
  };
  if (result && typeof result.then === 'function') {
    // Await a returned promise so a rejected dynamic import is reported
    // instead of being mistaken for a successful run.
    result.then(emit, (err) => {
      console.log('__VG_ERROR__' + JSON.stringify(err && err.message ? err.message : String(err)));
    });
  } else {
    emit(result);
  }
} catch (err) {
  console.log('__VG_ERROR__' + JSON.stringify(err && err.message ? err.message : String(err)));
}
`;

function nodeMajor() {
  return Number(String(process.versions.node || '0').split('.')[0]) || 0;
}

function processIsolationSupported() {
  return nodeMajor() >= 20;
}

function runInProcess(code, opts = {}) {
  const timeout = opts.timeout || DEFAULT_TIMEOUT;
  const maxMemory = opts.maxMemory || DEFAULT_MAX_MEMORY;
  const started = Date.now();
  const result = {
    success: false,
    output: null,
    error: null,
    audit: [],
    duration: 0,
    memoryCap: maxMemory,
    memoryEnforced: true,
    isolation: 'process-permission',
    supported: processIsolationSupported(),
  };

  if (!processIsolationSupported()) {
    result.error = 'VibeGuard Sandbox: process isolation requires Node 20+ (this runtime is ' + process.versions.node + '). Use the vm isolation level.';
    result.duration = Date.now() - started;
    return result;
  }

  let dir = null;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-sbx-'));
    const harness = path.join(dir, 'harness.js');
    const userFile = path.join(dir, 'user.js');
    fs.writeFileSync(harness, HARNESS_SOURCE, 'utf8');
    fs.writeFileSync(userFile, String(code == null ? '' : code), 'utf8');

    const major = nodeMajor();
    const flags = ['--no-warnings'];
    if (major >= 22) {
      flags.push('--permission', '--allow-fs-read=' + harness, '--allow-fs-read=' + userFile);
    } else {
      flags.push('--experimental-permission', '--allow-fs-read=' + harness, '--allow-fs-read=' + userFile);
    }
    const memoryMb = Math.max(8, Math.ceil(maxMemory / 1024 / 1024));
    flags.push('--max-old-space-size=' + memoryMb);

    const env = {
      PATH: process.env.PATH || '',
      SystemRoot: process.env.SystemRoot || '',
      TEMP: process.env.TEMP || dir,
      TMP: process.env.TMP || dir,
      NODE_OPTIONS: '',
    };

    const child = spawnSync(process.execPath, [...flags, harness], {
      cwd: dir,
      env,
      timeout,
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    });

    const stdout = child.stdout || '';
    const stderr = child.stderr || '';
    for (const line of stdout.split(/\r?\n/)) {
      if (line.startsWith('__VG_RESULT__')) {
        try {
          const parsed = JSON.parse(line.slice('__VG_RESULT__'.length));
          result.success = true;
          result.output = parsed.result;
        } catch { /* fallthrough to error */ }
      } else if (line.startsWith('__VG_ERROR__')) {
        try { result.error = JSON.parse(line.slice('__VG_ERROR__'.length)); } catch { result.error = 'sandbox error'; }
      } else if (line.startsWith('__VG_BLOCKED__')) {
        try { result.audit.push({ type: 'blocked_access', module: JSON.parse(line.slice('__VG_BLOCKED__'.length)), timestamp: Date.now() }); } catch { /* ignore */ }
      }
    }

    if (child.error && child.error.code === 'ETIMEDOUT') {
      result.error = 'VibeGuard Sandbox: Execution timed out (process killed)';
    } else if (!result.success && !result.error) {
      const denied = /ERR_ACCESS_DENIED/.exec(stderr);
      if (denied) result.error = 'VibeGuard Sandbox: access denied by the Node permission model';
      else result.error = (stderr || stdout || 'sandbox process exited without a result').slice(0, 500).trim();
    }
  } catch (err) {
    result.error = err && err.message ? err.message : String(err);
  } finally {
    if (dir) {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* Windows may hold a handle briefly */ }
    }
  }

  result.duration = Date.now() - started;
  return result;
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
  const isolation = result.isolation === 'isolated-vm'
    ? C.green + 'isolated-vm (hard boundary)' + C.reset
    : result.isolation === 'process-permission'
      ? C.green + 'process-permission (separate process + Node permission model)' + C.reset
      : C.yellow + 'vm (not a hard boundary)' + C.reset;
  const lines = [
    `${C.bold}VibeGuard Sandbox Execution${C.reset}`,
    `${C.dim}${'─'.repeat(60)}${C.reset}`,
    '',
    `  Success:  ${result.success ? C.green + 'YES' : C.red + 'NO'}${C.reset}`,
    `  Duration: ${result.duration}ms`,
    `  Isolation: ${isolation}`,
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

module.exports = { createSandbox, runInSandbox, runInVm, runInIsolatedVm, runInProcess, processIsolationSupported, getIsolationLevel, getAuditLog, renderSandboxReport, SAFE_GLOBALS, BLOCKED_GLOBALS };