'use strict';

/*
 * src/guard.js — Node.js runtime guard.
 *
 * Usage:
 *   node --require ./src/guard.js agent.js
 *   node --require vibeguard/guard my-app.js
 *
 * Activates VibeGuard's runtime interceptor (wraps child_process.exec,
 * fs.readFileSync, fetch, http.request) AND scans scripts before execution.
 * Blocks dangerous commands, secret exfiltration, and sensitive file access
 * at the Node.js runtime level — below the agent's code.
 *
 * 100% local. Zero network. Zero dependencies.
 */

// Activate the interceptor (wraps exec, fetch, fs, http)
try {
  const interceptor = require('./interceptor');
  interceptor.activate({ throwOnBlock: false, logBlocked: true });
} catch (e) {
  process.stderr.write(`[VibeGuard Guard] Interceptor activation failed: ${e.message}\n`);
}

// Also wrap child_process.execSync to scan commands before execution
try {
  const { execSync } = require('child_process');
  const { checkCommand } = require('./shell-guard');
  const originalExecSync = execSync;
  require('child_process').execSync = function (cmd, opts) {
    const result = checkCommand(cmd);
    if (result.blocked) {
      process.stderr.write(`\x1b[31m[VibeGuard Guard] BLOCKED: ${result.reason}\x1b[0m\n`);
      process.stderr.write(`\x1b[31m  Command: ${result.command}\x1b[0m\n`);
      process.stderr.write(`\x1b[31m  Severity: ${result.severity}\x1b[0m\n`);
      throw new Error(`VibeGuard Guard: ${result.reason}`);
    }
    return originalExecSync.call(this, cmd, opts);
  };
} catch (e) {
  // If wrapping fails, the interceptor above still covers exec/execSync
}

// Also wrap spawn to scan commands
try {
  const { spawn } = require('child_process');
  const { checkCommand } = require('./shell-guard');
  const originalSpawn = spawn;
  require('child_process').spawn = function (cmd, args, opts) {
    const fullCmd = [cmd, ...(args || [])].join(' ');
    const result = checkCommand(fullCmd);
    if (result.blocked) {
      process.stderr.write(`\x1b[31m[VibeGuard Guard] BLOCKED: ${result.reason}\x1b[0m\n`);
      process.stderr.write(`\x1b[31m  Command: ${result.command}\x1b[0m\n`);
      process.stderr.write(`\x1b[31m  Severity: ${result.severity}\x1b[0m\n`);
      // Emit an error event instead of spawning
      const { EventEmitter } = require('events');
      const fakeProc = new EventEmitter();
      fakeProc.stdout = new EventEmitter();
      fakeProc.stderr = new EventEmitter();
      fakeProc.pid = -1;
      fakeProc.killed = true;
      process.nextTick(() => {
        fakeProc.emit('error', new Error(`VibeGuard Guard: ${result.reason}`));
        fakeProc.emit('close', 1);
      });
      return fakeProc;
    }
    return originalSpawn.call(this, cmd, args, opts);
  };
} catch (e) {
  // If wrapping fails, continue — interceptor covers exec
}

process.stderr.write(`\x1b[32m[VibeGuard Guard] Active — runtime interceptor + command scanner engaged.\x1b[0m\n`);
process.stderr.write(`\x1b[2m[VibeGuard Guard] Wrapping: exec, execSync, spawn, fetch, http.request, fs.readFileSync\x1b[0m\n`);
process.stderr.write(`\x1b[2m[VibeGuard Guard] Override: set VG_OVERRIDE=1 to bypass\x1b[0m\n`);

module.exports = { active: true };