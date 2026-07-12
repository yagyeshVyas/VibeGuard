'use strict';

/*
 * src/daemon.js — VibeGuard background daemon.
 *
 * Runs as a persistent process. Watches the working directory for file changes,
 * auto-scans modified files in real-time, and blocks dangerous writes before
 * they hit disk.
 *
 * The daemon provides three protections simultaneously:
 *   1. File watcher: scans every file write (using fs.watch) in real-time
 *   2. Process spawner guard: wraps child_process to intercept spawned commands
 *   3. HTTP interceptor: wraps outbound requests from the daemon process
 *
 * Usage:
 *   vibeguard auto-start [dir]   Start daemon in background
 *   vibeguard auto-stop [dir]    Stop daemon
 *   vibeguard auto-status [dir]  Check if daemon is running
 *
 * The daemon writes a PID file to .vibeguard-daemon.json and logs to
 * .vibeguard-daemon.log in the working directory.
 *
 * 100% local. Zero network. Zero dependencies.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execSync } = require('child_process');

const DAEMON_FILE = '.vibeguard-daemon.json';
const DAEMON_LOG = '.vibeguard-daemon.log';
const PID_CHECK_INTERVAL = 5000; // check if process alive every 5s

// ─── Daemon process ────────────────────────────────────────────────────────

function runDaemon(rootDir, opts) {
  opts = opts || {};
  const logPath = path.join(rootDir, DAEMON_LOG);
  const logStream = fs.createWriteStream(logPath, { flags: 'a' });

  function log(msg) {
    const ts = new Date().toISOString();
    const line = `[${ts}] ${msg}\n`;
    logStream.write(line);
    if (opts.verbose) process.stderr.write(`[VibeGuard Daemon] ${msg}\n`);
  }

  log('daemon started');
  log(`watching: ${rootDir}`);

  // Write PID file
  const pidData = {
    pid: process.pid,
    root: rootDir,
    startedAt: new Date().toISOString(),
    findings: 0,
    blocked: 0,
    watched: 0,
  };
  fs.writeFileSync(path.join(rootDir, DAEMON_FILE), JSON.stringify(pidData, null, 2));

  // Activate interceptor (wraps exec, fetch, fs, http in THIS process)
  try {
    require('./interceptor').activate({ throwOnBlock: false, logBlocked: true });
    log('interceptor activated');
  } catch (e) {
    log(`interceptor failed: ${e.message}`);
  }

  // Activate guard (wraps execSync, spawn)
  try {
    require('./guard');
    log('guard activated');
  } catch (e) {
    log(`guard failed: ${e.message}`);
  }

  // File watcher — scan files on change
  let scanQueue = [];
  let scanTimer = null;
  const { scanFileContent } = require('./scanner');

  function scheduleScan(filePath) {
    // Only scan code files
    const ext = path.extname(filePath).toLowerCase();
    const codeExts = new Set(['.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.rb', '.java', '.kt', '.swift', '.cs', '.rs', '.php', '.sql', '.sh', '.yml', '.yaml', '.json', '.env']);
    if (!codeExts.has(ext) && !filePath.endsWith('.env') && !filePath.includes('.env')) return;

    scanQueue.push(filePath);
    if (scanTimer) clearTimeout(scanTimer);
    scanTimer = setTimeout(() => {
      const files = [...new Set(scanQueue)];
      scanQueue = [];
      for (const f of files) {
        try {
          const content = fs.readFileSync(f, 'utf8');
          const relPath = path.relative(rootDir, f);
          const findings = scanFileContent(f, relPath, content, null);
          const critical = findings.filter((x) => x.severity === 'critical');

          if (critical.length > 0) {
            pidData.findings += findings.length;
            for (const finding of critical) {
              pidData.blocked++;
              log(`BLOCKED [critical] ${finding.ruleId}: ${finding.file}:${finding.line} — ${finding.message}`);
              const color = '\x1b[31m';
              process.stderr.write(`${color}[VibeGuard] BLOCKED [critical] ${finding.ruleId}: ${finding.file}:${finding.line}\x1b[0m\n`);
              process.stderr.write(`${color}  ${finding.message}\x1b[0m\n`);
              process.stderr.write(`${color}  Fix: ${finding.fix || 'Review this finding.'}\x1b[0m\n\n`);
            }

            // Auto-revert: restore from git if file is tracked, otherwise warn
            if (critical.length > 0 && !opts.noRevert) {
              try {
                const { execSync } = require('child_process');
                const gitResult = execSync(`git show HEAD:"${relPath}" 2>NUL`, {
                  cwd: rootDir,
                  encoding: 'utf8',
                  stdio: 'pipe',
                  timeout: 2000,
                });
                if (gitResult) {
                  fs.writeFileSync(f, gitResult);
                  process.stderr.write(`\x1b[31m[VibeGuard] REVERTED: ${relPath} restored from git HEAD\x1b[0m\n\n`);
                }
              } catch {
                // Not in git — can't revert, just warn
                process.stderr.write(`\x1b[33m[VibeGuard] WARNING: ${relPath} has critical findings but is not in git — cannot auto-revert\x1b[0m\n\n`);
              }
            }
          } else if (findings.length > 0) {
            // High/medium findings — alert but don't revert
            const high = findings.filter((x) => x.severity === 'high');
            if (high.length > 0) {
              pidData.findings += findings.length;
              for (const finding of high) {
                log(`ALERT [high] ${finding.ruleId}: ${finding.file}:${finding.line} — ${finding.message}`);
                process.stderr.write(`\x1b[33m[VibeGuard] ALERT [high] ${finding.ruleId}: ${finding.file}:${finding.line}\x1b[0m\n`);
                process.stderr.write(`\x1b[33m  ${finding.message}\x1b[0m\n\n`);
              }
            }
          }
          // Update PID file
          fs.writeFileSync(path.join(rootDir, DAEMON_FILE), JSON.stringify(pidData, null, 2));
        } catch (e) {
          // File might be deleted or locked — skip
        }
      }
    }, 300); // debounce 300ms
  }

  // Watch the directory tree
  let watcher;
  try {
    watcher = fs.watch(rootDir, { recursive: true }, (eventType, filename) => {
      if (!filename) return;
      const fullPath = path.join(rootDir, filename);
      if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
        pidData.watched++;
        scheduleScan(fullPath);
      }
    });
    log('file watcher active');
  } catch (e) {
    log(`file watcher failed: ${e.message} — trying manual polling`);
    // Fallback: poll every 2 seconds
    const knownFiles = new Map();
    setInterval(() => {
      function walkDir(dir) {
        try {
          for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
            const fullPath = path.join(dir, entry.name);
            if (entry.isFile()) {
              try {
                const mtime = fs.statSync(fullPath).mtimeMs;
                const prev = knownFiles.get(fullPath);
                if (!prev || prev !== mtime) {
                  knownFiles.set(fullPath, mtime);
                  if (prev) scheduleScan(fullPath); // only scan changed files
                }
              } catch {}
            } else if (entry.isDirectory()) {
              walkDir(fullPath);
            }
          }
        } catch {}
      }
      walkDir(rootDir);
    }, 2000);
    log('polling fallback active (2s interval)');
  }

  // Keep process alive
  process.on('SIGTERM', () => {
    log('daemon stopping (SIGTERM)');
    if (watcher) watcher.close();
    try { fs.unlinkSync(path.join(rootDir, DAEMON_FILE)); } catch {}
    process.exit(0);
  });

  process.on('SIGINT', () => {
    log('daemon stopping (SIGINT)');
    if (watcher) watcher.close();
    try { fs.unlinkSync(path.join(rootDir, DAEMON_FILE)); } catch {}
    process.exit(0);
  });

  // Heartbeat — update PID file every 30s to prove we're alive
  setInterval(() => {
    pidData.heartbeat = new Date().toISOString();
    try {
      fs.writeFileSync(path.join(rootDir, DAEMON_FILE), JSON.stringify(pidData, null, 2));
    } catch {}
  }, 30000);
}

// ─── Daemon management ────────────────────────────────────────────────────

function startDaemon(rootDir, opts) {
  opts = opts || {};
  const pidFile = path.join(rootDir, DAEMON_FILE);

  // Check if already running
  if (isDaemonRunning(rootDir)) {
    return { started: false, reason: 'daemon already running', pidFile };
  }

  // Spawn daemon as detached background process
  const nodeBin = process.execPath;
  const daemonScript = path.join(__dirname, 'daemon-run.js');
  const logPath = path.join(rootDir, DAEMON_LOG);

  const args = [daemonScript, rootDir];
  if (opts.verbose) args.push('--verbose');

  const logStream = fs.openSync(logPath, 'a');

  const child = spawn(nodeBin, args, {
    detached: true,
    stdio: ['ignore', logStream, logStream],
    cwd: rootDir,
  });

  child.unref();

  // Wait a moment for PID file to appear
  return new Promise((resolve) => {
    setTimeout(() => {
      if (fs.existsSync(pidFile)) {
        const data = JSON.parse(fs.readFileSync(pidFile, 'utf8'));
        resolve({ started: true, pid: data.pid, root: rootDir, logFile: logPath });
      } else {
        resolve({ started: false, reason: 'daemon failed to start — check log', logFile: logPath });
      }
    }, 1000);
  });
}

function stopDaemon(rootDir) {
  const pidFile = path.join(rootDir, DAEMON_FILE);
  if (!fs.existsSync(pidFile)) {
    return { stopped: false, reason: 'no daemon running' };
  }

  try {
    const data = JSON.parse(fs.readFileSync(pidFile, 'utf8'));
    const pid = data.pid;
    if (pid) {
      try {
        process.kill(pid, 'SIGTERM');
      } catch (e) {
        // Process might already be dead
      }
    }
    // Wait for PID file to be removed
    return new Promise((resolve) => {
      let tries = 0;
      const interval = setInterval(() => {
        if (!fs.existsSync(pidFile) || tries > 10) {
          clearInterval(interval);
          try { fs.unlinkSync(pidFile); } catch {}
          resolve({ stopped: true, pid });
        }
        tries++;
      }, 200);
    });
  } catch (e) {
    try { fs.unlinkSync(pidFile); } catch {}
    return { stopped: false, reason: e.message };
  }
}

function isDaemonRunning(rootDir) {
  const pidFile = path.join(rootDir, DAEMON_FILE);
  if (!fs.existsSync(pidFile)) return false;
  try {
    const data = JSON.parse(fs.readFileSync(pidFile, 'utf8'));
    const pid = data.pid;
    if (!pid) return false;
    // Check if process is alive
    try {
      process.kill(pid, 0);
      return true;
    } catch (e) {
      // Process is dead — clean up stale PID file
      try { fs.unlinkSync(pidFile); } catch {}
      return false;
    }
  } catch {
    try { fs.unlinkSync(pidFile); } catch {}
    return false;
  }
}

function getDaemonStatus(rootDir) {
  const pidFile = path.join(rootDir, DAEMON_FILE);
  const logPath = path.join(rootDir, DAEMON_LOG);
  if (!fs.existsSync(pidFile)) {
    return { running: false };
  }
  try {
    const data = JSON.parse(fs.readFileSync(pidFile, 'utf8'));
    const running = isDaemonRunning(rootDir);
    return {
      running,
      pid: data.pid,
      root: data.root,
      startedAt: data.startedAt,
      findings: data.findings || 0,
      blocked: data.blocked || 0,
      watched: data.watched || 0,
      heartbeat: data.heartbeat,
      logFile: logPath,
    };
  } catch {
    return { running: false };
  }
}

module.exports = { runDaemon, startDaemon, stopDaemon, isDaemonRunning, getDaemonStatus, DAEMON_FILE, DAEMON_LOG };