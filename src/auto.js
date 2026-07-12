'use strict';

/*
 * src/auto.js — One-command autonomous protection orchestrator.
 *
 * `vibeguard auto`        → scan + daemon + hooks + shell guard (idempotent)
 * `vibeguard auto --stop`  → reverse everything, restore backups
 * `vibeguard auto --status` → show what's active
 *
 * Composes existing modules: scanner, daemon, hook, shell-guard.
 * All state under .vibeguard/auto.json.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execSync } = require('child_process');

const STATE_DIR = '.vibeguard';
const STATE_FILE = path.join(STATE_DIR, 'auto.json');
const REPORT_FILE = path.join(STATE_DIR, 'report.json');
const SARIF_FILE = path.join(STATE_DIR, 'report.sarif');
const EVENTS_LOG = path.join(STATE_DIR, 'events.log');
const BACKUP_DIR = path.join(STATE_DIR, 'backups');

// ─── Helpers ──────────────────────────────────────────────────────────────

function findProjectRoot(startDir) {
  let dir = path.resolve(startDir);
  for (let i = 0; i < 20; i++) {
    if (fs.existsSync(path.join(dir, 'package.json')) || fs.existsSync(path.join(dir, '.git'))) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function ensureStateDir(root) {
  const dir = path.join(root, STATE_DIR);
  fs.mkdirSync(dir, { recursive: true });
  fs.mkdirSync(path.join(root, BACKUP_DIR), { recursive: true });
  return dir;
}

function readState(root) {
  const p = path.join(root, STATE_FILE);
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; }
}

function writeState(root, state) {
  ensureStateDir(root);
  fs.writeFileSync(path.join(root, STATE_FILE), JSON.stringify(state, null, 2));
}

function removeState(root) {
  try { fs.unlinkSync(path.join(root, STATE_FILE)); } catch {}
}

function logEvent(root, msg) {
  const logPath = path.join(root, EVENTS_LOG);
  const ts = new Date().toISOString();
  fs.appendFileSync(logPath, `[${ts}] ${msg}\n`);
}

function backupFile(src, dst) {
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, dst);
    return true;
  }
  return false;
}

function restoreFile(dst, src) {
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, dst);
    return true;
  }
  return false;
}

function isProcessAlive(pid) {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

// ─── Auto Start ────────────────────────────────────────────────────────────

function autoStart(rootDir, opts) {
  opts = opts || {};
  const root = findProjectRoot(rootDir);
  if (!root) {
    return { ok: false, reason: 'No project root found (no package.json or .git). Run from a project directory.' };
  }

  // Idempotent: if already running, report status
  const existing = readState(root);
  if (existing && existing.pid && isProcessAlive(existing.pid)) {
    return { ok: true, alreadyRunning: true, state: existing };
  }

  ensureStateDir(root);
  const state = {
    pid: process.pid,
    root,
    startedAt: new Date().toISOString(),
    features: {},
    backups: {},
    lastScan: null,
    findingsSinceStart: 0,
  };

  const steps = [];

  // 1. Initial full scan (always run — CI mode needs it too)
  const { scan } = require('./scanner');
  const result = scan(root, { deps: true, deep: !!opts.deep });
  state.lastScan = new Date().toISOString();
  state.findingsSinceStart = result.findings.length;

  // Write report + SARIF
  ensureStateDir(root);
  fs.writeFileSync(path.join(root, REPORT_FILE), JSON.stringify(result, null, 2));
  try {
    const { renderSarif } = require('./report');
    fs.writeFileSync(path.join(root, SARIF_FILE), renderSarif(result));
  } catch {}

  steps.push({
    step: 'scan',
    grade: result.grade,
    counts: result.counts,
    findings: result.findings.length,
  });

  // CI mode: exit non-zero on critical, no daemon
  if (opts.ci) {
    writeState(root, state);
    return { ok: true, ci: true, steps, exitCode: result.counts.critical > 0 ? 1 : 0 };
  }

  // --fix: apply safe auto-fixes
  if (opts.fix) {
    try {
      const { computeAutoFixes } = require('./autofix');
      const fixes = computeAutoFixes(result.findings, result.root);
      if (fixes && fixes.length > 0) {
        steps.push({ step: 'fix', fixes: fixes.length, reversible: true });
      }
    } catch {}
  }

  // 2. Start daemon (file watcher)
  if (!opts.ci) {
    try {
      const { startDaemon, isDaemonRunning } = require('./daemon');
      if (!isDaemonRunning(root)) {
        startDaemon(root, { verbose: opts.verbose }).then((r) => {
          if (r.started) {
            state.features.daemon = true;
            state.daemonPid = r.pid;
            logEvent(root, `daemon started (PID ${r.pid})`);
          }
        }).catch(() => {});
      } else {
        state.features.daemon = true;
      }
      steps.push({ step: 'daemon', started: state.features.daemon });
    } catch (e) {
      steps.push({ step: 'daemon', error: e.message });
    }
  }

  // 3. Install git pre-commit hook (if .git exists)
  const gitDir = path.join(root, '.git');
  if (fs.existsSync(gitDir) && !opts.ci) {
    const hooksDir = path.join(gitDir, 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });
    const preCommit = path.join(hooksDir, 'pre-commit');
    const backupPath = path.join(root, BACKUP_DIR, 'pre-commit.bak');

    // Backup existing hook if present
    if (fs.existsSync(preCommit)) {
      backupFile(preCommit, backupPath);
      state.backups.preCommit = backupPath;
    }

    // Write the hook
    const nodeBin = process.execPath.replace(/\\/g, '/');
    const cliPath = path.join(__dirname, '..', 'bin', 'cli.js').replace(/\\/g, '/');
    const strictFlag = opts.strict ? ' --strict' : '';
    const hook = `#!/usr/bin/env sh\n# VibeGuard pre-commit hook (auto-installed).\nNODE="${nodeBin}"\nCLI="${cliPath}"\nif [ ! -f "$CLI" ]; then exit 0; fi\n"$NODE" "$CLI" scan . --precommit${strictFlag}\nSTATUS=$?\nif [ "$STATUS" -eq 2 ]; then\n  echo "VibeGuard: commit blocked — CRITICAL issue(s). Fix or use --no-verify."\n  exit 1\nfi\nexit 0\n`;
    fs.writeFileSync(preCommit, hook);
    try { fs.chmodSync(preCommit, 0o755); } catch {}
    state.features.preCommitHook = true;
    steps.push({ step: 'pre-commit-hook', installed: true, backedUp: state.backups.preCommit ? true : false });
  }

  // 4. Install PostToolUse hook (for AI agent edit scanning)
  if (!opts.ci) {
    try {
      const hookMod = require('./hook');
      const r = hookMod.installPostEditHook(root);
      state.features.postEditHook = r.installed;
      steps.push({ step: 'post-edit-hook', installed: r.installed, file: r.file });
    } catch (e) {
      steps.push({ step: 'post-edit-hook', error: e.message });
    }
  }

  // 5. Arm shell guard (install shell hook) — requires consent
  if (!opts.noShell && !opts.ci) {
    // Skip shell guard in auto unless --yes is passed (consent).
    if (!opts.yes) {
      steps.push({ step: 'shell-guard', installed: false, reason: 'skipped (use --yes to enable)' });
    } else {
    try {
      const srcDir = path.join(__dirname);
      const home = os.homedir();
      const marker = '# >>> VibeGuard shell hook >>>';
      const endMarker = '# <<< VibeGuard shell hook <<<';
      const psMarker = '### >>> VibeGuard shell hook >>>';
      const psEndMarker = '### <<< VibeGuard shell hook <<<';
      const hookContent = `${marker}\nVG_SCRIPT_DIR="${srcDir.replace(/\\/g, '\\\\')}"\nsource "${path.join(srcDir, 'shell-hook.sh').replace(/\\/g, '\\\\')}"\n${endMarker}`;

      // bash
      const bashrc = path.join(home, '.bashrc');
      if (fs.existsSync(bashrc) || true) {
        let content = fs.existsSync(bashrc) ? fs.readFileSync(bashrc, 'utf8') : '';
        if (!content.includes(marker)) {
          const backupPath = path.join(root, BACKUP_DIR, 'bashrc.bak');
          if (fs.existsSync(bashrc)) backupFile(bashrc, backupPath);
          state.backups.bashrc = backupPath;
          content = content.trimEnd() + '\n' + hookContent + '\n';
          fs.writeFileSync(bashrc, content);
        }
      }

      // zsh
      const zshrc = path.join(home, '.zshrc');
      if (fs.existsSync(zshrc)) {
        let content = fs.readFileSync(zshrc, 'utf8');
        if (!content.includes(marker)) {
          const backupPath = path.join(root, BACKUP_DIR, 'zshrc.bak');
          backupFile(zshrc, backupPath);
          state.backups.zshrc = backupPath;
          content = content.trimEnd() + '\n' + hookContent + '\n';
          fs.writeFileSync(zshrc, content);
        }
      }

      // PowerShell (Windows)
      if (process.platform === 'win32') {
        const psDir = path.join(home, 'Documents', 'WindowsPowerShell');
        fs.mkdirSync(psDir, { recursive: true });
        const psProfile = path.join(psDir, 'Microsoft.PowerShell_profile.ps1');
        let content = fs.existsSync(psProfile) ? fs.readFileSync(psProfile, 'utf8') : '';
        if (!content.includes(psMarker)) {
          const backupPath = path.join(root, BACKUP_DIR, 'ps-profile.bak');
          if (fs.existsSync(psProfile)) backupFile(psProfile, backupPath);
          state.backups.psProfile = backupPath;
          const psHook = `${psMarker}\n$VG_SCRIPT_DIR = "${srcDir.replace(/\\/g, '\\\\')}"\n. "${path.join(srcDir, 'shell-hook.ps1').replace(/\\/g, '\\\\')}"\n${psEndMarker}`;
          content = content.trimEnd() + '\n' + psHook + '\n';
          fs.writeFileSync(psProfile, content);
        }
      }

      state.features.shellGuard = true;
      steps.push({ step: 'shell-guard', installed: true });
    } catch (e) {
      steps.push({ step: 'shell-guard', error: e.message });
    }
    }
  }

  // Add .vibeguard/ to .gitignore
  const gitignore = path.join(root, '.gitignore');
  try {
    let content = fs.existsSync(gitignore) ? fs.readFileSync(gitignore, 'utf8') : '';
    if (!content.includes('.vibeguard/')) {
      content = content.trimEnd() + '\n.vibeguard/\n';
      fs.writeFileSync(gitignore, content);
    }
  } catch {}

  writeState(root, state);
  logEvent(root, 'auto started');

  return { ok: true, steps, state };
}

// ─── Auto Stop ─────────────────────────────────────────────────────────────

function autoStop(rootDir) {
  const root = findProjectRoot(rootDir) || path.resolve(rootDir);
  const state = readState(root);
  if (!state) {
    return { ok: false, reason: 'No auto state found. Was `vibeguard auto` run?' };
  }

  const reversed = [];

  // 1. Kill daemon
  if (state.daemonPid) {
    try { process.kill(state.daemonPid, 'SIGTERM'); } catch {}
    reversed.push('daemon stopped');
  }

  // 2. Remove pre-commit hook (restore backup if exists)
  const preCommit = path.join(root, '.git', 'hooks', 'pre-commit');
  if (fs.existsSync(preCommit) && state.backups && state.backups.preCommit) {
    restoreFile(preCommit, state.backups.preCommit);
    reversed.push('pre-commit hook restored from backup');
  } else if (fs.existsSync(preCommit)) {
    // Only remove if we installed it
    const content = fs.readFileSync(preCommit, 'utf8');
    if (content.includes('VibeGuard')) {
      fs.unlinkSync(preCommit);
      reversed.push('pre-commit hook removed');
    }
  }

  // 3. Remove PostToolUse hook
  try {
    const hookMod = require('./hook');
    const r = hookMod.uninstallPostEditHook(root);
    if (r.uninstalled) reversed.push('post-edit hook removed');
  } catch {}

  // 4. Disarm shell guard (remove from shell profiles)
  const marker = '# >>> VibeGuard shell hook >>>';
  const endMarker = '# <<< VibeGuard shell hook <<<';
  const psMarker = '### >>> VibeGuard shell hook >>>';
  const psEndMarker = '### <<< VibeGuard shell hook <<<';
  const home = os.homedir();

  for (const profile of ['.bashrc', '.zshrc']) {
    const p = path.join(home, profile);
    try {
      if (fs.existsSync(p)) {
        let content = fs.readFileSync(p, 'utf8');
        // Restore from backup if available
        const backupKey = profile === '.bashrc' ? 'bashrc' : 'zshrc';
        if (state.backups && state.backups[backupKey] && fs.existsSync(state.backups[backupKey])) {
          content = fs.readFileSync(state.backups[backupKey], 'utf8');
          fs.writeFileSync(p, content);
          reversed.push(`${profile} restored from backup`);
        } else {
          // Just remove our block
          const before = content;
          content = content.replace(new RegExp(marker + '[\\s\\S]*?' + endMarker + '\\n?', 'g'), '');
          if (content !== before) {
            fs.writeFileSync(p, content);
            reversed.push(`${profile} hook removed`);
          }
        }
      }
    } catch {}
  }

  if (process.platform === 'win32') {
    try {
      const psProfile = path.join(home, 'Documents', 'WindowsPowerShell', 'Microsoft.PowerShell_profile.ps1');
      if (fs.existsSync(psProfile)) {
        let content = fs.readFileSync(psProfile, 'utf8');
        if (state.backups && state.backups.psProfile && fs.existsSync(state.backups.psProfile)) {
          content = fs.readFileSync(state.backups.psProfile, 'utf8');
          fs.writeFileSync(psProfile, content);
          reversed.push('PowerShell profile restored from backup');
        } else {
          const before = content;
          content = content.replace(new RegExp(psMarker + '[\\s\\S]*?' + psEndMarker + '\\n?', 'g'), '');
          if (content !== before) {
            fs.writeFileSync(psProfile, content);
            reversed.push('PowerShell profile hook removed');
          }
        }
      }
    } catch {}
  }

  // 5. Remove state file
  removeState(root);
  reversed.push('state file removed');

  logEvent(root, 'auto stopped');

  return { ok: true, reversed };
}

// ─── Auto Status ──────────────────────────────────────────────────────────

function autoStatus(rootDir) {
  const root = findProjectRoot(rootDir) || path.resolve(rootDir);
  const state = readState(root);
  if (!state) {
    return { running: false, reason: 'No auto state found' };
  }

  const daemonAlive = state.daemonPid ? isProcessAlive(state.daemonPid) : false;
  const uptime = state.startedAt ? Date.now() - new Date(state.startedAt).getTime() : 0;

  return {
    running: true,
    pid: state.pid,
    daemonPid: state.daemonPid,
    daemonAlive,
    startedAt: state.startedAt,
    uptimeMs: uptime,
    features: state.features || {},
    findingsSinceStart: state.findingsSinceStart || 0,
    lastScan: state.lastScan,
    root: state.root,
  };
}

// ─── CI Mode ────────────────────────────────────────────────────────────────

function autoCI(rootDir, opts) {
  opts = opts || {};
  opts.ci = true;
  return autoStart(rootDir, opts);
}

module.exports = { autoStart, autoStop, autoStatus, autoCI, findProjectRoot };