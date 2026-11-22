'use strict';

/*
 * src/platform/runtime-monitor.js — process-level runtime guard.
 *
 * Polls a child process RSS against a configured cap and invokes the configured
 * quarantine callback once. This is not a filesystem or network monitor; those
 * require OS-specific tracing/WFP/netns integrations.
 */

const { execFileSync } = require('child_process');

function readRssBytes(pid, platform = process.platform) {
  if (!pid) return null;
  try {
    if (platform === 'linux' || platform === 'darwin') {
      const out = execFileSync('ps', ['-o', 'rss=', '-p', String(pid)], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
      const kb = Number(String(out).trim());
      return Number.isFinite(kb) && kb >= 0 ? kb * 1024 : null;
    }
    if (platform === 'win32') {
      const out = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `(Get-Process -Id ${Number(pid)} -ErrorAction Stop).WorkingSet64`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
      const bytes = Number(String(out).trim());
      return Number.isFinite(bytes) && bytes > 0 ? bytes : null;
    }
  } catch { /* process may have exited */ }
  return null;
}

class RuntimeMonitor {
  constructor(opts = {}) {
    this.pid = opts.pid;
    this.maxRssBytes = opts.maxRssBytes || 0;
    this.intervalMs = opts.intervalMs || 2000;
    this.onExceeded = opts.onExceeded || (() => {});
    this.read = opts.read || ((pid) => readRssBytes(pid));
    this.timer = null;
    this.lastRss = null;
    this.exceeded = false;
  }

  start() {
    if (!this.pid || !this.maxRssBytes || this.timer) return this;
    this.timer = setInterval(() => this.check(), this.intervalMs);
    if (this.timer.unref) this.timer.unref();
    return this;
  }

  check() {
    if (this.exceeded) return { exceeded: true, rss: this.lastRss };
    const rss = this.read(this.pid);
    this.lastRss = rss;
    if (rss != null && rss > this.maxRssBytes) {
      this.exceeded = true;
      this.stop();
      try { this.onExceeded({ pid: this.pid, rss, maxRssBytes: this.maxRssBytes }); } catch { /* callback must not crash monitor */ }
      return { exceeded: true, rss };
    }
    return { exceeded: false, rss };
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    return this;
  }
}

module.exports = { RuntimeMonitor, readRssBytes };
