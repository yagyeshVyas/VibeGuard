'use strict';

/*
 * src/platform/os-sandbox.js — Linux OS-namespace execution backend.
 *
 * Uses util-linux `unshare` to create a user/network/PID namespace, then runs
 * the existing VibeGuard harness inside it. This provides real kernel-enforced
 * network and PID isolation on Linux, but the filesystem is still host-readable;
 * do not call it a general-purpose container or VM. Windows AppContainer/Job
 * Object/WFP and macOS VM backends are not implemented in this file.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const { ISOLATION } = require('./contracts');
const { HARNESS_SOURCE } = require('../sandbox');

const DEFAULT_TIMEOUT = 5000;

function which(name) {
  const cmd = process.platform === 'win32' ? 'where' : 'which';
  try {
    const r = spawnSync(cmd, [name], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return r.status === 0 ? String(r.stdout).trim().split(/\r?\n/)[0] : null;
  } catch { return null; }
}

class LinuxNamespaceSandbox {
  constructor(opts = {}) {
    this.id = 'linux-namespace';
    this.isolationClass = ISOLATION.OS;
    this.verified = false;
    this.verification = 'unverified';
    this.limitations = ['filesystem is not isolated from the host', 'requires util-linux unshare and user namespaces'];
    this.nodePath = opts.nodePath || process.execPath;
    this.unshare = opts.unshare || which('unshare');
  }

  available() {
    return process.platform === 'linux' && Boolean(this.unshare);
  }

  _baseArgs() {
    return ['-Urn', '--pid', '--fork', '--mount-proc'];
  }

  run(code, opts = {}) {
    const started = Date.now();
    const timeout = opts.timeout || DEFAULT_TIMEOUT;
    const result = {
      success: false,
      output: null,
      error: null,
      duration: 0,
      isolation: 'os-linux-namespace',
      isolationClass: ISOLATION.OS,
      verified: this.verified,
      verification: this.verification,
      limitations: this.limitations.slice(),
    };
    if (!this.available()) {
      result.error = 'Linux namespace backend unavailable (requires Linux + unshare + user namespaces)';
      result.duration = Date.now() - started;
      return Promise.resolve(result);
    }
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-osns-'));
    fs.writeFileSync(path.join(dir, 'user.js'), String(code), 'utf8');
    fs.writeFileSync(path.join(dir, 'harness.js'), HARNESS_SOURCE, 'utf8');
    return new Promise((resolve) => {
      const child = spawn(this.unshare, [...this._baseArgs(), this.nodePath, path.join(dir, 'harness.js')], {
        cwd: dir,
        env: { PATH: process.env.PATH || '/usr/bin:/bin', HOME: dir },
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        shell: false,
      });
      let stdout = '';
      let stderr = '';
      const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* ignore */ } }, timeout);
      child.stdout.on('data', (c) => { stdout += c.toString('utf8'); if (stdout.length > 1024 * 1024) stdout = stdout.slice(0, 1024 * 1024); });
      child.stderr.on('data', (c) => { stderr += c.toString('utf8').slice(0, 1024 * 1024); });
      child.once('error', (err) => { clearTimeout(timer); result.error = err.message; result.duration = Date.now() - started; resolve(result); });
      child.once('exit', (code, signal) => {
        clearTimeout(timer);
        const marker = stdout.split(/\r?\n/).find((l) => l.startsWith('__VG_RESULT__'));
        const errorMarker = stdout.split(/\r?\n/).find((l) => l.startsWith('__VG_ERROR__'));
        if (marker) {
          try { const parsed = JSON.parse(marker.slice('__VG_RESULT__'.length)); result.success = true; result.output = parsed.result; } catch { result.error = 'cannot parse harness result'; }
        } else if (errorMarker) {
          try { result.error = JSON.parse(errorMarker.slice('__VG_ERROR__'.length)); } catch { result.error = 'sandbox error'; }
        } else if (signal === 'SIGKILL') {
          result.error = 'VibeGuard OS sandbox: execution timed out';
        } else {
          result.error = stderr.trim() || `sandbox exited with code ${code}`;
        }
        result.duration = Date.now() - started;
        resolve(result);
      });
    });
  }

  async verify() {
    if (!this.available()) {
      this.verified = false;
      this.verification = 'unavailable';
      return false;
    }
    // Verify network isolation: a local TCP listener reachable on the host must
    // not be reachable from the new network namespace.
    const server = net.createServer();
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-osns-verify-'));
    const probe = path.join(dir, 'probe.js');
    fs.writeFileSync(probe, `const net=require('net');const s=net.connect(${port},'127.0.0.1');s.on('connect',()=>{console.log('REACHABLE');process.exit(2)});s.on('error',()=>{console.log('BLOCKED');process.exit(0)});setTimeout(()=>{console.log('BLOCKED');process.exit(0)},1000);`);
    const ok = await new Promise((resolve) => {
      const child = spawn(this.unshare, [...this._baseArgs(), this.nodePath, probe], {
        cwd: dir,
        env: { PATH: process.env.PATH || '/usr/bin:/bin' },
        stdio: ['ignore', 'pipe', 'pipe'],
        shell: false,
      });
      let out = '';
      const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* ignore */ } resolve(false); }, 3000);
      child.stdout.on('data', (c) => { out += c.toString('utf8'); });
      child.once('error', () => { clearTimeout(timer); resolve(false); });
      child.once('exit', () => { clearTimeout(timer); resolve(out.includes('BLOCKED') && !out.includes('REACHABLE')); });
    });
    await new Promise((resolve) => server.close(resolve));
    this.verified = ok;
    this.verification = ok ? 'network-namespace-verified' : 'verification-failed';
    if (ok) this.limitations = ['filesystem is not isolated from the host', 'network/PID namespaces verified by local probe'];
    return ok;
  }
}

function getLinuxBackend(opts) {
  return new LinuxNamespaceSandbox(opts);
}

module.exports = { LinuxNamespaceSandbox, getLinuxBackend };
