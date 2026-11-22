'use strict';

/*
 * src/platform/os-sandbox.js — Linux OS isolation backends.
 *
 * Two backends are provided:
 *   - LinuxBubblewrapSandbox: bubblewrap user/mount/net/PID namespace with a
 *     minimal read-only system root and isolated /tmp. This is the preferred
 *     Linux backend when bwrap is installed.
 *   - LinuxNamespaceSandbox: util-linux unshare network/PID namespace only;
 *     filesystem remains host-readable. Kept as a fallback, explicitly limited.
 *
 * Neither is a full container/VM. Verification is executable and reported.
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

function parseHarnessOutput(stdout, stderr, signal, code) {
  const marker = stdout.split(/\r?\n/).find((l) => l.startsWith('__VG_RESULT__'));
  const errorMarker = stdout.split(/\r?\n/).find((l) => l.startsWith('__VG_ERROR__'));
  if (marker) {
    try { const parsed = JSON.parse(marker.slice('__VG_RESULT__'.length)); return { success: true, output: parsed.result, error: null }; } catch { return { success: false, output: null, error: 'cannot parse harness result' }; }
  }
  if (errorMarker) {
    try { return { success: false, output: null, error: JSON.parse(errorMarker.slice('__VG_ERROR__'.length)) }; } catch { return { success: false, output: null, error: 'sandbox error' }; }
  }
  if (signal === 'SIGKILL') return { success: false, output: null, error: 'VibeGuard OS sandbox: execution timed out' };
  return { success: false, output: null, error: stderr.trim() || `sandbox exited with code ${code}` };
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
      success: false, output: null, error: null, duration: 0,
      isolation: 'os-linux-namespace', isolationClass: ISOLATION.OS,
      verified: this.verified, verification: this.verification,
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
        stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, shell: false,
      });
      let stdout = '';
      let stderr = '';
      const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* ignore */ } }, timeout);
      child.stdout.on('data', (c) => { stdout += c.toString('utf8'); if (stdout.length > 1024 * 1024) stdout = stdout.slice(0, 1024 * 1024); });
      child.stderr.on('data', (c) => { stderr += c.toString('utf8').slice(0, 1024 * 1024); });
      child.once('error', (err) => { clearTimeout(timer); result.error = err.message; result.duration = Date.now() - started; resolve(result); });
      child.once('exit', (code, signal) => {
        clearTimeout(timer);
        Object.assign(result, parseHarnessOutput(stdout, stderr, signal, code));
        result.duration = Date.now() - started;
        resolve(result);
      });
    });
  }

  async verify() {
    if (!this.available()) { this.verified = false; this.verification = 'unavailable'; return false; }
    const ok = await verifyNetworkNamespace(this.unshare, this._baseArgs(), this.nodePath);
    this.verified = ok;
    this.verification = ok ? 'network-namespace-verified' : 'verification-failed';
    if (ok) this.limitations = ['filesystem is not isolated from the host', 'network/PID namespaces verified by local probe'];
    return ok;
  }
}

class LinuxBubblewrapSandbox {
  constructor(opts = {}) {
    this.id = 'linux-bubblewrap';
    this.isolationClass = ISOLATION.OS;
    this.verified = false;
    this.verification = 'unverified';
    this.limitations = ['user/mount/net/PID namespaces; not a VM/hardware boundary'];
    this.nodePath = opts.nodePath || process.execPath;
    this.bwrap = opts.bwrap || which('bwrap');
  }

  available() {
    return process.platform === 'linux' && Boolean(this.bwrap);
  }

  _args(dir) {
    const nodeRoot = path.dirname(path.dirname(this.nodePath));
    const nodeRel = path.relative(nodeRoot, this.nodePath);
    const args = [
      '--die-with-parent', '--new-session', '--unshare-all', '--clearenv',
      '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'HOME', '/tmp',
      '--proc', '/proc', '--dev', '/dev',
      '--tmpfs', '/tmp', '--tmpfs', '/home', '--tmpfs', '/root', '--tmpfs', '/var/tmp',
      '--ro-bind', '/usr', '/usr', '--ro-bind', '/bin', '/bin',
      '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
      '--ro-bind', nodeRoot, '/node',
      '--ro-bind', dir, '/work', '--chdir', '/work',
      '/node/' + nodeRel, '/work/harness.js',
    ];
    return args;
  }

  run(code, opts = {}) {
    const started = Date.now();
    const timeout = opts.timeout || DEFAULT_TIMEOUT;
    const result = {
      success: false, output: null, error: null, duration: 0,
      isolation: 'os-linux-bubblewrap', isolationClass: ISOLATION.OS,
      verified: this.verified, verification: this.verification,
      limitations: this.limitations.slice(),
    };
    if (!this.available()) {
      result.error = 'bubblewrap backend unavailable';
      result.duration = Date.now() - started;
      return Promise.resolve(result);
    }
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-bwrap-'));
    fs.writeFileSync(path.join(dir, 'user.js'), String(code), 'utf8');
    fs.writeFileSync(path.join(dir, 'harness.js'), HARNESS_SOURCE, 'utf8');
    return new Promise((resolve) => {
      const child = spawn(this.bwrap, this._args(dir), {
        cwd: dir, env: { PATH: '/usr/bin:/bin' }, stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true, shell: false,
      });
      let stdout = '';
      let stderr = '';
      const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* ignore */ } }, timeout);
      child.stdout.on('data', (c) => { stdout += c.toString('utf8'); if (stdout.length > 1024 * 1024) stdout = stdout.slice(0, 1024 * 1024); });
      child.stderr.on('data', (c) => { stderr += c.toString('utf8').slice(0, 1024 * 1024); });
      child.once('error', (err) => { clearTimeout(timer); result.error = err.message; result.duration = Date.now() - started; resolve(result); });
      child.once('exit', (code, signal) => {
        clearTimeout(timer);
        Object.assign(result, parseHarnessOutput(stdout, stderr, signal, code));
        result.duration = Date.now() - started;
        resolve(result);
      });
    });
  }

  async verify() {
    if (!this.available()) { this.verified = false; this.verification = 'unavailable'; return false; }
    const nodeRoot = path.dirname(path.dirname(this.nodePath));
    const nodeRel = path.relative(nodeRoot, this.nodePath);
    const network = await verifyNetworkNamespace(this.bwrap, ['--die-with-parent', '--unshare-all', '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64', '--ro-bind', '/bin', '/bin', '--ro-bind', nodeRoot, '/node'], '/node/' + nodeRel);
    const filesystem = await verifyFilesystemIsolation(this.bwrap, this.nodePath);
    this.verified = network && filesystem;
    this.verification = this.verified ? 'network-and-filesystem-isolation-verified' : `verification-failed(network=${network},filesystem=${filesystem})`;
    if (this.verified) this.limitations = ['user/mount/net/PID namespaces; not a VM/hardware boundary', 'minimal read-only system root; /tmp isolated'];
    return this.verified;
  }
}

async function verifyNetworkNamespace(command, baseArgs, nodePath) {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-osns-verify-'));
  const probe = path.join(dir, 'probe.js');
  fs.writeFileSync(probe, `const net=require('net');const s=net.connect(${port},'127.0.0.1');s.on('connect',()=>{console.log('REACHABLE');process.exit(2)});s.on('error',()=>{console.log('BLOCKED');process.exit(0)});setTimeout(()=>{console.log('BLOCKED');process.exit(0)},1000);`);
  const ok = await new Promise((resolve) => {
    const isBwrap = path.basename(command).includes('bwrap');
    const argv = isBwrap ? [...baseArgs, '--ro-bind', dir, '/work', '--chdir', '/work', nodePath, '/work/probe.js'] : [...baseArgs, nodePath, probe];
    const child = spawn(command, argv, {
      cwd: dir, env: { PATH: '/usr/bin:/bin' }, stdio: ['ignore', 'pipe', 'pipe'], shell: false,
    });
    let out = '';
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* ignore */ } resolve(false); }, 3000);
    child.stdout.on('data', (c) => { out += c.toString('utf8'); });
    child.once('error', () => { clearTimeout(timer); resolve(false); });
    child.once('exit', () => { clearTimeout(timer); resolve(out.includes('BLOCKED') && !out.includes('REACHABLE')); });
  });
  await new Promise((resolve) => server.close(resolve));
  return ok;
}

async function verifyFilesystemIsolation(bwrap, nodePath) {
  const marker = path.join(os.tmpdir(), 'vg-host-marker-' + cryptoRandom());
  fs.writeFileSync(marker, 'HOST-SECRET');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-bwrap-verify-'));
  const probe = path.join(dir, 'probe.js');
  fs.writeFileSync(probe, `const fs=require('fs');try{fs.readFileSync(${JSON.stringify(marker)});console.log('VISIBLE')}catch(e){console.log('BLOCKED')}`);
  const nodeRoot = path.dirname(path.dirname(nodePath));
  const nodeRel = path.relative(nodeRoot, nodePath);
  const args = ['--die-with-parent', '--unshare-all', '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin',
    '--ro-bind', '/usr', '/usr', '--ro-bind', '/bin', '/bin', '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
    '--ro-bind', nodeRoot, '/node', '--ro-bind', dir, '/work', '--chdir', '/work',
    '/node/' + nodeRel, '/work/probe.js'];
  const ok = await new Promise((resolve) => {
    const child = spawn(bwrap, args, { cwd: dir, env: { PATH: '/usr/bin:/bin' }, stdio: ['ignore', 'pipe', 'pipe'], shell: false });
    let out = '';
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* ignore */ } resolve(false); }, 3000);
    child.stdout.on('data', (c) => { out += c.toString('utf8'); });
    child.once('error', () => { clearTimeout(timer); resolve(false); });
    child.once('exit', () => { clearTimeout(timer); resolve(out.includes('BLOCKED') && !out.includes('VISIBLE')); });
  });
  try { fs.unlinkSync(marker); } catch { /* ignore */ }
  return ok;
}

function cryptoRandom() { return require('crypto').randomBytes(8).toString('hex'); }

function getLinuxBackend(opts = {}) {
  const bwrap = new LinuxBubblewrapSandbox(opts);
  if (bwrap.available()) return bwrap;
  return new LinuxNamespaceSandbox(opts);
}

module.exports = { LinuxNamespaceSandbox, LinuxBubblewrapSandbox, getLinuxBackend };
