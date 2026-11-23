'use strict';

/*
 * src/platform/macos-vm.js — hardware-VM isolation on macOS hosts.
 *
 * A QEMU/HVF VM is the boundary: the guest kernel is separate from macOS, the
 * VM has no network device, the disk is opened in snapshot mode and the only
 * host path exposed is a read-only 9p share containing the program.
 *
 * The caller supplies a bootable guest image. The image contract is:
 *   - Linux guest with Node.js on PATH
 *   - its init mounts the 9p share tagged "vibeguard" at /vibeguard and runs
 *     /vibeguard/entry.sh
 * If no image is configured, or the guest does not satisfy the contract, the
 * backend does not claim isolation. QEMU/HVF is used instead of a
 * Virtualization.framework helper because it is scriptable and can be verified
 * on the same host; the security property (separate kernel, no NIC, read-only
 * share) is the same class of boundary.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { ISOLATION } = require('./contracts');
const { HARNESS_SOURCE } = require('../sandbox');
const { defaultCacheFile, loadVerification, saveVerification } = require('./verification');

const SUITE_VERSION = 'macos-qemu-hvf-v1';
const DEFAULT_TIMEOUT = 30000;
const DEFAULT_MEMORY_MB = 512;

function which(name) {
  const cmd = process.platform === 'win32' ? 'where' : 'which';
  try {
    const r = spawnSync(cmd, [name], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return r.status === 0 ? String(r.stdout).trim().split(/\r?\n/)[0] : null;
  } catch {
    return null;
  }
}

function defaultQemu() {
  if (process.arch === 'arm64' || process.arch === 'aarch64') return which('qemu-system-aarch64');
  return which('qemu-system-x86_64');
}

function imageFormat(file) {
  return /\.(raw|img)$/i.test(file) ? 'raw' : 'qcow2';
}

function buildQemuArgs(opts) {
  const accel = opts.accel || 'hvf';
  const machine = process.arch === 'arm64' || process.arch === 'aarch64' ? 'virt' : 'q35';
  const args = [
    '-machine', `${machine},accel=${accel}`,
    '-m', String(opts.memoryMb || DEFAULT_MEMORY_MB),
    '-smp', '2',
    '-display', 'none',
    '-monitor', 'none',
    '-serial', 'stdio',
    '-nic', 'none',
    '-snapshot',
    '-no-reboot',
    '-virtfs', `local,path=${opts.shareDir},mount_tag=vibeguard,security_model=none,readonly=on`,
  ];
  if (opts.kernel) {
    args.push('-kernel', opts.kernel, '-append', opts.append || 'console=ttyS0');
    if (opts.initrd) args.push('-initrd', opts.initrd);
  } else {
    args.push('-drive', `file=${opts.image},format=${imageFormat(opts.image)},if=virtio`);
  }
  return args;
}

function parseGuestOutput(stdout) {
  const lines = String(stdout || '').split(/\r?\n/);
  const vmMarker = lines.find((l) => l.includes('__VG_VM_RESULT__'));
  const harnessMarker = lines.find((l) => l.includes('__VG_RESULT__'));
  const vmError = lines.find((l) => l.includes('__VG_VM_ERROR__'));
  const harnessError = lines.find((l) => l.includes('__VG_ERROR__'));
  if (vmMarker) {
    try {
      const parsed = JSON.parse(vmMarker.slice(vmMarker.indexOf('__VG_VM_RESULT__') + '__VG_VM_RESULT__'.length));
      return { matched: true, success: parsed.ok !== false, output: parsed.result === undefined ? null : parsed.result, error: parsed.error || null };
    } catch {
      return { matched: true, success: false, output: null, error: 'cannot parse guest result' };
    }
  }
  if (harnessMarker) {
    try {
      const parsed = JSON.parse(harnessMarker.slice(harnessMarker.indexOf('__VG_RESULT__') + '__VG_RESULT__'.length));
      return { matched: true, success: parsed.ok === true, output: parsed.result === undefined ? null : parsed.result, error: parsed.ok === true ? null : 'guest harness failed' };
    } catch {
      return { matched: true, success: false, output: null, error: 'cannot parse guest harness result' };
    }
  }
  if (harnessError || vmError) {
    const line = harnessError || vmError;
    const markerName = harnessError ? '__VG_ERROR__' : '__VG_VM_ERROR__';
    return { matched: true, success: false, output: null, error: line.slice(line.indexOf(markerName) + markerName.length).trim() };
  }
  return { matched: false, success: false, output: null, error: null };
}

const ENTRY_SCRIPT = `#!/bin/sh
set -u
if [ ! -d /vibeguard ]; then
  mkdir -p /vibeguard 2>/dev/null || true
  mount -t 9p -o trans=virtio,version=9p2000.L vibeguard /vibeguard 2>/dev/null || true
fi
if [ ! -f /vibeguard/run.js ]; then
  echo "__VG_VM_ERROR__share is not mounted at /vibeguard"
  poweroff -f
  exit 90
fi
if ! command -v node >/dev/null 2>&1; then
  echo "__VG_VM_ERROR__node is not installed in the guest image"
  poweroff -f
  exit 91
fi
node /vibeguard/run.js
code=$?
sync
poweroff -f 2>/dev/null || reboot -f 2>/dev/null || true
exit $code
`;

class MacVMSandbox {
  constructor(opts = {}) {
    this.id = 'macos-vm';
    this.isolationClass = ISOLATION.HARDWARE_VM;
    this.verified = false;
    this.verification = 'unverified';
    this.verifiedAt = null;
    this.evidence = [];
    this.suiteVersion = SUITE_VERSION;
    this.limitations = [
      'hardware VM (QEMU/HVF); guest kernel is separate from the macOS host',
      'the guest image and guest Node.js are caller-supplied and must be trusted',
      'no network device is attached; the only host path is a read-only 9p share',
      'the disk is opened with -snapshot; guest writes are discarded',
      'hypervisor/kernel zero-days remain in scope',
    ];
    this.image = opts.image || process.env.VIBEGUARD_VM_IMAGE || null;
    this.kernel = opts.kernel || process.env.VIBEGUARD_VM_KERNEL || null;
    this.initrd = opts.initrd || process.env.VIBEGUARD_VM_INITRD || null;
    this.append = opts.append || process.env.VIBEGUARD_VM_APPEND || null;
    this.qemu = opts.qemu || (process.platform === 'darwin' ? defaultQemu() : null);
    this.accel = opts.accel || 'hvf';
    this.memoryMb = opts.memoryMb || DEFAULT_MEMORY_MB;
    this.cacheFile = opts.cacheFile === undefined ? defaultCacheFile() : opts.cacheFile;
    this._shares = new Set();
    const cached = loadVerification(this.cacheFile, this.id, this.suiteVersion);
    if (cached && cached.verified === true) {
      this.verified = true;
      this.verification = cached.verification || 'cached';
      this.verifiedAt = cached.verifiedAt || null;
      this.evidence = Array.isArray(cached.evidence) ? cached.evidence : [];
    }
  }

  available() {
    if (process.platform !== 'darwin') return false;
    if (!this.qemu) return false;
    if (this.kernel) return fs.existsSync(this.kernel) && (!this.initrd || fs.existsSync(this.initrd));
    return Boolean(this.image) && fs.existsSync(this.image);
  }

  _reasonUnavailable() {
    if (process.platform !== 'darwin') return 'macOS VM backend requires a macOS host';
    if (!this.qemu) return 'qemu-system binary not found (install QEMU, e.g. brew install qemu)';
    if (this.kernel && !fs.existsSync(this.kernel)) return `VM kernel not found: ${this.kernel}`;
    if (this.initrd && !fs.existsSync(this.initrd)) return `VM initrd not found: ${this.initrd}`;
    if (!this.image && !this.kernel) return 'no VM image configured (set VIBEGUARD_VM_IMAGE or VIBEGUARD_VM_KERNEL)';
    return `VM image not found: ${this.image}`;
  }

  _shareDir() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-macvm-'));
    this._shares.add(dir);
    return dir;
  }

  _runGuest(script, opts = {}) {
    const started = Date.now();
    const timeout = opts.timeout || DEFAULT_TIMEOUT;
    const result = {
      success: false,
      output: null,
      error: null,
      duration: 0,
      isolation: 'hardware-vm-macos-qemu',
      isolationClass: ISOLATION.HARDWARE_VM,
      verified: this.verified,
      verification: this.verification,
      limitations: this.limitations.slice(),
      memoryCap: (opts.memoryMb || this.memoryMb) * 1024 * 1024,
      memoryEnforced: true,
    };
    if (!this.available()) {
      result.error = `macOS VM backend unavailable: ${this._reasonUnavailable()}`;
      result.duration = Date.now() - started;
      return Promise.resolve(result);
    }
    const share = this._shareDir();
    const entry = path.join(share, 'entry.sh');
    fs.writeFileSync(entry, ENTRY_SCRIPT, 'utf8');
    try { fs.chmodSync(entry, 0o755); } catch { /* Windows test hosts */ }
    fs.writeFileSync(path.join(share, 'run.js'), String(script == null ? '' : script), 'utf8');
    if (opts.userCode !== undefined) fs.writeFileSync(path.join(share, 'user.js'), String(opts.userCode == null ? '' : opts.userCode), 'utf8');
    const args = buildQemuArgs({
      shareDir: share,
      image: this.image,
      kernel: this.kernel,
      initrd: this.initrd,
      append: this.append,
      accel: this.accel,
      memoryMb: opts.memoryMb || this.memoryMb,
    });
    return new Promise((resolve) => {
      const child = spawn(this.qemu, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, shell: false });
      let stdout = '';
      let stderr = '';
      const timer = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch { /* ignore */ }
      }, timeout);
      const append = (current, chunk, cap) => (current + chunk.toString('utf8')).slice(-cap);
      child.stdout.on('data', (c) => { stdout = append(stdout, c, 4 * 1024 * 1024); });
      child.stderr.on('data', (c) => { stderr = append(stderr, c, 1024 * 1024); });
      child.once('error', (err) => {
        clearTimeout(timer);
        result.error = err.message;
        result.duration = Date.now() - started;
        this._cleanupShare(share);
        resolve(result);
      });
      child.once('exit', (code, signal) => {
        clearTimeout(timer);
        const parsed = parseGuestOutput(stdout);
        if (parsed.matched) {
          result.success = parsed.success;
          result.output = parsed.output;
          result.error = parsed.error;
        } else if (signal === 'SIGKILL') {
          result.error = 'VibeGuard macOS VM: execution timed out';
        } else {
          result.error = (stderr || stdout || `qemu exited with code ${code}`).trim().slice(-500);
        }
        result.duration = Date.now() - started;
        this._cleanupShare(share);
        resolve(result);
      });
    });
  }

  _cleanupShare(dir) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
    this._shares.delete(dir);
  }

  async run(code, opts = {}) {
    // Untrusted code runs through the same harness as the process/AppContainer
    // backends: a fresh V8 context with no host-realm objects. The guest's
    // entry script executes run.js, not user.js.
    const result = await this._runGuest(HARNESS_SOURCE, { ...opts, userCode: code });
    if (result.success) {
      result.output = result.output === null ? null : String(result.output);
    }
    return result;
  }

  async verify() {
    if (!this.available()) {
      this.verified = false;
      this.verification = `unavailable: ${this._reasonUnavailable()}`;
      this.verifiedAt = new Date().toISOString();
      this.evidence = [];
      saveVerification(this.cacheFile, this.id, {
        verified: false,
        verification: this.verification,
        verifiedAt: this.verifiedAt,
        suiteVersion: this.suiteVersion,
        evidence: [],
        limitations: this.limitations,
      });
      return false;
    }
    const evidence = [];
    const record = (testId, passed, details) => evidence.push({ testId, passed: !!passed, details: details ? String(details).slice(0, 500) : undefined });
    const hostMarker = path.join(os.tmpdir(), `vg-macvm-host-${Date.now()}-${Math.random().toString(16).slice(2)}`);
    try {
      fs.writeFileSync(hostMarker, 'HOST-SECRET', 'utf8');
      const probe = [
        "const fs=require('fs');",
        "const nets=Object.keys(require('os').networkInterfaces()).sort();",
        "let mounts=[]; try { mounts=fs.readFileSync('/proc/mounts','utf8').split('\\n').filter(l=>l.includes('vibeguard')); } catch (e) {}",
        `let hostVisible=false; try { hostVisible=fs.readFileSync(${JSON.stringify(hostMarker)},'utf8').includes('HOST-SECRET'); } catch (e) {}`,
        "let shareWritable=false; try { fs.writeFileSync('/vibeguard/.vg-write-test','x'); shareWritable=true; } catch (e) {}",
        "console.log('__VG_VM_RESULT__'+JSON.stringify({ok:true,result:{nets,mounts,hostVisible,shareWritable}}));",
      ].join('\n');
      const r = await this._runGuest(probe, { timeout: 60000 });
      let parsed = null;
      if (r.output && typeof r.output === 'object') parsed = r.output;
      else try { parsed = JSON.parse(String(r.output || '')); } catch { /* below */ }
      record('guest-boot-and-node', r.success && parsed && Array.isArray(parsed.nets), r.error || JSON.stringify(r.output || '').slice(0, 300));
      record('no-network-device', parsed && parsed.nets && !parsed.nets.some((n) => n !== 'lo'), parsed ? `interfaces=${parsed.nets.join(',')}` : 'no guest report');
      record('host-file-not-visible', parsed && parsed.hostVisible === false, parsed ? `hostVisible=${parsed.hostVisible}` : 'no guest report');
      record('share-readonly', parsed && parsed.shareWritable === false, parsed ? `shareWritable=${parsed.shareWritable}` : 'no guest report');
      const args = buildQemuArgs({ shareDir: '/tmp/vibeguard-verify', image: this.image, kernel: this.kernel, initrd: this.initrd, append: this.append, accel: this.accel, memoryMb: this.memoryMb });
      const text = args.join(' ');
      record('qemu-no-nic', /(^| )-nic none( |$)/.test(text), text.slice(0, 300));
      record('qemu-readonly-share', /readonly=on/.test(text), 'virtfs is mounted read-only');
      record('qemu-snapshot-disk', /(^| )-snapshot( |$)/.test(text) || Boolean(this.kernel), 'disk writes are discarded');
      const passed = evidence.every((e) => e.passed);
      this.verified = passed;
      this.verifiedAt = new Date().toISOString();
      this.evidence = evidence;
      this.verification = passed ? 'macos-qemu-hvf-verified' : `verification-failed(${evidence.filter((e) => !e.passed).map((e) => e.testId).join(',')})`;
      saveVerification(this.cacheFile, this.id, {
        verified: passed,
        verification: this.verification,
        verifiedAt: this.verifiedAt,
        suiteVersion: this.suiteVersion,
        evidence,
        limitations: this.limitations,
      });
      return passed;
    } catch (err) {
      this.verified = false;
      this.verification = `verification-failed(${err.message})`;
      this.verifiedAt = new Date().toISOString();
      this.evidence = evidence;
      saveVerification(this.cacheFile, this.id, {
        verified: false,
        verification: this.verification,
        verifiedAt: this.verifiedAt,
        suiteVersion: this.suiteVersion,
        evidence,
        limitations: this.limitations,
      });
      return false;
    } finally {
      try { fs.rmSync(hostMarker, { force: true }); } catch { /* ignore */ }
    }
  }

  dispose() {
    for (const dir of [...this._shares]) this._cleanupShare(dir);
  }
}

module.exports = { MacVMSandbox, buildQemuArgs, parseGuestOutput, ENTRY_SCRIPT, SUITE_VERSION };
