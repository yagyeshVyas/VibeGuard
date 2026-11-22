'use strict';

/*
 * src/platform/windows-sandbox.js — Windows Job Object execution boundary.
 *
 * This is a real kernel Job Object (process/memory limits, kill-on-close), but
 * it is NOT AppContainer and does not implement WFP network or filesystem
 * isolation. Do not call it a full OS sandbox; the limitations are reported.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { ISOLATION } = require('./contracts');
const { HARNESS_SOURCE } = require('../sandbox');

const CS_SOURCE = [
  'using System;',
  'using System.Diagnostics;',
  'using System.Runtime.InteropServices;',
  'using System.Text;',
  'public static class VGJob {',
  '  [StructLayout(LayoutKind.Sequential)] public struct IO_COUNTERS { public ulong ReadOperationCount; public ulong WriteOperationCount; public ulong OtherOperationCount; public ulong ReadTransferCount; public ulong WriteTransferCount; public ulong OtherTransferCount; }',
  '  [StructLayout(LayoutKind.Sequential)] public struct JOBOBJECT_BASIC_LIMIT_INFORMATION { public long PerProcessUserTimeLimit; public long PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass; public uint SchedulingClass; }',
  '  [StructLayout(LayoutKind.Sequential)] public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION { public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation; public IO_COUNTERS IoInfo; public UIntPtr ProcessMemoryLimit; public UIntPtr JobMemoryLimit; public UIntPtr PeakProcessMemoryUsed; public UIntPtr PeakJobMemoryUsed; }',
  '  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern IntPtr CreateJobObject(IntPtr a, string name);',
  '  [DllImport("kernel32.dll")] static extern bool SetInformationJobObject(IntPtr h, int info, IntPtr p, uint len);',
  '  [DllImport("kernel32.dll")] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);',
  '  [DllImport("kernel32.dll")] static extern bool TerminateJobObject(IntPtr job, uint code);',
  '  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);',
  '  public static string Run(string exe, string args, int timeoutMs, int memoryMb) {',
  '    IntPtr job = CreateJobObject(IntPtr.Zero, null);',
  '    if (job == IntPtr.Zero) return "__VG_STDERR__failed to create job object";',
  '    var ext = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();',
  '    ext.BasicLimitInformation.LimitFlags = 0x2000 | 0x100 | 0x200;',
  '    ext.ProcessMemoryLimit = (UIntPtr)(memoryMb * 1024L * 1024L);',
  '    ext.JobMemoryLimit = (UIntPtr)(memoryMb * 2L * 1024L * 1024L);',
  '    int len = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));',
  '    IntPtr ptr = Marshal.AllocHGlobal(len);',
  '    Marshal.StructureToPtr(ext, ptr, false);',
  '    SetInformationJobObject(job, 9, ptr, (uint)len);',
  '    Marshal.FreeHGlobal(ptr);',
  '    var psi = new ProcessStartInfo(exe, args);',
  '    psi.UseShellExecute = false; psi.CreateNoWindow = true; psi.RedirectStandardOutput = true; psi.RedirectStandardError = true;',
  '    var so = new StringBuilder(); var se = new StringBuilder();',
  '    var p = new Process(); p.StartInfo = psi;',
  '    p.OutputDataReceived += (s, e) => { if (e.Data != null) so.AppendLine(e.Data); };',
  '    p.ErrorDataReceived += (s, e) => { if (e.Data != null) se.AppendLine(e.Data); };',
  '    p.Start(); AssignProcessToJobObject(job, p.Handle);',
  '    p.BeginOutputReadLine(); p.BeginErrorReadLine();',
  '    bool exited = p.WaitForExit(timeoutMs);',
  '    if (!exited) { TerminateJobObject(job, 1); p.WaitForExit(1000); }',
  '    p.WaitForExit(); CloseHandle(job);',
  '    return "__VG_STDOUT__" + so.ToString() + "__VG_STDERR__" + se.ToString() + "__VG_EXIT__" + (exited ? p.ExitCode : 124);',
  '  }',
  '}'
].join('\n');

const PS_SOURCE = [
  'param()',
  '$src = Get-Content -Raw -LiteralPath $env:VG_CS',
  'Add-Type -TypeDefinition $src -Language CSharp',
  '$out = [VGJob]::Run($env:VG_NODE, $env:VG_ARGS, [int]$env:VG_TIMEOUT, [int]$env:VG_MEM)',
  '[Console]::Out.Write($out)'
].join('\r\n');

function parseOutput(raw) {
  const o = raw.indexOf('__VG_STDOUT__');
  const e = raw.indexOf('__VG_STDERR__');
  const x = raw.indexOf('__VG_EXIT__');
  if (o < 0 || e < 0 || x < 0) return { stdout: raw, stderr: '', exit: null };
  return { stdout: raw.slice(o + 13, e), stderr: raw.slice(e + 13, x), exit: Number(raw.slice(x + 11).trim()) };
}

class WindowsJobSandbox {
  constructor(opts = {}) {
    this.id = 'windows-job';
    this.isolationClass = ISOLATION.OS;
    this.verified = false;
    this.verification = 'unverified';
    this.limitations = ['Job Object process/memory limits and kill-on-close', 'does not implement AppContainer, WFP network isolation or filesystem isolation'];
    this.powershell = opts.powershell || (process.platform === 'win32' ? 'powershell.exe' : null);
    this.nodePath = opts.nodePath || process.execPath;
    this.memoryMb = opts.memoryMb || 256;
  }

  available() { return process.platform === 'win32' && Boolean(this.powershell); }

  _runWithExe(exe, args, timeout) {
    const started = Date.now();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-winjob-'));
    const cs = path.join(dir, 'VGJob.cs');
    const ps = path.join(dir, 'run.ps1');
    fs.writeFileSync(cs, CS_SOURCE, 'utf8');
    fs.writeFileSync(ps, PS_SOURCE, 'utf8');
    return new Promise((resolve) => {
      const child = spawn(this.powershell, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ps], {
        cwd: dir,
        env: { ...process.env, VG_CS: cs, VG_NODE: exe, VG_ARGS: args, VG_TIMEOUT: String(timeout), VG_MEM: String(this.memoryMb) },
        stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, shell: false,
      });
      let raw = '';
      let stderr = '';
      const timer = setTimeout(() => { try { child.kill(); } catch { /* ignore */ } }, timeout + 4000);
      child.stdout.on('data', (c) => { raw += c.toString('utf8'); });
      child.stderr.on('data', (c) => { stderr += c.toString('utf8').slice(0, 64 * 1024); });
      child.once('error', (err) => { clearTimeout(timer); resolve({ success: false, output: null, error: err.message, duration: Date.now() - started, isolation: this.id, isolationClass: ISOLATION.OS, verified: this.verified, verification: this.verification, limitations: this.limitations }); });
      child.once('exit', () => {
        clearTimeout(timer);
        const parsed = parseOutput(raw);
        const marker = parsed.stdout.split(/\r?\n/).find((l) => l.startsWith('__VG_RESULT__'));
        const errorMarker = parsed.stdout.split(/\r?\n/).find((l) => l.startsWith('__VG_ERROR__'));
        let success = false; let output = null; let error = null;
        if (marker) { try { const p = JSON.parse(marker.slice(13)); success = true; output = p.result; } catch { error = 'cannot parse harness result'; } }
        else if (errorMarker) { try { error = JSON.parse(errorMarker.slice(11)); } catch { error = 'sandbox error'; } }
        else if (parsed.exit === 124) error = 'VibeGuard Windows Job sandbox: execution timed out';
        else error = parsed.stderr.trim() || stderr.trim() || `sandbox exited with code ${parsed.exit}`;
        resolve({ success, output, error, duration: Date.now() - started, isolation: this.id, isolationClass: ISOLATION.OS, verified: this.verified, verification: this.verification, limitations: this.limitations });
      });
    });
  }

  async run(code, opts = {}) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-winjob-prog-'));
    fs.writeFileSync(path.join(dir, 'user.js'), String(code), 'utf8');
    fs.writeFileSync(path.join(dir, 'harness.js'), HARNESS_SOURCE, 'utf8');
    return this._runWithExe(this.nodePath, `"${path.join(dir, 'harness.js')}"`, opts.timeout || 5000);
  }

  async verify() {
    if (!this.available()) { this.verification = 'unavailable'; return false; }
    const safe = await this.run('const x = 1 + 1; x', { timeout: 5000 });
    const timeout = await this.run('while (true) {}', { timeout: 1200 });
    const killed = !timeout.success && /timed out|exit/i.test(String(timeout.error || ''));
    this.verified = Boolean(safe.success && killed);
    this.verification = this.verified ? 'job-object-process-containment-verified' : 'verification-failed';
    return this.verified;
  }
}

module.exports = { WindowsJobSandbox };
