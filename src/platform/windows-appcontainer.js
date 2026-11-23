'use strict';

/*
 * src/platform/windows-appcontainer.js — Windows AppContainer isolation.
 *
 * The launch path is:
 *   1. CreateAppContainerProfile (or derive the SID of an existing profile).
 *   2. GetAppContainerFolderPath, the only host location the package SID can
 *      write without an explicit ACL grant.
 *   3. Copy the Node executable and the program into that profile folder.
 *   4. CreateProcessW with PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES and a
 *      suspended child, assign it to a locked-down Job Object, then resume.
 *
 * No capability SIDs are attached, so the AppContainer has no network access
 * (not even loopback). The Job Object supplies process/memory limits, UI
 * restrictions and kill-on-close. The AppContainer is an OS boundary; it is
 * not a hypervisor boundary and the limitations are reported with every run.
 */

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { ISOLATION } = require('./contracts');
const { HARNESS_SOURCE } = require('../sandbox');
const { defaultCacheFile, loadVerification, saveVerification } = require('./verification');

const SUITE_VERSION = 'windows-appcontainer-job-v2';
const BACKEND_HASH = (() => {
  try { return require('crypto').createHash('sha256').update(fs.readFileSync(__filename)).digest('hex').slice(0, 16); }
  catch { return 'unknown'; }
})();
const DEFAULT_TIMEOUT = 5000;
const DEFAULT_MEMORY_MB = 256;
const DEFAULT_PROCESS_LIMIT = 16;

const CSHARP_SOURCE = String.raw`using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

public static class VGAppContainer
{
    const int EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    const int CREATE_SUSPENDED = 0x00000004;
    const int CREATE_NO_WINDOW = 0x08000000;
    const int STARTF_USESTDHANDLES = 0x00000100;
    const int HANDLE_FLAG_INHERIT = 0x00000001;
    const uint WAIT_TIMEOUT = 0x00000102;
    const uint PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009;
    const uint PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002;
    const int JobObjectExtendedLimitInformation = 9;
    const int JobObjectBasicUIRestrictions = 4;
    const uint JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100;
    const uint JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200;
    const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    const uint JOB_OBJECT_UILIMIT_HANDLES = 0x00000001;
    const uint JOB_OBJECT_UILIMIT_READCLIPBOARD = 0x00000002;
    const uint JOB_OBJECT_UILIMIT_WRITECLIPBOARD = 0x00000004;
    const uint JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS = 0x00000008;
    const uint JOB_OBJECT_UILIMIT_DISPLAYSETTINGS = 0x00000010;
    const uint JOB_OBJECT_UILIMIT_GLOBALATOMS = 0x00000020;
    const uint JOB_OBJECT_UILIMIT_DESKTOP = 0x00000040;
    const uint JOB_OBJECT_UILIMIT_EXITWINDOWS = 0x00000080;

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_UI_RESTRICTIONS
    {
        public uint UIRestrictionsClass;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_CAPABILITIES
    {
        public IntPtr AppContainerSid;
        public IntPtr Capabilities;
        public uint CapabilityCount;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int CreateAppContainerProfile(string pszAppContainerName, string pszDisplayName, string pszDescription, IntPtr pCapabilities, uint dwCapabilityCount, out IntPtr ppSidAppContainer);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int DeriveAppContainerSidFromAppContainerName(string pszAppContainerName, out IntPtr ppSidAppContainer);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int GetAppContainerFolderPath(string pszAppContainerSid, out IntPtr ppszPath);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int DeleteAppContainerProfile(string pszAppContainerName);

    [DllImport("advapi32.dll")]
    static extern IntPtr FreeSid(IntPtr pSid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr hJob, int infoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessW(string lpApplicationName, StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    static string SidString(IntPtr sid)
    {
        return new SecurityIdentifier(sid).Value;
    }

    static int CreateOrDerive(string name, out IntPtr sid)
    {
        sid = IntPtr.Zero;
        int hr = CreateAppContainerProfile(name, name, "VibeGuard AppContainer sandbox", IntPtr.Zero, 0, out sid);
        if (hr >= 0) return hr;
        if (hr != unchecked((int)0x800700B7)) return hr;
        return DeriveAppContainerSidFromAppContainerName(name, out sid);
    }

    public static string Prepare(string name)
    {
        IntPtr sid = IntPtr.Zero;
        IntPtr pathPtr = IntPtr.Zero;
        try
        {
            int hr = CreateOrDerive(name, out sid);
            if (hr < 0 || sid == IntPtr.Zero) return "__VG_STDERR__cannot create AppContainer profile (0x" + hr.ToString("x8") + ")";
            string sidValue = SidString(sid);
            hr = GetAppContainerFolderPath(sidValue, out pathPtr);
            if (hr < 0 || pathPtr == IntPtr.Zero) return "__VG_STDERR__cannot resolve AppContainer folder (0x" + hr.ToString("x8") + ")";
            string folder = Marshal.PtrToStringUni(pathPtr);
            return "__VG_PROFILE__" + "{\"sid\":\"" + sidValue + "\",\"path\":\"" + folder.Replace("\\", "\\\\") + "\"}";
        }
        finally
        {
            if (pathPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(pathPtr);
            if (sid != IntPtr.Zero) FreeSid(sid);
        }
    }

    public static string Delete(string name)
    {
        int hr = DeleteAppContainerProfile(name);
        return hr >= 0 ? "__VG_DELETED__" : "__VG_STDERR__cannot delete AppContainer profile (0x" + hr.ToString("x8") + ")";
    }

    static IntPtr BuildEnvironment(string workDir, string localAppData)
    {
        var env = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        env["SystemRoot"] = Environment.GetEnvironmentVariable("SystemRoot") ?? "C:\\Windows";
        env["windir"] = env["SystemRoot"];
        env["TEMP"] = workDir;
        env["TMP"] = workDir;
        env["PATH"] = env["SystemRoot"] + "\\System32";
        env["LOCALAPPDATA"] = localAppData ?? "";
        env["VG_KEEP"] = "keep";
        var sb = new StringBuilder();
        foreach (var kv in env)
        {
            sb.Append(kv.Key).Append('=').Append(kv.Value).Append('\0');
        }
        sb.Append('\0');
        return Marshal.StringToHGlobalUni(sb.ToString());
    }

    static string ReadPipe(IntPtr handle, int cap)
    {
        var ms = new MemoryStream();
        var buf = new byte[8192];
        uint read;
        while (ReadFile(handle, buf, (uint)buf.Length, out read, IntPtr.Zero) && read > 0)
        {
            if (ms.Length < cap)
            {
                int want = (int)Math.Min(read, cap - ms.Length);
                ms.Write(buf, 0, want);
            }
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    public static string Run(string name, string workDir, string exe, string args, int timeoutMs, int memoryMb, int processLimit, string localAppData)
    {
        IntPtr sid = IntPtr.Zero;
        int hr = DeriveAppContainerSidFromAppContainerName(name, out sid);
        if (hr < 0 || sid == IntPtr.Zero) return "__VG_STDERR__AppContainer profile not found (0x" + hr.ToString("x8") + ")";

        IntPtr job = IntPtr.Zero;
        IntPtr attrList = IntPtr.Zero;
        IntPtr secCapsPtr = IntPtr.Zero;
        IntPtr handleListPtr = IntPtr.Zero;
        IntPtr envPtr = IntPtr.Zero;
        IntPtr outRead = IntPtr.Zero, outWrite = IntPtr.Zero, errRead = IntPtr.Zero, errWrite = IntPtr.Zero;
        IntPtr hProcess = IntPtr.Zero, hThread = IntPtr.Zero;
        try
        {
            job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero) return "__VG_STDERR__failed to create job object";

            var ext = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            ext.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            ext.BasicLimitInformation.ActiveProcessLimit = (uint)processLimit;
            ext.ProcessMemoryLimit = (UIntPtr)((long)memoryMb * 1024L * 1024L);
            ext.JobMemoryLimit = (UIntPtr)((long)memoryMb * 2L * 1024L * 1024L);
            int extLen = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr extPtr = Marshal.AllocHGlobal(extLen);
            Marshal.StructureToPtr(ext, extPtr, false);
            bool extSet = SetInformationJobObject(job, JobObjectExtendedLimitInformation, extPtr, (uint)extLen);
            Marshal.FreeHGlobal(extPtr);
            if (!extSet) return "__VG_STDERR__cannot set Job Object memory/process limits: " + Marshal.GetLastWin32Error();

            var ui = new JOBOBJECT_BASIC_UI_RESTRICTIONS();
            ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_WRITECLIPBOARD | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS | JOB_OBJECT_UILIMIT_GLOBALATOMS | JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_EXITWINDOWS;
            int uiLen = Marshal.SizeOf(typeof(JOBOBJECT_BASIC_UI_RESTRICTIONS));
            IntPtr uiPtr = Marshal.AllocHGlobal(uiLen);
            Marshal.StructureToPtr(ui, uiPtr, false);
            bool uiSet = SetInformationJobObject(job, JobObjectBasicUIRestrictions, uiPtr, (uint)uiLen);
            Marshal.FreeHGlobal(uiPtr);
            if (!uiSet) return "__VG_STDERR__cannot set Job Object UI restrictions: " + Marshal.GetLastWin32Error();

            var sa = new SECURITY_ATTRIBUTES();
            sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            sa.bInheritHandle = 1;
            if (!CreatePipe(out outRead, out outWrite, ref sa, 0)) return "__VG_STDERR__cannot create stdout pipe";
            if (!CreatePipe(out errRead, out errWrite, ref sa, 0)) return "__VG_STDERR__cannot create stderr pipe";
            SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0);
            SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, 0);

            envPtr = BuildEnvironment(workDir, localAppData);

            var si = new STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            si.StartupInfo.hStdOutput = outWrite;
            si.StartupInfo.hStdError = errWrite;
            si.StartupInfo.hStdInput = IntPtr.Zero;

            IntPtr size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
            attrList = Marshal.AllocHGlobal(size);
            if (!InitializeProcThreadAttributeList(attrList, 2, 0, ref size)) return "__VG_STDERR__cannot initialize attribute list";

            var caps = new SECURITY_CAPABILITIES();
            caps.AppContainerSid = sid;
            caps.CapabilityCount = 0;
            secCapsPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SECURITY_CAPABILITIES)));
            Marshal.StructureToPtr(caps, secCapsPtr, false);
            if (!UpdateProcThreadAttribute(attrList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, secCapsPtr, (IntPtr)Marshal.SizeOf(typeof(SECURITY_CAPABILITIES)), IntPtr.Zero, IntPtr.Zero))
                return "__VG_STDERR__cannot set AppContainer security capabilities";

            handleListPtr = Marshal.AllocHGlobal(IntPtr.Size * 2);
            Marshal.WriteIntPtr(handleListPtr, 0, outWrite);
            Marshal.WriteIntPtr(handleListPtr, IntPtr.Size, errWrite);
            if (!UpdateProcThreadAttribute(attrList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handleListPtr, (IntPtr)(IntPtr.Size * 2), IntPtr.Zero, IntPtr.Zero))
                return "__VG_STDERR__cannot restrict inherited handles";
            si.lpAttributeList = attrList;

            var cmd = new StringBuilder();
            cmd.Append('"').Append(exe).Append('"');
            if (!string.IsNullOrEmpty(args)) cmd.Append(' ').Append(args);

            PROCESS_INFORMATION pi;
            bool ok = CreateProcessW(exe, cmd, IntPtr.Zero, IntPtr.Zero, true, EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | CREATE_NO_WINDOW, envPtr, workDir, ref si, out pi);
            if (!ok) return "__VG_STDERR__CreateProcess failed: " + Marshal.GetLastWin32Error();
            hProcess = pi.hProcess;
            hThread = pi.hThread;
            CloseHandle(outWrite); outWrite = IntPtr.Zero;
            CloseHandle(errWrite); errWrite = IntPtr.Zero;

            if (!AssignProcessToJobObject(job, hProcess))
            {
                int assignError = Marshal.GetLastWin32Error();
                TerminateProcess(hProcess, 1);
                return "__VG_STDERR__AssignProcessToJobObject failed: " + assignError;
            }
            if (ResumeThread(hThread) == 0xFFFFFFFF)
            {
                int resumeError = Marshal.GetLastWin32Error();
                TerminateJobObject(job, 1);
                return "__VG_STDERR__ResumeThread failed: " + resumeError;
            }

            var outTask = Task.Run(() => ReadPipe(outRead, 1024 * 1024));
            var errTask = Task.Run(() => ReadPipe(errRead, 1024 * 1024));

            uint wait = WaitForSingleObject(hProcess, (uint)timeoutMs);
            bool timedOut = wait == WAIT_TIMEOUT;
            if (timedOut) TerminateJobObject(job, 124);
            WaitForSingleObject(hProcess, 2000);

            string stdout = outTask.Wait(2000) ? outTask.Result : "";
            string stderr = errTask.Wait(2000) ? errTask.Result : "";
            uint exitCode = 124;
            GetExitCodeProcess(hProcess, out exitCode);
            if (timedOut) exitCode = 124;
            return "__VG_STDOUT64__" + Convert.ToBase64String(Encoding.UTF8.GetBytes(stdout)) + "__VG_STDERR64__" + Convert.ToBase64String(Encoding.UTF8.GetBytes(stderr)) + "__VG_EXIT__" + exitCode;
        }
        finally
        {
            if (hThread != IntPtr.Zero) CloseHandle(hThread);
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
            if (outWrite != IntPtr.Zero) CloseHandle(outWrite);
            if (errWrite != IntPtr.Zero) CloseHandle(errWrite);
            if (outRead != IntPtr.Zero) CloseHandle(outRead);
            if (errRead != IntPtr.Zero) CloseHandle(errRead);
            if (attrList != IntPtr.Zero) DeleteProcThreadAttributeList(attrList);
            if (job != IntPtr.Zero) CloseHandle(job);
            if (secCapsPtr != IntPtr.Zero) Marshal.FreeHGlobal(secCapsPtr);
            if (handleListPtr != IntPtr.Zero) Marshal.FreeHGlobal(handleListPtr);
            if (envPtr != IntPtr.Zero) Marshal.FreeHGlobal(envPtr);
            if (sid != IntPtr.Zero) FreeSid(sid);
        }
    }
}`;

const PS_SOURCE = [
  '$ErrorActionPreference = "Stop"',
  '$src = Get-Content -Raw -LiteralPath $env:VG_CS',
  'Add-Type -TypeDefinition $src -Language CSharp',
  'switch ($env:VG_MODE) {',
  '  "prepare" { [Console]::Out.Write([VGAppContainer]::Prepare($env:VG_NAME)); break }',
  '  "run" { [Console]::Out.Write([VGAppContainer]::Run($env:VG_NAME, $env:VG_WORK, $env:VG_EXE, $env:VG_ARGS, [int]$env:VG_TIMEOUT, [int]$env:VG_MEM, [int]$env:VG_PROC, $env:VG_LOCALAPPDATA)); break }',
  '  "delete" { [Console]::Out.Write([VGAppContainer]::Delete($env:VG_NAME)); break }',
  '  default { throw "unknown helper mode: $env:VG_MODE" }',
  '}',
].join('\r\n');

function randomId() {
  return crypto.randomBytes(8).toString('hex');
}

function clampInt(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(number)));
}

function parseRunnerOutput(raw) {
  const so = raw.indexOf('__VG_STDOUT64__');
  const se = raw.indexOf('__VG_STDERR64__');
  const x = raw.indexOf('__VG_EXIT__');
  if (so < 0 || se < 0 || x < 0) return { stdout: raw, stderr: '', exit: null };
  const decode = (value) => Buffer.from(value, 'base64').toString('utf8');
  return {
    stdout: decode(raw.slice(so + 15, se)),
    stderr: decode(raw.slice(se + 15, x)),
    exit: Number(raw.slice(x + 11).trim()),
  };
}

function parseHarness(stdout) {
  const marker = stdout.split(/\r?\n/).find((l) => l.startsWith('__VG_RESULT__'));
  const errorMarker = stdout.split(/\r?\n/).find((l) => l.startsWith('__VG_ERROR__'));
  if (marker) {
    try {
      const parsed = JSON.parse(marker.slice('__VG_RESULT__'.length));
      return { success: true, output: parsed.result, error: null };
    } catch {
      return { success: false, output: null, error: 'cannot parse harness result' };
    }
  }
  if (errorMarker) {
    try { return { success: false, output: null, error: JSON.parse(errorMarker.slice('__VG_ERROR__'.length)) }; }
    catch { return { success: false, output: null, error: 'sandbox error' }; }
  }
  return null;
}

class WindowsAppContainerSandbox {
  constructor(opts = {}) {
    this.id = 'windows-appcontainer';
    this.isolationClass = ISOLATION.OS;
    this.verified = false;
    this.verification = 'unverified';
    this.verifiedAt = null;
    this.evidence = [];
    this.suiteVersion = `${SUITE_VERSION}:${BACKEND_HASH}`;
    this.limitations = [
      'AppContainer is OS-mediated; the host kernel is shared',
      'network is denied by the absence of internetClient/privateNetworkClientServer capability SIDs',
      'AppContainer default grants allow read/execute of Windows and Program Files; the user profile, credentials and writable host paths are denied',
      'writes are limited to the per-profile AppContainer folder',
      'Job Object supplies memory/process limits, UI restrictions and kill-on-close; no WFP filter is installed',
      'child processes inherit the container and job, but are not individually brokered',
    ];
    this.powershell = opts.powershell || (process.platform === 'win32' ? 'powershell.exe' : null);
    this.nodePath = opts.nodePath || process.execPath;
    this.memoryMb = opts.memoryMb || DEFAULT_MEMORY_MB;
    this.processLimit = opts.processLimit || DEFAULT_PROCESS_LIMIT;
    this.configKey = require('crypto').createHash('sha256').update(JSON.stringify({ node: this.nodePath, powershell: this.powershell, memoryMb: this.memoryMb, processLimit: this.processLimit })).digest('hex').slice(0, 24);
    this.cacheFile = opts.cacheFile === undefined ? defaultCacheFile() : opts.cacheFile;
    this.profile = null;
    this._helperDir = null;
    this._exitHook = null;
    this._lastDisposeDeleted = null;
    const cached = loadVerification(this.cacheFile, this.id, this.suiteVersion, { configKey: this.configKey });
    if (cached && cached.verified === true) {
      this.verified = true;
      this.verification = cached.verification || 'cached';
      this.verifiedAt = cached.verifiedAt || null;
      this.evidence = Array.isArray(cached.evidence) ? cached.evidence : [];
    }
  }

  available() {
    return process.platform === 'win32' && Boolean(this.powershell) && fs.existsSync(this.nodePath);
  }

  _helper() {
    if (this._helperDir) return this._helperDir;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-ac-helper-'));
    fs.writeFileSync(path.join(dir, 'helper.cs'), CSHARP_SOURCE, 'utf8');
    fs.writeFileSync(path.join(dir, 'helper.ps1'), PS_SOURCE, 'utf8');
    this._helperDir = dir;
    return dir;
  }

  _invoke(mode, values, timeoutMs) {
    const dir = this._helper();
    const helperTimeout = clampInt(timeoutMs, DEFAULT_TIMEOUT, 100, 300000);
    const env = {
      ...process.env,
      VG_CS: path.join(dir, 'helper.cs'),
      VG_MODE: mode,
      VG_NAME: values.name || '',
      VG_WORK: values.workDir || '',
      VG_EXE: values.exe || '',
      VG_ARGS: values.args || '',
      VG_TIMEOUT: String(clampInt(values.timeoutMs, DEFAULT_TIMEOUT, 100, 300000)),
      VG_MEM: String(clampInt(values.memoryMb, this.memoryMb, 16, 16384)),
      VG_PROC: String(clampInt(values.processLimit, this.processLimit, 1, 256)),
      VG_LOCALAPPDATA: values.localAppData || process.env.LOCALAPPDATA || '',
    };
    const child = spawnSync(this.powershell, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', path.join(dir, 'helper.ps1')], {
      cwd: dir,
      env,
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 16 * 1024 * 1024,
      timeout: helperTimeout + 60000,
    });
    return {
      status: child.status,
      signal: child.signal,
      stdout: child.stdout || '',
      stderr: child.stderr || '',
      error: child.error ? child.error.message : null,
    };
  }

  _ensureProfile() {
    if (this.profile) return this.profile;
    if (!this.available()) throw new Error('Windows AppContainer backend unavailable');
    this._cleanupStaleProfiles();
    const name = `VibeGuard.Sbx.${randomId()}`;
    const result = this._invoke('prepare', { name });
    const marker = result.stdout.split(/\r?\n/).find((l) => l.startsWith('__VG_PROFILE__'));
    if (!marker) {
      throw new Error(`cannot prepare AppContainer profile: ${(result.stderr || result.stdout || result.error || '').trim().slice(0, 500)}`);
    }
    const profile = JSON.parse(marker.slice('__VG_PROFILE__'.length));
    profile.name = name;
    const candidateRoot = path.dirname(profile.path);
    if (/^vibeguard\.sbx\./i.test(path.basename(candidateRoot))) profile.root = candidateRoot;
    profile.binDir = path.join(profile.path, 'bin');
    profile.runsDir = path.join(profile.path, 'runs');
    fs.mkdirSync(profile.binDir, { recursive: true });
    fs.mkdirSync(profile.runsDir, { recursive: true });
    // The package root is host-writable but not writable by the AppContainer
    // SID; keep the liveness marker there so untrusted code cannot rewrite it.
    profile.ownerFile = path.join(path.dirname(profile.path), '.vg-owner');
    try {
      fs.writeFileSync(profile.ownerFile, JSON.stringify({ pid: process.pid, name }), 'utf8');
    } catch {
      profile.ownerFile = path.join(profile.path, '.vg-owner');
      fs.writeFileSync(profile.ownerFile, JSON.stringify({ pid: process.pid, name }), 'utf8');
    }
    const stagedNode = path.join(profile.binDir, 'node.exe');
    const source = fs.statSync(this.nodePath);
    let staged = null;
    try { staged = fs.statSync(stagedNode); } catch { /* copy below */ }
    if (!staged || staged.size !== source.size) fs.copyFileSync(this.nodePath, stagedNode);
    profile.nodePath = stagedNode;
    this.profile = profile;
    if (!this._exitHook) {
      this._exitHook = () => { try { this.dispose(); } catch { /* best effort */ } };
      process.once('exit', this._exitHook);
    }
    return profile;
  }

  _cleanupStaleProfiles() {
    // Profile folders are user scoped and contain only this backend's files.
    // A crashed process leaves an owner marker; a folder is removed only when
    // that PID is gone. An unmarked folder must also be old, so a profile
    // created between readdir and stat is never deleted.
    const root = path.join(process.env.LOCALAPPDATA || '', 'Packages');
    if (!root || !fs.existsSync(root)) return;
    let entries = [];
    try { entries = fs.readdirSync(root); } catch { return; }
    for (const entry of entries) {
      if (!/^vibeguard\.sbx\./i.test(entry)) continue;
      const dir = path.join(root, entry);
      let owner = null;
      for (const marker of [path.join(dir, '.vg-owner'), path.join(dir, 'AC', '.vg-owner')]) {
        try { owner = JSON.parse(fs.readFileSync(marker, 'utf8')); break; } catch { /* try next */ }
      }
      // The marker lives in a location sandboxed code may write. It can only
      // authorize cleanup of the profile directory it describes; never let it
      // name a different AppContainer profile.
      if (owner && (typeof owner.name !== 'string' || owner.name.toLowerCase() !== entry.toLowerCase())) {
        owner = null;
      }
      let alive = false;
      if (owner && Number.isInteger(owner.pid) && owner.pid > 0) {
        try { process.kill(owner.pid, 0); alive = true; } catch { alive = false; }
      }
      if (alive) continue;
      let age = 0;
      try { age = Date.now() - fs.statSync(dir).mtimeMs; } catch { continue; }
      if (!owner && age < 10 * 60 * 1000) continue;
      if (owner && typeof owner.name === 'string') {
        try { this._invoke('delete', { name: owner.name }); } catch { /* best effort */ }
      }
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
  }

  _exec(profile, workDir, exe, args, opts = {}) {
    const started = Date.now();
    const timeoutMs = opts.timeout || DEFAULT_TIMEOUT;
    const result = this._invoke('run', {
      name: profile.name,
      workDir,
      exe,
      args,
      timeoutMs,
      memoryMb: opts.memoryMb || this.memoryMb,
      processLimit: opts.processLimit || this.processLimit,
    }, timeoutMs);
    const parsed = parseRunnerOutput(result.stdout);
    const out = {
      success: false,
      output: null,
      error: null,
      duration: Date.now() - started,
      isolation: 'os-windows-appcontainer',
      isolationClass: ISOLATION.OS,
      verified: this.verified,
      verification: this.verification,
      limitations: this.limitations.slice(),
      exitCode: parsed.exit,
      stderr: parsed.stderr,
      isolationApplied: parsed.exit !== null,
    };
    if (parsed.exit === 124) out.error = 'VibeGuard AppContainer: execution timed out';
    else if (parsed.exit === null) {
      out.error = (parsed.stderr || parsed.stdout || result.stderr || result.error || 'AppContainer helper failed').trim().slice(0, 500);
      out.verified = false;
      out.verification = 'run-failed';
    } else out.error = parsed.stderr.trim() || null;
    out._stdout = parsed.stdout;
    out._rawExit = parsed.exit;
    out._helperStatus = result.status;
    return out;
  }

  _newRunDir(profile) {
    const dir = path.join(profile.runsDir, randomId());
    fs.mkdirSync(dir, { recursive: true });
    return dir;
  }

  async run(code, opts = {}) {
    const started = Date.now();
    let profile;
    try { profile = this._ensureProfile(); }
    catch (err) {
      return {
        success: false, output: null, error: err.message, duration: Date.now() - started,
        isolation: 'os-windows-appcontainer', isolationClass: ISOLATION.OS,
        verified: false, verification: 'run-failed', limitations: this.limitations.slice(),
        memoryCap: (opts.memoryMb || this.memoryMb) * 1024 * 1024, memoryEnforced: true,
        isolationApplied: false, audit: [],
      };
    }
    const dir = this._newRunDir(profile);
    fs.writeFileSync(path.join(dir, 'user.js'), String(code == null ? '' : code), 'utf8');
    fs.writeFileSync(path.join(dir, 'harness.js'), HARNESS_SOURCE, 'utf8');
    const exe = profile.nodePath;
    const args = `--preserve-symlinks-main "${path.join(dir, 'harness.js')}"`;
    const raw = this._exec(profile, dir, exe, args, opts);
    const parsed = parseHarness(raw._stdout || '');
    const result = {
      success: Boolean(parsed && parsed.success),
      output: parsed ? parsed.output : null,
      error: parsed ? parsed.error : raw.error,
      duration: Date.now() - started,
      isolation: 'os-windows-appcontainer',
      isolationClass: ISOLATION.OS,
      verified: raw.verified === false ? false : this.verified,
      verification: raw.verified === false ? raw.verification : this.verification,
      limitations: this.limitations.slice(),
      memoryCap: (opts.memoryMb || this.memoryMb) * 1024 * 1024,
      memoryEnforced: true,
      isolationApplied: raw.isolationApplied !== false,
      audit: [],
      exitCode: raw.exitCode,
    };
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* profile cleanup removes it */ }
    return result;
  }

  async probe(code, opts = {}) {
    const started = Date.now();
    let profile;
    try { profile = this._ensureProfile(); }
    catch (err) {
      return { success: false, output: null, error: err.message, stdout: '', stderr: '', duration: Date.now() - started };
    }
    const dir = this._newRunDir(profile);
    fs.writeFileSync(path.join(dir, 'probe.js'), String(code), 'utf8');
    const raw = this._exec(profile, dir, profile.nodePath, `--preserve-symlinks-main "${path.join(dir, 'probe.js')}"`, opts);
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
    return {
      success: raw._rawExit === 0,
      output: (raw._stdout || '').trim() || null,
      error: raw.error,
      stdout: raw._stdout || '',
      stderr: raw.stderr || '',
      exitCode: raw.exitCode,
      duration: Date.now() - started,
    };
  }

  async verify() {
    if (!this.available()) {
      this.verified = false;
      this.verification = 'unavailable';
      return false;
    }
    const evidence = [];
    const record = (testId, passed, details) => evidence.push({ testId, passed: !!passed, details: details ? String(details).slice(0, 500) : undefined });
    const probeCode = (body) => `console.log('__VG_PROBE__');${body}`;
    const ran = (result) => Boolean(result && /__VG_PROBE__/.test(String(result.stdout || '')));
    const marker = path.join(os.tmpdir(), `vg-ac-marker-${randomId()}`);
    const writeTarget = path.join(os.tmpdir(), `vg-ac-write-${randomId()}`);
    const homeDir = os.homedir();
    const homeMarker = path.join(homeDir, `.vibeguard-ac-probe-${randomId()}`);
    let server = null;
    let lanServer = null;
    try {
      const safe = await this.run('const x = 1 + 2; x', { timeout: 10000 });
      record('safe-exec', safe.success && String(safe.output) === '3', safe.error || `output=${safe.output}`);

      fs.writeFileSync(marker, 'HOST-SECRET', 'utf8');
      const readHost = await this.probe(probeCode(`const fs=require('fs');try{fs.readFileSync(${JSON.stringify(marker)});console.log('VISIBLE')}catch(e){console.log('DENIED:'+e.code)}`), { timeout: 10000 });
      record('host-file-read-denied', ran(readHost) && /DENIED/.test(readHost.stdout) && !/VISIBLE/.test(readHost.stdout), readHost.stdout.trim());

      fs.writeFileSync(homeMarker, 'HOME-SECRET', 'utf8');
      const readHome = await this.probe(probeCode(`const fs=require('fs');try{fs.readFileSync(${JSON.stringify(homeMarker)});console.log('VISIBLE')}catch(e){console.log('DENIED:'+e.code)}`), { timeout: 10000 });
      record('home-file-read-denied', ran(readHome) && /DENIED/.test(readHome.stdout) && !/VISIBLE/.test(readHome.stdout), readHome.stdout.trim());

      const writeHost = await this.probe(probeCode(`const fs=require('fs');try{fs.writeFileSync(${JSON.stringify(writeTarget)},'x');console.log('WROTE')}catch(e){console.log('DENIED:'+e.code)}`), { timeout: 10000 });
      record('host-write-denied', ran(writeHost) && /DENIED/.test(writeHost.stdout) && !/WROTE/.test(writeHost.stdout), writeHost.stdout.trim());

      const systemTemp = path.join(process.env.SystemRoot || 'C:\\Windows', 'Temp', `vg-ac-system-${randomId()}.txt`);
      const writeSystem = await this.probe(probeCode(`const fs=require('fs');try{fs.writeFileSync(${JSON.stringify(systemTemp)},'x');console.log('WROTE')}catch(e){console.log('DENIED:'+e.code)}`), { timeout: 10000 });
      record('system-temp-write-denied', ran(writeSystem) && /DENIED/.test(writeSystem.stdout) && !/WROTE/.test(writeSystem.stdout), writeSystem.stdout.trim());
      try { fs.rmSync(systemTemp, { force: true }); } catch { /* ignore */ }

      server = net.createServer();
      await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
      const port = server.address().port;
      const network = await this.probe(probeCode(`const net=require('net');const s=net.connect(${port},'127.0.0.1');s.setTimeout(1500);const done=(v)=>{console.log(v);s.destroy();process.exit(0)};s.on('connect',()=>done('REACHABLE'));s.on('timeout',()=>done('TIMEOUT'));s.on('error',(e)=>done('DENIED:'+e.code));`), { timeout: 10000 });
      record('network-egress-denied', ran(network) && /DENIED|TIMEOUT/.test(network.stdout) && !/REACHABLE/.test(network.stdout), network.stdout.trim());
      await new Promise((resolve) => server.close(resolve));
      server = null;

      const lan = Object.values(os.networkInterfaces()).flat().find((address) => address && address.family === 'IPv4' && !address.internal);
      if (lan) {
        lanServer = net.createServer();
        await new Promise((resolve) => lanServer.listen(0, '0.0.0.0', resolve));
        const lanPort = lanServer.address().port;
        const lanProbe = await this.probe(probeCode(`const net=require('net');const s=net.connect(${lanPort},${JSON.stringify(lan.address)});s.setTimeout(1500);const done=(v)=>{console.log(v);s.destroy();process.exit(0)};s.on('connect',()=>done('REACHABLE'));s.on('timeout',()=>done('TIMEOUT'));s.on('error',(e)=>done('DENIED:'+e.code));`), { timeout: 10000 });
        record('lan-egress-denied', ran(lanProbe) && /DENIED|TIMEOUT/.test(lanProbe.stdout) && !/REACHABLE/.test(lanProbe.stdout), `${lan.address}:${lanPort} ${lanProbe.stdout.trim()}`);
        await new Promise((resolve) => lanServer.close(resolve));
        lanServer = null;
      } else {
        record('lan-egress-denied', true, 'no non-loopback IPv4 address; LAN egress not exercised');
      }

      const previous = process.env.VG_SANDBOX_CANARY;
      process.env.VG_SANDBOX_CANARY = 'CANARY-LEAK';
      let envProbe;
      try {
        envProbe = await this.probe(probeCode("console.log('KEEP=' + String(process.env.VG_KEEP));console.log('CANARY=' + String(process.env.VG_SANDBOX_CANARY))"), { timeout: 10000 });
      } finally {
        if (previous === undefined) delete process.env.VG_SANDBOX_CANARY;
        else process.env.VG_SANDBOX_CANARY = previous;
      }
      record('host-env-not-inherited', ran(envProbe) && /KEEP=keep/.test(envProbe.stdout) && !/CANARY-LEAK/.test(envProbe.stdout), envProbe.stdout.trim());

      const timeout = await this.run('while (true) {}', { timeout: 1500 });
      record('wall-clock-timeout-killed', !timeout.success && /timed out/i.test(String(timeout.error || '')), timeout.error || 'no timeout error');

      const memory = await this.probe(probeCode("Buffer.alloc(1024*1024);console.log('SMALL_OK');const b=Buffer.alloc(512*1024*1024);b[0]=1;console.log('ALLOCATED')"), { timeout: 10000, memoryMb: 128 });
      record('memory-limit-enforced', ran(memory) && /SMALL_OK/.test(memory.stdout) && !/ALLOCATED/.test(memory.stdout), memory.error || memory.stdout.trim());

      const profilePath = this.profile ? this.profile.path : null;
      const profileRoot = this.profile ? this.profile.root : null;
      this.dispose();
      const cleaned = (!profilePath || !fs.existsSync(profilePath))
        && (!profileRoot || !fs.existsSync(profileRoot));
      const deleted = this._lastDisposeDeleted !== false;
      record('profile-cleanup', cleaned && deleted, cleaned && deleted ? 'profile folder removed and profile deleted' : `folderGone=${cleaned} profileDeleted=${deleted}${profilePath ? ` path=${profilePath}` : ''}${profileRoot ? ` root=${profileRoot}` : ''}`);

      const passed = evidence.every((e) => e.passed);
      this.verified = passed;
      this.verifiedAt = new Date().toISOString();
      this.evidence = evidence;
      this.verification = passed ? 'appcontainer-fs-network-env-timeout-memory-verified' : `verification-failed(${evidence.filter((e) => !e.passed).map((e) => e.testId).join(',')})`;
      saveVerification(this.cacheFile, this.id, {
        verified: passed,
        verification: this.verification,
        verifiedAt: this.verifiedAt,
        suiteVersion: this.suiteVersion,
        configKey: this.configKey,
        evidence,
        limitations: this.limitations,
      });
      return passed;
    } catch (err) {
      this.verified = false;
      this.verification = `verification-failed(${err.message})`;
      this.verifiedAt = new Date().toISOString();
      this.evidence = evidence;
      if (server) try { server.close(); } catch { /* ignore */ }
      if (lanServer) try { lanServer.close(); } catch { /* ignore */ }
      if (this.profile) this.dispose();
      saveVerification(this.cacheFile, this.id, {
        verified: false,
        verification: this.verification,
        verifiedAt: this.verifiedAt,
        suiteVersion: this.suiteVersion,
        configKey: this.configKey,
        evidence,
        limitations: this.limitations,
      });
      return false;
    } finally {
      for (const f of [marker, writeTarget, homeMarker]) {
        try { fs.rmSync(f, { force: true }); } catch { /* ignore */ }
      }
    }
  }

  dispose() {
    if (!this.profile) return true;
    const profile = this.profile;
    const dir = this._helperDir;
    let deleted = true;
    try {
      const result = this._invoke('delete', { name: profile.name });
      deleted = result.stdout.includes('__VG_DELETED__');
    } catch {
      deleted = false;
    }
    try { fs.rmSync(profile.path, { recursive: true, force: true }); } catch { /* ignore */ }
    // DeleteAppContainerProfile removes the registered profile but Windows
    // leaves the package directory behind. Remove only this backend's
    // package root, never the shared Packages directory.
    if (profile.root && /^vibeguard\.sbx\./i.test(path.basename(profile.root))) {
      try { fs.rmSync(profile.root, { recursive: true, force: true }); } catch { /* ignore */ }
    }
    this._lastDisposeDeleted = deleted;
    this.profile = null;
    if (dir) {
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
      this._helperDir = null;
    }
    return deleted;
  }
}

module.exports = { WindowsAppContainerSandbox, SUITE_VERSION };
