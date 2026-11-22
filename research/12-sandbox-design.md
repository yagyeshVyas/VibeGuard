# Sandbox and Isolation Design

**Design date:** 2026-11-21  
**Basis:** audit F-02/F-24, `08`–`10`  
**Status:** design only. No backend in this design has been verified yet; the current `vm`/process implementation must not be presented as isolation.

---

## 1. Threat model

### Assets the sandbox must protect

- Host filesystem outside the explicitly mounted workspace
- Host credentials, browser profiles, SSH keys, cloud tokens
- Host network / LAN / cloud metadata
- Other processes, sessions and tenants
- The VibeGuard gateway and its signing keys

### Adversary

- Untrusted code produced by an AI agent or a third-party skill/plugin
- A malicious MCP server that offers code execution
- A compromised package run during build/test
- An attacker who can choose the code but not the host kernel/administrator account

### Out of scope

- A host administrator/root attacker who can replace the sandbox binary or kernel
- Hardware side channels (Spectre-class) beyond what the backend documents
- Guaranteed absence of hypervisor/kernel zero-days

**No design can claim “unbreakable.”** The claim is a verified isolation class plus a documented residual risk.

---

## 2. Isolation classes

| Class | Example | Host kernel shared? | Credentials/network default | Claim |
|---|---|---|---|---|
| `none` | raw `eval`/same-process | yes | yes | **Never for untrusted code** |
| `process` | child Node process + permission model | yes | same user; network reachable | “raises the floor,” not a boundary |
| `os` | Windows AppContainer/Job Object, macOS App Sandbox | yes (OS-mediated) | no network/fs by default | OS sandbox; verified per OS |
| `container` | rootless OCI container, namespaces, seccomp, cgroups | yes (host kernel) | no network/creds; explicit mounts | container isolation; kernel shared |
| `microvm` | Firecracker/gVisor-class | no shared guest kernel (microVM) / user-space kernel (gVisor) | no network/creds | stronger boundary |
| `hardware-vm` | Hyper-V/VirtualBox/cloud VM | no | no network/creds | strongest practical |

Rules:

- `verified` is a separate boolean plus `verificationId`/`verifiedAt`; a backend that has not passed its suite is not allowed to claim a class.
- `legacy-vm` and `process` are labeled `unverified` for untrusted code and disabled in strict mode.
- The UI/API/CLI must show the actual class and verification, not a generic “sandboxed.”

---

## 3. Backend contract

```ts
interface SandboxBackend {
  id: string;                         // 'windows-appcontainer' | 'linux-container' | ...
  isolationClass: IsolationClass;
  supports: BackendCapabilities;      // stream, snapshot, networkProxy, gpu, ...
  verify(): Promise<BackendVerification>;
  prepare(spec: SandboxSpec): Promise<SandboxHandle>;
  run(handle: SandboxHandle, code: string, opts: RunOptions): Promise<RunResult>;
  stream?(handle: SandboxHandle, opts: RunOptions): AsyncIterable<OutputChunk>;
  terminate(handle: SandboxHandle): Promise<void>;
  snapshot?(handle: SandboxHandle): Promise<ForensicSnapshot>;
}

interface SandboxSpec {
  image?: string;                     // container/microVM only; hash-pinned
  workspace: MountSpec;               // read-only by default
  tmp: MountSpec;                     // writable, size-limited
  network: NetworkPolicy;             // 'none' | {proxy: string, allow: Host[]}
  env: Record<string,string>;         // allowlisted only; no secrets by default
  credentials: CredentialPolicy;      // 'none' | short-lived capability refs
  quotas: ResourceQuotas;
  timeoutMs: number;
  labels: string[];
}

interface BackendVerification {
  backend: string;
  isolationClass: IsolationClass;
  verified: boolean;
  suiteVersion: string;
  verifiedAt: string;
  evidence: { testId: string; passed: boolean; details?: string }[];
  limitations: string[];
}
```

The gateway **must** call `verify()` (cached with a TTL and signed evidence) before selecting a backend. If unavailable or failed → `VG_SANDBOX_UNAVAILABLE`; strict mode denies execution.

---

## 4. Windows backend design

### 4.1 Target: `windows-appcontainer` (`isolationClass: os`)

Use Windows primitives, not a Node vm:

- **AppContainer** process with a restricted token and a unique package/capability SID.
- **Job Object** for process tree containment, memory/process limits and kill-on-close.
- **Windows Filtering Platform (WFP)** / firewall rule per job/session to deny outbound network by default.
- **Filesystem**: brokered access; expose only a dedicated temp/workspace directory with a restricted ACL; do not grant `%USERPROFILE%`, `%APPDATA%`, `.ssh`, `.aws`, browser profiles.
- **Environment**: minimal allowlist (`PATH`, `TEMP`, `SystemRoot`), no tokens/credentials.
- **UI/desktop**: no interactive desktop access; no clipboard; no named pipes except a controlled result channel.
- **Process creation**: child processes confined by the job; deny breakaway.
- **DLL/module**: no host DLL injection; block known dangerous APIs through AppContainer policy where possible.
- **Output**: named pipe/file with size/time limits; no shared memory beyond the result channel.
- **Quotas**: `JOB_OBJECT_LIMIT_PROCESS_MEMORY`, `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`, CPU rate control, wall-clock timeout.
- **Verification suite**: read `C:\Windows\win.ini`, `%USERPROFILE%\.ssh`, open a TCP connection to a local listener, spawn a child, allocate memory, fork bomb, timeout, write outside mount. All must fail/deny.

### 4.2 Stronger optional: `windows-vm` (`isolationClass: hardware-vm`)

For hostile code, Windows Sandbox / Hyper-V VM with a disposable disk, no integrations, no clipboard, no mapped drives, network off. Heavier startup; use for high-risk execution or plugin verification.

### 4.3 Windows limitations

- AppContainer is an OS-mediated sandbox, not a hypervisor; kernel attack surface remains.
- Some legitimate tools require capabilities; policy must grant them explicitly.
- Antivirus/EDR interactions and AppLocker/WDAC can change behavior; verification must run on the target host.
- No claim of isolation if AppContainer/Job/WFP setup fails.

---

## 5. Linux backend design

### 5.1 Target: `linux-container` (`isolationClass: container`)

- Rootless container runtime (or a minimal in-house OCI launcher with runc/crun if already present); no Docker daemon dependency in core.
- Namespaces: user, mount, PID, network, IPC, UTS, cgroup.
- **seccomp-bpf** allowlist with a default-deny profile; no `ptrace`, `mount`, `bpf`, `keyctl`, `unshare`, `setns` unless explicitly required.
- **cgroups v2** for CPU, memory, pids, IO, and `pids.max`; `memory.max`, `cpu.max`, `io.max`.
- **Filesystem**: read-only bind of allowed workspace; a tmpfs for tmp; no host `/home`, `/etc`, `/proc` except controlled; `no_new_privs`.
- **Network**: network namespace with no interfaces by default; if egress allowed, route through the gateway proxy in a separate namespace, not host network.
- **Capabilities**: drop all Linux capabilities; add only a minimal explicit set.
- **Secrets**: none in env; short-lived credentials only via a mediated file descriptor/proxy if policy allows.
- **Quotas**: cgroup + wall timeout; kill cgroup on timeout.
- **Verification suite**: read `/etc/shadow`/`~/.ssh`, connect to a local listener, fork bomb, mount, ptrace, memory bomb, network, escape/vm28-style probes.

### 5.2 Stronger: `linux-microvm`

- Firecracker microVM or gVisor (`runsc`) runner.
- Separate guest kernel; no host device passthrough; no network by default; minimal rootfs; snapshot/restore optional.
- Use for high-risk skills/plugins/sandbox executions.
- Requires KVM (Linux) or a helper service; unavailable on Windows/macOS.

### 5.3 Linux limitations

- Containers share the host kernel; a kernel exploit can escape.
- Rootless/user namespaces may be disabled by the distro.
- eBPF monitoring may require privileges; the monitor must degrade explicitly.

---

## 6. macOS backend design

### 6.1 Target: `macos-vm` (`isolationClass: hardware-vm`)

- Virtualization.framework VM with a minimal guest, read-only workspace share, no network by default, no host clipboard/USB.
- App Sandbox/seatbelt alone is not a sufficient boundary for arbitrary untrusted native code; it can be a defense-in-depth layer for signed helpers, not the primary claim.
- `sandbox-exec` is deprecated; do not build a new security claim on it.

### 6.2 Fallback

If no VM/container backend is available: strict mode denies untrusted execution; a `process` backend may be used only in monitor mode and must report `unverified`.

---

## 7. Host access matrix

| Resource | Default | How to allow | Enforcement |
|---|---|---|---|
| Workspace `src/` | read-only | policy `filesystem.read` | bind/ACL |
| `/tmp` | writable, size-capped | implicit | tmpfs/ACL |
| Home directory | deny | explicit mount + policy | OS sandbox |
| `.ssh`/`.aws`/`.env` | deny | never in strict | path policy + sandbox |
| Network | deny | egress proxy + host allowlist | WFP/net namespace/VM |
| Environment | minimal | allowlist | process env |
| Credentials | none | short-lived broker | gateway/OS keystore |
| Child processes | confined | policy | Job Object/cgroup |
| GPU | deny | explicit | backend capability |
| Clipboard/UI | deny | never for untrusted | AppContainer/VM |

---

## 8. Lifecycle state machine

```
REQUESTED
  → VERIFYING_BACKEND
  → PREPARING
  → RUNNING
  → OUTPUT_STREAMING
  → COMPLETED | FAILED | TIMEOUT | KILLED | QUARANTINED
  → CLEANUP
  → ARCHIVED
```

Rules:

- Any transition failure → cleanup + `VG_SANDBOX_FAILED`; no retry automatically unless policy allows.
- Timeout/kill → terminate the whole process tree/cgroup/VM, not just the direct child.
- Snapshot after failure for forensics only if policy allows; snapshots may contain secrets—redact/limit.
- Cleanup verifies no processes/handles/mounts remain.

---

## 9. Resource quotas

| Resource | Mechanism | Default |
|---|---|---|
| Wall time | timer + hard kill | 10 s |
| CPU | cgroup `cpu.max` / Job CPU rate | 2 cores |
| Memory | cgroup `memory.max` / Job memory | 256 MiB |
| PIDs/processes | `pids.max` / active process limit | 32 |
| Disk | tmpfs/quota | 128 MiB |
| Network bytes | proxy counters / VM egress | 0 |
| Output | pipe/file cap | 1 MiB |
| Artifacts | size/count cap | 10 files / 10 MiB |

Quotas are policy-controlled; exceeding them terminates the execution and emits an incident.

---

## 10. Credentials and secrets

- Default `credentials: none`.
- A sandboxed program cannot read host env or files.
- If a policy explicitly grants `secret.use` for a specific outbound call, the **gateway**, not the sandbox, substitutes the credential at egress. The sandbox receives a reference, never the value.
- Short-lived credentials: TTL ≤ 15 minutes, audience-bound, sender-constrained where possible.
- Secret values are never written to sandbox logs or audit; only HMAC fingerprints.

---

## 11. Verification suite

A backend is usable only after its suite passes on the target OS/version. Tests:

| Test | Expected |
|---|---|
| Read host file outside mount | denied |
| Read `.env`/`.ssh`/`.aws` | denied |
| Write outside workspace/tmp | denied |
| Listen/connect network | denied (or proxy-only) |
| Resolve metadata endpoint | denied |
| Spawn child beyond pids/process limit | denied |
| Fork bomb | contained/killed |
| Memory bomb | OOM contained |
| Infinite loop | timeout/kill |
| Ptrace/mount/unshare | denied |
| Dynamic import/network module | denied |
| Host credential/env read | denied |
| Container/microVM escape corpus | no host access |
| Cleanup | no lingering processes/handles |

Backend evidence is signed and surfaced in `vibeguard sandbox backends` and the posture report. A backend update invalidates prior verification until re-run.

---

## 12. Compatibility

| Current API | New behavior |
|---|---|
| `runInSandbox(code)` | selects a verified backend; returns `isolationClass`, `verified`, `evidence`; never silently uses vm for untrusted code |
| `runInProcess(code)` | retained as `process` class, `verified:false`; disabled in strict |
| `vibeguard sandbox --isolation process` | allowed only in monitor mode or with explicit `--allow-unverified`; prints warning |
| `sandbox_exec` MCP tool | requires `sandbox.exec` capability; returns structured isolation metadata |
| `getIsolationLevel()` | returns backend ID/class, not a vague “vm” |

Existing tests that assert `vm`/`process` behavior remain as compatibility tests but are marked **legacy**, not security guarantees. New tests assert the verified backend matrix.

---

## 13. Residual risks

- Hypervisor/kernel zero-days.
- Side channels and resource-contention attacks.
- Host EDR interference.
- A user who can change the backend binary.
- Data inferred from output even when direct access is blocked.
- Cross-session state on a shared backend if snapshots/templates are reused incorrectly.

The design must publish these limitations with every isolation claim.
