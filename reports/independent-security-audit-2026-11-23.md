# Independent Security Audit — Sandbox Isolation

**Date:** 2026-11-23  
**Audited baseline:** `58296672fc` (`feat(sandbox): verified Windows AppContainer and macOS VM isolation`)  
**Remediation commit:** `18144aa54f` (`fix(sandbox): close thenable escape and harden isolation verification`)  
**Auditors:** three read-only independent review passes (`AuditWindowsAC`, `AuditMacVM`, `AuditWiring`) plus local reproduction by the coordinating auditor.

**Nature of this audit.** This is an independent in-session security review by separate reviewer agents, not a certified external audit firm and not a substitute for a paid third-party assessment. The reviewers did not modify the repository. The coordinating auditor reproduced the high-severity finding, applied remediation, and re-ran the suites.

**Execution limits.** The host is Windows (`10.0.26300`, Node `24.14.0`). The Windows AppContainer backend was exercised live. The macOS VM backend could not be booted: this host has no macOS, no QEMU, and no guest image. All macOS findings are static-analysis findings except the fail-closed and argument/parser tests. No external network egress was generated during testing.

---

## Executive verdict

1. **No direct host escape was found** in the AppContainer or QEMU/HVF configuration. The AppContainer token uses zero capability SIDs; a live probe confirmed denial of the user profile, repo, other volumes, `C:\ProgramData`, `C:\Users\Public`, loopback TCP, and LAN TCP/UDP. QEMU is configured with no NIC, one read-only 9p share, a snapshot disk, no display/monitor, and no host stdin.
2. **One high-severity JavaScript-layer escape was found and fixed.** `HARNESS_SOURCE` passed the host-realm `emit` callback to a user-returned thenable. User code could recover host `process`/`require` from `resolve.constructor` and read host files from inside the AppContainer. The AppContainer still contained the resulting Node process, but the documented “no fs/process/child_process” property was false and the escape made the sandbox-writable staging tree reachable. Remediation removes host callbacks from the context and adds regression tests.
3. **The verification cache is not a cryptographic trust anchor.** It is host-user-writable; a same-user process can forge `verified:true`. Remediation adds evidence/config/host checks, future-date rejection, and symlink rejection, but cannot protect against the cache owner. This remains an accepted residual documented in README/INSTALLATION.
4. **macOS VM isolation remains unverified on real hardware.** The backend is implemented and its fail-closed, argument, parser and mount-surface checks pass, but no guest image was booted. It must not be described as live-verified until `vibeguard sandbox verify` passes on macOS with a trusted image.

---

## Findings

| ID | Severity | Finding | Status |
|---|---|---|---|
| A-01 | **High** | `HARNESS_SOURCE` passed a host function (`emit`) into the vm context via a user thenable; `resolve.constructor('return process')()` recovered host `process`/`require`. Reproduced: `ESC:; f` read from `C:\Windows\win.ini` inside the AppContainer. | **Fixed** |
| A-02 | **High** | Verification cache is unauthenticated and user-writable; forged `verified:true` selects an OS backend without a suite. | **Partially mitigated / accepted residual** |
| A-03 | Medium | `.vg-owner` was written under `...\AC`, but stale cleanup read the package root, so liveness was never checked and live profiles could be removed after 10 minutes. | **Fixed** |
| A-04 | Medium | `sandbox_exec` created a new profile and copied ~87 MiB `node.exe` per call, never disposing; long-lived MCP server leaked profiles and disk. | **Fixed** |
| A-05 | Medium | Staging tree (`bin`, `runs`) is sandbox-writable on a reused instance; a reparse point could redirect host writes. Reachable only through A-01. | **Mitigated by A-01; accepted residual for direct API reuse** |
| A-06 | Medium | Verification accepted negative-only evidence; a broken `probe()` could pass 7/10 checks; `profile-cleanup` ignored `DeleteAppContainerProfile` failure; memory check could pass for any allocation failure. | **Fixed** |
| A-07 | Low | `AssignProcessToJobObject` failure left a permanently suspended child; `ResumeThread` result unchecked. | **Fixed** |
| A-08 | Low | `ReadPipe` broke on a short read, truncating multi-chunk output or causing a timeout. | **Fixed** |
| A-09 | Low | Renderer printed untrusted output/error without control-character filtering (ANSI/OSC terminal spoofing). | **Fixed** |
| A-10 | Info | Timeout/memory/process-limit inputs were not clamped. | **Fixed** |
| A-11 | Info | MCP reported any backend execution failure as “no verified backend”; failed runs could show cached `Verified: yes`. | **Fixed** |
| A-12 | Medium | macOS result object omitted `audit`, so `renderSandboxReport` crashed after every human-readable VM run; hardware-VM label was green even when unverified. | **Fixed** |
| A-13 | Low | macOS verification cache was not bound to image/kernel/initrd/QEMU/args. | **Fixed** |
| A-14 | Low | macOS verification did not assert the exact host-path surface; extra writable `-virtfs` or extra `-drive` would pass. | **Fixed** |
| A-15 | Low | Guest output marker parsing could prefer a forged `__VG_VM_RESULT__`; no nonce. | **Partially fixed** (marker-kind separation; nonce remains open) |
| A-16 | Low | VM timeout: a guest that printed a result then hung was reported success with no timeout indication; `dispose()` did not kill QEMU. | **Fixed** |
| A-17 | Info | A qcow2 backing chain is a host-file read by QEMU even with `-snapshot`; header/docs were too absolute. | **Documented** |
| A-18 | Info | VM `memoryMb`/`timeout` were unvalidated. | **Fixed** |
| A-19 | Medium | Unknown `isolation` values silently downgraded to process/vm instead of failing closed. | **Fixed** |
| A-20 | Medium | Windows network verification tested loopback only; an added `internetClient` capability would not be caught. | **Improved** (LAN TCP probe + positive token; internet egress still not tested offline) |
| A-21 | Medium | Linux `sandbox verify` was not persisted, so a later `--isolation os` never selected the verified Linux backend. | **Fixed** |
| A-22 | Medium | Tests counted early returns as passes; no thenable/cache/renderer/unknown-mode tests; macOS success path never exercised. | **Partially fixed** (thenable, cache negatives, renderer, unknown mode; live macOS and child/fork/credential-vector tests remain) |
| A-23 | Medium | Documentation contradicted itself: stale release gate/AISVS said Windows/macOS absent; “per-run” profile was per-backend; “7-day cache” lacked a trust caveat. | **Partially fixed** (README/CHANGELOG/INSTALLATION caveats; historical release-gate/AISVS snapshots remain) |
| A-24 | Medium | Design says `sandbox_exec` requires `sandbox.exec` capability; the MCP handler checks only `args.code` and permits explicit `process`/`vm`. | **Open / design gap** |

---

## A-01 — thenable host-callback escape (reproduced, fixed)

**Before remediation:**

```js
({ then(resolve) {
  const p = resolve.constructor('return process')();
  const req = p.mainModule.require.bind(p.mainModule);
  const fs = req('fs');
  resolve('ESC:' + fs.readFileSync('C:/Windows/win.ini', 'utf8').slice(0, 3));
} })
```

`vibeguard sandbox ... --isolation os` returned `success:true, output:"ESC:; f"`. The AppContainer correctly denied the user profile, repository, `C:\`, `D:\`, `C:\Users\Public` and `C:\ProgramData`; the failure was the JavaScript layer, not the OS boundary.

**Fix.** `src/sandbox.js` now creates `__vg_state` inside the context, attaches context-side `then` handlers, stores the context-realm result, and polls a boolean from the host. No host function is passed into the context. `emit` is invoked only host-side with a context value.

**Regression tests.** `test/platform-security-tests.js` now asserts the thenable payload returns `SAFE` (not `ESCAPED`) in both `runInProcess` and `run` on the AppContainer backend. A normal `Promise.resolve(42)` still returns `42`.

---

## A-02 — verification cache trust (accepted residual)

The cache at `~/.vibeguard/sandbox-verification.json` is plain JSON. Same-user code can write a record with `verified:true`, evidence and host fields, and `SandboxManager.select(OS)` will use it. Remediation:

- requires `verified === true`;
- requires at least one evidence item and every item `passed:true`;
- rejects timestamps more than 5 minutes in the future and older than the TTL;
- fingerprints platform, arch, OS release, Node, hostname and user;
- binds the record to a backend/config key (Node/PowerShell/limits, or image/kernel/initrd/QEMU/args for the VM);
- rejects symlinked cache reads and writes, uses an exclusive temp file, and mode `0600`.

This stops stale, cross-image, empty-evidence and trivial forged records, but **does not stop a same-user process that writes a syntactically valid forged record**. The design's signed-evidence requirement is not met by this cache. The correct operational guidance, now in README/INSTALLATION, is: run `vibeguard sandbox verify` before trusting the claim. A future revision should re-verify on selection or protect the record with an OS keystore (acknowledging that DPAPI/Keychain protect against other users, not the same user).

---

## A-06 — verification evidence (fixed)

The Windows suite now requires a unique `__VG_PROBE__` token from every probe and:

- requires `profile-cleanup` to confirm both folder removal and `DeleteAppContainerProfile` success;
- requires `SMALL_OK` before the oversized allocation in the memory probe;
- requires `KEEP=keep` in the environment probe while the canary must be absent;
- adds loopback TCP and LAN TCP egress probes (LAN is skipped with a recorded reason when no non-loopback IPv4 exists);
- keeps a positive `safe-exec` control.

The macOS suite now asserts exactly one read-only 9p share, no `-fsdev`/`virtio-9p`/`virtiofs`, the expected disk surface, a guest-reported `vibeguard` mount with `ro`, guest boot, no network interface, host-marker invisibility, read-only share write denial, and timeout/kill tracking.

---

## Independent boundary probes (Windows)

Executed against the AppContainer backend after remediation:

| Probe | Result |
|---|---|
| user home marker | `EPERM` |
| sibling AppContainer profile | `EPERM` |
| repository `D:\vibe guard\package.json` | `EPERM` |
| `D:\` | `EPERM` |
| `C:\` | `EPERM` |
| `C:\Users\Public` | `EPERM` |
| `C:\ProgramData` | `EPERM` |
| `C:\Windows\win.ini` | readable (documented default grant) |
| `C:\Program Files` | readable (documented default grant) |
| host temp write | `EPERM` |
| `C:\Windows\Temp` write | `EPERM` |
| TCP loopback | `ETIMEDOUT` |
| UDP loopback | packet not received |
| UDP LAN (`192.168.10.231`) | packet not received |
| DNS lookup | `ENOTFOUND` |
| `reg.exe query HKCU` | no successful output (blocked/hung; terminated) |
| `cmd.exe /c echo` child | no successful output (blocked/hung; terminated) |

The `reg.exe`/`cmd.exe` hangs are capability limitations, not evidence of a host escape. Child-process and registry containment are **not** part of the automated suite.

---

## Regression and verification results after remediation

- `npm test`: **634 passed, 0 failed**.
- `node test/run-platform.js`: **40 passed, 0 failed**.
- `npm run lint`: **0 errors** (139 pre-existing warnings; none in the new isolation modules).
- `vibeguard sandbox verify`: Windows AppContainer **passes** all evidence classes (11, including the LAN probe).
- `vibeguard sandbox backends`: `windows-appcontainer:os:verified`.
- `node bin/cli.js self-check`: integrity verified over 52 modules.
- Cache isolation test: same config loads; changed PowerShell path invalidates; future/empty/config-mismatch records rejected.
- Thenable escape test: `SAFE` in process and AppContainer modes; direct reproduction now returns no host `process`.

macOS VM: fail-closed, argument/parser, exact-share/disk, renderer and cache-binding tests pass; **no live guest was booted**.

---

## Residual risks and recommendations

1. **Cache forgery (A-02):** accepted residual. Do not treat `verified` as signed evidence; re-run `sandbox verify` before high-assurance use. Prefer an OS-keystore-backed record or re-verification on selection in a future revision.
2. **macOS VM is not live-verified here (A-13/A-14/A-15/A-17):** require a macOS host, a trusted image with Node and a 9p-mounting init, and a passing `sandbox verify`. Pin the image digest and reject qcow2 backing chains if the image is not fully trusted.
3. **Guest output is unauthenticated (A-15):** a guest can spoof markers in its serial output. The backend now separates verifier and harness marker kinds, but a per-run nonce is recommended.
4. **`sandbox_exec` authorization (A-24):** the design’s `sandbox.exec` capability is not enforced. Any connected MCP client can request code execution in process/vm/os modes. This is a design gap, not an isolation escape.
5. **Coverage gaps (A-22):** no automated child-process containment, fork-bomb, process-limit, registry, named-pipe, COM, inherited-handle-enumeration or live macOS VM tests. The Windows suite is the only automated OS-boundary coverage in this environment.
6. **Documentation (A-23):** README/CHANGELOG/INSTALLATION now carry the cache and image-trust caveats. `research/RELEASE_READINESS.md`, `reports/known-limitations.md` and `src/platform/aisvs.js` are historical snapshots and still say Windows/macOS isolation is absent; treat them as pre-change snapshots until regenerated.
7. **AppContainer fundamentals:** the host kernel is shared; no WFP filter is installed; Windows/Program Files and some system state remain readable by default; AppContainer is an OS boundary, not a hypervisor boundary.

---

## Reproduction commands

```bash
# AppContainer live suite
node bin/cli.js sandbox verify
node bin/cli.js sandbox backends --json
node bin/cli.js sandbox "const x = 2 + 2; x" --isolation os

# Thenable regression (must not print host process/fs data)
node -e "const {runInProcess}=require('./src/sandbox');console.log(runInProcess(\"({then(r){let e=false;try{r.constructor('return process')();e=true}catch{}if(e)throw new Error('ESCAPED');r('SAFE')}})\").output)"

# Full and platform suites
npm test
node test/run-platform.js

# Unknown mode must fail, not downgrade
node bin/cli.js sandbox "1" --isolation container; echo "exit=$?"
```

---

## Attestation

The three reviewer agents were read-only and did not modify the repository. The coordinating auditor applied the remediation in `18144aa54f`, re-ran the live Windows suite and the full test suite, and did not change the `.mcp.json` worktree file (a pre-existing user edit). No finding in this report should be read as a guarantee of absence of unknown vulnerabilities, especially for the unexecuted macOS path.
