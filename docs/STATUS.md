# VibeGuard status

This file is the single authoritative status summary. Release notes and
historical audits keep the counts and claims from their own dates; they are not
current status. `package.json` is the authoritative version number.

| Field | Value |
|---|---|
| Release version | **1.15.0** (`package.json`; published as `@yagyeshvyas/vibeguard@1.15.0`) |
| Repository state | Released 1.15.0; see `CHANGELOG.md` |
| Security status | **INTERNAL TESTING** — not beta, not production-ready |
| Rules | **861** (live `node scripts/counts.js`) |
| MCP tools | **95** (live count, duplicate names rejected by tests) |
| Languages | **18** |
| Compliance frameworks | **10** |
| Defense layers | **13** |
| Full test suite on the Windows audit host | **659 passed, 0 failed** |
| Platform security suite | **50 passed, 0 failed** |
| npm package | `@yagyeshvyas/vibeguard@1.15.0` |
| Telemetry | none |

## OS isolation

A backend is reported as verified only after its live suite passes on the
current host and the host-bound verification cache is valid. Presence of a
backend or a binary is never enough.

| Platform | Backend | Status | Evidence |
|---|---|---|---|
| Windows | `windows-appcontainer` + Job Object | **Verified on this audit host** | 11/11 live checks: safe execution; host-file, home-file, host-write and system-temp denial; loopback and LAN egress denial; host environment not inherited; wall-clock timeout; memory cap; profile and package-directory cleanup |
| macOS | `macos-vm` (QEMU/HVF) | **Implemented; unverified without a guest image** | Fails closed with `unavailable` off macOS or without `VIBEGUARD_VM_IMAGE` / `VIBEGUARD_VM_KERNEL`; verification requires booting the caller-supplied guest and passing the no-NIC, read-only-share and host-file probes |
| Linux | bubblewrap / `unshare` | Backend-dependent | Network/PID/filesystem checks run on the host; not a hardware-VM boundary |

Windows AppContainer shares the host kernel. It has no internet/private-network
capability SIDs (so no network, including loopback), no WFP filter, and reads
of Windows/Program Files remain available by default; the user profile,
credential stores and writable host paths are denied. The job object provides
memory/process/UI limits and kill-on-close. Those limitations are returned with
every result.

macOS VM isolation is QEMU/HVF with a separate guest kernel, `-nic none`, a
read-only 9p share, `-snapshot`, and guest-side Node. The guest image and its
backing chain are caller-supplied and must be trusted. The repository does not
ship an image, so it cannot claim verified macOS hardware-VM isolation on this
Windows host.

## Strict MCP default

The MCP firewall is strict by default: unknown tools are denied, strict mode
writes signed audit events, and an unavailable audit sink fails closed. An
operator can explicitly opt out with `--allow-unknown`; that choice is printed
as a warning and recorded in the policy mode. Missing policy files and policy
parse errors do not silently allow tools.

## Reproduce

```bash
node scripts/counts.js
node test/run.js
node test/run-platform.js
node bin/cli.js sandbox verify
```

On Windows, `sandbox verify` runs the AppContainer suite. On macOS, it requires
a bootable guest image. CI run
[`45104005496`](https://github.com/yagyeshVyas/VibeGuard/actions/runs/45104005496)
passed the full suite on Windows, Linux and macOS (659/659 each) and the
platform suite on Windows and macOS (50/50 each); results are attached to the
workflow run and summarized in
[`reports/ci-test-results.md`](../reports/ci-test-results.md).

## Known gaps

- macOS hardware-VM verification is image-dependent and must be run on macOS.
- Windows AppContainer is an OS boundary, not a hypervisor boundary; no WFP
  network filter is installed.
- Independent external human penetration testing and representative
  cross-language precision/recall data are not complete.
- The approval service is a local service with password authentication, not an
  enterprise SSO/IdP.
- Memory/delegation controls are tested libraries, not a complete distributed
  runtime.
