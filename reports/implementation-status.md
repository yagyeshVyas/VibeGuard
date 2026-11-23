# Implementation Status — Security Baseline v2

**Status:** INTERNAL TESTING. The authoritative summary is
[`docs/STATUS.md`](../docs/STATUS.md); this file records what the current
hardening pass changed.

## Verified results

- Full suite: **654 passed, 0 failed** on the Windows audit host.
- Platform security suite: **50 passed, 0 failed** on the Windows audit host.
- Windows AppContainer live suite: **11/11 checks passed**.
- Integrity manifest covers the platform and sandbox modules.
- `npm audit --audit-level=high`: 0 critical/high.
- Labeled corpus: precision/recall 1.0 on a small curated set (not
  representative).

## Implemented

- Signed Ed25519 gateway audit for strict mode, with key persistence,
  checkpoint sidecar, tamper/truncation detection and fail-closed audit errors.
- **Strict MCP default-deny:** missing policy files and unknown tools are
  denied, signed audit is enabled by default, and `--allow-unknown` is an
  explicit, warned opt-out.
- Authenticated HTTP JSON-RPC + SSE MCP bridge over a spawned stdio upstream.
- Stdio VGAT token capability checks and signed single-use approval tokens.
- `--kill-on-block` / `--max-blocks` quarantine response.
- Linux bubblewrap/unshare network/PID/filesystem backend where available.
- **Windows AppContainer + Job Object** backend with live filesystem, network,
  environment, timeout and memory verification; package-directory cleanup is
  part of the suite.
- **macOS QEMU/HVF hardware-VM** backend with no NIC, read-only 9p share,
  snapshot disk and caller-supplied trusted image; it fails closed until the
  guest passes verification.
- MemoryGuard provenance/hash/injection guard and DelegationGraph
  attenuation/depth/signature checks.
- Labeled detection corpus runner and AISVS-style readiness mapping.
- Plugin default-deny, all-method MCP inspection, deep secret detection,
  realpath policy, Windows shell coverage, deep prompt detector.

## Remaining blockers

- macOS hardware-VM verification is image-dependent and has not run without a
  bootable guest image on a macOS host.
- Windows AppContainer shares the host kernel and has no WFP filter.
- External anchor is opt-in; local log + sidecar + anchor deletion remains
  possible.
- Independent external human penetration test is outstanding.
- Memory/multi-agent controls are libraries, not end-to-end runtime enforcement.
