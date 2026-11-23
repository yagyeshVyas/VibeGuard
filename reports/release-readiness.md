# Release Readiness

**Decision: INTERNAL TESTING**

The authoritative current status, counts and isolation evidence are in
[`docs/STATUS.md`](../docs/STATUS.md). The dated independent gate report in
[`research/RELEASE_READINESS.md`](../research/RELEASE_READINESS.md) is a
historical snapshot and its findings are superseded where they say Windows or
macOS isolation is absent.

Current evidence:

- Full suite: **659 passed, 0 failed** on the Windows audit host.
- Platform security suite: **50 passed, 0 failed** on the Windows audit host.
- Windows AppContainer live verification: **11/11 checks passed**, including
  host-file/home-file/host-write denial, loopback and LAN egress denial,
  environment isolation, timeout, memory cap and profile cleanup.
- Strict MCP default-deny is active; `--allow-unknown` is the explicit opt-out.
- Signed gateway audit, HTTP/SSE bridge, stdio token/approval, kill switch,
  Linux network/PID namespace, memory/delegation libraries, corpus and
  AISVS-style mapping are implemented and tested.

Still not beta/production ready:

- macOS hardware-VM verification requires a caller-supplied bootable guest on
  a macOS host; this repository does not ship one.
- Windows AppContainer shares the host kernel; no WFP filter is installed.
- Independent external human penetration testing is outstanding.
- macOS full-suite evidence is CI-produced, not local to the Windows host.
- The external anchor remains opt-in; a local log + sidecar + anchor deletion
  remains possible.
- Memory/multi-agent controls are libraries, not a complete distributed
  runtime.

Allowed: controlled internal testing with all limitations disclosed.
Not allowed: external beta, production candidate, or production-ready claims.
