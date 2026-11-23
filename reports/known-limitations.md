# Known Limitations

**Status:** INTERNAL TESTING. Current authoritative status:
[`docs/STATUS.md`](../docs/STATUS.md).

## Implemented and tested

- Strict MCP default-deny; missing policy and parse errors fail closed.
- Strict gateway uses signed Ed25519 audit events with a checkpoint sidecar and
  fails closed if the audit sink is unavailable.
- HTTP bridge supports authenticated JSON-RPC POST and SSE notifications over a
  spawned stdio upstream.
- Stdio supports VGAT token capability checks and signed single-use approval
  tokens.
- `--kill-on-block`/`--max-blocks` provides a quarantine kill response.
- Linux `unshare`/bubblewrap network/PID isolation where available.
- Windows AppContainer + Job Object backend verified on the Windows audit host.
- macOS QEMU/HVF VM backend is implemented and gated on a caller-supplied guest
  image.
- MemoryGuard and DelegationGraph libraries provide tested memory provenance and
  capability-attenuating delegation.
- Labeled corpus and AISVS-style readiness mapping exist.

## Remaining blockers

- Windows AppContainer shares the host kernel and has no WFP filter; Windows and
  Program Files remain readable by default.
- macOS hardware-VM verification is image-dependent and has not run on this
  Windows host; no guest image is shipped.
- External anchor is opt-in; local log + sidecar + anchor deletion remains
  possible.
- TLS/mTLS server options exist; live OAuth/multi-session remain incomplete.
- No independent process/filesystem/network monitor/quarantine service beyond
  kill-on-block.
- Memory/multi-agent controls are libraries, not runtime enforcement.
- Detection corpus is small and curated; multilingual/mutation coverage absent.
- Independent external human penetration testing is outstanding.
- 10 moderate npm advisories may remain on transitive dependencies.

Do not claim hypervisor isolation on Windows, verified macOS VM isolation
without a passing guest image, complete remote MCP security, enterprise SSO, or
production readiness.
