# Known Limitations (updated after second hardening pass)

**Status:** INTERNAL TESTING. The authoritative independent residual-risk list
is [`research/KNOWN_LIMITATIONS.md`](../research/KNOWN_LIMITATIONS.md). This
file exists for the implementation-report series and must not overstate
protection.

## Fixed blockers

- Strict gateway uses signed Ed25519 audit events with a checkpoint sidecar and
  fails closed if the audit sink is unavailable.
- HTTP bridge supports authenticated JSON-RPC POST and SSE notifications over a
  spawned stdio upstream.
- Stdio supports VGAT token capability checks and signed single-use approval
  tokens.
- `--kill-on-block`/`--max-blocks` provides a quarantine kill response.
- Linux `unshare` network/PID namespace backend is implemented and verified by
  a local probe.
- MemoryGuard and DelegationGraph libraries provide tested memory provenance and
  capability-attenuating delegation.
- Labeled corpus and AISVS-style readiness mapping exist.

## Remaining blockers

- Windows AppContainer/Job Object/WFP and macOS VM backends are absent; Linux
  filesystem is not isolated.
- ApprovalBroker.decide() still accepts an unauthenticated human string.
- No external audit anchor/transparency log; local sidecar deletion/rollback is
  undetectable.
- No TLS/mTLS/live OAuth server flow or multi-session remote deployment.
- No independent process/filesystem/network monitor/quarantine service beyond
  kill-on-block.
- Memory/multi-agent controls are libraries, not runtime enforcement.
- Legacy non-strict mode still defaults to allow unknown tools.
- Detection corpus is small and curated; multilingual/mutation coverage absent.
- macOS not verified; no independent penetration test; npm release not
  published; 10 moderate npm advisories remain.

Do not claim OS isolation on Windows/macOS, complete remote MCP security,
authenticated human approval, or production readiness.
