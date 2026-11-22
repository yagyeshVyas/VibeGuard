# Implementation Status — Security Baseline v2 (updated)

**Status:** INTERNAL TESTING. This file summarizes the second hardening pass;
the independent evidence is in `research/`.

## Verified results

- Full Windows Node24 suite: **625 passed, 0 failed**.
- Full Windows Node18 suite: **625 passed, 0 failed**.
- Full Linux WSL Node22 suite: **625 passed, 0 failed**.
- Platform security suite: **31/31** on Node18/20/22/24 and Linux.
- Integrity: **46 modules** verified.
- `npm audit --audit-level=high`: 0 critical/high, 10 moderate.
- Labeled corpus: precision/recall 1.0 on a small curated set (not representative).

## Implemented in this pass

- Signed Ed25519 gateway audit for strict mode, with key persistence,
  checkpoint sidecar, tamper/truncation detection and fail-closed audit errors.
- Authenticated HTTP JSON-RPC + SSE MCP bridge over a spawned stdio upstream.
- Stdio VGAT token capability checks and signed single-use approval tokens.
- `--kill-on-block` / `--max-blocks` quarantine kill response.
- Linux `unshare` network/PID namespace backend with a live network-isolation
  verification (`vibeguard sandbox verify`).
- MemoryGuard provenance/hash/injection guard and DelegationGraph
  attenuation/depth/signature checks.
- Labeled detection corpus runner and AISVS-style readiness mapping/CLI.
- Plugin default-deny, all-method MCP inspection, deep secret detection,
  realpath policy, Windows shell coverage, deep prompt detector.

## Remaining blockers

- Windows AppContainer/Job Object/WFP and macOS VM backends are absent; Linux
  filesystem is not isolated.
- ApprovalBroker.decide() still accepts an unauthenticated human string; no
  approval UI/service.
- External anchor is opt-in (`audit verify --anchor`); local log+sidecar+anchor deletion is still possible.
- TLS/mTLS server options exist; live OAuth server flow and multi-session persistence do not.
- No independent runtime process/filesystem/network monitor/quarantine service.
- Memory/multi-agent controls are libraries, not runtime enforcement.
- Legacy non-strict mode still default-allows unknown tools.
- Small curated corpus; no independent penetration test.
- macOS unverified; npm release not published.

## Compatibility

Existing CLI/MCP APIs are preserved. Two tests intentionally changed to reflect
security behavior: plugin test opts into `{trustPlugins:true}`; firewall test
accepts the new `INJECT.DEEP_DETECTOR` finding. No security assertion removed.

## Evidence

- `test/platform-security-tests.js` (31 tests)
- `test/corpus/run.js`
- `research/SECURITY_TEST_MATRIX.md`
- `research/KNOWN_LIMITATIONS.md`
- `research/RELEASE_READINESS.md`
- `reports/benchmark.json`
