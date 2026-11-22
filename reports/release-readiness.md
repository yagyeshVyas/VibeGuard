# Release Readiness (updated)

**Decision: INTERNAL TESTING**

The independent gate report is
[`research/RELEASE_READINESS.md`](../research/RELEASE_READINESS.md). Current
evidence:

- Full suite: **623 passed, 0 failed** on Windows Node24, Windows Node18 and
  Linux WSL Node22.
- Platform security suite: **29/29** on Windows Node18/20/22/24 and Linux
  Node22.
- `npm audit --audit-level=high`: **0 critical/high**, 10 moderate.
- Integrity: **45 modules** verified.
- Signed gateway audit, HTTP/SSE bridge, stdio token/approval, kill switch,
  Linux network/PID namespace, memory/delegation libraries, corpus and
  AISVS-style mapping are implemented and tested.

Still not beta/production ready:

- Windows/macOS OS isolation absent; Linux filesystem not isolated.
- Approval broker human identity is unauthenticated.
- No external audit anchor.
- No TLS/OAuth remote deployment or independent runtime monitor/quarantine.
- Memory/multi-agent controls not wired end-to-end.
- Small curated corpus; no independent penetration test.
- macOS full suite not run; npm publication is complete (`1.11.2`).

Allowed: controlled internal testing with no untrusted code on Windows/macOS.
Not allowed: external beta, production candidate, or production-ready claims.
