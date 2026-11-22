# VibeGuard Independent Known Limitations

**Verification date:** 2026-11-21/22  
**Status:** INTERNAL TESTING — not beta/production ready.

This is the authoritative residual-risk list after the independent fixes and
the second hardening pass.

---

## Confirmed and fixed during verification

| ID | Issue | Fix | Evidence |
|---|---|---|---|
| IV-FIX-01 | `inspectPrompt` missed natural-language secret instructions | shared deep detector | platform prompt/skill test |
| IV-FIX-02 | legacy vm host constructor escape | fresh context, eval/Function/dynamic-import blocks | platform vm test |
| IV-FIX-03 | strict gateway audit fail-open | audit probe + per-call fail-closed | platform test |
| IV-FIX-04 | PowerShell `-e` shell bypass | encoded-command regex | platform test |
| IV-FIX-05 | skill “add .env” bypass | detector extension | corpus/platform |
| IV-FIX-06 | invalid `defaultAction` normalized allow | fail closed to block | platform test |
| IV-FIX-07 | installer unpinned/wrong package | pinned package/version | installer test |
| IV-FIX-08 | HTTP gateway without policy | constructor rejects | platform test |
| IV-FIX-09 | server requests/resources/non-JSON bypass | inspection/drop/resource checks | platform test + stdio probe |
| IV-FIX-10 | signed audit truncation | checkpoint sidecar | truncation test |
| IV-FIX-11 | signed audit not gateway sink | strict gateway signed logger | signed-gateway test |
| IV-FIX-12 | no HTTP/SSE MCP bridge | authenticated bridge + SSE | bridge/SSE tests |
| IV-FIX-13 | no stdio identity/approval | VGAT capability + signed approval | end-to-end test |
| IV-FIX-14 | no runtime response | kill-on-block | exit-3 test |
| IV-FIX-15 | no OS isolation | Linux unshare network/PID backend | Linux test + CLI verify |
| IV-FIX-16 | no memory/multi-agent controls | MemoryGuard + DelegationGraph | platform tests |
| IV-FIX-17 | no precision/AISVS evidence | corpus runner + AISVS CLI | corpus/AISVS |

Two existing tests were intentionally updated for new detector IDs/trust flags;
no security assertion was removed.

---

## Residual Critical/High limitations

### L-01 — OS isolation is Linux-only and incomplete (High; beta blocker)

- Linux backend uses `unshare -Urn --pid --fork --mount-proc`: network and PID
  namespaces are verified by a local probe.
- **Filesystem is not isolated**; the user process can read host files.
- No Windows AppContainer/Job Object/WFP backend.
- No macOS VM/App Sandbox backend.
- The process/vm runners remain unverified; do not claim cross-platform
  isolation. `vibeguard sandbox backends` reports verified=NO until
  `sandbox verify` runs on Linux.

### L-02 — Approval broker human identity remains spoofable (High)

`ApprovalBroker.decide()` accepts any string starting with `human:`; a
compromised agent with in-process access can approve itself. The stdio path
does verify a signed single-use approval token against a public key, but the
approval-issuing side has no authenticated UI/service. Use only in a trusted
process for internal testing.

### L-03 — External audit anchor absent (High)

Strict MCP gateway now writes signed Ed25519 events + checkpoint sidecar, and
tamper/truncation is detected while the sidecar remains. Deleting both the log
and sidecar, or rewriting both with the same key, is not detectable without an
external transparency log/anchor. Legacy non-strict gateway audit remains
hash-chained only.

### L-04 — Remote deployment/TLS/OAuth incomplete (High)

The HTTP bridge supports authenticated JSON-RPC POST and SSE notifications on
loopback, with VGAT or JWT auth. It does not implement TLS/mTLS termination,
live OAuth authorization-server flows, remote token exchange, multi-session
persistence or a full remote lifecycle.

### L-05 — Runtime monitoring incomplete (High)

`--kill-on-block`/`--max-blocks` provides an enforcement response, but there is
no independent process/filesystem/network monitor, quarantine service, session
revocation broker or SIEM integration.

### L-06 — Memory/multi-agent controls are libraries (High)

`MemoryGuard` and `DelegationGraph` are tested primitives with no persistent
memory server, runtime multi-agent graph, or cross-session enforcement. Do not
claim ASI06/07/10 protection.

### L-07 — Detection quality is unproven (High/Medium)

The labeled corpus currently reports precision/recall 1.0 on a small curated
set (20 prompts + 10 tools). This is not representative. Multilingual,
paraphrased, mutation, encoding and tool-schema corpora are missing. Pattern
and semantic heuristic false negatives remain likely.

### L-08 — Default legacy behavior still allows unknown tools (High)

`mcp-firewall` without `--strict` uses the legacy default-allow policy. Strict
mode and signed v2 policy are opt-in; a compromised agent/user can avoid them.

### L-09 — Platform verification incomplete (High/Medium)

- Windows: Node18/20/22/24 platform and Node18/24 full suites pass locally.
- Linux: WSL Node22 full/platform suites pass in the final run.
- **macOS:** platform suite passed in CI (29/29); full macOS suite not run.
- No Windows/macOS OS backend tests.
- No real-disk network/TLS deployment tests.

### L-10 — Supply chain/release incomplete (Medium)

- `npm audit`: 0 critical/high, **10 moderate** remain.
- No package provenance/signature verification or signed plugin/skill manifests.
- No SBOM/checksum/SLSA attestation for this tree.
- Actions are tag-pinned, not SHA-pinned.
- npm publication is complete (`1.11.2`); no independent provenance/SLSA attestation.

### L-11 — DNS rebinding enforcement not integrated (Medium)

`assertAllowedUrl` resolves and returns a pinned address and blocks private/
metadata ranges, but the HTTP bridge does not use this validator for upstream
connections/redirects. No OS-level network egress policy on Windows/macOS.

### L-12 — Test hygiene (Low/Medium)

The install tests mutate the tracked `.mcp.json`; it was restored after
verification. Tests should run in temp cwd and clean up.

### L-13 — Claims/documentation (Medium)

Prior README/report claims (“100% offline”, “production-ready”, “world-class”)
are not supported. This research report set is the source of truth; absolute
claims must be removed before any external communication.

### L-14 — No independent penetration test/certification (Medium)

This was a local code and controlled-probe verification, not an accredited
penetration test, fuzzing campaign or AISVS certification. No security
guarantee is implied.

---

## Explicitly not verified

- Windows AppContainer/Job Object/WFP escape resistance.
- macOS sandbox/VM.
- Linux filesystem isolation/container escape.
- TLS/mTLS/OAuth remote deployment and multi-session MCP behavior.
- Hardware-backed keys/rotation and external audit anchors.
- Large-scale concurrency/soak/disk-full behavior.
- Full memory/multi-agent attack classes.
- Malicious package registry/provenance behavior.
- Independent third-party review.
