# VibeGuard Independent Known Limitations

**Verification date:** 2026-11-22  
**Status:** INTERNAL TESTING — not beta/production ready.

This is the residual-risk list after the v1.13.0 hardening pass.

---

## Residual Critical/High limitations

### L-01 — OS isolation is partial across platforms (High; beta blocker)

- **Linux:** bubblewrap backend provides verified network, PID and filesystem
  isolation when installed (read-only system root, isolated `/tmp`). `unshare`
  fallback isolates network/PID only. Neither is a VM/hardware boundary.
- **Windows:** Job Object backend provides process/memory limits and
  kill-on-close, verified. **AppContainer and WFP network/filesystem isolation
  are absent.**
- **macOS:** no VM/App Sandbox backend. The platform test suite passes in CI,
  but no macOS isolation claim is possible.
- The process/vm runners remain unverified.

### L-02 — Approval issuance has no hosted authenticated service (High)

`ApprovalBroker.decide()` now requires a signed approver proof by default and
registered approver keys; unauthenticated human strings are rejected. There is
still no hosted approval service/UI, approver key rotation, or durable ticket
store. Use a trusted process for internal testing.

### L-03 — External anchor is opt-in and local (High)

Strict gateway audit is signed; checkpoint sidecars and an optional anchor file
(`audit verify --anchor`) detect truncation after sidecar deletion. If the log,
sidecar and anchor are all deleted/rewritten by an attacker with full local
access, no local anchor can prove it. A remote transparency log is still needed.
Legacy non-strict gateway audit remains hash-chained only.

### L-04 — Remote deployment/TLS/OAuth is partial (High)

The HTTP bridge supports authenticated JSON-RPC POST and SSE notifications with
optional HTTPS/mTLS server options. Live OAuth authorization-server flow,
remote token exchange, multi-session persistence and remote lifecycle remain
unimplemented.

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
set (23 prompts + 13 tools). This is not representative. Multilingual,
paraphrased, mutation, encoding and tool-schema corpora are missing.

### L-08 — Default legacy behavior still allows unknown tools (High)

`mcp-firewall` without `--strict` uses the legacy default-allow policy. Strict
mode and signed v2 policy are opt-in; a compromised agent/user can avoid them.

### L-09 — Platform verification incomplete (High/Medium)

- Windows: Node18/20/22/24 platform and Node18/24 full suites pass locally;
  Job Object backend verified locally.
- Linux: WSL Node22 full/platform suites pass; bubblewrap verified in WSL.
- **macOS:** platform suite passed in CI (35/35); full macOS suite not run.
- No macOS isolation backend.

### L-10 — Supply chain/release incomplete (Medium)

- `npm audit`: 0 critical/high, **10 moderate** remain.
- No package provenance/SLSA attestation or signed plugin/skill manifests.
- Actions are tag-pinned, not SHA-pinned.
- npm `1.13.0` is published; GitHub Actions still lacks the `NPM_TOKEN` secret,
  so its publish step skips.

### L-11 — DNS rebinding enforcement not integrated (Medium)

`assertAllowedUrl` resolves and returns a pinned address and blocks private/
metadata ranges, but the HTTP bridge does not use this validator for upstream
connections/redirects. No OS-level network egress policy on Windows/macOS.

### L-12 — Test hygiene (Low/Medium)

The install tests mutate the tracked `.mcp.json`; restore it after tests. Tests
should run in temp cwd and clean up.

### L-13 — Claims/documentation (Medium)

Prior README/report claims (“100% offline”, “production-ready”, “world-class”)
are not supported. This research set is the source of truth.

### L-14 — No independent penetration test/certification (Medium)

This was local code/probe verification, not an accredited penetration test,
fuzzing campaign or AISVS certification. No security guarantee is implied.

---

## Explicitly not verified

- Windows AppContainer/WFP escape resistance.
- macOS VM/App Sandbox.
- Live OAuth/multi-session remote MCP deployment.
- Remote transparency-log anchoring.
- Large-scale concurrency/soak/disk-full behavior.
- Full memory/multi-agent attack classes.
- Malicious package registry/provenance behavior.
- Independent third-party review.
