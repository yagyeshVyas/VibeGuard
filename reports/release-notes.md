# Release Notes — Security Preview

**Status:** unreleased internal-testing build. **Not beta/production-ready.**

This is a record of the implementation change set built on v1.10.0 (`2ce5b36`).
It is not a published semver release and does not carry a production security
guarantee.

## Verified statistics

- Full test suite: **623 passed, 0 failed** (local Windows, Node 24; CI
  matrix includes Node 18/20/22 on Ubuntu and platform jobs for Windows/macOS;
  Node18 and Linux full suites also passed).
- New platform security suite: **29 passed, 0 failed**.
- MCP firewall self-test: **11/11**.
- Integrity manifest: **45 modules** SHA-256 verified.
- Dependency audit: **0 critical/high**, 10 moderate remaining.
- Benchmark: `reports/benchmark.json` (machine-specific).
- Signed audit: chain, signature, checkpoint and tamper tests pass.
- Strict policy example: signature verified with included public key.

## Added

- Strict v2 policy engine with signed Ed25519 policy documents, default deny,
  capabilities, per-tool/per-resource rules, realpath checks, secret/DLP and
  shell-egress checks.
- VGAT Ed25519 capability tokens (audience, expiry, replay).
- Signed single-use human approvals bound to action digests.
- Signed audit events (Ed25519 + Merkle checkpoints) and CLI verification.
- Offline EdDSA JWT/JWKS validation and SSRF/destination validation.
- Authenticated loopback HTTP JSON-RPC + SSE bridge over a stdio upstream.
- Strict gateway signed audit by default; stdio token/approval; kill-on-block.
- Linux unshare network/PID namespace with live verification.
- MemoryGuard/DelegationGraph libraries, detection corpus and AISVS mapping.
- All-method MCP response inspection, size/depth/pending limits and deep secret
  redaction.
- Windows destructive-command coverage; realpath path handling.
- New CLI: `policy validate/sign`, `audit verify`, `sandbox backends`.
- Windows/macOS CI platform jobs and dependency high/critical audit gate.

## Changed

- Scanner plugins are disabled by default; `--trust-plugins` is an explicit,
  dangerous opt-in.
- Process sandbox no longer exposes host-realm objects; results are labeled
  `verified:false` and are **not** an OS boundary.
- Tests: one legacy plugin test now opts into explicit trust (behavior change,
  not a skipped control).
- MCP SDK upgraded; vulnerable transitive overrides applied.

## Not included

Windows/macOS OS isolation, external audit anchoring, an authenticated
approver service/UI, TLS/OAuth remote deployment and independent runtime
monitoring remain incomplete. Linux network/PID namespace, signed gateway
audit, HTTP/SSE bridge, stdio token/approval, kill-on-block, memory/delegation
libraries, corpus and AISVS-style mapping are present. See
`research/KNOWN_LIMITATIONS.md` and `research/RELEASE_READINESS.md`.

## Installation

See `docs/INSTALLATION.md` and `docs/WINDOWS.md`.

## Safety statement

Do not deploy this preview as an enforcement boundary for untrusted agents or
untrusted code. The process sandbox is unverified and the legacy vm runner is
not a security boundary. Do not use the output to claim production readiness.
