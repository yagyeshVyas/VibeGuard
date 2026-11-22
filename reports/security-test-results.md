# Security Test Results — VibeGuard Security Baseline v2

**Date:** 2026-11-21  
**Environment:** Windows 11/Node24 (full), Windows Node18 (full), Linux WSL Node22 (full), Windows/macOS CI platform suites  
**Base revision:** `2ce5b36` plus implementation changes  
**Status:** results are local and reproducible; no independent penetration test has been performed.

---

## 1. Test runs

| Command | Result | Notes |
|---|---|---|
| `npm test` | **629 passed, 0 failed** | full legacy + platform suite; last local run |
| `node test/run-platform.js` | **35 passed, 0 failed** | focused v2 security suite |
| `node bin/cli.js mcp-firewall --selftest` | **11/11 passed** | firewall scenarios |
| `node bin/cli.js sandbox backends` | process/legacy-vm `verified=NO` | intentional truthfulness |
| `node bin/cli.js policy validate docs/security-policy.strict.example.json --pub docs/security-policy.strict.example.pub.pem` | valid, signature verified | signed policy v2 |
| `node bin/cli.js audit verify <signed-log> --pub <key>` | VALID (when key supplied) | signed chain/checkpoint |
| `npm audit --audit-level=high` | exit 0 | **0 critical/high**, 10 moderate remain |
| `node scripts/security-bench.js --out reports/benchmark.json` | success | metrics below |
| `self-check` | 45/49 modules intact | SHA-256 manifest |

> If the exact full-suite count changes after additional commits, rerun the
> command and update this report; do not infer it from this snapshot.

---

## 2. Platform security tests (29)

| # | Test | Verified behavior |
|---|---|---|
| 1 | Canonical JSON/hash | sorted keys, deterministic hash, rejects undefined/cycles |
| 2 | Identity | issue/verify, audience, expiry, tamper, replay |
| 3 | Approval | human-only, no self-approval, digest binding, single use |
| 4 | Signed audit | valid chain, tamper detection, checkpoint, empty-log failure |
| 5 | Strict policy v2 | default deny, allow rule, credential path, outside-root, secret denial |
| 6 | Unsigned strict policy | rejected without trusted public key |
| 7 | Plugin trust | target `.vibeguardrc` does **not** execute code by default |
| 8 | Windows shell | destructive `Remove-Item`/`del`/`format`/`diskpart`/`vssadmin`/`powershell -enc/-e` blocked |
| 9 | MCP all methods | `resources/read` and `prompts/get` secrets/injection withheld |
| 10 | Result redaction | unknown entropy token redacted |
| 11 | Deep secrets | base64 and split Stripe key blocked; entropy blocked |
| 12 | Prompt detector | “guidance” no longer false-positive; “include .env”/“add .env” caught |
| 13 | Tool poisoning | natural-language/homoglyph/encoded definitions removed |
| 14 | Strict gateway | unknown tools blocked; explicit allow works |
| 15 | Sandbox | process host-object escape blocked; process mode `verified:NO` |
| 16 | SSRF | loopback/private/metadata blocked; public with injected resolver allowed |
| 17 | JWT | EdDSA JWKS, issuer/audience/scope, replay |
| 18 | HTTP gateway | auth required, policy allow/deny on loopback; policy-less listener rejected |
| 19 | Legacy vm runner | host-object constructor/eval/require/process escapes blocked after fix |
| 20 | Strict audit fail-closed | unavailable audit sink blocks a strict tool call |
| 21 | MCP server-originated content | strict resource URI + sampling/notification injection blocked |
| 22 | Signed gateway audit | strict gateway writes Ed25519 events; tamper invalid |
| 23 | Memory guard | provenance/trust/hash/injection checks |
| 24 | Delegation | attenuation, depth, signature/capability checks |
| 25 | Linux OS namespace | network/PID isolation verified when available |
| 26 | HTTP stdio bridge | authenticated tool call reaches upstream |
| 27 | Bridge SSE | authenticated server notification forwarded |
| 28 | Runtime kill | blocked call terminates proxy with exit 3 |
| 29 | Stdio auth/approval | capability + signed single-use approval enforced |
| 30 | Windows Job Object | process/memory containment and kill-on-close; limitations disclosed |
| 31 | External audit anchor | detects truncation after sidecar deletion |

---

## 3. Legacy regression coverage

The legacy suite remains green, including:

- scanner rules/fixtures (clean fixture zero findings);
- MCP server handshake and tool list/call;
- 30 MCP firewall tests (live stdio proxy, poisoned tools, drift, scrubbing, audit, CLI);
- agentic/agent-scan, v18/v19 reachability/bundle, pentest, PR scan, token-lean, taint depth;
- sandbox legacy tests (vm compatibility tests remain but are labeled unverified);
- audit trail tests;
- pre-deploy clean fixture gates (integrity manifest 49 modules).

One intentional test change: `test/run.js` plugin v2 test passes
`{trustPlugins:true}` because target plugin execution is now disabled by
default. This is a security behavior change, not a skipped control.

---

## 4. Dependency audit

After upgrading `@modelcontextprotocol/sdk` to `^1.32.2` and adding overrides:

```text
14 vulnerabilities → 10 moderate, 0 high, 0 critical (at time of run)
```

No critical/high production advisory remains from `npm audit`. Moderate
findings remain in development/transitive packages and are tracked in
`known-limitations.md`. `npm audit` is now a CI gate at `--audit-level=high`.

**Caveat:** `npm audit` is not a complete supply-chain guarantee; it does not
prove package provenance, signature validity or absence of malicious code.

---

## 5. Security probe evidence (selected)

### 5.1 Plugin RCE

Before: a target `.vibeguardrc.json` `plugins` entry caused `require()` and a
marker file. After the fix, the same probe produced:

```text
{"markerExists":false}
```

Explicit `--trust-plugins` remains dangerous by design and is documented.

### 5.2 Sandbox host-object escape

Process mode payloads:

```text
console.log.constructor('return process')().versions.node  → failure
this.constructor.constructor('return process')().versions.node → failure
JSON.parse.constructor('return process')().versions.node → failure
```

Result: `success:false`, `process is not defined`. Safe code still returns `3`.
The result is explicitly `isolationClass:"process", verified:false`. This is
**not** an OS sandbox; the legacy `vm` runner remains unsafe and is labeled
`NOT a security boundary`.

### 5.3 MCP resource/prompt bypass

`resources/read` and `prompts/get` responses containing a fake Stripe key and
`IGNORE ALL PREVIOUS INSTRUCTIONS` are now withheld/replaced before reaching
the model. Tests assert neither string survives.

### 5.4 Audit forgery

The legacy hash chain could be rewritten with recomputed hashes. The new
`SignedAuditLog` test verifies Ed25519 signatures and detects a modified event.
The legacy gateway audit remains unsigned (see limitations); signed audit is a
separate, tested logger/CLI.

### 5.5 Policy/path/secret attacks

- strict unknown tool → deny;
- junction to outside target → deny (realpath);
- `.env`/`.ssh` → deny;
- base64/split/entropy secret → deny/redact;
- shell `curl` to non-allowlisted host with `allowedHosts` → deny;
- Windows destructive commands → deny.

### 5.6 Identity/approval/HTTP/SSRF/JWT

- token tamper/expiry/audience/replay rejected;
- self-approval rejected; approval replay/digest mismatch rejected;
- unsigned strict policy rejected;
- HTTP gateway 401 without token, 200 for allowed, 403 for denied;
- JWT wrong audience/scope/replay rejected;
- SSRF private/loopback/metadata destinations rejected.

---

## 6. Performance results

From `reports/benchmark.json` (Windows 11, Node 24, i5-11400H):

| Operation | Iterations | Result |
|---|---:|---|
| identity issue+verify | 1,000 | ~3,752 ops/s; p95 0.34 ms |
| policy evaluate | 5,000 | ~3,359 ops/s; p95 0.38 ms |
| injection scan 1 KB | 2,000 | ~16,182 ops/s; p95 0.066 ms |
| signed audit append+fsync | 200 | ~169 ops/s |
| signed audit verify 200 | 200 | 39 ms |
| process sandbox spawn+run | 5 | ~13.4 ops/s; p95 78 ms |
| MCP engine checkToolCall | 2,000 | ~1,464 ops/s; p95 0.84 ms |

These are microbenchmarks on one machine, not a service-level capacity claim.
They omit process/network/disk variance and do not measure full HTTP MCP
throughput.

---

## 7. What is not proven

- No independent penetration test.
- No full fuzzing campaign or detection precision/recall corpus.
- Linux unshare network/PID backend is verified; Windows/macOS OS backends and Linux filesystem isolation are not verified.
- No macOS CI result observed locally; workflow is configured.
- No live OAuth provider integration; only offline JWT/JWKS verification.
- No full Streamable HTTP/SSE MCP proxy test.
- No large-scale load/soak test.

These are limitations, not passes.
