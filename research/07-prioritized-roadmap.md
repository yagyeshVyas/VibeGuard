# Prioritized Security Roadmap

**Audit date:** 2026-11-21  
**Revision:** `2ce5b36` / v1.10.0  
**Status:** planning only; no implementation in this phase.

The goal is not “add more rules.” The goal is to make VibeGuard a platform whose **enforcement boundaries are real, whose detection has measured false-positive/false-negative rates, whose evidence is authenticated, and whose standards claims are defensible.**

---

## 0. Guiding principles

1. **Do not ship a boundary you cannot defend.** A vm/process wrapper must either be replaced with OS-level isolation or be labeled as a convenience runner.
2. **Fail closed on unknown.** Unknown tools, invalid policy values, unparsed messages, unsigned policy/pins and missing audit files should produce a deny/error/unknown state, not an implicit allow.
3. **Separate detection from assurance.** “Mapped to OWASP” is not “verified against OWASP.” Report `partial`, `not tested`, `unknown`.
4. **Never execute target-controlled code during scanning.** A security scanner that scans untrusted repositories must be more isolated than the code it scans.
5. **Measure detection.** Every rule family needs a corpus with precision/recall and a regression gate.
6. **Sign the evidence.** A local hash chain is useful; an authenticated receipt/checkpoint is trustworthy.
7. **Prefer capability separation over parsing.** No shell tool is safer than a perfect shell parser.

---

## 1. P0 — Stop-ship blockers (0–30 days)

These should block any “secure” or “production-ready” claim.

| # | Action | Findings addressed | Effort | Owner | Acceptance test |
|---|---|---|---|---|---|
| P0-1 | **Remove plugin auto-execution from scan.** Do not `require()` project `node_modules` or config plugins. Add an explicit `--trust-plugin` path/allowlist; run trusted plugins in a separate process; never let `.vibeguardrc` execute code. | F-01 | 2–4 days | Scanner lead | A temp repo with `poc.js`/`vibeguard-rules-pwn` produces no marker and exits with a clear “plugins disabled” message. |
| P0-2 | **Stop presenting vm sandbox as a boundary.** For untrusted code: refuse on Node 18/vm, or integrate a real isolation backend. In process mode, block network at the OS level; do not expose host-realm objects. | F-02 | 5–15 days | Runtime lead + platform | Constructor-chain escape and `getBuiltinModule('net')` exfil tests fail closed. |
| P0-3 | **Scan every server-to-client MCP payload**, not just `tools/call`: `resources/read`, `prompts/get`, `sampling/createMessage`, notifications, unknown content. | F-03 | 3–5 days | MCP lead | Secret/injection returned via resource/prompt is stripped/withheld and audited. |
| P0-4 | **Authenticate/sign the audit log; fix CLI verification.** HMAC/Ed25519 + signed checkpoints; CLI loads the file; zero entries = error; append-only/single-writer. | F-04, F-19 | 3–7 days | Audit lead | Rewriting all entries is detected without the key; `audit-trail verify` on a persisted file reports the real count or fails. |
| P0-5 | **Fail-closed policy defaults and strict schema.** No policy = deny (or refuse to start); invalid `defaultAction` = error; unknown tools = deny/warn with explicit configuration. | F-05 | 2–4 days | Policy lead | `defaultAction:'deny'` cannot normalize to allow; unknown tool is blocked by default; invalid policy exits non-zero. |
| P0-6 | **Canonicalize paths and enforce realpath scope.** Reject junctions/symlinks outside root; use `realpath` for allowed/denied paths. | F-06 | 2–3 days | Policy lead | Junction to outside is blocked; allowed explicit symlink works only if configured. |
| P0-7 | **Close shell egress and Windows command gaps.** No shell/network capability by default; if enabled, parse argv and apply host policy; add Windows cmd/PowerShell denylist with `-enc` decoding. | F-11, F-15 | 4–8 days | Runtime + Windows | `curl` to a non-allowlisted host is blocked; Windows destructive commands are blocked on Windows CI. |
| P0-8 | **Update vulnerable dependencies and gate CI.** SDK 1.32.2+, overrides, `npm audit --audit-level=high`, lockfile refresh; pin Actions by SHA; fix lock metadata. | F-13 | 1–3 days | Release/CI | `npm audit` has no high/critical prod findings; CI fails on regression; lock version matches package. |
| P0-9 | **Make release integrity real.** Publish v1.10.0 (or next) from the tested commit; attach SBOM/checksums/signed assets; sign tags/commits; verify integrity at startup or document explicit verification. | F-13 | 2–5 days | Release lead | npm version matches tag; release has SBOM/checksums; `self-check` runs on demand and reports 30 modules. |
| P0-10 | **Correct standards labels and claims immediately.** Fix MCP06 name; label LLM 2025 as historical; remove/qualify “100% OWASP coverage,” “tamper-proof,” “100% offline,” and “sandbox” claims. | F-14, F-28 | 1 day | Docs/security lead | Website/README/CLI help use qualified language; OWASP report says “mapped, not verified.” |

**P0 exit criteria**

- F-01, F-02, F-04, F-05, F-06, F-11/F-15, F-13 closed with regression tests.
- No unconditional target-code execution in `scan`.
- No unauthenticated “PASS” audit verification.
- No “100%” security/coverage claim without evidence.

---

## 2. P1 — Production hardening (30–90 days)

| # | Action | Findings | Effort | Dependencies | Acceptance |
|---|---|---|---|---|---|
| P1-1 | **Agent identity and authorization model** (principal, agent ID, tenant, scopes, quotas). For local stdio, peer credentials + registry; for remote, OAuth 2.1/mTLS. | F-12, F-23 | 10–20 days | Identity provider/key store; MCP SDK transport | Tool list/invocation is scoped to a principal; unauthenticated remote access fails. |
| P1-2 | **Remote MCP proxy** (streamable HTTP/SSE) with TLS, Origin/Host validation, redirect/DNS controls, OAuth/mTLS. | F-23 | 10–20 days | HTTP stack, auth | Remote server is inspected and authenticated; no direct bypass. |
| P1-3 | **Human approval + reversibility** workflow with canonical action parameters, single-use nonce, signed approval, audit record. | F-21 | 8–15 days | Key management, UI/API | High-impact action blocks until a signed approval; approval replay fails. |
| P1-4 | **Schema validation and payload limits** both directions; JSON Schema, depth/size caps, unknown params rejection. | F-22, F-17 | 5–10 days | JSON Schema validator | Malformed/oversized responses are rejected/truncated and audited; no unbounded buffer. |
| P1-5 | **DLP/secret engine upgrade**: entropy, base64/hex/url decode, split-value normalization, result scanning, destination-aware policy. | F-07 | 5–10 days | `src/entropy.js`; false-positive corpus | Unknown/base64/split secrets blocked; known false positives (hashes/UUIDs) remain clean. |
| P1-6 | **Tool-poisoning/prompt/skill detection corpus and normalization** (NFKC/confusables, paraphrase, multilingual, base64 any length). | F-08, F-09, F-10 | 8–15 days | Labeled corpus; optional local model | Bypass corpus blocked; benign “guidance” no longer blocked; published precision/recall. |
| P1-7 | **First-sight tool approval and signed policy/pins** outside the project; endpoint binding. | F-26, F-27 | 5–10 days | Policy store, approval UI | Target repo cannot auto-trust its own policy/pins; changed definition requires approval. |
| P1-8 | **Complete MCP config discovery** and pinned installer spec; centralize with doctor. | F-16 | 3–5 days | Client config matrix | Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Cline, etc. are discovered; npm spec is pinned. |
| P1-9 | **CI/platform matrix**: Windows + macOS jobs, OS-specific shell/path/sandbox tests, Node 18 behavior explicit. | F-24, F-15 | 3–7 days | CI budget | All three OSes green; Node 18 refuses unsafe sandbox. |
| P1-10 | **Release engineering**: SBOM (CycloneDX), checksums, signed artifacts, npm provenance, dependency review, action SHA pins. | F-13 | 3–7 days | Release token, signing key | Every release has SBOM/checksums; npm version = tag = tested commit. |

**P1 exit criteria**

- No unauthenticated remote MCP path.
- High-impact actions require approval with signed evidence.
- Unknown/base64/split secrets and common paraphrased injections are caught with measured false positives.
- Windows/macOS CI green; policy/pins not target-controlled.

---

## 3. P2 — World-class assurance (90–180 days)

| # | Action | Findings | Effort | Dependencies | Acceptance |
|---|---|---|---|---|---|
| P2-1 | **Real OS sandbox** for untrusted code: Firecracker/gVisor/E2B or Windows AppContainer/Job Objects, per-session network namespace, no host credentials. | F-02 | 20–40 days | Linux infra / Windows native helper | Escape corpus cannot reach host fs/network; resource limits enforced. |
| P2-2 | **Signed action receipts/checkpoints** tied to policy hash, principal, tool, args, timestamp; verifier outside agent. | F-04 | 10–20 days | Key management, receipt spec | Independent verifier validates a receipt; tampering/replay fails. |
| P2-3 | **AISVS 1.01 mapping and verification** (start C9/C10; then C11/C12) with requirements, levels, evidence and tests. | F-14 | 15–30 days | Standards working group | Every claimed AISVS requirement has a test/evidence or is explicitly out of scope. |
| P2-4 | **Adversarial evaluation program**: Promptfoo-style corpus, fuzzing, mutation, red-team CI. | F-08/F-09/F-10/F-17/F-22 | 10–20 days | Corpus, harness | Regression gate with precision/recall and bypass corpus. |
| P2-5 | **Risk-score calibration**: separate risk from coverage, confidence/unknown states, AIVSS/CVSS mapping. | F-20 | 8–15 days | Labeled incidents/benchmark | Score has documented calibration and uncertainty; missing evidence is `unknown`. |
| P2-6 | **Behavior monitoring enforcement**: kill switch, session revocation, SIEM/OTel alerts, lease/quotas. | F-18 | 8–15 days | Control channel/auth | Critical pattern stops subsequent calls; operator can revoke. |
| P2-7 | **Independent penetration test and bug bounty** for MCP proxy, policy, sandbox, audit. | All | 10–20 days | Budget, scope | External report with no Critical/High open; fixes verified. |
| P2-8 | **Public SDK/API** with versioning, types, auth, policy evaluation API. | F-29 | 10–20 days | API design, auth | Stable v1 SDK; breaking-change policy; examples. |

**P2 exit criteria**

- A real isolation backend is the default for untrusted execution.
- An external verifier can validate audit receipts without trusting the agent.
- AISVS C9/C10 claims are evidence-backed.
- Adversarial corpus/fuzzing runs in CI with a published score.

---

## 4. P3 — Platform maturity (180+ days)

- Enterprise management (multi-tenant policy, fleet discovery, key rotation, SSO/SCIM).
- SIEM/OTel export and incident workflows.
- Plugin marketplace with signatures, sandboxing and review.
- Cross-platform sandbox backends and performance parity.
- Published threat model updates per release, CVE response process, security advisories.
- Transparent benchmark harness and reproducible test corpus.
- SOC 2/ISO 27001 readiness if commercial claims are made (independent audit).

---

## 5. Target architecture

```
                       ┌────────────────────────────┐
Untrusted repo ───────►│ Scanner (no target code)   │
                       │  - rules/taint/AST         │
                       │  - plugins: explicit+sandbox│
                       └──────────────┬─────────────┘
                                      │ findings
Agent/client ──► [ authenticated MCP proxy ] ──► MCP server
                    │  identity/scopes          │
                    │  all-method content scan  │
                    │  schema/size validation   │
                    │  policy (deny default)    │
                    │  approvals/reversibility  │
                    │  signed receipt + log     │
                    ▼
              [ external verifier / SIEM ]
Untrusted code ──► [ OS sandbox: microVM/gVisor/AppContainer ] ──► no host creds/network
```

Non-negotiable properties:

- No target-controlled code executes in the scanner trust domain.
- The proxy covers every MCP content path, not just tools.
- The policy is deny-by-default and authenticated.
- The sandbox is an OS boundary or is not called a sandbox.
- Every security claim has a test and an explicit limitation.

---

## 6. Metrics / KPIs

| Area | Metric | Target |
|---|---|---|
| Detection | Bypass-corpus block rate | ≥95% for Critical/High classes |
| Detection | False-positive rate on benign corpus | ≤2% (document per class) |
| Enforcement | Policy bypass tests | 0 Critical/High |
| Sandbox | Escape corpus | 0 host fs/network access |
| Audit | Forged/rewritten log detection | 100% without key |
| MCP coverage | Methods scanned | 100% of content-bearing methods |
| Auth | Unauthenticated remote requests | 0 allowed |
| Release | npm/tag/commit match | 100% |
| Release | SBOM/checksums/signature | 100% of releases |
| Standards | AISVS claimed requirements with evidence | 100% of claimed |
| Performance | Proxy p95 overhead | Documented budget; no unbounded growth |
| Platform | CI OS coverage | Linux + Windows + macOS |

---

## 7. Dependency and compatibility risks

| Change | Risk | Mitigation |
|---|---|---|
| Remove plugin auto-exec | Breaks existing plugin users | `--trust-plugin` + migration guide |
| OS sandbox | Native deps, Windows/macOS differences | Start with optional Linux backend; refuse on unsupported OS |
| Auth/OAuth | Protocol/complexity; breaks local setup | Local peer auth for stdio; remote OAuth optional |
| Deny-by-default | Breaks working agents | `vibeguard mcp-firewall --init` with curated policy; warn/allow migration mode |
| HMAC/signing | Key management/rotation | OS keystore/TPM; documented recovery |
| Realpath enforcement | Legitimate symlinked projects | Explicit allowedPaths realpath |
| SDK upgrade | MCP behavior changes | Full proxy/transport tests; pin/rollback |
| AISVS mapping | Large scope/claims | Start C9/C10, mark others out of scope |
| Release signing | Token/CI setup | Manual release only if token absent; do not claim published |

---

## 8. Recommended sequencing

**Week 1:** P0-1 (plugin RCE), P0-4 (audit), P0-5 (fail-closed), P0-10 (claims).
**Week 2:** P0-2 (sandbox truth), P0-6 (symlink), P0-7 (shell/Windows), P0-8 (deps), P0-9 (release).
**Weeks 3–6:** P1-1/P1-2 (identity/remote), P1-3 (approval), P1-4 (schema), P1-5/P1-6 (DLP/detection corpus).
**Weeks 7–12:** P1-7..P1-10, then P2-1/P2-2/P2-3.
**Quarter 2:** P2-4..P2-8 and independent testing.

Do not start with “more rules” or “more MCP tools.” The current findings show that additional features would expand an already weak boundary.

---

## 9. Definition of “world-class” for this product

VibeGuard can credibly claim world-class agent security when:

1. Scanning an untrusted repo cannot execute its code.
2. The proxy covers every MCP content path and fails closed on unknown content.
3. Every tool call is attributable to an authenticated principal and authorized by explicit policy.
4. High-impact actions require signed approval and respect reversibility.
5. Untrusted code runs in a real OS isolation boundary with no host credentials/network.
6. Audit evidence is authenticated, append-only and independently verifiable.
7. Detection has published precision/recall and a maintained bypass corpus.
8. Standards claims (OWASP Agentic/MCP/AISVS/LLM) are versioned, evidence-backed and honest.
9. Releases have SBOM, checksums, signatures and match the tested commit.
10. The independent penetration test has no open Critical/High findings in these areas.

Until then, the correct claim is: **“a promising local AI security toolkit with real detection breadth and an enforcement layer that is not yet trustworthy under adversarial conditions.”**
