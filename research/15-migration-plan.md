# Migration Plan

**Design date:** 2026-11-21  
**Basis:** audit findings F-01…F-30 and `08`–`14`  
**Status:** design only. No implementation starts until this plan and the architecture are internally consistent.

---

## 1. Migration principles

1. **Security fixes ship before feature expansion.** The Critical/High enforcement gaps are not “later.”
2. **Preserve existing workflows.** CLI names, MCP tools, output fields and exit-code families remain unless a security behavior must change; changes are documented and gated.
3. **Dual-run before enforcement.** New policy/detection/audit paths can run in shadow mode and compare decisions with the legacy path.
4. **No silent default changes.** A changed default (deny, signed audit, verified sandbox) is announced, configurable during a transition window, and visible in `posture`.
5. **Data is forward-compatible.** New formats include a reader for old data; no destructive migration.
6. **Rollback is possible for code/config, not for signed audit history.** Signing keys, policy versions and checkpoints are retained.
7. **Every phase has an exit test and an owner.**

---

## 2. Release strategy

### 2.1 Version lines

| Line | Purpose |
|---|---|
| `1.10.x` | Security patches for the audited code (plugin RCE, sandbox claims, audit CLI, dependency fixes) without platform migration |
| `1.11.0` | Compatibility facades + shadow-mode platform modules behind flags; no forced strict mode |
| `2.0.0` | Strict gateway, signed audit, verified sandbox backends, policy v2; legacy modes opt-in and explicitly marked |

Why a major version: some fixes change security semantics (no target plugin execution, no vm claim, signed audit). Pretending they are patch-level changes would hide the behavior change.

### 2.2 Defaults by release

| Behavior | 1.10.x | 1.11 | 2.0 |
|---|---|---|---|
| Scan target plugins | disabled by default (security patch) | disabled | disabled; signed extension only |
| Gateway | optional `mcp-firewall` | shadow-capable | default for protected agents |
| Policy v2 | no | shadow/opt-in | default; legacy adapter |
| Audit signing | no | opt-in | default; fail closed if unavailable |
| Sandbox | legacy vm/process (warned) | verified backend if available | verified required for untrusted |
| Direct MCP path | allowed | detected/warned | detected; strict mode refuses protection claim |
| OWASP claims | static | qualified | evidence-based |

---

## 3. Phase plan

### Phase 0 — Stop-ship security fixes (days 0–14)

**Goal:** remove the two Critical paths and false assurance before platform work.

| Work | Findings | Compatibility |
|---|---|---|
| Remove target plugin auto-execution; `scan` never `require()`s project code | F-01 | Existing plugins stop loading; explicit `--trust-plugin` escape hatch with warning |
| Disable `vm` for untrusted code; process backend labeled unverified; refuse in strict | F-02 | `sandbox` still works for trusted/convenience code with explicit flag |
| Scan all MCP content methods | F-03 | adds blocking; may affect servers returning malicious/injected resources |
| Fix audit CLI/file loading and signing plan | F-04 | old logs readable; new verifier reports count |
| Fail-closed policy defaults/typos | F-05 | legacy policy adapter warns; strict requires review |
| Canonicalize paths | F-06 | legitimate symlinked paths need allowlisting |
| Dependency upgrades/audit gate | F-13 | SDK/proxy behavior tests required |
| Correct standards/claims | F-14/F-28 | docs only |
| Pin installer spec | F-16 | existing generated configs remain, flagged |

**Exit tests:** F-01 marker absent; F-02 escape/exfil blocked or refused; F-03 resource/prompt withheld; F-04 forged chain detected and CLI count>0; F-05 typo denies; F-06 junction blocked.

**Rollback:** revert the patch release; no data format changes except additive audit metadata.

---

### Phase 1 — Contracts and pure core (weeks 2–5)

**Deliverables**

- `platform/contracts` types/errors/canonical/clock.
- `platform/policy` v2 evaluator + validator + legacy adapter.
- `platform/identity` principal model + token interfaces (local implementation).
- `platform/protocol` JSON-RPC parser/content extraction/schema limits.
- Import-boundary/cycle tests.

**Compatibility**

- Existing `agent-policy.evaluateToolCall` delegates to v2 in `legacy` mode.
- `.vibeguard-mcp.json` auto-loaded into a monitor policy; no enforcement change until signed.
- Existing tests remain.

**Exit tests**

- Policy precedence/property tests (deny overrides, default deny, invalid policy).
- Canonical JSON/hash golden tests.
- Facade differential tests: legacy vs v2 in shadow mode.
- No I/O in policy module.

**Rollback:** feature flag `VG_PLATFORM_CORE=off`; facades keep old path.

---

### Phase 2 — Signed audit and verification (weeks 4–7)

**Deliverables**

- Event schema v1 (signed), canonicalization, hash chain, Ed25519 signer/verifier, checkpoints, external anchor adapter.
- Legacy JSONL import/verify.
- CLI `audit verify` loads real files; fails on zero entries; verifies signatures/checkpoints.
- Key management abstraction (OS keystore).

**Compatibility**

- Old `audit-trail` API writes legacy or signed events via adapter.
- Old logs remain verifiable; new logs include both a legacy-visible line and a signed envelope if needed.
- No deletion of old logs.

**Exit tests**

- Full-chain rewrite without key fails.
- Missing/rotated key, truncated log, corrupt checkpoint, concurrent writer.
- CLI zero-entry failure.
- Verification independent of gateway process.

**Rollback:** switch writer to legacy unsigned mode in 1.11 only; in 2.0 strict, unsigned enforcement is disabled.

---

### Phase 3 — Gateway protocols and all-method inspection (weeks 6–10)

**Deliverables**

- Gateway stdio adapter (compat `mcp-firewall`).
- Streamable HTTP/SSE adapter + auth skeleton.
- Protocol inspector for all content-bearing methods.
- Size/depth/count limits; backpressure; session management.
- Upstream manager (local child, remote client).
- Posture report and direct-path detection.

**Compatibility**

- `mcp-firewall --server/--exec` keeps working via alias.
- Existing test fixture MCP server still passes.
- Additive flags; old policy adapter.
- Tools/list definitions and tools/call behavior compatible; new denials only in strict mode.

**Exit tests**

- Resource/prompt injection and secrets withheld.
- No upstream call on deny (fixture assertion).
- Huge line/pending exhaustion rejected.
- Batch/duplicate-ID handling.
- HTTP auth/origin/host tests.

**Rollback:** `mcp-firewall` legacy implementation remains available for one release; gateway disabled by flag.

---

### Phase 4 — Detection and data protection (weeks 8–14)

**Deliverables**

- Normalization/decoder pipeline.
- Tool poisoning, prompt injection, hidden Unicode, schema manipulation, memory/multi-agent detectors.
- Secret/PII/DLP with entropy/base64/split handling.
- Detector evidence schema; policy integration.
- Optional local AI classifier port (off by default).

**Compatibility**

- Existing `skill-scan`, `firewall`, `mcp-audit` outputs remain; new findings additive.
- Existing rule IDs preserved where possible; new IDs documented.
- `owasp-coverage` statuses become evidence-based; percentages may drop.

**Exit tests**

- Audit bypass corpus (F-08/F-09/F-10/F-07) fails closed in strict.
- Benign corpus FPR measured, thresholds met.
- AI timeout/benign cannot allow.
- Detection budgets.

**Rollback:** detector pipeline can be disabled per family; policy falls back to legacy deterministic checks (with a posture warning).

---

### Phase 5 — Supply chain and trusted extensions (weeks 10–16)

**Deliverables**

- Trust registry for MCP servers/skills/packages; signed manifests; hashes.
- Plugin system disabled by default; signed extension SDK + sandbox.
- Installer writes gateway/pinned config; direct-path detection.
- Package provenance/lockfile integrity/offline snapshot.

**Compatibility**

- `mcp-audit` output preserved; trust state added.
- Old plugin configs fail with a clear migration message, not silent execution.
- Existing `.mcp.json` remains readable; installer backs up.

**Exit tests**

- Unknown/unsigned server denied in strict.
- Malicious plugin cannot execute without explicit trust.
- Revoked key/hash fails.
- Installer output pinned and gateway-wrapped.

**Rollback:** trust registry can run in observe mode; plugin execution remains disabled.

---

### Phase 6 — Verified sandbox backends (weeks 12–22)

**Deliverables**

- Backend contract/manager/quotas.
- Windows AppContainer/Job/WFP backend; optional Windows VM.
- Linux rootless container + seccomp/cgroups; optional microVM/gVisor.
- macOS VM backend.
- Verification suite and evidence.
- Legacy `vm`/`process` marked unverified and disabled for untrusted code.

**Compatibility**

- `runInSandbox`/`runInProcess` signatures kept; new metadata added.
- `vibeguard sandbox` defaults to verified backend; explicit `--allow-unverified` for monitor mode.
- `sandbox_exec` MCP tool adds metadata; existing fields retained.

**Exit tests**

- F-02 escape corpus, host fs/net, quotas, cleanup.
- Windows/Linux/macOS runners.
- Backend failure → fail closed.

**Rollback:** select previous backend via config/feature flag; unsafe backend remains disabled in strict.

---

### Phase 7 — Runtime supervisor, monitoring, quarantine (weeks 16–24)

**Deliverables**

- Process/filesystem/network monitors per OS.
- Behavior engine v2; incident timeline; quarantine/terminate; kill switch.
- Signed control command; session revocation; credential revocation.

**Compatibility**

- `agent-monitor` remains a read-only view by default; new `--kill`/API requires auth.
- Behavior risk fields additive.

**Exit tests**

- Critical pattern stops subsequent calls; quarantine freezes process/revokes credentials; kill switch across sessions; false-positive behavior tests.

**Rollback:** monitor-only mode; kill switch disabled by policy.

---

### Phase 8 — API, SDK, dashboard, integrations (weeks 18–28)

**Deliverables**

- Local REST API + OpenAPI + auth.
- TypeScript SDK.
- Dashboard.
- GitHub Action; IDE extension/config helper.
- CLI new commands and compatibility aliases.

**Compatibility**

- Existing CLI/MCP unchanged.
- API `/v1` additive; SDK semver.
- Dashboard localhost-only.

**Exit tests**

- API contract/auth/error tests; SDK round-trip; offline Action; dashboard origin/CSRF; no secret exposure.

**Rollback:** API can be disabled; CLI/MCP continue.

---

### Phase 9 — Standards and benchmark (weeks 20–30)

**Deliverables**

- Correct OWASP Agentic/MCP/LLM 2026 catalogs + AISVS 1.01 C9/C10 mapping.
- Evidence-backed coverage statuses.
- Adversarial corpus, metrics, performance benchmarks, CI gates.
- Independent red-team plan.

**Compatibility**

- Existing `owasp-coverage` output keeps framework IDs; adds evidence/unknown.
- Headline percentages may decrease; documented.

**Exit tests**

- Corpus gates; no Critical/High bypass; performance budgets; AISVS evidence per claimed requirement.
- Published limitations.

---

## 4. Data migration

### 4.1 Policy

```
.vibeguard-mcp.json
  → read by legacy adapter
  → transformed to policy v2 (mode: monitor)
  → operator reviews/signs (mode: strict)
```

- Invalid legacy values are **rejected**, not normalized to allow.
- Legacy project policy files are not auto-trusted in strict mode; the user must sign a user-level policy.
- Policy v2 and legacy policy can coexist during 1.11; the gateway selects v2 if present and signed, else legacy with a warning.

### 4.2 Audit

```
legacy JSONL (hash chain, no signature)
  → `vg audit import --legacy` computes verification + records import event
  → new signed event stream starts at sequence 1 with `genesisHash` referencing the legacy root
  → old logs retained read-only
```

- Do not rewrite old logs.
- New signed events include `legacyRoot` so a verifier can link history.
- If the old chain is invalid, report fail; do not silently continue.

### 4.3 Pins and trust

```
.vibeguard/mcp-tool-pins.json
  → imported into trust registry as `pending` (never auto-trusted)
  → operator approves known hashes
  → unknown/changed tools denied in strict
```

### 4.4 Plugin configs

- Not executed. Migration message points to signed extension manifest and sandbox permissions.
- Plugin authors receive a migration guide and a test harness.

### 4.5 Sandbox

- Existing `vm`/`process` calls remain API-compatible but return `legacyMode:true` and `verified:false`.
- Default backend is selected by OS/policy; if unavailable, strict refuses.
- No migration of running sandboxes; termination is explicit.

---

## 5. Feature flags and rollout

| Flag | Values | Removal target |
|---|---|---|
| `VG_PLATFORM_MODE` | `legacy`, `shadow`, `strict` | 2.1 |
| `VG_GATEWAY` | `off`, `stdio`, `http`, `both` | 2.1 |
| `VG_POLICY_V2` | `off`, `shadow`, `enforce` | 2.1 |
| `VG_AUDIT_SIGN` | `off`, `shadow`, `enforce` | 2.0 |
| `VG_SANDBOX_BACKEND` | backend ID/`auto` | 2.1 |
| `VG_DETECTORS_AI` | `off`, `advisory` | keep (advisory always) |

Rules:

- `strict` cannot silently fall back to `legacy`.
- `shadow` records both decisions; differences are reviewed before enforcement.
- Flags are ignored in air-gapped release if policy says strict.
- Posture/dashboard shows active mode and degraded components.

---

## 6. Rollback and incident handling

| Failure | Rollback |
|---|---|
| Gateway blocks legitimate traffic | switch to `shadow` (policy still evaluates but does not block); preserve audit; open incident |
| Policy v2 regression | revert to previous signed `policyVersion`; never unsigned |
| Audit signing key issue | stop enforcement (fail closed) or use backup key; do not write unsigned in strict |
| Sandbox backend failure | no fallback to unverified; disable execution, report degraded |
| Detection false-positive spike | disable detector family via signed policy, keep deterministic baseline; open incident |
| API/dashboard regression | disable API; CLI/MCP remain |
| Bad plugin/trust approval | revoke in registry; quarantine; audit |
| Release regression | pin previous version; signed audit history remains |

**No rollback deletes audit events.** New events record the rollback/decision.

---

## 7. Compatibility matrix

| Surface | Compatibility commitment |
|---|---|
| CLI command names | kept; aliases for renames |
| CLI exit-code families | kept; security errors add codes but preserve documented families |
| MCP tool names/schemas | existing 93 kept; new tools additive |
| JSON/SARIF output | existing fields kept; new fields additive |
| Policy `.vibeguard-mcp.json` | readable via adapter; not auto-trusted in strict |
| Audit JSONL | readable/importable; old verifier retained |
| Sandbox functions | signatures kept; metadata added; unsafe mode explicit |
| npm package name | same package; 2.0 major |
| Node support | 18 legacy only; 20/22 platform (macOS/Linux/Windows) |
| Offline | scan/policy/audit/sandbox local; network features opt-in |

---

## 8. Implementation order and dependencies

```
Phase 0 (security blockers)
   ├─ F-01 plugin removal
   ├─ F-02 sandbox truth
   ├─ F-04/F-05/F-06 policy/audit/path
   └─ F-13 deps/release
        │
Phase 1 contracts/policy/identity ──► Phase 2 signed audit
        │                                   │
        └────────────► Phase 3 gateway ◄────┘
                             │
               ┌─────────────┼─────────────┐
               ▼             ▼             ▼
          Phase 4 detect  Phase 5 supply  Phase 6 sandbox
               │             │             │
               └─────────────┼─────────────┘
                             ▼
                    Phase 7 runtime
                             │
                    Phase 8 API/SDK/UX
                             │
                    Phase 9 standards/bench
```

Dependencies:

- Gateway needs policy/identity/audit/protocol.
- Detection needs contracts; data protection needs secret broker/keystore.
- Sandbox can start independently but integration needs policy/audit.
- Supply registry needs signatures/keystore/audit.
- API/dashboard need gateway/policy/audit/sandbox.
- Benchmark needs all enforcement paths; can start early with corpus/harness.

---

## 9. Acceptance criteria for the whole migration

1. Audit F-01…F-16 closed with regression tests; F-17…F-30 addressed or explicitly deferred with risk acceptance.
2. Existing CLI/MCP tests pass (or documented intentional changes with migration notes).
3. Strict gateway covers all MCP content methods; no upstream call on deny.
4. Policy v2 is signed/default-deny; legacy policy loads in monitor mode only.
5. Audit signatures/checkpoints verified independently; CLI zero-entry fails.
6. A verified sandbox backend runs the escape suite with no host access on Windows and Linux; macOS backend verified or explicitly unavailable.
7. Trust registry denies unknown/unsigned servers/skills in strict.
8. Runtime kill switch works across sessions.
9. API/SDK/dashboard contract tests pass; offline mode has no network.
10. Adversarial corpus meets stated thresholds; performance budgets documented.
11. AISVS/OWASP claims are evidence-backed and qualified.
12. Release has SBOM, checksums, signatures and matches the tested commit.

Until all P0/P1 gates pass, the product must use **monitor/legacy** language and must not claim “enforced” or “isolated.”
