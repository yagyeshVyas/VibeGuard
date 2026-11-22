# VibeGuard Target Architecture

**Design date:** 2026-11-21  
**Basis:** audit revision `2ce5b36` / v1.10.0 and findings F-01…F-30  
**Status:** design only; no implementation in this phase.

---

## 1. Purpose

Design VibeGuard as a modular, offline-first security enforcement platform for:

- AI agents and autonomous workflows
- MCP servers over stdio and Streamable HTTP
- agent skills, plugins and tool manifests
- generated code and build artifacts
- local developer machines, CI and air-gapped environments

The design must fix the audit’s two Critical findings (target-controlled plugin execution, sandbox escape) and the High enforcement/evidence gaps **without discarding the working v1.10 scanner, MCP server, CLI and integrations**.

The defining rule:

> **Deterministic enforcement is the authority. Detection can be heuristic; optional AI can assist; an LLM never makes the final security decision.**

---

## 2. Constraints and non-goals

### Hard constraints

1. Preserve existing public behavior: `vibeguard` CLI commands, 93 MCP tools, existing exit codes where documented, existing policy files where possible.
2. Modular components with acyclic dependencies; no monolithic rewrite.
3. Offline-first: scanning, policy enforcement, audit verification and sandbox orchestration work without network. Optional enrichers (CVE feeds, AI classifiers, external checkpoints) are explicitly opt-in.
4. No new dependency without a security and maintenance justification.
5. Fail safely: if authentication, policy, audit signing, approval or the selected sandbox is unavailable, strict mode denies. Degraded mode is explicit, never silently “allow”.
6. Never claim an isolation level that has not passed the backend’s verification suite.
7. Separate deterministic controls from AI-assisted analysis in code, configuration, UI and audit output.

### Non-goals for this design phase

- Implementing the modules.
- Replacing Semgrep/Gitleaks/Trivy rule depth.
- Running a hosted multi-tenant SaaS.
- Providing a general-purpose VPN or EDR.
- Guaranteeing host security against a local administrator who can replace VibeGuard itself.

### Preserved v1.10 behavior

| Existing capability | Preservation approach |
|---|---|
| `vibeguard scan/fix/verify/...` | Keep `bin/cli.js` as a compatibility facade; route security-sensitive parts through new modules; keep output formats |
| 93 MCP tools | Keep `src/mcp-server.js`; add gateway/identity/policy tools; existing tools continue |
| `vibeguard mcp-firewall` | Reimplemented as the **Gateway stdio adapter**, with the same flags where possible |
| `vibeguard mcp-audit` | Wrapped by policy/supply registry; existing output kept |
| `vibeguard skill-scan` | Routed through detector framework; existing CLI output kept |
| `vibeguard agent-risk` | Becomes risk engine v2; existing fields kept, new confidence/unknown fields added |
| `vibeguard sandbox` | Kept as a convenience command, but its isolation claim becomes backend-derived and verified |
| `.vibeguard-mcp.json` | Auto-migrated to policy schema v1 with a compatibility loader |
| `.vibeguard/audit/*.jsonl` | Kept readable; new signed event format added with a migration/verification adapter |
| `install` | Updated to install the gateway/pinned spec; existing clients remain supported |

---

## 3. Architecture at a glance

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              CONTROL PLANE                                   │
│                                                                              │
│  Policy & Identity Engine        Approval Broker        Trust Registry       │
│  - policy evaluation             - signed approvals     - MCP servers        │
│  - capability tokens             - quorum/expiry        - skills/plugins     │
│  - default deny                  - audit binding        - package hashes     │
│                                                                              │
│  Incidence/Quarantine Controller        Risk Engine        Key/Secret Broker │
│  - kill switch                          - evidence-based  - OS keystore      │
│  - session revocation                   - confidence      - short-lived creds│
└───────────────┬──────────────────────────────────────────────┬───────────────┘
                │ control/events                               │ policy/keys
┌───────────────▼──────────────────────────────────────────────▼───────────────┐
│                               DATA PLANE                                     │
│                                                                              │
│  ┌───────────────┐    ┌────────────────────┐    ┌────────────────────────┐   │
│  │ Agent/Client  │───►│  SECURITY GATEWAY   │───►│  MCP server             │   │
│  │ MCP client    │    │  - stdio adapter    │    │  stdio / Streamable HTTP│   │
│  │ (or SDK/API)  │◄───│  - HTTP/SSE adapter │◄───│  (upstream)             │   │
│  └───────────────┘    │  - protocol parser  │    └────────────────────────┘   │
│                       │  - content inspector│                                 │
│                       │  - schema/size guard│                                 │
│                       │  - decision point   │                                 │
│                       └─────────┬───────────┘                                 │
│                                 │ obligations                                 │
│              ┌──────────────────┼───────────────────┐                        │
│              ▼                  ▼                   ▼                        │
│     ┌────────────────┐  ┌────────────────┐  ┌────────────────┐               │
│     │ Detection      │  │ Data Protection│  │ Sandbox        │               │
│     │ (deterministic │  │ (DLP/secret)   │  │ (OS isolation) │               │
│     │  + optional AI)│  │                │  │                │               │
│     └────────────────┘  └────────────────┘  └────────────────┘               │
│                                 │                                             │
│                       ┌─────────▼───────────┐                                │
│                       │ Runtime Supervisor  │                                │
│                       │ process/fs/network  │                                │
│                       └─────────┬───────────┘                                │
│                                 │                                             │
│                       ┌─────────▼───────────┐      ┌────────────────────┐    │
│                       │ Signed Audit Log    │─────►│ External checkpoint│    │
│                       │ events + Merkle     │      │ (optional/offline) │    │
│                       └─────────────────────┘      └────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Deployment modes

| Mode | Where | Enforcement claim |
|---|---|---|
| **Local strict** | Developer machine; gateway owns MCP child processes; OS controls prevent direct upstream access | “All MCP traffic through this agent passes the gateway; direct-path detection is active.” Not “unbreakable by the OS user.” |
| **Remote gateway** | Team service; Streamable HTTP + OAuth/mTLS; upstream egress only from gateway network namespace | “Remote agents authenticate and are authorized; direct upstream access is blocked by network policy.” |
| **CI/scan-only** | Build runner; offline scanner/detectors; no long-lived gateway | “Scanning is isolated from target code; no agent runtime claim.” |
| **Air-gapped** | No network; bundled policy, trust registry, offline vulnerability data, local keys | “No network calls; enforcement uses local trust anchors.” |

Each mode exposes a machine-readable **posture report** (`protected`, `degraded`, `unprotected`) with evidence. The dashboard must show it; no UI should imply protection that the posture report does not support.

---

## 4. Components and responsibilities

### 4.1 Security Gateway

The central data-plane enforcer.

Responsibilities:

- Accept MCP messages from stdio and Streamable HTTP/SSE transports.
- Parse, validate and normalize JSON-RPC; enforce size/depth/count limits.
- Resolve the caller (identity), session and target server.
- Call the policy engine for every content-bearing operation.
- Apply obligations: redact, block, require approval, quarantine, inject credential reference, log at level.
- Inspect **all** server-to-client content, not only `tools/call`.
- Maintain a session/flow graph for multi-agent and memory attacks.
- Emit signed audit events.
- Never forward a denied operation to the upstream.
- Fail closed on parser/policy/identity/audit/sandbox errors in strict mode.

Interfaces:

- `TransportAdapter`: `stdio`, `streamable-http`, later `sse-legacy`.
- `ProtocolInspector`: method classification, schema validation, content extraction.
- `DecisionPoint`: policy + approval + obligations.
- `UpstreamManager`: spawn/connect to MCP server; enforce no direct egress.
- `GatewaySession`: identity, server, policy version, counters, trace IDs.

### 4.2 Policy and Identity Engine

Deterministic, side-effect-free core:

- Authenticate token/peer credential.
- Resolve principal, tenant, agent and delegated authority.
- Evaluate policy (deny-overrides, default deny in strict mode).
- Return a decision with reasons, obligations and a policy version.
- Validate policy itself (schema + semantic checks).
- Never call an LLM, network or filesystem during evaluation.

### 4.3 AI Threat Detection

- Deterministic normalization/decoding + detectors first.
- Optional local AI-assisted classifier runs **after** deterministic checks, as an advisory signal.
- Final decision remains policy deterministic: AI can raise `approval_required`/`deny` (if configured) but can never turn a deny into allow, and cannot override fail-closed conditions.
- All detector outputs have stable IDs, evidence spans, confidence and provenance.

### 4.4 Data Protection

- Secret/PII/classification engine.
- Credential broker and OS keystore abstraction.
- DLP at arguments, results, resources, prompts, memory writes and outbound requests.
- Fingerprints (HMAC) for secret matching; raw secrets never logged.
- Short-lived credentials issued to a sandbox/server under a capability, not placed in model context.

### 4.5 Runtime Protection

- Supervisor for agents/servers/sandboxes.
- Monitors: process creation/exit, filesystem writes/reads of sensitive paths, network connects/DNS, syscalls where available.
- Behavior engine consumes signed events; produces risk/incident signals.
- Actions: block, quarantine (freeze/isolate/revoke credentials), terminate, snapshot.
- Kill switch: signed local command and optional remote control channel.

### 4.6 Secure Execution

- Backend contract for Windows, Linux, macOS.
- Isolation classes and verification evidence.
- No host access by default; explicit mounts and network policy only.
- Resource quotas enforced by OS primitives.
- The gateway uses the execution backend for `sandbox_exec` and for untrusted plugins/skills.

### 4.7 Supply-Chain Security

- Trust registry for MCP servers, tools, skills, plugins and packages.
- Cryptographic verification: Ed25519 signatures, SHA-256 content hashes, package provenance, lockfile integrity.
- Policy: unknown = deny/quarantine in strict mode; trust-on-first-use requires explicit approval.
- No auto-`require()` of target code.

### 4.8 Audit and Incident Response

- Canonical, signed event schema.
- Hash chain + Merkle checkpoints + optional external anchor.
- Incident timeline, correlation, risk, export.
- Verification tool independent of the agent runtime.
- Redaction/retention/privacy controls.

### 4.9 Developer Experience

- CLI (existing + new platform commands).
- Local dashboard (localhost-only, authenticated).
- REST API + TypeScript SDK.
- MCP integration/wrapper generator.
- GitHub Action, IDE config helpers, approval UI.
- Offline examples and test fixtures.

### 4.10 Benchmark and Assurance

- Reproducible attack corpus.
- Benign corpus and false-positive measurement.
- Performance benchmarks.
- CI regression gates.
- Independent red-team plan.

---

## 5. Existing modules → target modules

This is an incremental extraction, not a rewrite.

| Current | Target role | Compatibility path |
|---|---|---|
| `bin/cli.js` | CLI adapter | Keep file; delegate to `src/platform/cli/*`; preserve commands/flags |
| `src/mcp-server.js` | Legacy MCP tool host | Keep; add platform tools; route security decisions through gateway/policy |
| `src/mcp-firewall.js` | Gateway stdio adapter | Keep exported `createEngine/startProxy` as compatibility facade; internal implementation moves to gateway modules |
| `src/agent-policy.js` | Policy engine v0 | Becomes `platform/policy`; `.vibeguard-mcp.json` loader compatibility |
| `src/audit-trail.js` | Audit v0 | Becomes `platform/audit` signed events; JSONL import/verify adapter |
| `src/sandbox.js` | Sandbox facade | Becomes `platform/sandbox` backends; legacy mode explicitly `legacy-vm`/`process-unverified` |
| `src/skill-scan.js` | Skill detector | Wrapped by detection framework; existing CLI output kept |
| `src/agent-monitor.js` | Monitor/report | Becomes runtime/incident view; existing `--watch` kept |
| `src/agent-risk.js` | Risk engine | v2 with confidence/unknown; existing JSON fields retained |
| `src/owasp-agentic.js` | Standards mapper | Corrected catalogs + AISVS; versioned reports |
| `src/plugin.js` | Scanner plugin loader | **Removed from default scan path**; trusted plugin SDK with signatures/sandbox |
| `src/install.js` | Installer | Writes gateway/pinned config; keeps client support |
| `src/protocol` (new) | JSON-RPC/MCP protocol | No current equivalent; gateway only |
| `src/identity` (new) | Identity/auth | No current equivalent |
| `src/approval` (new) | Approval broker | No current equivalent |
| `src/runtime` (new) | Supervisor/monitors | Behavior engine partial |

### Dependency rule

```
contracts  ←  policy / identity / detect / data / audit / transport
                    ↑
             gateway / runtime / sandbox / supply
                    ↑
             cli / api / dashboard / sdk / integrations
```

- No lower layer imports an upper layer.
- `contracts` has zero runtime dependencies.
- Detectors do not import the gateway; the gateway imports detectors.
- Policy has no I/O and no network; it receives a normalized `PolicyRequest`.
- Optional AI classifier is an adapter behind a `Classifier` port, imported only by the detection orchestrator.

---

## 6. Data flows

### 6.1 Tool call (allowed)

```
client → gateway (stdio/HTTP)
  → parse + schema/size validation
  → authenticate token/peer credential
  → resolve identity/session/target
  → detect content (deterministic; optional AI advisory)
  → policy decision (allow)
  → apply obligations (credential ref, redaction, logging)
  → forward to upstream
  → inspect upstream result (content, schema, DLP)
  → sign + append audit event
  → return sanitized result
```

### 6.2 Tool call (denied)

```
client → gateway → ... → policy decision = deny
  → no upstream call
  → signed audit event (deny + reason + policy version)
  → return JSON-RPC error/tool result with stable code
```

### 6.3 Approval-required

```
... policy = approval_required
  → create approval request (canonical action digest, principal, nonce, expiry)
  → notify local UI/CLI/webhook
  → client receives "approval pending" (or blocks)
  → human approves with signed approval token
  → approval broker verifies nonce/digest/identity/expiry
  → policy re-evaluates with approval evidence
  → forward or deny; both audited
```

### 6.4 Sandbox execution

```
caller → gateway/policy → sandbox manager
  → choose backend by policy and OS
  → verify backend (self-test/attestation) or fail closed
  → create isolated context (no host creds, quotas)
  → stream stdout/stderr/result
  → runtime monitor (process/fs/net)
  → destroy context + snapshot evidence
  → signed audit event
```

### 6.5 Supply chain trust

```
install/discover server/skill/package
  → compute SHA-256; fetch signature metadata (offline registry/cache)
  → verify publisher key and provenance
  → check lockfile/attestation/SBOM
  → trust state unknown/pending/trusted/revoked
  → strict mode: unknown = deny; approval can move to trusted
  → record trust decision + hash in audit
```

### 6.6 Audit and checkpointing

```
event → canonicalize (JCS) → hash chain → Ed25519 sign → append
  → every N events/interval: Merkle root checkpoint → sign
  → optional external anchor (file, S3 object, transparency log, SIEM)
  → verifier: sequence, chain, signature, checkpoint, external root
```

---

## 7. Trust boundaries

| Boundary | Trusted | Untrusted | Control |
|---|---|---|---|
| Model context | system policy, approved instructions | user text, web, docs, tool descriptions/results/resources | provenance labels + detectors; policy cannot allow unknown instruction sources to become policy |
| Client ↔ gateway | authenticated principal | network/stdio input | VGAT/JWS token/mTLS/peer credentials; schema/size validation |
| Gateway ↔ upstream | gateway enforcement | MCP server code/results | content inspection, schema validation, trust registry, egress policy |
| Policy ↔ agent | operator-signed policy | agent-writable repo | signed user-level policy; strict mode; project policy opt-in |
| Sandbox ↔ host | OS isolation backend | untrusted code | OS sandbox, no creds, network deny, verified evidence |
| Scanner ↔ target repo | operator | target `.vibeguardrc`, plugins, node_modules | no target code execution; isolated plugins only with explicit trust |
| Audit ↔ attacker | signing key/OS keystore | log writer with file access | Ed25519 chain + checkpoint; append-only |
| Release ↔ registry | signing key/account | npm/GitHub artifact | signatures, SBOM, checksums, provenance, pinned actions |

### Explicit assumptions

- The OS user running the gateway is trusted not to replace its binary (a local admin can defeat any user-mode tool).
- The signing key is protected by OS keystore/DPAPI/Keychain/TPM; if compromised, signatures can be forged.
- The upstream MCP server may be malicious.
- The network may be hostile; TLS is required for remote transport.
- The local dashboard is not exposed to the network by default.
- Optional AI models are untrusted advisors; their output is data, never authority.
- Offline mode uses a bundled trust/update snapshot; its freshness is an explicit property.

---

## 8. Failure model (fail safe)

| Missing/failed component | Strict mode | Monitor mode | Audit |
|---|---|---|---|
| Identity/auth unavailable | deny | deny high-risk, warn rest | `identity_unavailable` |
| Policy unavailable/invalid | deny all | warn/deny high-risk | `policy_unavailable` |
| Audit signing key unavailable | deny (no unsigned enforcement) | allow with `unsigned` posture | `audit_degraded` |
| Approval broker unavailable | approval_required → deny | deny high-risk | `approval_unavailable` |
| Sandbox backend unavailable | deny untrusted execution | deny execution, not scan | `sandbox_unavailable` |
| Detector engine error | deny if configured strict detectors | warn + allow only if policy says | `detector_error` |
| AI classifier timeout/error | ignore AI; deterministic verdict | same | `ai_advisory_unavailable` |
| External checkpoint unavailable | continue local signed log; mark degraded | same | `checkpoint_unavailable` |
| Trust registry unavailable | deny unknown in strict | warn | `trust_unavailable` |

No silent fail-open. The posture report must show the active mode and all degraded components.

---

## 9. Enforcement posture and “no bypass”

The requirement “no unmonitored direct bypass paths” is a **deployment property**, not just a code feature. The design provides:

1. **Gateway-owned child**: local strict mode spawns the MCP server as a child of the gateway; the client cannot reach the child’s stdio directly.
2. **Remote network policy**: the upstream only accepts connections from the gateway identity/network namespace; clients cannot route around it.
3. **Direct-path detection**: the gateway inventories MCP configs and process/network sockets; in strict mode a detected direct path is an incident and the posture is `unprotected`.
4. **OS controls**: firewalls/namespaces for remote; Windows AppContainer/network capability for local; no host network for sandboxes.
5. **Fail posture**: if the gateway cannot prove enforcement, it reports `degraded`/`unprotected` and refuses to claim protection. It cannot magically revoke a user’s direct server connection, so the product must expose evidence rather than a false guarantee.

---

## 10. Architecture decisions

| ID | Decision | Rationale | Consequence |
|---|---|---|---|
| AD-01 | Gateway + deterministic policy core | Single enforcement point, testable | Requires proxy deployment; compatibility adapter |
| AD-02 | Ed25519 + SHA-256 + canonical JSON | No dependency; Node crypto | Key management required |
| AD-03 | Identity via signed capability token (JWS EdDSA) | Offline issuance; standard format | Token issuance/rotation UI |
| AD-04 | Deny-overrides, default deny in strict | Predictable, fail closed | Migration friction |
| AD-05 | All content-bearing MCP methods inspected | Turns F-03 into a design invariant | Protocol/schema work |
| AD-06 | OS-level sandbox backends; no vm claim | Fixes F-02 honestly | Platform-specific work |
| AD-07 | AI advisory only, never authority | Trust, determinism, offline | AI is optional; false positives remain policy-controlled |
| AD-08 | Signed audit + external checkpoint | Authentic evidence | Key/checkpoint infrastructure |
| AD-09 | Trust registry + signed manifests | Supply-chain control | Registry/approval UX |
| AD-10 | In-repo modular extraction, not a monorepo rewrite | Preserve working functionality | Strict dependency/lint rules |
| AD-11 | Compatibility facades for v1.10 APIs | Users/tests keep working | Dual paths until deprecation |
| AD-12 | Posture report as first-class output | Never claim unverified protection | UI/CI changes |

---

## 11. Open questions to resolve before implementation

1. Identity issuance UX for solo developers: local auto-issued agent identity vs explicit `vg identity init`.
2. Windows OS-isolation backend choice: AppContainer + Job Object + WFP (available now) vs Windows Sandbox/VM (stronger, heavier).
3. Linux default: rootless container + seccomp/cgroups vs optional microVM; what is “verified” for each.
4. Policy condition language: JSON AST subset vs CEL; security review needed before accepting expressions.
5. External checkpoint anchor for offline users: signed file, OS credential vault, second disk, or optional remote.
6. Whether to keep the scanner plugin system at all, or replace it with a signed extension SDK executed in a sandbox.
7. Protocol version support matrix for Streamable HTTP/SSE and MCP 2025-11-25/2026 revisions.
8. How long to maintain legacy v1.10 policy/audit formats.

These are decisions for implementation phase, not blockers to this architecture.

---

## 12. Implementation order (summary)

1. **Contracts + policy/identity core** (pure, no I/O) and compatibility adapters.
2. **Signed audit/event schema + verifier**, replacing F-04.
3. **Gateway protocol core** with full method/content coverage, no AI.
4. **Deterministic detection/data-protection pipeline**; optional AI behind a port.
5. **Supply-chain trust registry and plugin removal/sandboxing**.
6. **OS sandbox backends** with verification suites; remove unsafe claims.
7. **Runtime supervisor/monitors and kill switch**.
8. **REST/SDK/dashboard/CI/IDE integration**.
9. **Adversarial benchmark, migration, deprecations**.

Detailed boundaries and schemas are in `09`–`15`.
