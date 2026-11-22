# Module Boundaries and Contracts

**Design date:** 2026-11-21  
**Basis:** `08-target-architecture.md`, audit findings F-01…F-30  
**Status:** design only.

---

## 1. Boundary principles

1. **One reason to change per module.** Policy evaluation must not know HTTP; protocol parsing must not know DLP; audit must not know sandbox.
2. **Ports and adapters.** Core logic depends on interfaces, not concrete transports, OS backends or optional AI.
3. **Pure core where possible.** Policy, canonicalization, decision precedence and detector scoring are pure functions. I/O lives at the edges.
4. **No cycles.** A module may import only from layers below it. Enforced by a dependency test, not convention.
5. **Compatibility lives at the facade.** Legacy modules may import new modules; new modules must never import legacy CLI.
6. **Fail closed at the boundary.** A missing adapter returns a typed error; the caller decides deny/posture, not a silent fallback.
7. **No target-controlled code in the scanner trust domain.** Plugin/extension execution is an explicit, sandboxed, trusted-only path.
8. **Stable serialization.** Events, decisions and policies have versioned canonical schemas.

---

## 2. Proposed layout

```
src/
  platform/
    contracts/
      types.js            # shared JSDoc typedefs / constants
      errors.js           # typed errors + stable codes
      ids.js              # UUIDv7-ish / ULID-compatible IDs (no dependency)
      canonical.js        # RFC 8785-compatible canonical JSON (subset)
      clock.js            # injectable clock (deterministic tests)
    policy/
      engine.js
      loader.js
      validator.js
      compiler.js
      compatibility.js    # .vibeguard-mcp.json → policy v1
    identity/
      principals.js
      tokens.js           # JWS EdDSA capability tokens
      authenticators/
        local-peer.js
        bearer.js
        mtls.js
        oauth.js          # optional, only for remote mode
      store.js
    approval/
      broker.js
      tokens.js
      canonical-action.js
    protocol/
      jsonrpc.js
      content.js          # method classification/content extraction
      schema.js           # JSON Schema validation + limits
      errors.js
    gateway/
      gateway.js
      session.js
      stdio-adapter.js
      streamable-http-adapter.js
      sse-adapter.js      # legacy/opt-in
      upstream.js
      obligations.js
      posture.js
    detect/
      pipeline.js
      normalize.js
      decode.js
      detectors/
        prompt-injection.js
        tool-poisoning.js
        hidden-unicode.js
        schema-manipulation.js
        memory-poisoning.js
        multi-agent.js
        secret.js
        pii.js
        skill.js
      classifier-port.js  # optional AI adapter interface
      evidence.js
    data/
      labels.js
      classifier.js
      dlp.js
      secret-broker.js
      credential-refs.js
      redact.js
    audit/
      event.js
      canonical-event.js
      signer.js
      chain.js
      checkpoint.js
      verifier.js
      store.js
      legacy-import.js
    sandbox/
      manager.js
      contract.js
      quotas.js
      backends/
        windows-appcontainer.js
        linux-container.js
        linux-microvm.js
        macos-vm.js
        legacy-vm.js      # explicitly unverified, disabled for untrusted code by default
      verification.js
    runtime/
      supervisor.js
      monitors/
        process.js
        filesystem.js
        network.js
      behavior.js
      quarantine.js
      kill-switch.js
    supply/
      registry.js
      manifests.js
      signatures.js
      provenance.js
      package-audit.js
    risk/
      engine.js
      calibration.js
    storage/
      files.js            # atomic writes, permissions
      keystore.js         # OS keystore abstraction
      locks.js
    api/
      server.js
      auth.js
      routes/
      openapi.js
    sdk/
      index.js            # public typed facade
    dashboard/
      # static UI served by api; no framework dependency required
    integrations/
      cli/
      mcp/
      github-action/
      ide/
```

Existing `src/*.js` remains at its current path as a compatibility facade during migration.

---

## 3. Dependency graph

```
                     ┌─────────────────────────────┐
                     │        contracts            │
                     └─────────────┬───────────────┘
        ┌───────────────┬───────────┼────────────┬───────────────┐
        ▼               ▼           ▼            ▼               ▼
     policy         identity     detect        data           audit
        │               │           │            │               │
        └───────────────┴─────┬─────┴────────────┴───────────────┘
                              ▼
                    ┌───────────────────┐
                    │      gateway      │
                    └─────┬───────┬─────┘
                          │       │
         ┌────────────────┘       └─────────────────┐
         ▼                                          ▼
    approval                                  runtime/sandbox
         │                                          │
         └───────────────┬──────────────────────────┘
                         ▼
                 supply / risk / storage
                         │
                         ▼
                 api / sdk / dashboard / integrations / cli
```

Allowed imports:

| Module | May import |
|---|---|
| `contracts` | Node built-ins only (none for pure data) |
| `policy` | `contracts` |
| `identity` | `contracts`, `storage/keystore` |
| `detect` | `contracts` (optional `classifier-port` only) |
| `data` | `contracts`, `storage/keystore` |
| `audit` | `contracts`, `storage`, `signer` |
| `gateway` | `contracts`, `policy`, `identity`, `protocol`, `detect`, `data`, `audit`, `approval`, `runtime`, `sandbox` |
| `runtime` | `contracts`, `audit` (via port), `storage` |
| `sandbox` | `contracts`, `storage` |
| `supply` | `contracts`, `storage`, `audit` (via port) |
| `risk` | `contracts`, `audit` (read), `supply` (read) |
| `api` | `gateway` (via service interface), `audit`, `policy`, `identity`, `approval`, `sandbox`, `risk` |
| `cli`/`integrations` | public facades; never imported by core |
| `sdk` | `contracts` + API client types |

Forbidden:

- `policy → gateway`, `detect → gateway`, `audit → gateway`, `sandbox → gateway`.
- `core → cli`, `core → api`, `core → dashboard`.
- Any required import of an optional AI model or network client.
- Any scanner core importing `plugin.js` or target-controlled code.

Enforcement:

- A custom import-boundary test scans `require()`/`import` statements and fails on forbidden edges.
- Circular dependency detection via a small DFS test.
- Core modules must load with no optional dependency installed (except explicit adapters).

---

## 4. Core contracts

These are design-level TypeScript-like signatures; the implementation can use JSDoc + plain JS.

### 4.1 Policy

```ts
interface PolicyRequest {
  principal: Principal;
  session: SessionContext;
  target: Target;               // server/tool/resource/prompt
  capability: Capability;
  action: ActionDescriptor;     // canonical args digest, paths, hosts, data labels
  labels: DataLabelSet;
  evidence: EvidenceSet;        // detector/trust/approval facts
  context: { now: string; policyVersion?: string; mode: 'strict'|'monitor'|'legacy' };
}

interface PolicyDecision {
  decision: 'allow' | 'deny' | 'approval_required' | 'quarantine';
  reasonCode: string;           // stable VG_* code
  policyId: string;
  policyVersion: string;
  matchedRules: RuleRef[];
  obligations: Obligation[];
  approval?: ApprovalRequirement;
  ttlMs?: number;
  explanation: string;          // human-readable, no secrets
}
```

Rules:

- `deny` and `quarantine` override `approval_required`, which overrides `allow`.
- If no rule matches, `defaults.decision` applies; strict mode requires `deny`.
- Any evaluator error returns `deny` with `VG_POLICY_EVALUATION_ERROR`.
- The engine never reads files, env, network or clocks directly.

### 4.2 Identity

```ts
interface Principal {
  principalId: string;          // 'agent:<tenant>/<name>'
  kind: 'human' | 'agent' | 'service' | 'mcp-server';
  tenantId: string;
  displayName: string;
  status: 'active' | 'suspended' | 'revoked';
  capabilities: Capability[];
  publicKeys?: PublicKeyRef[];
  attributes?: Record<string, string | number | boolean>;
}

interface Authenticator {
  authenticate(credential: Credential, ctx: AuthContext): Promise<AuthResult>;
}

interface TokenIssuer {
  issue(request: TokenRequest): Promise<SignedToken>;  // short TTL, audience-bound
  verify(token: string, ctx: AuthContext): Promise<AuthResult>;
}
```

- Local stdio: OS peer credentials + registered agent manifest.
- HTTP: mTLS and/or OAuth 2.1 bearer token; VGAT (JWS EdDSA) optional for offline/local.
- Every principal has an immutable ID; display names are not authorization.

### 4.3 Detection

```ts
interface Detector {
  id: string;
  version: string;
  deterministic: boolean;
  detect(input: DetectionInput, ctx: DetectionContext): Promise<DetectorResult>;
}

interface DetectorResult {
  findings: Finding[];           // id, severity, confidence, spans, evidence, labels
  labels: DataLabelSet;
  errors: DetectorError[];
}

interface ClassifierPort {       // optional AI
  classify(input: DetectionInput, ctx: DetectionContext): Promise<AdvisoryResult>;
}
```

- Detector results cannot change policy to allow.
- AI adapter failures/timeouts produce no finding, `ai_unavailable` evidence, and never block deterministic processing.
- Detection is content-type aware and bounded by size/depth/time budgets.

### 4.4 Data protection

```ts
interface DataClassifier {
  classify(content: string | Buffer, ctx: ContentContext): Promise<DataLabelSet>;
}

interface SecretBroker {
  resolve(ref: CredentialRef, principal: Principal, purpose: string): Promise<ShortLivedCredential>;
  fingerprint(secret: string): string;   // HMAC, never raw
}

interface DlpEngine {
  inspect(content: string | Buffer, labels: DataLabelSet, destination: Destination): DlpVerdict;
}
```

### 4.5 Audit

```ts
interface AuditWriter {
  append(event: UnsignedAuditEvent): Promise<SignedAuditEvent>;
  checkpoint(): Promise<SignedCheckpoint>;
}

interface AuditVerifier {
  verify(logPath: string, trust: VerificationTrust): Promise<VerificationReport>;
}
```

- Signing key unavailable + strict mode = deny operations.
- Append is serialized by a single writer; the writer is a separate process/service or a locked store.
- Audit event schema is versioned (`schemaVersion: '1.0'`).

### 4.6 Sandbox

```ts
interface SandboxBackend {
  id: string;                   // 'windows-appcontainer', 'linux-container', ...
  isolationClass: 'none'|'process'|'os'|'container'|'microvm'|'hardware-vm';
  verify(): Promise<BackendVerification>;
  prepare(spec: SandboxSpec): Promise<SandboxHandle>;
  run(handle: SandboxHandle, code: string, opts: RunOptions): Promise<RunResult>;
  stream?(handle: SandboxHandle, opts: RunOptions): AsyncIterable<OutputChunk>;
  terminate(handle: SandboxHandle): Promise<void>;
  snapshot?(handle: SandboxHandle): Promise<ForensicSnapshot>;
}
```

- `verify()` must pass before the gateway reports a verified isolation class.
- `legacy-vm` must not be selectable for untrusted code in strict mode.
- `isolationClass: 'none'` is always accompanied by an explicit posture warning.

### 4.7 Runtime / supply / approval

```ts
interface RuntimeMonitor {
  start(ctx: MonitorContext): Promise<void>;
  stop(): Promise<void>;
  events(): AsyncIterable<RuntimeEvent>;
}

interface TrustRegistry {
  resolve(ref: ArtifactRef): Promise<TrustState>;   // unknown|pending|trusted|revoked
  approve(ref: ArtifactRef, approval: ApprovalToken): Promise<TrustState>;
  verify(ref: ArtifactRef): Promise<VerificationResult>;
}

interface ApprovalBroker {
  request(req: ApprovalRequest): Promise<ApprovalTicket>;
  decide(ticketId: string, decision: ApprovalDecision, token: ApprovalToken): Promise<ApprovalResult>;
}
```

### 4.8 Transport / gateway

```ts
interface TransportAdapter {
  readonly kind: 'stdio'|'streamable-http'|'sse';
  start(opts: TransportOptions): Promise<void>;
  send(message: JsonRpcMessage): Promise<void>;
  onMessage(handler: (message: JsonRpcMessage) => Promise<void>): void;
  close(): Promise<void>;
}

interface GatewayService {
  handle(message: JsonRpcMessage, ctx: GatewayContext): Promise<GatewayResult>;
  posture(): PostureReport;
  shutdown(): Promise<void>;
}
```

---

## 5. Data ownership

| Data | Owner | Access |
|---|---|---|
| Principal, token keys | Identity store | Identity only; audit gets IDs/claims |
| Policy + version | Policy store | Policy engine read; API/dashboard read; audit stores policy hash/version |
| Sessions, flow graph | Gateway | Gateway only; audit gets IDs |
| Detector results | Detection orchestrator | Gateway/policy read; audit stores summary/hashes/evidence IDs |
| Data labels | Data protection | Gateway/policy read; never raw secret values |
| Secret material | Secret broker/OS keystore | Broker only; audit stores HMAC fingerprints |
| Trust state | Trust registry | Gateway/supply/CLI read; audit records transitions |
| Audit events | Audit store | Append by writer; read by verifier/API |
| Runtime incidents | Runtime supervisor | Incident controller/audit |
| Risk score | Risk engine | API/dashboard; derived, not authority |
| Approval tickets | Approval broker | Broker, audit (IDs/digests) |
| Dashboard state | API view | Read-only projections; no raw secrets |

---

## 6. Compatibility facades

| Legacy module | Facade behavior |
|---|---|
| `src/mcp-firewall.js` | Exports `createEngine`, `startProxy`, `createEngine` shape; internally delegates to gateway v2. Legacy policy semantics mapped; deprecation warning in monitor mode. |
| `src/agent-policy.js` | Exports `evaluateToolCall`; wraps policy engine v2 with legacy defaults; `DEFAULT_POLICY` retained. |
| `src/audit-trail.js` | Exports old logger API; writes legacy JSONL or signed events via adapter; `verifyEntries` retained for old logs. |
| `src/sandbox.js` | Exports `runInSandbox`/`runInProcess`; returns new `isolationClass`/`verification`; legacy `vm` is marked `legacy-vm` and disabled for untrusted code by default. |
| `src/skill-scan.js` | Exports old `scanSkills`; uses new detector pipeline; output compatible. |
| `src/agent-risk.js` | Exports old `computeAgentRisk`; new fields additive. |
| `src/owasp-agentic.js` | Exports old catalogs/functions; corrected catalogs + deprecation metadata. |
| `src/plugin.js` | Deprecated; default scan no longer loads plugins; explicit trusted extension path only. |
| `src/mcp-server.js` | Keeps 93 tools; new platform tools registered; existing handlers delegate unchanged where safe. |

Public API stability:

- Keep CLI command names and documented flags; new flags additive.
- Keep MCP tool names/schemas; add new tools rather than change existing shapes. If a security fix requires a behavior change, gate it behind policy mode and document.
- Keep JSON output fields; add fields, do not remove in v1.x.
- Version the platform API independently (`/v1`).

---

## 7. Error model

Every module returns typed errors with stable codes. No string matching for control flow.

| Code | Meaning | Default handling |
|---|---|---|
| `VG_AUTH_REQUIRED` | no credential | 401/deny |
| `VG_AUTH_INVALID` | bad/expired/revoked token | 401/deny |
| `VG_AUTHORIZATION_DENIED` | policy deny | 403/deny |
| `VG_APPROVAL_REQUIRED` | approval needed | 202/pending |
| `VG_APPROVAL_INVALID` | bad nonce/digest/expiry | deny |
| `VG_POLICY_INVALID` | policy schema/semantic error | fail closed |
| `VG_POLICY_UNAVAILABLE` | policy store/key unavailable | deny |
| `VG_AUDIT_UNAVAILABLE` | signing/append failure | deny strict |
| `VG_DETECTOR_ERROR` | detector exception | policy decides; strict fail |
| `VG_SCHEMA_INVALID` | malformed message/schema | deny/close |
| `VG_LIMIT_EXCEEDED` | size/count/time quota | deny |
| `VG_SANDBOX_UNAVAILABLE` | no verified backend | deny execution |
| `VG_TRUST_UNKNOWN` | artifact not trusted | deny strict |
| `VG_POSTURE_DEGRADED` | missing enforcement component | deny strict |
| `VG_INTERNAL` | unexpected | deny strict; incident |

Error responses must not include secrets, raw policy keys or stack traces. They include `traceId`, `reasonCode`, `retryable`, and a safe explanation.

---

## 8. Testing boundaries

Each module must have:

- contract tests (interface behavior, errors, fail-closed);
- property tests for policy precedence, canonicalization, hash chain, path normalization;
- golden tests for event/policy API schemas;
- integration tests for gateway transports and sandbox backends;
- compatibility tests for legacy facades;
- import-boundary and cycle tests.

No module may claim support for an OS backend without its backend verification suite passing on that OS.

---

## 9. Boundary risks

| Risk | Mitigation |
|---|---|
| Facades become a second implementation | Facades delegate; no security logic in facades; code review rule |
| Policy module accidentally performs I/O | Pure-function tests + lint rule; no `fs`/`http` imports |
| Optional AI leaks into core | `classifier-port` only; dependency test forbids model/network imports in core |
| Sandbox backend claims exceed verification | Posture report + `verify()` gate |
| Gateway becomes monolith | Protocol/transport/detection/policy ports; each adapter independently testable |
| Compatibility keeps insecure defaults | strict mode opt-in migration; legacy mode marked and warned |
| Circular dependencies | automated graph test in CI |
