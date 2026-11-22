# API and Integration Design

**Design date:** 2026-11-21  
**Basis:** `08`–`10`, audit findings F-12/F-16/F-23/F-29  
**Status:** design only.

---

## 1. Integration surfaces

VibeGuard exposes five integration surfaces, each with the same policy/identity/audit core:

| Surface | Consumer | Transport | Auth |
|---|---|---|---|
| CLI | developers, CI | local process | OS user + local policy |
| MCP Gateway | AI clients (Claude Code, Cursor, Codex, etc.) | stdio, Streamable HTTP/SSE | peer credentials, VGAT/JWS, OAuth/mTLS for remote |
| Local REST API | dashboard, IDE, scripts | HTTP on loopback | local bearer token + CSRF/origin checks |
| SDK | TypeScript/JavaScript integrations | REST/CLI wrapper | scoped token |
| GitHub Action | CI | process/API | GitHub OIDC or local token |
| IDE extension | editor | local API + MCP config | local token; approval UI |

No surface may bypass the gateway for an operation that policy classifies as protected. The API returns a posture warning if a direct path is detected.

---

## 2. CLI compatibility and extensions

### 2.1 Existing commands preserved

All current commands continue to exist with the same names and documented exit-code families:

```
scan, fix, verify, pre-deploy, dashboard, mcp, auto, rules, explain, doctor,
compliance, cve, slopsquat, secure-prompt, trace, repl, auth-coverage,
attack-surface, bundle-scan, diff, deep-scan, html, inject-rules, bench,
risk-score, why, preset, guard, install-shell-hook, privacy-audit, net-audit,
ai-guard, firewall, exfil-check, dep-firewall, sandbox, self-check, env-lock,
vault, audit-trail, redact, detect-pii, sbom, reachability, container-scan,
license, mcp-audit, mcp-firewall, skill-scan, agent-risk, owasp-coverage,
agent-monitor
```

Behavior that changes for security reasons is gated and documented:

- `sandbox` selects a verified backend; unsafe `vm` is refused for untrusted code.
- `scan` no longer executes target plugins; trusted extensions require a flag.
- `agent-risk`/`owasp-coverage` report confidence/unknown; headline percentages may decrease.
- `audit-trail verify` loads the actual log and fails on zero entries.
- `mcp-firewall` remains as a compatibility alias for `gateway stdio`.

### 2.2 New commands

| Command | Purpose |
|---|---|
| `vibeguard gateway stdio --server <name>` | start a strict stdio gateway |
| `vibeguard gateway http --listen 127.0.0.1:8787` | Streamable HTTP gateway |
| `vibeguard policy init --strict` | create a signed strict policy template |
| `vibeguard policy validate <file>` | schema + semantic validation |
| `vibeguard policy sign <file> --key <id>` | sign with local key |
| `vibeguard identity init` | local agent/human identity |
| `vibeguard identity issue --agent <id> --ttl 15m` | short-lived VGAT |
| `vibeguard approve <ticket>` | interactive approval |
| `vibeguard audit verify <log>` | verify chain/signatures/checkpoints |
| `vibeguard audit anchor <log>` | write external checkpoint |
| `vibeguard trust list/approve/revoke` | supply-chain registry |
| `vibeguard sandbox backends` | list verified/unverified isolation backends |
| `vibeguard posture` | machine-readable enforcement posture |
| `vibeguard incident kill --all` | signed emergency stop |
| `vibeguard api --listen 127.0.0.1:8787` | local REST API |
| `vibeguard bench security` | attack corpus + precision/recall |

Backward-compatible aliases exist for renamed commands; deprecations are announced for at least one minor release.

---

## 3. MCP Gateway protocol contract

### 3.1 Transports

| Transport | Endpoint | Auth | Notes |
|---|---|---|---|
| stdio | child process stdin/stdout | OS peer credentials + registered agent manifest | default for local clients |
| Streamable HTTP | `POST/GET /mcp` | OAuth 2.1 bearer or mTLS | session header, SSE/streamable responses |
| Legacy SSE | `GET /sse` + `POST /messages` | same | opt-in compatibility; not the default |

Gateway JSON-RPC rules:

- Newline-delimited JSON-RPC for stdio; Content-Type `application/json` for HTTP.
- Batch arrays are split and each item validated; batch size bounded.
- Duplicate IDs rejected within a session.
- Notifications are accepted but never executed as privileged tool calls without policy if the method implies an action.
- Maximum message size/depth/count enforced before parsing (`VG_LIMIT_EXCEEDED`).
- Unknown methods are forwarded only if policy allows `mcp.protocol.unknown`; otherwise deny.

### 3.2 Method inspection matrix

| Method | Request inspection | Response inspection | Policy |
|---|---|---|---|
| `initialize` | client info, protocol version | server info | allowlist protocol versions |
| `tools/list` | — | definitions, schema, descriptions | poisoning/schema/trust filters |
| `tools/call` | args, capability, identity | content, schema, DLP | full policy |
| `resources/list` | — | metadata | trust/limit |
| `resources/read` | URI | text/blob content | full policy + DLP |
| `resources/templates/list` | — | templates | trust/limit |
| `prompts/list` | — | metadata | trust/limit |
| `prompts/get` | arguments | prompt messages | full policy + injection scan |
| `sampling/createMessage` | request | model output? | deny by default; only if policy explicitly allows |
| notifications | metadata | content | scan content if it becomes model context |
| unknown | method name | any | deny by default in strict |

No response-bearing method may reach the model without passing the content inspector.

### 3.3 Gateway error mapping

| Condition | JSON-RPC error | HTTP (streamable) |
|---|---|---|
| auth missing | `-32001` `VG_AUTH_REQUIRED` | 401 |
| auth invalid | `-32001` | 401 |
| policy deny | `-32003` `VG_AUTHORIZATION_DENIED` | 403 |
| approval required | `-32004` `VG_APPROVAL_REQUIRED` | 202 (ticket in result) |
| schema/size | `-32602` `VG_SCHEMA_INVALID` / `VG_LIMIT_EXCEEDED` | 400/413 |
| upstream unavailable | `-32010` `VG_UPSTREAM_UNAVAILABLE` | 502 |
| gateway degraded | `-32011` `VG_POSTURE_DEGRADED` | 503 |

Tool-call denials preserve MCP semantics: return `result.content` with `isError:true` when the client expects tool-result errors; protocol-level errors use `error`.

---

## 4. Local REST API

### 4.1 Binding and authentication

- Default bind: `127.0.0.1`, ephemeral/configured port.
- No remote bind without explicit `--allow-remote` + TLS + auth.
- Local auth token stored in the OS keystore or a `0600` file; sent as `Authorization: Bearer`.
- Browser requests require an `Origin`/`Sec-Fetch-Site` check and CSRF token for state-changing calls.
- Request ID (`X-Request-Id`) and trace ID returned.
- Rate limits per token/route.

### 4.2 Endpoints

| Method | Path | Purpose | Scope |
|---|---|---|---|
| GET | `/v1/health` | liveness/readiness | none/local |
| GET | `/v1/version` | component versions | local |
| GET | `/v1/posture` | protected/degraded/unprotected + evidence | `status:read` |
| POST | `/v1/authorize` | evaluate one action without executing | `policy:evaluate` |
| POST | `/v1/sessions` | create agent session | `session:write` |
| GET | `/v1/sessions/{id}` | session state | `session:read` |
| DELETE | `/v1/sessions/{id}` | revoke session | `session:write` |
| GET | `/v1/approvals` | list pending | `approval:read` |
| POST | `/v1/approvals` | create approval ticket | `approval:write` |
| POST | `/v1/approvals/{id}/decision` | approve/deny with signed approval | `approval:decide` |
| GET | `/v1/events` | list audit/incident events | `audit:read` |
| GET | `/v1/events/stream` | SSE stream | `audit:read` |
| POST | `/v1/audit/verify` | verify log/checkpoints | `audit:verify` |
| GET | `/v1/audit/checkpoints` | checkpoint list | `audit:read` |
| POST | `/v1/sandbox/executions` | run untrusted code | `sandbox:exec` |
| GET | `/v1/sandbox/executions/{id}` | status/output | `sandbox:read` |
| DELETE | `/v1/sandbox/executions/{id}` | terminate/quarantine | `sandbox:exec` |
| GET | `/v1/policy` | active policy metadata/hash | `policy:read` |
| POST | `/v1/policy/validate` | validate unsigned draft | `policy:write` |
| POST | `/v1/policy/apply` | apply signed policy | `policy:admin` |
| GET | `/v1/trust` | trust registry | `trust:read` |
| POST | `/v1/trust/{artifactId}/approve` | approve artifact | `trust:admin` |
| POST | `/v1/trust/{artifactId}/revoke` | revoke artifact | `trust:admin` |
| POST | `/v1/kill-switch` | signed emergency stop | `incident:admin` |
| GET | `/v1/incidents/{id}` | incident timeline | `audit:read` |
| POST | `/v1/incidents/{id}/export` | signed export | `audit:read` |

### 4.3 `POST /v1/authorize`

Request:

```json
{
  "principal": "agent:acme/ci",
  "sessionId": "ses_01...",
  "target": {"server":"filesystem","tool":"read_file"},
  "capability": "fs.read",
  "action": {
    "args": {"path": "../.env"},
    "argsDigest": "sha256:...",
    "resources": ["path:../.env"]
  },
  "labels": ["internal"],
  "traceId": "..."
}
```

Response:

```json
{
  "decision": "deny",
  "reasonCode": "VG_AUTHORIZATION_DENIED",
  "policyId": "acme-default",
  "policyVersion": "2026.11.1",
  "matchedRules": ["deny-credential-stores"],
  "obligations": [],
  "explanation": "Path is outside the project and matches a denied credential path.",
  "traceId": "..."
}
```

The API never returns raw policy expressions or secrets.

### 4.4 Error format (RFC 9457)

```json
{
  "type": "https://vibeguard.dev/errors/authorization-denied",
  "title": "Authorization denied",
  "status": 403,
  "code": "VG_AUTHORIZATION_DENIED",
  "detail": "The action is denied by policy acme-default@2026.11.1.",
  "instance": "/v1/authorize",
  "traceId": "...",
  "retryable": false
}
```

### 4.5 Versioning and idempotency

- URI version `/v1`; additive changes within v1; breaking changes to `/v2`.
- `Idempotency-Key` required for creation/approval/sandbox/kill endpoints.
- Pagination: `limit` + opaque `cursor`; stable ordering by event sequence.
- SSE resumption via `Last-Event-ID`.

---

## 5. TypeScript SDK contract

```ts
import { VibeGuardClient } from '@yagyeshvyas/vibeguard-sdk';

const vg = new VibeGuardClient({
  baseUrl: 'http://127.0.0.1:8787',
  token: process.env.VG_TOKEN!,   // local scoped token
  timeoutMs: 5000,
});

const decision = await vg.authorize({
  principal: 'agent:local/dev',
  target: { server: 'filesystem', tool: 'read_file' },
  capability: 'fs.read',
  action: { args: { path: 'src/index.ts' } },
});

if (decision.decision === 'approval_required') {
  const ticket = await vg.approvals.create({ actionDigest: decision.actionDigest });
  // UI shows ticket; human decides
}

await vg.audit.verify({ path: '.vibeguard/audit/events.jsonl' });
```

SDK rules:

- No hidden network calls; explicit endpoints.
- Structured errors (`VibeGuardError` with `code`, `status`, `retryable`).
- No raw secret values in logs or errors.
- Optional `@yagyeshvyas/vibeguard-sdk` package, semver 1.0 when stable.
- A CLI wrapper is available for languages without an SDK; REST is the stable contract.

---

## 6. MCP integration design

### 6.1 Local strict wrapper

Client config example (generated by `vibeguard install`):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "vibeguard",
      "args": ["gateway", "stdio", "--server", "filesystem", "--agent", "claude-code"],
      "env": {"VG_GATEWAY_CONFIG": "..."}
    }
  }
}
```

- The original server command moves into the gateway/trust registry, not the client config.
- `--server` resolves from the signed trust registry; raw commands require `--exec` + explicit trust.
- `install` pins the VibeGuard version (no `npx -y`).
- The gateway owns the upstream child.

### 6.2 Remote gateway

```text
Client → https://gateway.example.com/mcp (OAuth/mTLS)
Gateway → upstream MCP server (private network only)
```

- Upstream should accept only gateway identity/IP; network policy enforces.
- `Origin`/`Host` validation, protocol version checks, `requestState` binding.
- No client token passthrough to upstream; use token exchange/scopes.

### 6.3 Direct-path detection

- Inventory client configs and listening upstreams.
- If a direct path is detected in strict mode, posture becomes `unprotected`; API/dashboard raise an incident.
- The gateway cannot revoke a user’s direct connection without OS controls; it must report the gap rather than claim enforcement.

---

## 7. GitHub Action

`.github/actions/vibeguard-security/action.yml`:

Inputs:

- `mode`: `scan` | `gateway-test` | `policy-validate`
- `path`: target
- `policy`: signed policy file
- `offline`: default `true`
- `sarif`: upload SARIF
- `fail-on`: severity
- `benchmark`: run security corpus
- `audit-key`: optional key reference

Outputs:

- `grade`, `findings`, `policyHash`, `posture`, `sarifFile`

Behavior:

- No network unless explicitly enabled.
- No target plugin execution.
- SARIF 2.1.0 with rule IDs and security-severity.
- Optional signed attestation of scan/policy hash.
- Pinned action version; least-privilege `permissions`.
- Runs on Node 20/22; Windows/macOS jobs for platform tests.

---

## 8. IDE integration

Minimum viable integration (design):

- Generate/validate MCP client config for the gateway.
- Show inline policy decisions/denials on tool calls (via API/events).
- Approval prompt panel for pending tickets (local UI).
- Commands: “VibeGuard: show posture”, “approve ticket”, “open incident”, “validate policy”.
- Language Server optional; start with a VS Code extension using the local API.
- Never expose the local API token to webviews or remote content; use a nonce and strict origin checks.

---

## 9. Compatibility and rollout

| Integration | v1.10 behavior | v2 behavior | Migration |
|---|---|---|---|
| MCP stdio | proxy command | gateway stdio | keep flags; new `gateway` alias |
| MCP HTTP | not supported | streamable HTTP | new config; no forced migration |
| Direct server config | allowed | flagged as unprotected | installer migrates |
| MCP tools | 93 tools | 93 + platform tools | additive |
| CLI flags | existing | additive; security changes gated | documented |
| JSON output | fields | additive fields | do not remove |
| Policy | legacy JSON | v2 signed | auto-adapter, monitor mode |

---

## 10. API acceptance tests

- Auth missing/invalid/revoked → 401, no upstream call, audit event.
- Policy deny → 403, no upstream call, signed event.
- Approval required → 202 ticket; approval replay/nonce reuse fails.
- `authorize` is deterministic for identical inputs/policy/time.
- Every REST call has traceId and no secrets in errors.
- SSE resumes with `Last-Event-ID`.
- Remote bind refuses without TLS/auth.
- SDK round-trips all endpoints and preserves error codes.
- Installer produces pinned gateway config; direct config is flagged.
- Action runs offline with no network and generates SARIF.
