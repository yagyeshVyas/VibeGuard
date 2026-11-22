# Security Policy Schema

**Design date:** 2026-11-21  
**Basis:** `08`/`09`, audit findings F-05/F-06/F-12/F-21/F-26/F-27  
**Status:** design only. This schema is the contract for policy v2; the legacy `.vibeguard-mcp.json` loader remains as a migration adapter.

---

## 1. Design goals

- **Default deny in strict mode.**
- **Deny overrides allow.** No priority games that let a later allow undo an explicit deny.
- **Capability-based.** Authorization is by capability + resource + conditions, not just tool name.
- **Per-tool and per-resource.** A tool may be allowed for one path/host/tenant and denied for another.
- **Human approval for sensitive operations**, bound to the exact action.
- **No arbitrary code in policy.** Conditions are a small JSON AST, not `eval`.
- **Policy is signed.** The gateway verifies the policy signature/key before use.
- **Deterministic.** No network, model, clock or environment reads during evaluation.
- **Versioned and migratable.**

---

## 2. Canonical concepts

### 2.1 Principals

```
agent:<tenant>/<name>        e.g. agent:acme/ci-runner
human:<tenant>/<email>       e.g. human:acme/alice@example.com
service:<tenant>/<name>      e.g. service:acme/gateway
mcp-server:<tenant>/<name>   e.g. mcp-server:acme/files
```

Display names are not identities. Identity status (`active`, `suspended`, `revoked`) is checked before policy.

### 2.2 Capabilities

| Capability | Meaning |
|---|---|
| `mcp.tool.invoke` | call an MCP tool |
| `mcp.resource.read` | read an MCP resource |
| `mcp.prompt.get` | obtain an MCP prompt |
| `mcp.server.manage` | start/stop/configure an MCP server |
| `fs.read` | read files through a mediated tool |
| `fs.write` | write/modify files |
| `net.egress` | reach a network destination |
| `proc.exec` | execute a command/process |
| `secret.read` | read a secret value |
| `secret.use` | use a secret without revealing it |
| `sandbox.exec` | execute code in a sandbox |
| `package.install` | install/update packages |
| `skill.load` | load a skill/plugin |
| `memory.write` | write agent memory |
| `agent.delegate` | delegate authority to another agent |
| `policy.admin` | read/modify policy |
| `audit.read` | read audit events |

Capabilities are attached to principals and also requested by actions. Policy can require both.

### 2.3 Resources

```
path:<project>/src/**
path:<project>/.env
uri:mcp://server/resource
host:api.example.com:443
tool:<server>/<tool>
secret:<name>
```

Paths are canonicalized with `realpath`; symlinks/junctions are resolved before matching. Hosts include scheme/port where relevant.

### 2.4 Data labels

`public`, `internal`, `confidential`, `restricted`, `pii`, `secret`, `credential`, `untrusted`.

Labels propagate through the gateway; policy can deny a combination (e.g., `secret` + `net.egress` to an untrusted host).

### 2.5 Decisions

```
allow | deny | approval_required | quarantine
```

Precedence: `deny`/`quarantine` > `approval_required` > `allow` > default.

---

## 3. Policy document

```json
{
  "schemaVersion": "2.0",
  "policyId": "acme-default",
  "policyVersion": "2026.11.1",
  "mode": "strict",
  "description": "Default-deny policy for local agents",
  "issuer": "human:acme/security@example.com",
  "issuedAt": "2026-11-21T00:00:00Z",
  "expiresAt": "2027-11-21T00:00:00Z",
  "defaults": {
    "decision": "deny",
    "unknownTool": "deny",
    "unknownResource": "deny",
    "onError": "deny",
    "failClosed": true
  },
  "subjects": [],
  "capabilities": {},
  "tools": [],
  "resources": [],
  "data": {},
  "approval": {},
  "quotas": {},
  "audit": {},
  "supply": {},
  "detectors": {},
  "sandbox": {},
  "runtime": {},
  "signature": {
    "alg": "Ed25519",
    "keyId": "acme-policy-2026-11",
    "sig": "base64url..."
  }
}
```

### 3.1 Top-level fields

| Field | Type | Required | Meaning |
|---|---|---|---|
| `schemaVersion` | string | yes | `"2.0"` |
| `policyId` | string | yes | stable identifier |
| `policyVersion` | string | yes | monotonic version |
| `mode` | enum | yes | `strict`, `monitor`, `legacy` |
| `description` | string | no | human summary |
| `issuer` | principal | yes | signer identity |
| `issuedAt`/`expiresAt` | RFC3339 | yes | validity window |
| `defaults` | object | yes | fallback behavior |
| `subjects` | array | no | principal/agent definitions |
| `capabilities` | object | no | capability grants/denies |
| `tools` | array | no | tool rules |
| `resources` | array | no | path/URI/host rules |
| `data` | object | no | DLP/classification |
| `approval` | object | no | approval requirements |
| `quotas` | object | no | limits |
| `audit` | object | no | audit requirements |
| `supply` | object | no | trust requirements |
| `detectors` | object | no | detector enablement |
| `sandbox` | object | no | backend/isolation requirements |
| `runtime` | object | no | monitor/quarantine behavior |
| `signature` | object | yes in strict | policy signature |

### 3.2 Defaults

```json
"defaults": {
  "decision": "deny",
  "unknownTool": "deny",
  "unknownResource": "deny",
  "onError": "deny",
  "failClosed": true
}
```

Rules:

- `strict` requires `decision:"deny"`, `unknownTool:"deny"`, `onError:"deny"`, `failClosed:true`.
- `monitor` may use `allow`/`warn` but the posture is `degraded`; the dashboard must show it.
- `legacy` is only for migration; no security claim.
- Invalid policy values are rejected, never normalized to `allow` (fixes F-05).

### 3.3 Subjects

```json
"subjects": [
  {
    "principal": "agent:acme/ci-runner",
    "kind": "agent",
    "status": "active",
    "capabilities": [
      "mcp.tool.invoke",
      "fs.read",
      "sandbox.exec"
    ],
    "tenant": "acme",
    "metadata": {"purpose": "CI remediation"},
    "expiresAt": "2027-01-01T00:00:00Z"
  }
]
```

The identity store is still authoritative; policy cannot create a principal that does not exist. `subjects` constrains which existing principals are eligible and which capabilities they may receive.

### 3.4 Tool rules

```json
"tools": [
  {
    "id": "read-project-files",
    "effect": "allow",
    "match": {
      "server": "filesystem",
      "tool": "read_file",
      "capability": "fs.read",
      "principal": "agent:acme/*"
    },
    "resources": {"paths": ["path:<project>/src/**"]},
    "conditions": {
      "op": "and",
      "args": [
        {"op": "not", "args": [{"op": "contains", "path": "$args.path", "value": ".."}]},
        {"op": "labelIn", "path": "$labels", "value": ["public", "internal"]}
      ]
    }
  },
  {
    "id": "write-outside-project",
    "effect": "deny",
    "match": {"server": "filesystem", "tool": "write_file", "capability": "fs.write"},
    "resources": {"paths": ["path:<outside>/**"]}
  },
  {
    "id": "delete-requires-human",
    "effect": "approval_required",
    "match": {"server": "filesystem", "tool": "delete_file", "capability": "fs.write"},
    "approval": {"profile": "destructive", "maxTtlSeconds": 300}
  }
]
```

Rule fields:

| Field | Meaning |
|---|---|
| `id` | stable rule ID for audit/explanations |
| `effect` | `allow`, `deny`, `approval_required`, `quarantine` |
| `match` | principal/server/tool/capability selectors; globs allowed |
| `resources` | path/URI/host/secret selectors |
| `conditions` | JSON AST; no arbitrary code |
| `approval` | approval profile reference/overrides |
| `obligations` | redact, useCredentialRef, auditLevel, timeout, requireSandbox |
| `reason` | safe human explanation |

Glob matching must be case-normalized for tool names, canonical for paths, and explicitly tested for Unicode.

### 3.5 Resource rules

```json
"resources": [
  {
    "id": "deny-credential-stores",
    "effect": "deny",
    "match": {"capability": ["fs.read", "fs.write"]},
    "resources": {
      "paths": [
        "path:**/.ssh/**",
        "path:**/.aws/credentials",
        "path:**/.env",
        "path:**/*.pem",
        "path:**/*.key"
      ]
    }
  },
  {
    "id": "egress-allowlist",
    "effect": "deny",
    "match": {"capability": "net.egress"},
    "resources": {"hosts": ["*"]},
    "except": {"hosts": ["api.example.com:443", "localhost:*/127.0.0.1"]}
  }
]
```

- Paths are canonicalized (`realpath`) and normalized before matching.
- `except` is explicit and auditable; deny rules cannot be overridden by a later allow.
- `hosts` includes scheme/port/IP; DNS/IP checks happen in the gateway/egress layer.

### 3.6 Conditions

A small, total language:

```json
{"op":"and","args":[
  {"op":"eq","path":"$args.mode","value":"read"},
  {"op":"not","args":[{"op":"contains","path":"$args.path","value":".."}]},
  {"op":"labelIn","path":"$labels","value":["public","internal"]},
  {"op":"within","path":"$resource.path","value":"path:<project>/src/**"}
]}
```

Operators:

- `and`, `or`, `not`
- `eq`, `neq`, `in`, `notIn`
- `contains`, `startsWith`, `endsWith`, `matches` (RE2-safe subset; no backtracking catastrophic patterns; maximum length)
- `labelIn`, `labelSuperset`
- `within` (canonical path/URI)
- `timeBefore`, `timeAfter` (RFC3339, injected clock)
- `count` (session/rate counters, bounded)

Forbidden:

- arbitrary JS, `eval`, `Function`, filesystem/network/env access
- unbounded regex; ReDoS limits
- reads of secrets/raw data; conditions operate on labels/digests/canonicalized strings

Evaluation is total: missing paths are `null`; type errors deny with `VG_POLICY_EVALUATION_ERROR`.

### 3.7 Data protection

```json
"data": {
  "classify": true,
  "labels": ["public", "internal", "confidential", "restricted", "pii", "secret", "credential"],
  "secretScan": {
    "enabled": true,
    "entropy": {"enabled": true, "minBitsPerChar": 3.5, "minLength": 20},
    "decode": ["base64", "base64url", "hex", "percent"],
    "unknownSecrets": "deny",
    "allowPatterns": ["sha256:[0-9a-f]{64}", "uuid"]
  },
  "pii": {"enabled": true, "action": "redact", "types": ["email", "phone", "ssn", "card", "iban", "jwt"]},
  "dlp": {
    "outbound": "block",
    "destinations": {"default": "deny", "allow": ["host:api.example.com:443"]},
    "labels": {
      "secret": ["*"],
      "credential": ["*"],
      "restricted": ["host:api.example.com:443"]
    }
  }
}
```

- Raw secrets are never stored in events or explanations.
- Secret matching uses patterns, decoded forms, entropy and HMAC fingerprints.
- DLP applies to arguments, results, resources, prompts, memory writes and outbound requests (F-07/F-03).

### 3.8 Approval

```json
"approval": {
  "enabled": true,
  "profiles": {
    "destructive": {
      "methods": ["local-ui", "cli"],
      "maxTtlSeconds": 300,
      "requireReason": true,
      "canonicalize": ["command", "path", "url", "recipient", "amount", "scope"]
    },
    "production-deploy": {
      "methods": ["local-ui"],
      "quorum": 1,
      "maxTtlSeconds": 600,
      "requireReason": true
    }
  },
  "bind": ["principal", "actionDigest", "sessionId", "nonce", "expiry"],
  "singleUse": true
}
```

Approval evidence:

```json
{
  "approvalId": "apr_...",
  "ticketId": "tkt_...",
  "principal": "human:acme/alice@example.com",
  "actionDigest": "sha256:...",
  "nonce": "base64url...",
  "issuedAt": "...",
  "expiresAt": "...",
  "signature": {"alg":"Ed25519","keyId":"...","sig":"..."}
}
```

No self-approval: the approver principal must differ from the agent principal. Approval keys are isolated from the agent runtime.

### 3.9 Quotas

```json
"quotas": {
  "callsPerMinute": 120,
  "tokensPerHour": 100000,
  "bytesPerCall": 65536,
  "bytesPerResponse": 1048576,
  "maxConcurrent": 4,
  "sandbox": {
    "cpuMillis": 5000,
    "memoryMiB": 256,
    "diskMiB": 128,
    "pids": 32,
    "wallSeconds": 10
  }
}
```

Quotas are enforced by the gateway/sandbox backend; counters are per principal/session and reset deterministically.

### 3.10 Audit

```json
"audit": {
  "enabled": true,
  "level": "full",              // full | metadata | off (off is invalid in strict)
  "sign": true,
  "checkpointEvery": 512,
  "checkpointIntervalSeconds": 3600,
  "externalAnchor": {
    "enabled": false,
    "type": "file",             // file | siem | transparency-log
    "path": "anchors/audit.root"
  },
  "redact": ["secret", "credential", "pii"]
}
```

Strict mode requires `sign:true` and rejects `level:"off"`.

### 3.11 Supply chain

```json
"supply": {
  "servers": {
    "unknown": "deny",
    "requireSignature": true,
    "requirePinnedVersion": true,
    "allow": [
      {"id":"filesystem","publisher":"modelcontextprotocol","version":"2026.1.0","sha256":"..."}
    ]
  },
  "skills": {"unknown":"deny","requireSignature":true},
  "packages": {
    "lockfileIntegrity": "require",
    "provenance": "require",
    "allowRegistries": ["registry.npmjs.org"]
  }
}
```

### 3.12 Detectors

```json
"detectors": {
  "deterministic": {
    "promptInjection": "block",
    "toolPoisoning": "block",
    "hiddenUnicode": "block",
    "schemaManipulation": "block",
    "memoryPoisoning": "block",
    "multiAgent": "warn",
    "secret": "block",
    "pii": "redact"
  },
  "aiAssist": {
    "enabled": false,
    "mode": "advisory",         // only 'advisory' is valid
    "mayEscalateTo": ["approval_required"],
    "timeoutMs": 2000,
    "maxInputBytes": 65536,
    "offlineOnly": true
  }
}
```

`aiAssist` is optional. No `mode:"authority"` is allowed. Detector strictness is enforced by policy; an AI timeout never flips a deny.

### 3.13 Sandbox

```json
"sandbox": {
  "requiredIsolationClass": "container",
  "allowUnverified": false,
  "backends": ["windows-appcontainer", "linux-container"],
  "network": "none",
  "filesystem": {
    "read": ["path:<workspace>/src/**"],
    "write": ["path:<tmp>/**"],
    "deny": ["path:**/.ssh/**", "path:**/.aws/**"]
  },
  "credentials": "none",
  "inheritEnv": ["PATH"],
  "timeoutSeconds": 10
}
```

- `allowUnverified:false` in strict mode. If no backend passes verification, execution is denied.
- `network:"none"` is enforced at the OS level, not by module removal.
- No host credentials by default.

### 3.14 Runtime

```json
"runtime": {
  "monitor": ["process", "filesystem", "network"],
  "onCritical": "quarantine",     // quarantine | terminate | block
  "onHigh": "block",
  "killSwitch": {"enabled": true, "requireSignedCommand": true},
  "alerts": {"type": "local", "webhook": null}
}
```

---

## 4. Policy signature

The policy body (all fields except `signature`) is canonicalized (RFC 8785 subset: sorted keys, UTF-8, no NaN/Infinity), hashed with SHA-256, and signed with Ed25519.

```json
"signature": {
  "alg": "Ed25519",
  "keyId": "acme-policy-2026-11",
  "signedAt": "2026-11-21T00:00:00Z",
  "bodyHash": "sha256:...",
  "sig": "base64url..."
}
```

Verification requirements:

- key exists in the trusted key store for the issuer;
- key is not expired/revoked;
- body hash matches;
- policy `issuer` matches the key's principal;
- policy is within validity window;
- signature algorithm is allowed.

If any check fails: `VG_POLICY_INVALID` → deny in strict mode. No unsigned policy in strict mode.

---

## 5. Evaluation algorithm

```
1. Authenticate principal (identity layer, not policy).
2. Check principal status active; check tenant/session.
3. Build PolicyRequest from canonical action + labels + evidence.
4. Evaluate explicit deny rules (all matches); any deny → deny.
5. Evaluate quarantine rules; any match → quarantine.
6. Evaluate approval-required rules; collect requirements.
7. Evaluate allow rules; only if an allow rule matches AND no deny/approval conflict.
8. If no allow:
   - strict → defaults.deny
   - monitor → defaults.decision (warn)
9. Attach obligations; return decision + policy hash/version.
10. On any evaluator error → VG_POLICY_EVALUATION_ERROR + defaults.onError (deny in strict).
```

No “last match wins.” Deny is absolute for the request. A later allow cannot override an earlier deny (fixes policy ambiguity).

---

## 6. Validation rules

The policy validator must reject:

- unknown top-level fields (or warn with `strictSchema` behavior);
- `defaults.decision` other than `allow|deny` in strict;
- `mode` not in enum;
- `defaults.onError` not `deny` in strict;
- unsigned policy in strict;
- expired policy or validity > configured max;
- duplicate rule IDs;
- empty/unknown `effect`;
- conditions with unknown operators, excessive depth, regex length/ReDoS shape;
- paths that cannot be canonicalized;
- approval `singleUse:false` in strict;
- AI `mode` other than `advisory`;
- `sandbox.allowUnverified:true` in strict;
- an allow rule for a capability the principal does not have;
- a rule for an unknown principal/tenant in strict (or require an explicit `subjects` entry).

Errors include JSON Pointer paths and stable codes.

---

## 7. Migration from `.vibeguard-mcp.json`

Legacy fields map as follows:

| Legacy | Policy v2 |
|---|---|
| `defaultAction` | `defaults.decision` (only `allow`/`deny`; invalid → reject, not allow) |
| `toolRules` | `tools[]` with `match.tool`, `effect` |
| `denyTools` | `tools[]` effect deny |
| `allowTools` | `tools[]` effect allow + default deny |
| `approvalRequired` | `tools[]` effect approval_required |
| `deniedPaths`/`allowedPaths` | `resources[]` paths |
| `allowedHosts`/`trustedHosts` | `data.dlp.destinations` + `resources` hosts |
| `secretScan`/`piiMode` | `data` |
| `maxArgumentBytes`/`maxCallsPerMinute` | `quotas` |
| `pinToolDefinitions` | `supply.servers.requirePinnedVersion` |
| `scrubToolResults`/`blockToolResultInjection` | `data.dlp` + `detectors` |
| `failClosed` | `defaults.failClosed` (strict always true) |

Migration is one-way and emits a policy with `mode:"monitor"` by default. The operator must review and switch to `strict` explicitly. Legacy files continue to load through the adapter with a deprecation warning.

---

## 8. Examples

### 8.1 Strict local developer policy

```json
{
  "schemaVersion": "2.0",
  "policyId": "local-strict",
  "policyVersion": "1",
  "mode": "strict",
  "issuer": "human:local/me",
  "issuedAt": "2026-11-21T00:00:00Z",
  "expiresAt": "2027-11-21T00:00:00Z",
  "defaults": {"decision":"deny","unknownTool":"deny","onError":"deny","failClosed":true},
  "subjects": [
    {"principal":"agent:local/dev","kind":"agent","status":"active",
     "capabilities":["mcp.tool.invoke","fs.read","sandbox.exec"]}
  ],
  "tools": [
    {"id":"read-src","effect":"allow",
     "match":{"principal":"agent:local/*","server":"filesystem","tool":"read_file","capability":"fs.read"},
     "resources":{"paths":["path:<project>/src/**"]}},
    {"id":"deny-env","effect":"deny",
     "match":{"capability":["fs.read","fs.write"]},
     "resources":{"paths":["path:**/.env","path:**/.ssh/**","path:**/.aws/**"]}}
  ],
  "approval":{"enabled":true,"profiles":{"destructive":{"maxTtlSeconds":300,"singleUse":true}}},
  "audit":{"enabled":true,"sign":true,"level":"full"},
  "sandbox":{"requiredIsolationClass":"container","allowUnverified":false,"network":"none"},
  "detectors":{"deterministic":{"promptInjection":"block","toolPoisoning":"block"},"aiAssist":{"enabled":false}},
  "signature":{"alg":"Ed25519","keyId":"local-2026","sig":"..."}
}
```

### 8.2 Team/remote policy

Adds OAuth/mTLS principals, per-tenant scopes, remote egress allowlist, external anchor, quorum approvals.

### 8.3 Air-gapped policy

`externalAnchor.enabled:false`, `supply` uses a bundled signed registry snapshot, `detectors.aiAssist.enabled:false`, and all network resources deny.

---

## 9. Policy lifecycle

1. Draft (`mode:monitor`) → validate → sign.
2. Test against a replay corpus in shadow mode.
3. Promote to strict with a new `policyVersion`.
4. Audit the policy hash/version in every decision.
5. Rotate signing keys; retain old public keys for verification.
6. Revoke compromised keys and re-sign.

No policy update is accepted without a new signature and version. The gateway never hot-reloads an unsigned policy in strict mode.

---

## 10. Open schema decisions

- Whether to allow `monitor` mode to be signed with `decision:allow` and still call it “enforced” (recommend: no; it is “observed”).
- Whether `except` rules are necessary or can be expressed as ordered deny/allow with explicit IDs (recommend: keep `except` only if avoidable ambiguity; otherwise remove).
- Condition regex engine choice (RE2-compatible subset vs a tiny custom matcher).
- Multi-tenant policy composition (base + tenant overlay) and conflict resolution.
- Policy size limits and canonicalization limits.
