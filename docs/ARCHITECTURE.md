# VibeGuard Architecture (v2 security baseline)

This document describes what is **implemented** in the repository today, and
separates it from the target design in `research/08`–`15`. If a control is not
listed as implemented, do not treat it as available.

## Implemented baseline

```
Legacy v1.10 scanner + MCP server (preserved)
        │
        ├─ platform/canonical + contracts
        ├─ platform/identity  (Ed25519 VGAT capability tokens, replay cache)
        ├─ platform/approval  (signed, single-use human approvals + authenticated service)
        ├─ platform/signed-audit (Ed25519 event chain + Merkle checkpoints)
        ├─ platform/policy    (strict v2 engine, signed policies, default deny)
        ├─ platform/jwt       (offline EdDSA JWT/JWKS validation)
        ├─ platform/mcp-http-bridge (authenticated JSON-RPC + SSE ↔ stdio)
        ├─ platform/os-sandbox (Linux unshare network/PID namespace)
        ├─ platform/memory-guard + delegation (library controls)
        ├─ platform/ssrf      (private/metadata/loopback destination blocking)
        ├─ platform/http-gateway (authenticated JSON-RPC HTTP slice)
        ├─ platform/sandbox-manager (fail-closed backend registry)
        └─ hardened legacy modules:
             mcp-firewall: all-method response inspection, limits, strict mode
             agent-policy: strict option, realpath, shell egress, deep secrets
             scanner/plugin: no target-controlled plugin execution by default
             sandbox: process harness without host-realm objects
             shell-guard: Windows destructive command coverage
```

### Enforcement path

```
agent/client ──► mcp-firewall (stdio) ──► MCP server
                    │
                    ├─ policy (strict legacy engine or v2 library)
                    ├─ all-method content scan (tools/resources/prompts/unknown)
                    ├─ secret/PII/entropy/DLP
                    └─ legacy hash-chained audit log

vibeguard policy sign/validate ──► Ed25519 signed policy v2
vibeguard audit verify ──► signed event chain + checkpoints
vibeguard sandbox backends ──► explicitly unverified/verified status
```

## What is not implemented / not verified

- **Windows AppContainer** (`windows-appcontainer`) is implemented with a Job
  Object and a live verification suite. Network denial is capability-based; no
  WFP rule is installed, and Windows/Program Files remain readable by default.
- **macOS hardware VM** (`macos-vm`) is implemented with QEMU/HVF, no NIC, a
  read-only 9p share and a snapshot disk. It requires a caller-supplied guest
  image and verifies only on a macOS host.
- Linux has bubblewrap and `unshare` network/PID backends verified by live
  probes. Do not claim cross-platform isolation until `sandbox verify` passes
  on the target host.
- The HTTP bridge supports authenticated JSON-RPC POST and SSE notifications
  over a spawned stdio upstream, but not TLS/mTLS, remote OAuth server flow or
  multi-session persistence.
- Strict mode writes signed gateway audit events; non-strict mode still uses the
  legacy hash chain. External checkpoint/anchor remains absent.
- Approval tickets and used tokens are persisted by the hosted approval service; the broker itself remains storage-agnostic. The authenticated human UI uses a password login (scrypt), HttpOnly session cookies, CSRF tokens, signed approver proofs, optional quorum and signed approval audit events.
- Independent runtime monitors and quarantine service; an optional kill-on-block switch exists.
- REST API/SDK/dashboard/IDE integrations beyond the primitive HTTP gateway.
- AISVS 1.01 mapping, evidence-backed OWASP statuses, complete supply-chain
  registry, and production release signing.

See `reports/known-limitations.md` for the authoritative list.

## Trust boundaries

| Boundary | Control in this build |
|---|---|
| Client → gateway | VGAT Ed25519 token (stdio legacy path has no identity yet), audience/expiry/replay validation in the HTTP slice |
| Tool arguments/results | Policy v2, secret/PII/entropy checks, all-method response scan |
| Target repo → scanner | Plugins disabled unless explicit `--trust-plugins`; sandbox not used for plugins |
| Untrusted code → host | Fresh V8 context + Node permission model; **unverified**, same-user |
| Audit writer → attacker | Hash chain; signed events when using `SignedAuditLog`; no OS append-only anchor |
| Policy → agent | Signed strict policy v2; legacy project policy is monitor-only |

## Compatibility

Legacy CLI commands and the 95 MCP tools remain. The MCP firewall is strict
default-deny; `--allow-unknown` is the explicit compatibility opt-out. New
platform commands are additive. Partial unsafe behavior is explicitly labeled
in output (`verified=NO`).
