# Installation and Deployment

## Requirements

- Node.js **20 or 22** for the v2 platform primitives (Node 18 can scan and use
  the legacy sandbox, but process isolation is unavailable).
- No account, API key or network connection is required for scanning, policy
  evaluation, signed audit, HTTP loopback gateway or the platform tests.
- Windows 11, Linux and macOS are supported by the code paths in this repo;
  Windows CI runs `node test/run-platform.js`. macOS CI is configured but has
  not been observed as a verified release gate in this environment.

## From a checkout

```bash
npm ci
node test/run.js            # legacy + platform suites
node test/run-platform.js   # focused security suite
node bin/cli.js scan .
```

Do not use `npm install` in an untrusted project with lifecycle scripts unless
you have reviewed it; the project itself does not modify shell profiles.

## Strict MCP gateway (stdio)

1. Create and sign a strict policy:

```bash
node bin/cli.js policy validate docs/security-policy.strict.example.json \
  --pub docs/security-policy.strict.example.pub.pem
```

2. Use a signed policy with the legacy strict gateway:

```bash
node bin/cli.js mcp-firewall --server <name> --strict
```

This mode uses the legacy policy engine with strict default-deny after an
explicit allow list. The signed policy-v2 engine is available as a library and
via `policy validate/sign`; wiring it to a production upstream bridge is not
complete.

3. Audit:

```bash
node bin/cli.js audit verify .vibeguard/audit/events.jsonl --pub audit-public.pem
```

## HTTP gateway slice

`src/platform/http-gateway.js` is a loopback-first, authenticated JSON-RPC POST
endpoint with an injected message handler. It is **not** a complete Streamable
HTTP MCP bridge. Example usage is in `test/platform-security-tests.js`.

Bind to loopback by default. Do not expose it without TLS, authentication and
network policy; the current CLI does not start it automatically.

## Sandbox

```bash
node bin/cli.js sandbox backends
node bin/cli.js sandbox "const x = 1 + 2; x" --isolation process
```

The process backend is explicitly unverified: fresh V8 context + Node
permission model, same OS user, network not blocked by the kernel. On Linux
(including WSL), `vibeguard sandbox verify` creates a `unshare` user/network/PID
namespace and verifies network isolation. Filesystem isolation is not provided.
Windows AppContainer/Job/WFP and macOS VM backends are not implemented.

## Offline operation

Scanning, policy, identity, approval, signed audit, SSRF checks, JWT/JWKS and
the platform tests are offline. Existing `cve`, `url`, `pentest`, `proxy`,
`llm-proxy` and GIF commands are network features and must be explicitly
invoked; see `reports/known-limitations.md`.

## Useful commands

```bash
node bin/cli.js mcp-firewall --selftest
node bin/cli.js mcp-audit
node bin/cli.js skill-scan .
node bin/cli.js agent-risk
node bin/cli.js owasp-coverage
node bin/cli.js policy sign policy.json --key policy-private.pem
node bin/cli.js audit verify audit.jsonl --pub audit-public.pem
npm run security-bench
```

## Signed gateway audit

Strict mode writes Ed25519-signed events to `.vibeguard/audit/mcp-firewall.signed.jsonl` and a checkpoint sidecar; the key is generated at `.vibeguard/audit/ed25519.pem` (permissions 0600). Verify with:

```bash
vibeguard audit verify .vibeguard/audit/mcp-firewall.signed.jsonl \
  --pub .vibeguard/audit/ed25519.pub.pem
```

Non-strict mode keeps the legacy hash-chained log.

## Stdio identity/approval

```bash
vibeguard mcp-firewall --exec "<server>" --dir . \
  --token <VGAT> --token-pub token.pub.pem --token-issuer human:acme/security \
  --token-tenant acme --token-key-id k1
```

A signed single-use approval can be supplied with `--approval-token`, `--approval-pub`, `--approval-issuer`, `--approval-tenant`, `--approval-key-id`. There is no authenticated approval UI yet.

## HTTP/SSE bridge

Use `src/platform/mcp-http-bridge.js` with a policy and authority; it supports authenticated JSON-RPC POST and an SSE `GET /mcp` notification stream. It is loopback-tested, not a TLS/OAuth remote deployment.

## Kill switch

```bash
vibeguard mcp-firewall --exec "<server>" --strict --kill-on-block
```

Exit code 3 means the proxy quarantined/killed the upstream after a blocked call.

## Linux OS namespace verification

```bash
vibeguard sandbox verify   # only meaningful on Linux with unshare/user namespaces
```

Windows/macOS OS backends are not implemented.

## Detection corpus

```bash
node test/corpus/run.js --gate
vibeguard aisvs --json
```
