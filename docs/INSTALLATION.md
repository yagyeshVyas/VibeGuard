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
node bin/cli.js sandbox verify
node bin/cli.js sandbox "const x = 1 + 2; x" --isolation os
node bin/cli.js sandbox "const x = 1 + 2; x" --isolation process
```

`--isolation os` uses a verified OS backend and fails closed when none has
passed verification on this host. On Windows, `sandbox verify` creates an
AppContainer profile, runs the live probe suite (host reads/writes, network,
environment, timeout, memory) and caches the result for 7 days. On macOS it
verifies the QEMU/HVF hardware-VM backend; a caller-supplied guest image
(`VIBEGUARD_VM_IMAGE` or `VIBEGUARD_VM_KERNEL`/`VIBEGUARD_VM_INITRD`) is
required. On Linux it verifies the `unshare`/bubblewrap network/PID backend;
Linux filesystem isolation requires bubblewrap.

The process backend is explicitly unverified: fresh V8 context + Node
permission model, same OS user, network not blocked by the kernel. It is a
convenience boundary, not an OS boundary.

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

## OS backend verification

```bash
vibeguard sandbox verify   # Windows AppContainer, macOS VM, or Linux namespaces
vibeguard sandbox backends # show the verified class and evidence
```

Windows uses AppContainer + Job Object; macOS uses a QEMU/HVF hardware VM when
a guest image is configured; Linux uses bubblewrap or `unshare`. The command
fails closed on a host where the expected backend cannot pass its probes.

### macOS VM prerequisites

1. Install QEMU (`brew install qemu`).
2. Provide a bootable Linux guest image with Node.js on `PATH`:
   - disk image: `VIBEGUARD_VM_IMAGE=/path/to/guest.qcow2`
   - or kernel/initramfs: `VIBEGUARD_VM_KERNEL=/path/to/vmlinuz` and
     `VIBEGUARD_VM_INITRD=/path/to/initrd`.
3. The guest init must mount the 9p share tagged `vibeguard` at `/vibeguard`
   and execute `/vibeguard/entry.sh`. The backend writes the harness as
   `/vibeguard/run.js` and the program as `/vibeguard/user.js`, with no NIC,
   a read-only share and a snapshot disk.
4. Run `vibeguard sandbox verify`. It boots the VM and checks guest boot,
   absence of a network interface, host-file invisibility, `-nic none`,
   read-only 9p and snapshot mode. The backend stays unverified if any probe
   fails.

## Detection corpus

```bash
node test/corpus/run.js --gate
vibeguard aisvs --json
```
