# VibeGuard MCP Firewall

A real-time firewall between an AI agent and the MCP servers it trusts.

Most agent stacks treat MCP as a trusted bus: the client asks, the server
answers, tool descriptions and tool results flow straight into the model's
context. Every one of those channels is attacker-controlled in a compromised or
malicious server. VibeGuard proxies the channel in both directions and enforces
policy on every message — offline, no network, no dependencies.

```
Agent / MCP client  ──►  vibeguard mcp-firewall  ──►  MCP server
   (Claude Code,            policy + definition       (filesystem, shell,
    Cursor, SDK)             pinning + secret scan       database, SaaS)
                                  │
                                  ▼
                       .vibeguard/audit/mcp-firewall.jsonl
                         hash-chained, tamper-evident
```

## What it does

| Layer | What is checked | When |
|---|---|---|
| Tool poisoning | Injection text, hidden Unicode, concealment instructions, forced invocation, encoded payloads, `readOnlyHint` lies in tool names/descriptions/schemas | `tools/list` response |
| Definition pinning | SHA-256 of each tool definition; a changed description after approval is a rug-pull | `tools/list` response |
| Permissions | Per-tool allow/deny/approval rules, capability gates, project-scoped paths, denied credential stores | `tools/call` request |
| Command safety | Destructive/obfuscated shell commands, exfil pipelines | `tools/call` request |
| Egress | Host allow/deny lists, cloud-metadata block, secret-in-URL | `tools/call` request |
| Secret exfiltration | Live credentials in arguments, credential + destination in one call | `tools/call` request |
| Result scrubbing | Secrets and PII redacted from tool output before it enters the model context | `tools/call` response |
| Result poisoning | Prompt-injection text inside tool output is withheld and replaced with an explicit notice | `tools/call` response |
| Prompt prompts | Injection scan on `prompts/get` arguments | request |
| Audit + risk | Every verdict appended to a hash-chained log with a risk value | always |

Blocked `tools/call` requests are answered locally and **never forwarded** to
the server. Poisoned tools are removed from the `tools/list` result, with a
`_vibeguard` note listing what was removed and why.

## Quick start

```bash
# 1. Audit what you already trust (config only, never runs a server)
vibeguard mcp-audit

# 2. Write a policy you can edit, or copy the example
vibeguard mcp-firewall --init

# 3. Verify the firewall works offline
vibeguard mcp-firewall --selftest

# 4. Proxy a configured server by name (.mcp.json / .cursor/mcp.json / .vscode/mcp.json)
vibeguard mcp-firewall --server filesystem

# Or an ad-hoc command (quote the whole command line)
vibeguard mcp-firewall --exec "npx -y @modelcontextprotocol/server-filesystem ."

# 5. Point your MCP client at the proxy instead of the server.
#    Claude Code example:
claude mcp add filesystem -- vibeguard mcp-firewall --server filesystem
```

If you edit the *same* config file the proxy reads, `--server <name>` would
resolve to the proxy entry and recurse. The proxy refuses that with a clear
error; use `--exec "<original server command>"` in that case, or put the proxy
entry in a different client config.

The proxy speaks newline-delimited JSON-RPC 2.0 on stdio. Stdout carries only
protocol traffic; all banners and diagnostics go to stderr.

## Modes

```bash
vibeguard mcp-firewall --server <name>          # long-running stdio proxy
vibeguard mcp-firewall --exec "<command>"       # long-running ad-hoc proxy
vibeguard mcp-firewall --check '<json>'         # evaluate one tool call
vibeguard mcp-firewall --init                   # write a default policy
vibeguard mcp-firewall --selftest [--json]      # 11 offline attack scenarios
vibeguard mcp-firewall --status [--json]        # summarize the audit log
vibeguard mcp-firewall --list-servers           # show configured servers
vibeguard mcp-firewall --policy <file>          # inspect a policy
```

`--check` exits `2` on block, `1` on warn, `0` on allow:

```bash
vibeguard mcp-firewall --check '{"server":"fs","tool":"read_file","args":{"path":".env"}}'
```

## Policy

Place `.vibeguard-mcp.json` in the project root (or pass `--policy`). Every
field is optional; the defaults are **strict default-deny**. See
[`.vibeguard-mcp.example.json`](.vibeguard-mcp.example.json) for a copy-paste
starting point.

```json
{
  "version": 1,
  "defaultAction": "block",
  "toolRules": [
    { "match": "mcp__filesystem__write_*", "action": "warn", "reason": "writes are reviewed" },
    { "match": "mcp__shell__*", "action": "block" }
  ],
  "denyTools": ["dangerous_*"],
  "allowTools": ["read_file", "list_directory"],
  "approvalRequired": ["delete_*"],
  "blockedCapabilities": ["shell"],
  "allowedPaths": ["../shared-config"],
  "deniedPaths": ["**/.env", "**/.ssh/**", "**/*.pem"],
  "enforceProjectScope": true,
  "allowedHosts": ["api.example.com"],
  "deniedHosts": ["169.254.169.254", "metadata.google.internal"],
  "trustedHosts": ["localhost"],
  "blockExternalNetwork": false,
  "secretScan": true,
  "piiScan": true,
  "piiMode": "warn",
  "blockPromptInjection": true,
  "pinToolDefinitions": true,
  "scrubToolResults": true,
  "blockToolResultInjection": true,
  "maxArgumentBytes": 65536,
  "maxCallsPerMinute": 240,
  "logAllowedCalls": true,
  "failClosed": true
}
```

### Field notes

- `defaultAction` — `allow`, `warn` or `block` for tools with no matching rule.
  The default is `block`; add trusted tools to `allowTools`. Use
  `--allow-unknown` only for a deliberate compatibility opt-out.
- `toolRules` — ordered; first match wins. `match` is a glob (`*`, `**`, `?`).
  Actions: `allow`, `warn`, `block`, `approval` (headless proxies convert
  approval to a block with a clear reason).
- `allowTools` — when non-empty, only these tools (or an explicit allow rule)
  may run.
- `blockedCapabilities` / `allowedCapabilities` — capability classes derived
  from tool name and arguments: `shell`, `code-exec`, `fs.read`, `fs.write`,
  `network`, `database`, `secrets`, `generic`.
- `enforceProjectScope` — reads outside the project are warned; writes are
  blocked unless the path matches `allowedPaths`.
- `allowedHosts` — when non-empty, external egress to anything else is blocked.
  Localhost/private IPs are not "external".
- `trustedHosts` — hosts explicitly allowed to receive sensitive data.
- `piiMode` — `warn` (default) or `block` for personal data in arguments.
- `pinToolDefinitions` — first sight pins each tool definition under
  `.vibeguard/mcp-tool-pins.json`; a later change is blocked as drift.
- `blockToolResultInjection` — tool output containing prompt-injection text is
  withheld and replaced with a notice instead of entering the model context.
- `failClosed` — if the policy file is invalid, block everything instead of
  falling back to defaults.

## Audit and monitoring

Every decision is appended to `.vibeguard/audit/mcp-firewall.jsonl`. Each entry
commits to the previous entry's SHA-256, so edits and deletions are detectable:

```bash
vibeguard mcp-firewall --status     # counts, top blocked tools, anomalies
vibeguard agent-monitor             # richer runtime report
vibeguard agent-monitor --watch     # live tail (one line per decision)
vibeguard audit-trail verify        # verify the in-process chain
```

The monitor maps runtime events into the behavior engine and flags trust
building, data gathering before egress, slow exfiltration, privilege
escalation, repeated blocks, rapid fire and tampering.

## Risk scoring

```bash
vibeguard agent-risk [dir] [--json]
vibeguard owasp-coverage [dir] [--all]
```

`agent-risk` combines five domains into a 0-100 score and A-F grade:

| Domain | Weight | Input |
|---|---|---|
| MCP config | 35% | tool poisoning, unpinned servers, shells, secrets, broad FS, drift |
| Skills | 30% | malicious skill/plugin/instruction files |
| Runtime | 20% | blocked calls, poisoned tools, redactions, behavior anomalies |
| Policy | 10% | explicit policy vs defaults, egress allowlist |
| Audit | 5% | log present, chain intact |

Exit codes: `2` critical or F, `1` any risk, `0` clean.

## OWASP coverage

`vibeguard owasp-coverage` maps every implemented control to:

- **OWASP Top 10 for Agentic Applications** (ASI01-ASI10)
- **OWASP MCP Top 10** (MCP01-MCP10)
- optionally the **OWASP LLM Top 10** (`--all`)

Statuses are explicit: `ENFORCED` (runtime can block), `DETECTED` (scanner
reports it), `MONITORED` (audit/behavior exposes it), `ADVISORY` (guidance only).
The command exits `0` only when every selected control is mapped. Coverage is
not a claim that a risk is eliminated; the status says what the control does.

## Skills and plugins

```bash
vibeguard skill-scan [dir] [extra paths...] [--json] [--all]
```

Scans `SKILL.md`, `AGENTS.md`, `CLAUDE.md`, `.cursor/rules`, `.claude/agents`,
`.claude/skills`, `plugin.json`, marketplace files and embedded MCP server
configs for prompt injection, hidden Unicode, exfiltration instructions,
credential-store access, destructive commands, remote code loaders,
obfuscation, permission bypass, self-modification, risky/unpinned packages and
secrets.

## The MCP tools

The same engines are available to an agent through the MCP server:

| Tool | Purpose |
|---|---|
| `mcp_firewall` | `check` a tool call, `selftest`, `status`, `policy` |
| `scan_skills` | malicious skill/plugin scan |
| `agent_risk` | unified agent risk score |
| `owasp_coverage` | OWASP mapping |
| `agent_monitor` | runtime activity and anomaly report |
| `sandbox_exec` | run untrusted code (`isolation: auto/os/process/vm`) |
| `approval_request` | request a human approval ticket for an exact action |
| `approval_status` | read a ticket's status and single-use approval token |

## Sandbox

`vibeguard sandbox "<code>"` executes JavaScript in a locked context.
`isolation: "os"` selects a verified OS backend and **fails closed** if none
is verified on the host:

- **Windows** — AppContainer profile with no capability SIDs, Job Object
  memory/process/UI limits, minimal environment and profile-scoped writes.
  Network (including loopback) is denied by the OS. Verify with
  `vibeguard sandbox verify`.
- **macOS** — QEMU/HVF hardware VM, separate guest kernel, `-nic none`,
  read-only 9p share and snapshot disk. Requires a caller-supplied guest image;
  the backend reports unavailable until the image passes verification.

`isolation: "auto"` prefers a verified OS backend, then the process backend.
`process` remains a separate Node process under the permission model
(filesystem and `child_process` denied by the runtime, network modules
blocked, stripped environment, memory cap, hard timeout). It is a process
boundary, not an OS boundary.

```bash
vibeguard sandbox verify
vibeguard sandbox "const x = 1 + 2; x" --isolation os --json
vibeguard sandbox "const x = 1 + 2; x" --isolation process --json
```

## Windows and offline

- No network calls anywhere in the firewall, monitor, skill scanner, risk or
  coverage code. The only network code in VibeGuard remains the opt-in `url`,
  `cve`, `pentest`, proxy and GIF commands.
- No symlink traversal, no shell invocation for the proxy (`spawn` with an argv
  array), no POSIX-only paths. The process sandbox works on Windows 11 with
  Node 20+.
- ANSI colors degrade gracefully (set `NO_COLOR=1` to disable).
- Audit logs use forward-slash normalization for path matching on Windows.

## Strict mode

Strict default-deny is the default. The MCP firewall blocks an unknown tool
unless an explicit allow rule/allowlist admits it, and it writes signed audit
events by default. `--strict` remains accepted as an explicit assertion of that
mode; `--allow-unknown` is the deliberate compatibility opt-out and prints a
warning. The additive v2 policy engine (`src/platform/policy.js`) supports
signed Ed25519 policies, realpath path checks, approvals and per-resource
rules; it is tested as a library/CLI but is not yet the live stdio gateway
policy. See [`reports/known-limitations.md`](reports/known-limitations.md).

The v2 gateway also inspects all content-bearing response methods
(`resources/read`, `prompts/get`, unknown methods), not only `tools/call`.

## Honest status

The process sandbox is **unverified, same-user and not an OS boundary**. The
`vibeguard sandbox backends` command reports verification per backend; it says
`verified=NO` until `vibeguard sandbox verify` passes on the host. Windows
AppContainer is an OS boundary but shares the host kernel and has no WFP rule;
macOS VM isolation requires a configured guest image. Do not describe
`process`/`vm` as OS isolation.


- The proxy currently speaks the **stdio** MCP transport (the transport Claude
  Code, Cursor and most local clients use). HTTP/SSE remote transports are not
  proxied; audit those with `vibeguard mcp-audit`.
- The proxy is a **filter, not a sandbox for the server**. A malicious server
  can still do whatever its own code does when it is invoked. The proxy
  guarantees the agent cannot ask it to do the dangerous thing through this
  channel, and that there is a tamper-evident record of the attempt.
- Pattern rules can be evaded by a determined attacker who knows them. The
  semantic prompt classifier and the policy engine raise the bar; they do not
  prove absence of risk.
- `pinToolDefinitions` pins on first sight. Review a server before first use;
  the pin only protects against later changes.
- `sandbox_exec` with `isolation: "process"` or `"vm"` is not an OS boundary; use `isolation: "os"` for a verified OS backend.
- OWASP coverage maps controls, not perfect prevention.

## Signed audit, auth and kill switch

- Strict mode writes signed Ed25519 gateway events by default and fails closed if the audit sink is unavailable.
- `--token` + `--token-pub` enforce a VGAT principal capability set on stdio; `--approval-token` + `--approval-pub` enforce a signed single-use approval for approval-required rules; `--approval-used` makes the replay store durable across processes. Human decisions can be collected through `vibeguard approval serve`/the authenticated UI.
- `--kill-on-block` / `--max-blocks N` quarantine-kills the upstream and exits 3 after blocked calls.
- `src/platform/mcp-http-bridge.js` provides authenticated JSON-RPC POST and SSE notification flow over stdio; it is loopback-tested and does not provide TLS/OAuth remote deployment.
- Linux `unshare`/bubblewrap, Windows AppContainer and macOS hardware-VM isolation are verified through `vibeguard sandbox verify` when the host (and, for macOS, a guest image) provides them.
