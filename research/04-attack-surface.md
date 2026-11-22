# VibeGuard Attack Surface

**Audit date:** 2026-11-21  
**Revision:** `2ce5b36` / v1.10.0  
**Purpose:** enumerate every place an attacker can influence a VibeGuard decision or execute code through VibeGuard, and map it to the findings in `03-security-gaps.md`.

---

## 1. Surface overview

VibeGuard has six externally reachable surfaces:

1. **CLI** — `bin/cli.js` with 90+ commands. Accepts paths, code, prompts, commands, URLs, config flags.
2. **MCP server** — 93 tools over stdio (`src/mcp-server.js`). Accepts arbitrary tool arguments from an agent.
3. **MCP firewall proxy** — newline-delimited JSON-RPC between a client and a server (`src/mcp-firewall.js`).
4. **Scanned project** — source files, config, `node_modules`, skills, MCP configs, git history.
5. **Network commands** — `url`, `cve`, `pentest`, `proxy`, `llm-proxy`, GIF.
6. **Release/update** — npm package, GitHub tag/release, integrity manifest, installer-written client config.

The most dangerous surfaces are the ones where VibeGuard **executes or trusts target-controlled content**:

- scanner plugins (F-01),
- the sandbox (F-02),
- MCP resource/prompt responses (F-03),
- shell commands (F-11/F-15),
- MCP config/install (F-16),
- dependencies/release (F-13).

---

## 2. MCP protocol surface

### 2.1 Methods the proxy sees

| Method | Direction | Proxy behavior | Content scanned? | Finding |
|---|---|---|---|---|
| `initialize` | client → server | forwarded | no | — |
| `notifications/initialized` | client → server | forwarded | no | — |
| `tools/list` request | client → server | tracked | request not | — |
| `tools/list` response | server → client | tool definitions inspected/pinned | names/descriptions/schema (limited) | F-08/F-27 |
| `tools/call` request | client → server | policy evaluated; may block | args (limited) | F-05/F-06/F-07/F-11 |
| `tools/call` response | server → client | result scrubbing | known secrets/PII/injection patterns | F-03/F-07 |
| `prompts/get` request | client → server | injection-scan arguments; tracked | arguments only | F-09 |
| `prompts/get` response | server → client | **not scanned** | no | F-03 |
| `resources/read` request | client → server | **not tracked** | no | F-03 |
| `resources/read` response | server → client | **not scanned** | no | F-03 |
| `resources/list` response | server → client | not scanned | no | F-03 |
| `sampling/createMessage` | server → client | not scanned | no | F-03/F-12 |
| notifications | server → client | forwarded | no | F-03 |
| unknown methods | either | forwarded | no | F-03/F-22 |

**Key code:** `src/mcp-firewall.js:374-400` (client), `:427-447` (server), `:514-548` (line buffering).

### 2.2 Protocol-level abuse cases

| Abuse | Preconditions | Impact |
|---|---|---|
| Return secret/injection via `resources/read` | Malicious server | Model context compromise (F-03) |
| Return injection via `prompts/get` | Malicious server | Model follows hidden prompt (F-03) |
| Huge JSON line without newline | Malicious server/client | Proxy memory exhaustion (F-17) |
| Many unanswered requests | Malicious server | `pending` memory growth (F-17) |
| Malformed schema / huge response | Malicious server | Parser/CPU/DoS; no schema validation (F-22) |
| Tool-list drift after pin | Malicious server | Blocked if pinned; bypass if no pin/approval (F-27) |
| Notification with injection | Malicious server | Unfiltered model context (F-03) |
| Shared proxy for multiple clients | No identity | Confused deputy / scope mixing (F-12) |
| Remote HTTP/SSE server | Not proxied | No policy/auth (F-23) |

### 2.3 MCP server tool surface

`src/mcp-server.js` exposes 93 tools. High-risk tool classes:

- **Execution:** `sandbox_exec`, `check_command`, `guard_action`, `scan_project` (plugin RCE path), `pre_deploy` (scanner plugin path).
- **Filesystem/path:** `scan_file`, `scan_staged`, `scan_project`, `bundle_scan`, `scan_bundles`, `generate_html_report`, `fix_code` (may reveal source).
- **Network:** `scan_url`, `scan_dependencies`, `cve_intel`, `scan_container_image`, `gif_search`, `llm_proxy`-adjacent tools.
- **Configuration:** `install`/`mcp_audit`/`mcp_firewall` actions, `preset_apply`, `config_dump`.
- **Secrets:** `scan_secrets`, `vault_manage`, `env_lock`, `audit_log`.
- **Agent runtime:** `mcp_firewall`, `agent_risk`, `scan_skills`, `owasp_coverage`, `agent_monitor`.

No tool-level authentication or per-caller authorization exists (F-12). A caller can invoke `sandbox_exec` or `scan_project` with attacker-chosen content. `sandbox_exec` is filtered by the sandbox only (F-02); `scan_project` can reach the plugin loader (F-01).

---

## 3. CLI surface

`bin/cli.js` dispatches commands at `bin/cli.js:1013-1116`. Security-relevant sinks:

| Command | Untrusted input | Sink | Risk |
|---|---|---|---|
| `scan [dir]` | target repo | plugin loader, parser, AST | **RCE via plugin (F-01)**, rule suppression |
| `pre-deploy [dir]` | target repo | plugin loader/scanner, network pentest | RCE, SSRF/pentest |
| `auto [dir]` | target repo + hooks | daemon, file writes, shell hooks | persistence, privileged writes |
| `sandbox <code>` | code string | vm/process | sandbox escape (F-02) |
| `guard-action <action>` | command/JSON | action guard | pattern bypass |
| `guard "<cmd>"` | shell command | shell-guard | Windows/egress bypass (F-11/F-15) |
| `mcp-firewall` | MCP config/server | spawn server, policy | policy trust, server execution |
| `mcp-audit` | config files | no execution | incomplete discovery (F-16) |
| `skill-scan` | skill files | no execution | false negatives (F-10) |
| `cve`, `url`, `pentest`, `proxy`, `llm-proxy`, `gif` | URLs/targets | network | egress/privacy; offline claim (F-28) |
| `install` | user config | writes JSON/YAML | unpinned server (F-16) |
| `fix` | target repo | writes source | mutation; backup/rollback |
| `history` | git history | git commands | no execution of content |
| `plugin` (implicit) | node_modules/config | `require()` | **RCE (F-01)** |

### 3.1 Shell hook surface

- `src/hook.js` installs PostToolUse hooks; `hooks/` contains templates.
- `src/shell-hook.ps1` and `shell-hook.sh` intercept shell commands.
- A malicious project can edit hook config? Hooks are installed in user config; the hook content itself is code. If an attacker can write the hook path, arbitrary execution. Not separately probed; note as deployment trust assumption.

### 3.2 Installer surface

`src/install.js` writes MCP configs for Claude Code, Cursor, Windsurf, VS Code, Cline, Gemini, Codex, etc. It uses `writeJsonMcp` and backups. Risks:

- Writes into user config directories (expected, but broad).
- Writes an unpinned `npx -y vibeguard mcp` (F-16).
- Does not authenticate the package or verify the installed binary.
- Does not automatically wrap servers with the firewall.

---

## 4. Filesystem and configuration surface

### 4.1 Files read by the scanner/proxy

| Path/pattern | Reader | Trust |
|---|---|---|
| Source tree | `src/scanner.js` walk | untrusted |
| `.vibeguardrc.json`, `vibeguard.config.json` | `src/scanner.js:28-36` | untrusted; can set plugins/rules |
| `node_modules/vibeguard-rules-*` | `src/plugin.js:44-84` | untrusted; executes |
| `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` | `src/mcp-audit.js:53-58` | untrusted config |
| `.vibeguard-mcp.json`, `.vibeguard/mcp-policy.json`, `vibeguard.mcp.json` | `src/agent-policy.js:32-33/184-191` | project-controlled policy |
| `.vibeguard/mcp-tool-pins.json` | `src/mcp-firewall.js:52-99` | project-controlled pins |
| `SKILL.md`, `AGENTS.md`, `CLAUDE.md`, Cursor rules, plugin manifests | `src/skill-scan.js` | untrusted text |
| `.vibeguard/audit/*.jsonl` | `src/audit-trail.js`, monitor | local evidence |
| `~/.claude.json`, `~/.cursor/mcp.json`, `~/.codeium/...` | `src/doctor.js:95-98` | user config |
| `claude_desktop_config.json` | **not read by mcp-audit** | blind spot (F-16) |

### 4.2 Files written

- `.vibeguard/audit/*.jsonl` (logs)
- `.vibeguard/mcp-tool-pins.json` (pins)
- `.vibeguard/*` (cache/snapshots/auto state)
- `.mcp.json` backups (`.vibeguard-bak`)
- Fix/rollback files
- Client configs via install
- Shell hooks (if installed)

### 4.3 Symlink/junction paths

`src/agent-policy.js:263-279,366-378` uses lexical `path.resolve`; symlinks/junctions are followed without canonicalization. This is an attack surface for any tool that reads/writes a path (F-06).

---

## 5. Network surface

| Command/module | Destination | Auth | Data sent | Notes |
|---|---|---|---|---|
| `cve` / `scan_dependencies` | `api.osv.dev` | none | package names/versions | network despite “offline” claim |
| `url` | arbitrary URL | none | URL/headers | SSRF-ish; user-provided |
| `pentest` | arbitrary target | none | probes/payloads | active testing; explicit |
| `proxy` / `llm-proxy` | upstream LLM API | upstream key | prompts/responses | MITM CA; local interception |
| `gif` | GIF provider | API key maybe | query | existing feature |
| `slopsquat` | npm registry? | none | package names | verify source |

No telemetry was found. The new agent runtime modules do not initiate network calls.

---

## 6. Release/update surface

| Asset | Trust | Current control | Gap |
|---|---|---|---|
| npm package `@yagyeshvyas/vibeguard` | Registry + token | CI tests; `npm publish --provenance` if token | npm currently 1.3.0; 1.10.0 not published (F-13) |
| GitHub tag `v1.10.0` | GitHub account | signed? tag not signed; release manual | no signed tag/asset checksums (F-13) |
| `src/integrity.json` | Package | SHA-256 manifest of 30 modules | unsigned; normal startup does not verify (F-04/F-13) |
| GitHub Actions | Action tags | `actions/*@v4/v7` | tag not SHA; no dependency review (F-13) |
| Installer config | User machine | writes JSON | unpinned npx (F-16) |
| MCP server definition | Client config | none | user can point to any command; no allowlist (F-12/F-16) |

---

## 7. Attack matrix (preconditions → impact → evidence)

| # | Attack | Preconditions | Impact | Evidence |
|---|---|---|---|---|
| A1 | Malicious repo executes plugin code | `vibeguard scan` or MCP `scan_project` on repo | Host RCE | F-01; marker `config-exec` |
| A2 | Escape vm sandbox and read host files | `vibeguard sandbox` on Node 18/default vm | Host FS read/RCE | F-02; `README.md` read |
| A3 | Escape process sandbox and exfiltrate via network | `--isolation process` | Network exfil | F-02; `VG_EXFIL` loopback |
| A4 | Return secret/injection via MCP resource | Malicious MCP server | Context compromise | F-03; unchanged response |
| A5 | Forge audit log / get false PASS | Write access to log | Repudiation | F-04; valid forged chain |
| A6 | Read `.ssh` via junction | Malicious repo or local user | Credential theft | F-06; `TOP SECRET` read |
| A7 | Send unknown/base64/split secret | Agent/tool | Exfil | F-07; all allowed |
| A8 | Use shell `curl` despite host allowlist | Policy configured | Egress | F-11; allow |
| A9 | Windows destructive command | Windows shell tool | Data loss | F-15; blocked false |
| A10 | Install unpinned MCP server | Normal user | Rug-pull | F-16; mcp-audit high |
| A11 | Remote MCP bypass | Remote server | No firewall | F-23 |
| A12 | Exploit vulnerable SDK transitive | Dependency install | Depends on advisory | F-13; npm audit |

---

## 8. Fuzzing and test plan

Recommended next test layers (no implementation in this phase):

1. **Protocol fuzzing** — malformed JSON-RPC, huge lines, duplicate IDs, nested results, missing fields, batch arrays, notifications, schema confusion.
2. **Policy fuzzing** — invalid `defaultAction`, weird globs, Unicode tool names, symlink paths, URL schemes, shell syntax, oversized args.
3. **Detection corpus** — paraphrases, homoglyphs, base64/hex, multilingual injections, benign “guidance” false positives, unknown secrets, split secrets.
4. **Sandbox escapes** — constructor chains, dynamic import, `getBuiltinModule`, worker threads, async/timers, vm2-style escapes, OS-specific paths.
5. **Supply chain** — malicious `.vibeguardrc`, malicious plugin, unpinned MCP, compromised lockfile, action pinning.
6. **Audit** — concurrent writers, crash/fsync, truncation, full-chain rewrite, CLI zero-entry.
7. **OS matrix** — Windows/Linux/macOS shell, path, junction/symlink, sandbox availability.

Exit criteria: every F-01..F-16 has a regression test that fails before the fix and passes after; no new unauthenticated path can be added without a test.
