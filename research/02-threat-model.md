# VibeGuard Threat Model

**Audit date:** 2026-11-21  
**Revision:** `2ce5b36` / v1.10.0  
**Method:** asset/actor/trust-boundary analysis, STRIDE, attack-tree reasoning and black-box probes documented in `03-security-gaps.md`.

---

## 1. Security objectives

VibeGuard is trying to provide five distinct security functions. They have different trust assumptions and should not be conflated:

1. **Scanner integrity** — scanning a repository must not execute that repository’s code or let it suppress findings.
2. **Detection correctness** — malicious content should be found with acceptable false-positive/false-negative rates.
3. **Runtime enforcement** — an agent must not be able to perform a denied action through a protected MCP path.
4. **Isolation** — untrusted code executed by VibeGuard must not reach the host filesystem, network, credentials or other processes.
5. **Evidence integrity** — logs and reports must be trustworthy enough to support investigation and audit.

A failure in any one of these can defeat the platform even if the other four are strong.

---

## 2. Assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| API keys, tokens, passwords, private keys | Direct account/cloud compromise | Source, env, tool arguments, tool results, `.env`, vault, audit logs |
| User PII and business data | Privacy/regulatory harm, cross-tenant leakage | Prompts, tool arguments/results, memory/context, logs |
| Host filesystem and OS credentials | Full local compromise | `fs`, `~/.ssh`, `.aws`, browser profiles, Windows registry |
| Network reachability | Exfiltration, SSRF, cloud metadata theft, lateral movement | `fetch`, HTTP clients, shell `curl`, MCP network tools |
| Agent tool authority | Destructive actions, spend, data loss, privilege escalation | MCP tool names/arguments, policy, model context |
| MCP server code/config | Supply-chain compromise, rug-pull, credential theft | `.mcp.json`, client configs, server packages, tool definitions |
| Skill/plugin/instruction files | Persistent behavior change, prompt injection | `SKILL.md`, `AGENTS.md`, `CLAUDE.md`, Cursor rules, plugin manifests |
| Policy and pins | The enforcement decision itself | `.vibeguard-mcp.json`, `.vibeguard/mcp-tool-pins.json` |
| Audit log | Non-repudiation, incident response, risk scoring | `.vibeguard/audit/*.jsonl` |
| Release artifacts | Supply-chain trust for every user | npm package, GitHub tag/release, integrity manifest |
| Trust in the tool | Users rely on “secure by default” claims | README, website, OWASP report, risk score |

---

## 3. Actors and capabilities

| Actor | Capability | Relevant surfaces |
|---|---|---|
| **Curious/benign agent** | Can call any exposed MCP tool, follow injected instructions, make mistakes | `tools/call`, shell, filesystem, network |
| **Malicious MCP server** | Controls tool names/descriptions/schemas, results, resources, prompts; can change later | `tools/list`, `tools/call`, `resources/read`, `prompts/get` |
| **Prompt injector** | Controls a document, web page, email, issue, tool output or resource | Any text entering the model context |
| **Malicious repository author** | Controls `.vibeguardrc.json`, `node_modules`, source, skills, `.mcp.json` | Scanner plugin loader, config parsing, skill scanner, MCP audit |
| **Compromised dependency/package** | Executes at install or scan time, alters rules/behavior | `npm install`, plugin discovery, MCP server packages |
| **Malicious local process** | Same OS user; can spawn its own MCP server/proxy, read project files | Local files, configs, logs, environment |
| **Remote MCP operator** | Controls TLS endpoint, OAuth metadata, tool data | Remote MCP transports (not currently proxied) |
| **Supply-chain attacker on release** | Can alter package or manifest if registry/GitHub account compromised | npm, GitHub tag/release, integrity manifest |
| **Insider/operator error** | Misconfigures policy, approvals, paths, allowlists | Policy, installer, CLI flags |

### Non-adversarial assumptions currently made by the code

- The OS user is trusted enough to run VibeGuard.
- The MCP client is not malicious (only the server is).
- A project policy file is operator-authored, not attacker-authored.
- Plugin packages in `node_modules` are trusted.
- The audit log writer and reader are the same trusted process.
- The local filesystem path does not contain symlinks/junctions.
- Shell commands are POSIX-like.
- The agent cannot spawn its own uninstrumented MCP client.
- The model will follow text from a tool result as data, not instruction.

Every one of these assumptions is false in at least one realistic deployment. The gaps that follow show which ones are load-bearing.

---

## 4. Trust boundaries

```
[ user / web / email / docs ]  (untrusted text)
              │
              ▼
[ model context ]  ◄──── tool descriptions, resources, prompts, results (untrusted)
              │
              ▼
[ agent client ]  ── stdio ──► [ mcp-firewall ] ── stdio ──► [ MCP server ]
      │                              │                              │
      │                              ├─ policy file (project)       ├─ host FS
      │                              ├─ audit file                  ├─ network
      │                              └─ pins                        └─ shell/child procs
      │
      ├─ CLI scan ──► [ scanner ] ──► [ plugin loader ] ──► require(target code)
      │
      └─ sandbox ──► [ vm / child process ] ──► host (same user)
```

Critical boundary observations:

1. **Policy is target-controlled.** `.vibeguard-mcp.json` is read from the project root (`src/agent-policy.js:184-191`). A repository can ship a permissive policy; an agent with filesystem write can change it.
2. **Plugins are target-controlled code.** `loadPlugins` scans `node_modules/vibeguard-rules-*` and config `plugins` and calls `require()` (`src/plugin.js:44-84`; invoked at `src/scanner.js:674`).
3. **Tool descriptions and results are model-facing untrusted text.** The proxy inspects `tools/list` and `tools/call`, but not `resources/read` or `prompts/get` responses (`src/mcp-firewall.js:374-400`, `432-447`).
4. **The sandbox is not an OS boundary.** The vm mode passes host-realm objects; the process mode still runs as the same user and network is reachable through the host-realm `process` object.
5. **The audit log is local and unsigned.** Anyone who can write the file can rewrite the whole chain; the CLI verifier does not load the file.

---

## 5. STRIDE analysis

| STRIDE | Threat | Current control | Residual risk / finding |
|---|---|---|---|
| **Spoofing** | Malicious MCP server impersonates a trusted tool; client identity is absent | Tool hash pinning after first sight; no identity/auth | F-12, F-27 |
| **Tampering** | Server changes tool description after approval; attacker edits policy/pins/log | Definition hash + drift block; plain SHA-256 chain | F-04, F-26, F-27 |
| **Repudiation** | Agent/tool denies an action; log altered | Hash-chained JSONL, `mcp_blocked` entries | F-04, F-19 |
| **Information disclosure** | Secrets/PII in arguments/results; symlink reads; proxy resources; logs | Pattern scan + result scrubbing + denied paths | F-06, F-07, F-03, F-19 |
| **Denial of service** | Huge JSON line, unlimited pending calls, huge tool result, agent loop | `maxArgumentBytes`, `maxCallsPerMinute`, sandbox timeout | F-17, F-22 |
| **Elevation of privilege** | Sandbox escape, plugin require, shell command, unpinned installer | vm/process sandbox, shell guard, no wildcard allow | F-01, F-02, F-11, F-15, F-16 |

---

## 6. Attack trees

### 6.1 Compromise secrets through an MCP server

```
Goal: read a credential and send it to an attacker
├─ Inject instruction into model context
│  ├─ prompt injection in user/document/web text (F-09)
│  ├─ poisoned tool description (F-08)
│  ├─ tool result/resource/prompt content (F-03, F-07)
│  └─ malicious skill/instruction file (F-10)
├─ Ask a tool to read a credential
│  ├─ path is blocked by policy? bypass via symlink/junction (F-06)
│  ├─ read is allowed outside project (warning only) (F-05/F-06)
│  └─ tool result secret is unknown/base64/split (F-07)
└─ Send it out
   ├─ URL argument is scanned? use a shell command instead (F-11)
   ├─ use file:// or another non-http scheme under default policy (F-05)
   └─ use a trusted host or a second server not using the proxy (F-12)
```

### 6.2 Execute code on the host

```
Goal: arbitrary code execution outside the agent’s intended authority
├─ scanner plugin path
│  ├─ malicious .vibeguardrc.json `plugins` entry (F-01)
│  └─ malicious `node_modules/vibeguard-rules-*` (F-01)
├─ sandbox path
│  ├─ vm escape via host object constructor (F-02)
│  ├─ process host-realm escape + getBuiltinModule (F-02)
│  └─ network exfiltration even without fs permission (F-02)
├─ MCP shell tool
│  ├─ POSIX denylist bypass (F-11)
│  └─ Windows commands not in the denylist (F-15)
└─ supply chain
   ├─ unpinned npx server (F-16)
   └─ vulnerable SDK/express/proxy-addr (F-13)
```

### 6.3 Poison the agent’s behavior persistently

```
Goal: make future turns follow attacker instructions
├─ tool description (first sight or changed) (F-08/F-27)
├─ skill/agent instruction file (F-10)
├─ resource/read result or prompt template (F-03)
├─ memory/context over-sharing (MCP10; no memory isolation controls)
└─ policy/pin tampering (F-26)
```

### 6.4 Forge the evidence trail

```
Goal: make a blocked action look allowed, or a malicious action disappear
├─ edit first entry and recompute hashes sequentially (F-04)
├─ delete/truncate the log (no append-only/OS lock) (F-19)
├─ rewrite the integrity manifest and modules together (F-04/F-13)
├─ make CLI `audit-trail verify` read zero entries and print PASS (F-04)
└─ tamper with risk inputs so `agent-risk` reports A (F-20)
```

### 6.5 Abuse the proxy itself

```
Goal: make the firewall ineffective
├─ use a client/server path not proxied (remote HTTP, direct server) (F-12/F-23)
├─ send a response type the proxy does not scan (resources/prompts) (F-03)
├─ make policy default allow / typo defaultAction (F-05)
├─ flood an unbounded line/pending map (F-17)
└─ use a permissive project policy or pins (F-26)
```

---

## 7. Threat scenarios worth testing first

| ID | Scenario | Preconditions | Impact | Finding |
|---|---|---|---|---|
| S1 | Scan an untrusted repo with `.vibeguardrc` plugin | User runs `vibeguard scan` on repo | Arbitrary code execution in scanner/MCP server | F-01 |
| S2 | Escape sandbox via `console.log.constructor` | Run untrusted code with default/`vm` or process mode | Host code execution/network exfil | F-02 |
| S3 | Return secret/injection from `resources/read` | Malicious MCP server | Secret/injection enters model context | F-03 |
| S4 | Forge audit log and run CLI verify | Write access to log | False PASS / repudiation | F-04 |
| S5 | Use a junction inside project to read outside | Malicious repo or local file | Credential read despite deny list | F-06 |
| S6 | Send unknown/base64/split secret | Agent or malicious tool | Exfiltration bypass | F-07 |
| S7 | Use shell `curl` with no URL argument | Policy allowlist configured | Egress bypass | F-11 |
| S8 | Run a Windows destructive command through shell tool | Windows deployment | Host data loss | F-15 |
| S9 | Install via default `npx -y vibeguard mcp` | Normal user setup | Rug-pull/supply chain | F-16 |
| S10 | Call a non-proxied MCP server / remote transport | Agent config | Firewall bypass | F-12/F-23 |

---

## 8. Risk methodology

Severity in this audit is **impact-based**, not a CVSS claim:

- **Critical** — direct path to host code execution, full boundary escape, or credible mass compromise with low preconditions.
- **High** — reliable bypass of an advertised security control, credential/data exfiltration, or release/supply-chain integrity failure.
- **Medium** — meaningful weakening, DoS, missing assurance/accountability, or a gap that requires configuration/insider action.
- **Low** — documentation/claim mismatch, scalability, or defense-in-depth improvement.

No CVSS numeric scores are assigned because the audit did not perform a full exploitability/environmental assessment. Any future CVSS must state the vector and assumptions.

---

## 9. Explicit non-goals / unverified areas

The audit did **not** verify:

- exploitability against every supported OS (macOS, Linux desktop);
- network-level isolation of the process sandbox under all Node permission-model versions;
- resistance to a determined local attacker who can ptrace/replace the VibeGuard process;
- remote MCP OAuth/SSE implementations (not present);
- cryptographic strength of npm provenance or the maintainer’s account security;
- absence of zero-days in dependencies not covered by `npm audit`;
- performance under adversarial large payloads.

These are marked as residual/unverified in `03-security-gaps.md` rather than assumed safe.
