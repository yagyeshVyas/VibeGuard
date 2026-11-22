# Competitor Capability Matrix

**Audit date:** 2026-11-21  
**Comparison target:** VibeGuard `2ce5b36` / v1.10.0  
**Method:** official project documentation and source repositories, not vendor marketing pages alone. Features change quickly; this matrix is a snapshot, not a permanent ranking.

Legend:

- **Yes** — documented, primary feature.
- **Partial** — present with a meaningful limitation.
- **No** — not a documented capability of that project.
- **N/A** — outside the project’s category.
- **?** — not verified from primary sources in this audit.

---

## 1. High-level positioning

| Project | Category | Primary language / license | Best fit |
|---|---|---|---|
| **VibeGuard** | Offline code/agent security scanner + MCP firewall + skills + risk | Node.js / MIT | Local-first teams that want one tool for code and agent runtime |
| **Pipelock** | Inline AI egress/MCP/A2A firewall with signed receipts | Go / Apache-2.0 | Organizations that need an inline mediation layer with signed evidence |
| **Snyk Agent Scan** | Agent/MCP/skill discovery and cloud-backed scanning | Python/binary; Apache-2.0 repo / proprietary Snyk service | Snyk customers needing fleet discovery and risk analysis |
| **Cisco MCP Scanner** | MCP server/tool static and live scanning | Python / Apache-2.0 | Security teams wanting YARA/LLM/API scanning and a REST service |
| **Semgrep** | SAST / AppSec platform with MCP access to findings | OCaml/TypeScript; LGPL-2.1 OSS core / commercial platform | Code scanning and remediation workflows |
| **Gitleaks** | Secret scanning | Go / MIT | Git/filesystem secret detection |
| **Trivy** | Vulnerability/SBOM/container scanning | Go / Apache-2.0 | Dependencies, images, IaC, SBOM |
| **Promptfoo** | LLM red-team/evaluation harness | TypeScript / MIT | Adversarial testing of agents and MCP servers |
| **E2B / Firecracker / gVisor** | Isolation infrastructure | Rust/Go/C / open source | Running untrusted code with a real OS/kernel boundary |

---

## 2. Capability matrix

| Capability | VibeGuard | Pipelock | Snyk Agent Scan | Cisco MCP Scanner | Semgrep | Gitleaks | Trivy | Promptfoo | E2B/Firecracker/gVisor |
|---|---|---|---|---|---|---|---|---|---|
| Inline MCP request/response enforcement | **Partial** (stdio; tools only) | **Yes** (MCP/HTTP/WS/A2A) | **No** (scan, not inline) | **No** (scan) | **No** | **No** | **No** | **No** (test harness) | **N/A** |
| MCP `tools/list` poisoning scan | **Yes** (limited patterns) | **Yes** (normalization + hidden instructions) | **Yes** | **Yes** (YARA/LLM/API) | **No** | **No** | **No** | **Yes** (red-team) | **N/A** |
| Tool-definition pinning / rug-pull | **Yes** (hash pin, no approval) | **Yes** (mid-session rug-pull) | **?** | **?** | **No** | **No** | **No** | **Yes** (tests rug-pull) | **N/A** |
| `resources/read` / prompts response scanning | **No** (gap F-03) | **Yes** (bidirectional content) | **Yes** (scans resources/prompts) | **Yes** (scans prompts/resources) | **No** | **No** | **No** | **Yes** (test cases) | **N/A** |
| Remote HTTP/SSE MCP proxy | **No** (stdio only) | **Yes** (streamable HTTP/stdio bridge) | **Scan only** | **Scan only** (OAuth) | **No** | **No** | **No** | **Yes** (as a client target) | **N/A** |
| Agent identity / OAuth / mTLS | **No** | **Partial** (MCP HTTP listener auth token; workload identity verifier-side) | **Snyk token** (not agent identity) | **OAuth for scans** | **Platform token** | **No** | **No** | **No** | **N/A** |
| Per-agent authorization / scoped tools | **No** (tool-name policy only) | **Partial** (tool policy; not full principal model) | **No** | **No** | **No** | **No** | **No** | **No** | **N/A** |
| Default-deny permission policy | **Optional** (default allow; F-05) | **Yes** (policy/allowlist; fail-closed MCP listeners) | **No** | **No** | **No** | **No** | **No** | **No** | **N/A** |
| Human approval / reversibility | **No** (block only; F-21) | **Partial** (actions `block/strip/warn/ask`; no evident signed approval) | **No** | **No** | **No** | **No** | **No** | **No** | **N/A** |
| Secret/DLP egress scanning | **Partial** (known patterns; no entropy/base64/split; F-07) | **Yes** (74 DLP patterns, entropy, normalization, BIP-39) | **Yes** (cloud analysis) | **Partial** (YARA/LLM; not a DLP proxy) | **No** | **Yes** (secrets) | **Partial** (secrets in images/files) | **No** | **N/A** |
| Shell/command injection protection | **Partial** (POSIX; Windows gap; F-15) | **Yes** (tool policy; not a general shell firewall) | **No** | **Partial** (YARA) | **No** | **No** | **No** | **No** | **N/A** |
| Behavior monitoring / kill switch | **Partial** (log/monitor; no kill; F-18) | **Partial** (tool-call chains; no OS kill) | **Partial** (risk analysis) | **No** | **No** | **No** | **No** | **Yes** (evaluations, not runtime) | **N/A** |
| Malicious skill/plugin scanning | **Yes** (local patterns; F-10) | **?** | **Yes** | **No** (MCP/tools) | **No** | **No** | **No** | **Yes** (test generation) | **N/A** |
| Sandbox / OS isolation | **No** (vm/process, escapable; F-02) | **Partial** (capability separation; not a general sandbox) | **No** (recommends user sandbox) | **Partial** (Docker for packages) | **No** | **No** | **No** | **No** | **Yes** (Firecracker/gVisor/VM) |
| Signed audit / action receipts | **No** (hash chain only; F-04) | **Yes** (mediator-signed receipts) | **Cloud logging** | **Scan reports** | **Platform audit** | **No** | **No** | **No** | **N/A** |
| Offline / no cloud dependency | **Yes** (new runtime; some commands network) | **Yes** (self-hosted proxy) | **No** (Snyk API/token) | **Partial** (static mode; API/YARA/LLM optional) | **Partial** (local Semgrep; platform optional) | **Yes** | **Yes** | **Yes** | **Yes** (self-hosted) |
| Public standards mapping | **Partial/overclaimed** (F-14) | **?** (not the primary focus) | **?** | **?** | **?** | **No** | **No** | **Partial** (OWASP LLM/MCP test plugins) | **N/A** |
| Cross-platform | **Partial** (CI Linux; Windows local; macOS untested) | **Partial** (Go; OS-dependent) | **Yes** (macOS/Windows/Linux binaries) | **Yes** (Python cross-platform) | **Yes** | **Yes** | **Yes** | **Yes** | **Linux-first** |
| License / cost | MIT / free | Apache-2.0 / free | Apache-2.0 repo / proprietary service | Apache-2.0 | LGPL-2.1 OSS core / commercial platform | MIT | Apache-2.0 | MIT | Apache-2.0 / hosted service |

**Do not interpret this matrix as “VibeGuard is better/worse.”** It shows scope differences. A scanner is not an inline firewall; an inline firewall is not a code scanner; a VM sandbox is not an agent policy engine.

---

## 3. Project profiles and primary-source evidence

### 3.1 Pipelock

- Repository: https://github.com/pipelab-org/pipelock
- Documented features: inline HTTP/WebSocket/MCP/A2A scanning; secret exfiltration, SSRF, prompt injection, tool poisoning, risky tool-call chains; 74 DLP patterns; 34 response-injection patterns with six normalization passes; tool policy with 30 built-in rules; signed action receipts; MCP HTTP listener authentication; capability separation.
- Relevant strengths over VibeGuard: protocol coverage, normalization, signed receipts, auth listener, tool-call chains, explicit bypass-resistance documentation.
- Relevant differences: Go self-hosted proxy, not a code scanner; no evidence of a broad SAST rule set or skill/plugin marketplace scanner; requires a proxy deployment and capability separation to be effective.
- What VibeGuard could reuse conceptually: signed receipts, normalization pipeline, conformance tests, fail-closed listener defaults.

### 3.2 Snyk Agent Scan

- Repository: https://github.com/snyk/agent-scan
- Documented features: discovers agents/MCP servers/skills; scans prompts, tools, resources and skills; executes stdio servers (with explicit consent) and contacts remote servers; remote MCP with configured headers; cloud API analysis and Snyk token; standalone binaries with SBOM/checksums/signed checksums.
- Relevant strengths: discovery breadth, skill scanning, resource/prompt coverage, signed release artifacts.
- Relevant differences: cloud/Snyk token required; warnings explicitly say scanning MCP configs can execute commands or make outbound requests; not an inline firewall.
- Lesson: VibeGuard needs broader discovery and signed release assets, but should not execute untrusted servers merely to scan them.

### 3.3 Cisco MCP Scanner

- Repository: https://github.com/cisco-ai-defense/mcp-scanner
- Documented features: Python CLI/REST API; YARA + LLM + Cisco AI Defense engines; static/live scanning; MCP tools, prompts, resources and server instructions; remote HTTP/SSE and stdio; OAuth; package/binary scanning (VirusTotal); PyPI scanning in Docker; static JSON for air-gapped CI.
- Relevant strengths: multi-engine analysis, REST service, remote/OAuth, package/binary scanning, air-gapped mode.
- Relevant differences: scanning, not inline enforcement; LLM/API components can be non-deterministic/networked; Python stack.
- Lesson: a REST/API mode and schema-aware content coverage are enterprise requirements; YARA/LLM are complementary to deterministic rules, not a substitute.

### 3.4 Semgrep

- Docs: https://docs.semgrep.dev/mcp/overview
- Documented features: hosted MCP server for findings, triage, fixes, scans and policies; Semgrep Guardian for local agent scanning; SAST/supply-chain/secrets; role/token-scoped read-only URLs.
- Relevant strengths: deep code analysis, platform integration, auth/scoping.
- Relevant differences: not a runtime MCP firewall; VibeGuard’s code scanner is broader in AI-specific rules but not a replacement for Semgrep’s engine/ecosystem.
- Lesson: treat Semgrep as a complementary scanner; VibeGuard’s unique niche is offline agent-runtime control, not rule-engine depth.

### 3.5 Gitleaks

- Repository: https://github.com/gitleaks/gitleaks
- Documented features: regex + entropy secret detection in git repos, files and stdin; pre-commit/action integrations; cross-platform binaries. The project states it is feature-complete and will receive security patches only.
- Relevant strengths: mature secret detection and history scanning.
- Relevant differences: no agent runtime, MCP, policy or sandbox.
- Lesson: VibeGuard should not claim to replace Gitleaks; it should integrate or defer for deep secret scanning. Its own DLP is weaker (F-07).

### 3.6 Trivy

- Docs: https://www.trivy.dev/docs/latest/guide/target/sbom/
- Documented features: vulnerability/license/SBOM scanning for images, filesystems, repos; CycloneDX/SPDX input; container/Kubernetes/IaC.
- Relevant strengths: dependency/container depth, SBOM.
- Relevant differences: no agent runtime/MCP policy.
- Lesson: use Trivy for image/dependency depth; VibeGuard’s `npm audit`/SBOM gaps (F-13) can be closed by integration.

### 3.7 Promptfoo

- Docs: https://www.promptfoo.dev/docs/red-team/mcp-security-testing/
- Documented features: MCP attack plugins for tool poisoning, exfiltration, rug pulls, tool shadowing, indirect injection; red-team configuration; evaluations; PII/BOLA/BFLA/other plugins.
- Relevant strengths: adversarial test generation and regression suites.
- Relevant differences: testing harness, not inline enforcement or signed audit.
- Lesson: VibeGuard needs a Promptfoo-like adversarial corpus for the MCP firewall and detectors; this is a roadmap item.

### 3.8 E2B / Firecracker / gVisor

- E2B security: https://docs.e2b.dev/faq/security-and-compliance
- E2B architecture: https://github.com/e2b-dev/infra/blob/main/docs/ARCHITECTURE.md
- gVisor: https://gvisor.dev/docs/
- Firecracker: https://aws.amazon.com/blogs/aws/firecracker-lightweight-virtualization-for-serverless-computing/
- Documented features: Firecracker microVMs with separate kernels; gVisor application kernel; E2B sandboxes as Firecracker microVMs, cgroups/network namespaces, snapshot/resume; AWS Lambda MicroVMs use Firecracker for per-session isolation.
- Relevant strengths: actual OS/kernel isolation, resource controls, no shared kernel (E2B/Firecracker).
- Relevant differences: infrastructure, not agent policy/scanner.
- Lesson: VibeGuard’s sandbox should delegate to one of these or clearly state that it is a convenience runner, not a security boundary.

---

## 4. Where VibeGuard genuinely leads

1. **Free + offline integration of code scanning and agent runtime policy.** Pipelock is inline but not a broad code scanner; Snyk/Cisco are scanners with cloud/API components; Semgrep/Gitleaks/Trivy are code/dependency tools.
2. **Single local toolchain for MCP config audit + skills + policy + audit + risk.** The combination is unusual.
3. **Token-lean agent output and 93 MCP tools.** Useful for agent-native workflows.
4. **Open, dependency-light implementation.** Easy to inspect and extend.

## 5. Where VibeGuard clearly lags

1. **Enforcement boundary:** no real OS sandbox; escapable vm/process.
2. **Protocol coverage:** stdio only; resources/prompts unscanned; no HTTP/SSE/A2A.
3. **Identity/auth:** no principal model, OAuth/mTLS, token validation or scoped tool lists.
4. **Evidence:** unsigned hash chain; no signed receipts/checkpoints; CLI false PASS.
5. **Detection robustness:** small regex lists; no normalization/entropy/base64/split-secret coverage.
6. **Assurance:** static OWASP mapping, wrong MCP06, outdated LLM catalog, no AISVS.
7. **Release integrity:** npm not published for v1.10.0; no SBOM/checksum/signed assets; actions not SHA-pinned; vulnerable dependencies.

## 6. Complementary, not “versus”

A realistic world-class stack could be:

- **VibeGuard** for local agent policy/MCP proxy and code scanning,
- **Semgrep + Gitleaks + Trivy** for deep code/secret/dependency coverage,
- **Pipelock** (or equivalent) for inline network/MCP mediation and signed receipts,
- **Promptfoo** for adversarial evaluation,
- **E2B/Firecracker/gVisor** for untrusted execution.

VibeGuard’s roadmap should focus on being excellent in its niche rather than claiming to replace every specialized tool.

## 7. Sources

- Pipelock: https://github.com/pipelab-org/pipelock
- Snyk Agent Scan: https://github.com/snyk/agent-scan
- Cisco MCP Scanner: https://github.com/cisco-ai-defense/mcp-scanner
- Semgrep MCP: https://docs.semgrep.dev/mcp/overview
- Gitleaks: https://github.com/gitleaks/gitleaks
- Trivy SBOM: https://www.trivy.dev/docs/latest/guide/target/sbom/
- Promptfoo MCP security testing: https://www.promptfoo.dev/docs/red-team/mcp-security-testing/
- E2B security: https://docs.e2b.dev/faq/security-and-compliance
- E2B architecture: https://github.com/e2b-dev/infra/blob/main/docs/ARCHITECTURE.md
- gVisor: https://gvisor.dev/docs/
- Firecracker: https://aws.amazon.com/blogs/aws/firecracker-lightweight-virtualization-for-serverless-computing/
- AWS Lambda MicroVMs: https://docs.aws.amazon.com/lambda/latest/dg/lambda-microvms-guide.html
