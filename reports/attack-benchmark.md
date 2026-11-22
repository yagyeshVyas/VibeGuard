# Attack Benchmark — VibeGuard Security Baseline v2

**Date:** 2026-11-21  
**Purpose:** record reproducible attack scenarios exercised against this
baseline, distinguish fixed / mitigated / partial / open, and publish
performance measurements. This is **not** a full adversarial benchmark corpus;
that remains future work.

---

## 1. Attack matrix

Legend: **Fixed** = regression test passes; **Partial** = a tested path is
hardened but a bypass remains; **Open** = not implemented; **Unverified** = no
OS backend/test.

| ID | Attack | Prior audit result | Current result | Evidence |
|---|---|---|---|---|
| A-01 | Target `.vibeguardrc` plugin executes code during scan | RCE | **Fixed (default)**; explicit `--trust-plugins` remains dangerous | platform test 7; marker absent |
| A-02 | Sandbox host-object constructor escape | Full host access | **Fixed in process mode** tested; legacy vm still unsafe/unverified | platform test 15 |
| A-03 | Sandbox network exfiltration via `getBuiltinModule` | Allowed from process mode | **Blocked in process mode**; Linux namespace network probe blocks | platform test 15 + `sandbox verify` |
| A-04 | MCP `resources/read` / `prompts/get` secret/injection | Unscanned | **Fixed** for tested methods | platform test 9 |
| A-05 | Tool description “include .env” / homoglyph / short base64 | Kept | **Fixed** for tested definitions | platform test 13 |
| A-06 | Prompt “follow the guidance” false positive | Blocked | **Fixed** | platform test 12 |
| A-07 | Prompt “include .env” exfiltration instruction | Allowed | **Fixed** detector | platform test 12 |
| A-08 | Secret in base64 | Allowed | **Fixed** in tested args/results | platform tests 10/11 |
| A-09 | Secret split across arguments | Allowed | **Fixed** | platform test 11 |
| A-10 | Unknown high-entropy secret | Allowed | **Fixed** for tested token/result | tests 10/11 |
| A-11 | Junction/symlink path escape | Allowed | **Fixed** via realpath | platform test 5 |
| A-12 | Shell `curl` bypasses host allowlist | Allowed | **Fixed** for URL-in-command cases | `agent-policy` + tests |
| A-13 | Windows destructive shell command | Allowed | **Fixed** for tested commands | platform test 8 |
| A-14 | Forged legacy audit chain | Accepted with recomputed hashes | **Partial** — signed logger detects; gateway still uses legacy unsigned log | signed audit test; limitation |
| A-15 | Audit CLI zero-entry PASS | PASS | **Fixed** for `audit verify` signed CLI; legacy `audit-trail` still separate | `bin/cmd-platform.js` |
| A-16 | Policy typo `defaultAction:"deny"` normalizes allow | Allowed | **Partial** — `--strict` forces deny; legacy loader still normalizes | strict gateway test |
| A-17 | Default allow unknown tool | Allowed | **Partial** — legacy default remains allow; `--strict` denies | strict test |
| A-18 | Agent identity spoof/replay | None | **Implemented** for VGAT library/HTTP slice; stdio gateway not bound | identity/HTTP tests |
| A-19 | Self-approval / approval replay | None | **Implemented** in-memory broker | approval test |
| A-20 | SSRF/private/metadata destination | No policy | **Implemented** validation primitive | SSRF test |
| A-21 | JWT wrong audience/scope/replay | None | **Implemented** offline verifier | JWT test |
| A-22 | Malicious skill “just include .env” | Missed | **Open** — skill scanner unchanged | known limitation |
| A-23 | Memory manipulation / multi-agent split attack | Not covered | **Open** | known limitation |
| A-24 | OS sandbox escape (Windows AppContainer/Linux container) | No OS backend | **Partial** | Linux unshare network/PID verified; Windows/macOS absent |
| A-25 | Full remote Streamable HTTP bypass | Not supported | **Open/partial** | HTTP slice only |
| A-26 | Runtime kill switch after anomaly | Advisory only | **Open** | known limitation |
| A-27 | AISVS/OWASP evidence-backed compliance | Static mapping | **Partial** | AISVS-style CLI; not certified |
| A-28 | Remote HTTP/SSE MCP bypass | No bridge | **Fixed on loopback** | bridge/SSE tests; no TLS/OAuth |
| A-29 | Stdio identity/approval bypass | None | **Partial** | VGAT + signed approval; approver UI absent |
| A-30 | Rogue agent keeps running after block | Advisory | **Mitigated** | kill-on-block exit 3 |
| A-31 | Linux network/PID escape | No OS backend | **Partial** | unshare verify; filesystem not isolated |
| A-32 | Memory/multi-agent poisoning | None | **Partial** | MemoryGuard/DelegationGraph libraries |

---

## 2. What was actually executed

The platform suite (`test/run-platform.js`) executes 18 tests. The critical
attack probes are code-level and local; no external network destination was
contacted.

Selected observed results:

```text
plugin target config marker:     false
process constructor escape:      success false / "process is not defined"
resources/prompts injection:     withheld/redacted
base64/split/entropy secret:     blocked
junction outside path:           denied
Windows destructive commands:    blocked
signed audit tamper:             invalid
VGAT replay:                     VG_REPLAY_DETECTED
JWT replay:                      VG_REPLAY_DETECTED
HTTP no token:                   401
HTTP denied policy:              403
```

The legacy `vm` runner was not re-tested as a trusted boundary because the
design and implementation explicitly label it unsafe. Do not use it for
untrusted code.

---

## 3. Performance benchmark

Reproduce with:

```bash
node scripts/security-bench.js --out reports/benchmark.json
```

Environment: Windows 11, Node v24.14.0, i5-11400H, 34 GB RAM.

| Operation | Iterations | Throughput | p95 |
|---|---:|---:|---:|
| identity issue+verify | 1,000 | 3,752 ops/s | 0.34 ms |
| strict policy evaluate | 5,000 | 3,359 ops/s | 0.38 ms |
| injection scan (1 KB) | 2,000 | 16,182 ops/s | 0.066 ms |
| signed audit append+fsync | 200 | 169 ops/s | — |
| signed audit verify (200) | 200 | 39 ms total | — |
| process sandbox spawn+run | 5 | 13.4 ops/s | 78 ms |
| MCP engine checkToolCall | 2,000 | 1,464 ops/s | 0.84 ms |

**Interpretation:** these measure local CPU-bound primitives. They do not
measure full gateway throughput, large-result inspection cost, filesystem
variance, Windows AppContainer/VM startup, or concurrent sessions. Do not
compare across machines without the same hardware metadata.

---

## 4. Detection metrics still missing

No precision/recall/false-positive corpus has been built for:

- prompt injection paraphrases/multilingual;
- tool poisoning;
- malicious skills;
- memory/multi-agent attacks.

The 18 tests verify specific regressions, not statistical detection quality.
The target is a labeled attack/benign corpus with per-detector precision,
recall, FPR and bypass rate (`research/14`), but that is not implemented.

---

## 5. Regression policy

Every fixed attack above has a regression test. Every open/partial item remains
in `known-limitations.md` and must not be described as protected. Future work
must add a failing test before a fix and keep the legacy suite green.
