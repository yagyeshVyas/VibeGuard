# Independent Security Review — Post-Remediation

**Date:** 2026-11-23  
**Reviewer:** `IndependentRedTeam` (separate read-only reviewer agent)  
**Baseline reviewed:** `dd27c88` plus documentation edits  
**Nature:** independent in-session code review with attempted local probes. This
is **not** an external human audit, not a certified assessment, and not a
substitute for a paid third-party penetration test.

## Execution limits

The reviewer ran on a Windows host. Its Windows process-capture path reported
`capability_unavailable`; the fallback Frida runner worked for simple commands
but mangled the generated Node runner, so the reviewer did **not** obtain live
product results for the AppContainer, MCP firewall or `sandbox --isolation os`
probes. Those live results are recorded separately in
[`ci-test-results.md`](ci-test-results.md) and the AppContainer evidence in
[`docs/STATUS.md`](../docs/STATUS.md). macOS was static-only; no guest image or
macOS host was available.

## Findings and disposition

| ID | Severity | Finding | Disposition |
|---|---|---|---|
| R-01 | Medium-High | URL authority normalization bypassed `deniedHosts` with trailing root dots, userinfo, IPv4-mapped IPv6 and numeric IPv4 forms. | **Fixed** in `src/action-guard.js` (`canonicalHost`/WHATWG URL parsing); regression test covers five forms. |
| R-02 | Medium | MCP secrets could pass through tool descriptions, JSON-RPC errors and server-originated notification/request params; only `msg.result` was scrubbed. | **Fixed** in `src/mcp-firewall.js`; definitions, errors and params are scrubbed before forwarding. Tests added. |
| R-03 | Medium | Strict mode coerced `defaultAction:"allow"` but not `"warn"` to block, so a policy could forward unknown tools. | **Fixed** in `src/agent-policy.js`; strict warn now blocks. Test added. |
| R-04 | Medium | Strict `resources/read` used a shallow URI regex; Windows credential files and Chrome profile paths passed when `resources/read` was allowlisted. | **Fixed**; strict mode now rejects credential-store/metadata URIs and `file:` URIs outside the project. Test added. |
| R-05 | Medium | Tool pins and policy files are project-writable by an agent with `fs.write`. | **Accepted design limitation**; documented. Pins are a drift detector, not a tamper-proof trust anchor. |
| R-06 | Low-Medium | AppContainer stale-profile cleanup trusted `.vg-owner` names; a planted marker could name a different profile. | **Fixed**; marker name must equal the profile directory. Live cleanup suite still passes. |
| R-07 | Low | Staged `node.exe` is checked by size only. | **Accepted residual**; sandboxed code can replace it but remains in the same AppContainer, so this is not a host escape. |
| R-08 | Low | A process-sandbox comment claimed a network-blocking prelude that does not exist. | **Fixed**; comment now states that Node's permission model does not restrict network. |
| R-09 | Residual | Path policy only inspected path-named keys; a tool with an arbitrary key could pass a path. | **Improved**: known credential path shapes are now checked regardless of key. Arbitrary path keys remain a server-trust boundary. |
| R-10 | Info | macOS `host-file-not-visible` probe uses a host path that is not mounted in the guest; it is a weak positive signal. | **Documented**; macOS VM remains unverified without a live guest. |

## No new live-confirmed bypass

The reviewer found no live-confirmed host escape or strict-default bypass. The
strongest findings were conditional on an explicitly allowlisted network or
resource tool and are addressed above. Residual risks remain: Windows
AppContainer shares the host kernel and has no WFP filter; macOS VM verification
is image-dependent; tool pins/policy are project-writable; and external human
penetration testing is outstanding.
