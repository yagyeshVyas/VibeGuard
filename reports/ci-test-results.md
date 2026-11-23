# CI test results

Current status: [`docs/STATUS.md`](../docs/STATUS.md).

## Local audit host — 2026-11-23

| Command | Result |
|---|---|
| `node test/run.js` | **653 passed, 0 failed** |
| `node test/run-platform.js` | **50 passed, 0 failed** |
| `node bin/cli.js mcp-firewall --selftest` | **12/12 passed** |
| `node bin/cli.js sandbox "const x=2+3; x" --isolation os --json` | success, output `5`, `verified: true` |
| `node bin/cli.js sandbox verify` (Windows AppContainer) | **11/11 evidence classes passed** |
| `npm run lint` | 0 errors (warnings only) |

Environment: Windows 11 `10.0.26300`, x64, Node 24, PowerShell 5.1.
The AppContainer suite was run live; its verification cache is host-bound and
does not transfer to another machine.

## GitHub Actions

The `full-suite` matrix runs `node test/run.js` on `windows-latest`,
`ubuntu-latest` and `macos-latest` (Node 22) and uploads each complete log as an
artifact. The `platform-security` job runs the focused suite on Windows and
macOS.

CI run link and per-OS results are recorded after the workflow run. Do not
treat the local Windows count as macOS isolation evidence; the macOS VM backend
still requires a caller-supplied guest image and a passing guest probe.
