# CI test results

Current status: [`docs/STATUS.md`](../docs/STATUS.md).

## Local audit host — 2026-11-23

| Command | Result |
|---|---|
| `node test/run.js` | **659 passed, 0 failed** |
| `node test/run-platform.js` | **50 passed, 0 failed** |
| `node bin/cli.js mcp-firewall --selftest` | **12/12 passed** |
| `node bin/cli.js sandbox "const x=2+3; x" --isolation os --json` | success, output `5`, `verified: true` |
| `node bin/cli.js sandbox verify` (Windows AppContainer) | **11/11 evidence classes passed** |
| `npm run lint` | 0 errors (warnings only) |

Environment: Windows 11 (`10.0.26300`), x64, Node 24, PowerShell 5.1.
The AppContainer suite was run live; its verification cache is host-bound and
does not transfer to another machine.

## GitHub Actions

Workflow run [`45102610378`](https://github.com/yagyeshVyas/VibeGuard/actions/runs/45102610378)
completed successfully on commit `f1fc374` (all jobs shown below passed):

| Job | OS | Node | Result |
|---|---|---|---|
| full suite | Windows | 22 | **654 passed, 0 failed** |
| full suite | Ubuntu | 22 | **654 passed, 0 failed** |
| full suite | macOS | 22 | **654 passed, 0 failed** |
| platform security | Windows | 22 | **50 passed, 0 failed** |
| platform security | macOS | 22 | **50 passed, 0 failed** |
| test | Ubuntu | 18, 20, 22 | success |

Each full-suite job uploads `full-suite-<os>-latest.txt` as an artifact. The
macOS job proves the full suite on macOS, not that the macOS hardware-VM
backend booted: that backend still requires a caller-supplied guest image and a
passing guest probe on a macOS host.
