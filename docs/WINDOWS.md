# Windows Setup and Testing

## Verified environment

- Windows 11
- Node.js 24.14.0 for this audit/implementation run
- PowerShell 7
- Git for Windows

The platform security suite is run on Windows in CI (`.github/workflows/ci.yml`,
`platform-security` matrix) and locally with:

```powershell
npm ci
node test/run-platform.js
node bin/cli.js sandbox backends
```

## What works on Windows

- `vibeguard scan`, `mcp`, `mcp-firewall`, `mcp-audit`, `skill-scan`,
  `agent-risk`, `owasp-coverage`, `agent-monitor`
- policy validation/signing, signed audit verification
- process sandbox with a fresh V8 context and Node permission model
- Windows destructive-command blocking in `shell-guard` (`Remove-Item`,
  `del /f /s /q`, `format X:`, `diskpart`, `vssadmin`, `bcdedit`,
  `powershell -enc`, security-setting changes)
- junction/symlink-aware path policy (uses `fs.realpathSync.native`)

## What is not available or verified

- **The Windows AppContainer backend is implemented** (`windows-appcontainer`).
  It creates a per-run profile, runs the child in an AppContainer with no
  capability SIDs, and confines it with a Job Object. Run
  `node bin/cli.js sandbox verify` once per host; `sandbox backends` reports
  `verified=NO` until that suite passes.
- **No WFP filter is installed.** Network denial comes from the AppContainer
  capability model (no internetClient/privateNetworkClientServer), not a
  per-process firewall rule. The AppContainer boundary shares the host kernel.
  Windows and Program Files remain readable under AppContainer's default grants;
  the user profile, credentials and writable host paths are denied.
- The process backend is same-user and does not block network at the Windows
  kernel/firewall layer. It is a code-execution convenience boundary, not a
  security boundary.
- macOS hardware-VM isolation is implemented (`macos-vm`, QEMU/HVF) but needs a
  caller-supplied guest image; it reports unavailable/unverified until that
  image passes `sandbox verify` on a macOS host.
- The HTTP gateway has not been integrated with a Windows service/TLS deployment.
- Windows CI is configured; results depend on the GitHub runner and are not
  asserted by this local report beyond the Windows run recorded in
  `reports/security-test-results.md`.

## Windows commands

```powershell
# scan and policy work
node bin/cli.js scan .
node bin/cli.js policy validate docs/security-policy.strict.example.json `
  --pub docs/security-policy.strict.example.pub.pem

# verify and use the AppContainer boundary (fails closed until verified)
node bin/cli.js sandbox verify
node bin/cli.js sandbox "const x = 1 + 2; x" --isolation os

# explicit non-OS sandbox (reports unverified)
node bin/cli.js sandbox "const x = 1 + 2; x" --isolation process

# show truthful isolation status and evidence
node bin/cli.js sandbox backends --json
```

## Paths and junctions

Policy path checks canonicalize with `fs.realpathSync.native`. A junction inside
a project that points outside is denied as outside-project; credential paths
are matched on the canonical target. Legitimate external paths must be added
explicitly to policy `allowedPaths`/allow resources.

## Shell behavior

`shell-guard` now blocks the Windows commands above. It is still a denylist and
cannot guarantee that every destructive PowerShell/cmd construct is covered.
For untrusted code, use a real OS/VM backend when one is available; do not rely
on the denylist.
