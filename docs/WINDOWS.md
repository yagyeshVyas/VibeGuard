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

- **No Windows AppContainer/Job Object/WFP backend is implemented in this
  build.** `sandbox backends` prints `verified=NO` on Windows. The Linux-only
  `unshare` backend can be verified from WSL (`node bin/cli.js sandbox verify`)
  but that is Linux network/PID isolation, not Windows isolation. Do not claim
  Windows OS isolation.
- The process backend is same-user and does not block network at the Windows
  kernel/firewall layer. It is a code-execution convenience boundary, not a
  security boundary.
- macOS-specific isolation is not available; Windows/Linux only for the
  primitives that exist.
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

# explicit non-OS sandbox (reports unverified)
node bin/cli.js sandbox "const x = 1 + 2; x" --isolation process

# show truthful isolation status
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
