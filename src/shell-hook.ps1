# VibeGuard preexec hook for PowerShell.
# Installed by `vibeguard auto` or `vibeguard install-shell-hook`.
# Scans every command BEFORE it runs. Blocks dangerous commands.
#
# POLICY: default-allow. Only block when checkCommand returns blocked=true.
# If VibeGuard cannot load (missing module, node error), ALLOW the command.

function Invoke-VibeGuardCheck {
    param([string]$Command)

    # Override bypass
    if ($env:VG_OVERRIDE -eq "1") { return $true }
    if (-not $Command -or $Command.Trim() -eq "") { return $true }

    # Find shell-guard.js — try multiple paths
    $vgPaths = @()
    if ($VG_SCRIPT_DIR) { $vgPaths += Join-Path $VG_SCRIPT_DIR "shell-guard.js" }
    try { $vgPaths += Join-Path (npm root -g 2>$null) "@yagyeshvyas\vibeguard\src\shell-guard.js" } catch {}
    $vgPaths += Join-Path $PSScriptRoot "shell-guard.js"
    $vgPaths += Join-Path $env:APPDATA "npm\node_modules\@yagyeshvyas\vibeguard\src\shell-guard.js"

    $vgGuard = $null
    foreach ($p in $vgPaths) {
        if ($p -and (Test-Path $p)) { $vgGuard = $p; break }
    }

    # FAIL OPEN: if we can't find shell-guard.js, allow the command
    if (-not $vgGuard) { return $true }

    try {
        $output = node -e "
            try {
                const { checkCommand } = require('$vgGuard');
                const r = checkCommand(process.argv[1]);
                if (r.blocked) {
                    process.stdout.write(JSON.stringify(r));
                    process.exit(1);
                }
            } catch(e) {
                process.exit(0);
            }
        " $Command 2>$null

        if ($LASTEXITCODE -eq 1 -and $output) {
            $info = $output | ConvertFrom-Json
            Write-Host ""
            Write-Host "  [VibeGuard] BLOCKED: $($Command.Substring(0, [Math]::Min(100, $Command.Length)))" -ForegroundColor Red
            Write-Host "  Reason:   $($info.reason)" -ForegroundColor Red
            Write-Host "  Severity: $($info.severity)" -ForegroundColor Red
            Write-Host ""
            Write-Host "  Override: `$env:VG_OVERRIDE=1" -ForegroundColor Yellow
            Write-Host ""
            return $false
        }
    } catch {
        # FAIL OPEN: any error means allow
    }
    return $true
}

# Use PSReadLine to intercept Enter key
if (Get-Module -ListAvailable -Name PSReadLine) {
    Set-PSReadLineKeyHandler -Key Enter -ScriptBlock {
        param($key, $arg)

        $line = $null
        $cursor = $null
        [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)

        if (-not $line -or $line.Trim() -eq "") {
            [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
            return
        }

        # Override bypass
        if ($env:VG_OVERRIDE -eq "1") {
            [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
            return
        }

        # Find shell-guard.js
        $vgPaths = @()
        if ($VG_SCRIPT_DIR) { $vgPaths += Join-Path $VG_SCRIPT_DIR "shell-guard.js" }
        try { $vgPaths += Join-Path (npm root -g 2>$null) "@yagyeshvyas\vibeguard\src\shell-guard.js" } catch {}
        $vgPaths += Join-Path $PSScriptRoot "shell-guard.js"
        $vgPaths += Join-Path $env:APPDATA "npm\node_modules\@yagyeshvyas\vibeguard\src\shell-guard.js"

        $vgGuard = $null
        foreach ($p in $vgPaths) {
            if ($p -and (Test-Path $p)) { $vgGuard = $p; break }
        }

        # FAIL OPEN: if we can't find it, allow
        if (-not $vgGuard) {
            [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
            return
        }

        $blocked = $false
        try {
            $output = node -e "
                try {
                    const { checkCommand } = require('$vgGuard');
                    const r = checkCommand(process.argv[1]);
                    if (r.blocked) {
                        process.stdout.write(JSON.stringify(r));
                        process.exit(1);
                    }
                } catch(e) {
                    process.exit(0);
                }
            " $line 2>$null

            if ($LASTEXITCODE -eq 1 -and $output) {
                $blocked = $true
                $info = $output | ConvertFrom-Json
                Write-Host ""
                Write-Host "  [VibeGuard] BLOCKED: $($line.Substring(0, [Math]::Min(100, $line.Length)))" -ForegroundColor Red
                Write-Host "  Reason:   $($info.reason)" -ForegroundColor Red
                Write-Host "  Severity: $($info.severity)" -ForegroundColor Red
                Write-Host ""
                Write-Host "  Override: `$env:VG_OVERRIDE=1" -ForegroundColor Yellow
                Write-Host ""
                [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
                return
            }
        } catch {
            # FAIL OPEN
        }

        if (-not $blocked) {
            [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
        }
    }
}