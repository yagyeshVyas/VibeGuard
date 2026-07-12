#!/usr/bin/env bash
# VibeGuard preexec hook for bash/zsh.
# Installed by `vibeguard auto` or `vibeguard install-shell-hook`.
# Scans every command BEFORE it runs. Blocks dangerous commands.
#
# POLICY: default-allow. Only block when checkCommand returns blocked=true.
# If VibeGuard cannot load (missing module, node error), ALLOW the command.
# A guard that bricks the terminal is worse than no guard.

__vibeguard_check() {
  local cmd="$1"

  # Override bypass
  if [ -n "$VG_OVERRIDE" ]; then return 0; fi

  # Find shell-guard.js — try multiple paths
  local vg_guard=""
  for p in \
    "$VG_SCRIPT_DIR/shell-guard.js" \
    "$(npm root -g 2>/dev/null)/vibeguard/src/shell-guard.js" \
    "$(dirname "$(readlink -f "$BASH_SOURCE" 2>/dev/null || echo "$0")")/shell-guard.js" \
    "$HOME/.npm-global/lib/node_modules/vibeguard/src/shell-guard.js" \
    "/usr/local/lib/node_modules/vibeguard/src/shell-guard.js" \
    "/usr/lib/node_modules/vibeguard/src/shell-guard.js"; do
    if [ -f "$p" ]; then vg_guard="$p"; break; fi
  done

  # FAIL OPEN: if we can't find shell-guard.js, allow the command
  if [ -z "$vg_guard" ]; then return 0; fi

  # Run checkCommand — only block on explicit blocked=true
  local output
  output=$(node -e "
    try {
      const { checkCommand } = require('$vg_guard');
      const r = checkCommand(process.argv[1]);
      if (r.blocked) {
        process.stdout.write(JSON.stringify(r));
        process.exit(1);
      }
    } catch(e) {
      // FAIL OPEN: any error means allow
      process.exit(0);
    }
  " "$cmd" 2>/dev/null)

  local exitcode=$?

  # Exit 0 = allowed, exit 1 = blocked (with JSON on stdout)
  if [ $exitcode -eq 1 ] && [ -n "$output" ]; then
    echo ""
    echo -e "  \033[31m[VibeGuard] BLOCKED:\033[0m \033[1m${cmd:0:100}\033[0m"
    echo "$output" | node -e "
      try {
        const d = JSON.parse(require('fs').readFileSync(0,'utf8'));
        console.log('  \033[31mReason:\033[0m   ' + (d.reason || 'unknown'));
        console.log('  \033[31mSeverity:\033[0m ' + (d.severity || 'unknown'));
      } catch(e) {
        console.log('  \033[31mReason:\033[0m   blocked by VibeGuard');
      }
    " 2>/dev/null
    echo ""
    echo -e "  \033[33mOverride:\033[0m VG_OVERRIDE=1 <command>"
    echo ""
    return 1
  fi

  # Exit 0 or empty output = allowed (fail open)
  return 0
}

# bash: use DEBUG trap
if [ -n "$BASH_VERSION" ]; then
  __vibeguard_preexec() {
    if ! __vibeguard_check "$BASH_COMMAND"; then
      return 1
    fi
  }
  trap '__vibeguard_preexec' DEBUG
fi

# zsh: use preexec hook
if [ -n "$ZSH_VERSION" ]; then
  __vibeguard_zsh_preexec() {
    if ! __vibeguard_check "$1"; then
      return 1
    fi
  }
  preexec_functions+=(__vibeguard_zsh_preexec)
fi