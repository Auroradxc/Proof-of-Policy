#!/usr/bin/env bash
# Retry installing Foundry (anvil/forge) so the P7-c on-chain anchoring e2e can run.
# Network here is intermittent: this script fails fast when the network is down and
# is safe to run repeatedly (lock file; no partial installs).
#
# Exit: 0 installed+verified | 2 network still blocked | 1 attempted but failed
#
# Usage:  bash scripts/retry_install_foundry.sh [--check]
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$HERE/.install_foundry.lock"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

log() { echo "[foundry $(date +%H:%M:%S)] $*"; }

# already installed?
if command -v anvil >/dev/null 2>&1 && command -v forge >/dev/null 2>&1; then
  log "already installed: $(anvil --version 2>&1 | head -1)"
  exit 0
fi
for c in "$HOME/.foundry/bin/anvil" "$HOME/.foundry/bin/forge"; do
  [ -x "$c" ] && export PATH="$HOME/.foundry/bin:$PATH"
done
if command -v anvil >/dev/null 2>&1 && command -v forge >/dev/null 2>&1; then
  log "already installed (~/.foundry): $(anvil --version 2>&1 | head -1)"
  exit 0
fi

# ---- network probe (cheap; mirrors truncate when blocked) ----
probe() {
  for u in "https://github.com" "https://gh-proxy.com" \
           "https://foundry.paradigm.xyz"; do
    code=$(curl -s -o /dev/null --max-time 8 -w "%{http_code}" "$u" 2>/dev/null || echo 000)
    [ "$code" != "000" ] && { echo "$u"; return 0; }
  done
  return 1
}
SRC="$(probe)" || { log "network blocked; nothing to do"; exit 2; }
log "network up via $SRC"
[ "$CHECK_ONLY" = "1" ] && exit 0

mkdir "$LOCK" 2>/dev/null || { log "another attempt running"; exit 0; }
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

install_script() {
  # try the official installer, then the same script through the gh-proxy mirror
  if curl -sL --max-time 60 https://foundry.paradigm.xyz -o /tmp/foundry_install.sh 2>/dev/null \
     && [ -s /tmp/foundry_install.sh ]; then return 0; fi
  if curl -sL --max-time 60 \
      "https://gh-proxy.com/https://raw.githubusercontent.com/foundry-rs/foundry/master/foundryup/install" \
      -o /tmp/foundry_install.sh 2>/dev/null && [ -s /tmp/foundry_install.sh ]; then return 0; fi
  return 1
}

if ! install_script; then log "could not fetch foundry installer"; exit 1; fi
log "running foundryup installer ..."
bash /tmp/foundry_install.sh >/tmp/foundry_install.log 2>&1 || { log "installer failed"; tail -5 /tmp/foundry_install.log; exit 1; }

export PATH="$HOME/.foundry/bin:$PATH"
if ! command -v foundryup >/dev/null 2>&1; then log "foundryup missing after install"; exit 1; fi
log "foundryup (downloading binaries) ..."
foundryup >/tmp/foundryup.log 2>&1 || { log "foundryup failed"; tail -8 /tmp/foundryup.log; exit 1; }

if command -v anvil >/dev/null 2>&1 && command -v forge >/dev/null 2>&1; then
  log "DONE: $(anvil --version 2>&1 | head -1) | $(forge --version 2>&1 | head -1)"
  exit 0
fi
log "installed but anvil/forge not on PATH"; exit 1
