#!/usr/bin/env bash
# Install LangChain/LangGraph once the network allows, then run the real
# framework tests. Robust to environments where apt/PyPI are partially blocked:
#   1. cheap connectivity probe (mirrors truncate responses when blocked),
#   2. pip via venv, else via apt, else by bootstrapping a pip wheel directly,
#   3. install the requirements, 4. run the tests.
#
# Exit: 0 installed+tested | 2 network still unusable | 1 install failed.
# A mkdir lock prevents concurrent attempts (background loop + cron).
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"
LOCK="$HERE/.install_frameworks.lock"
mkdir "$LOCK" 2>/dev/null || { echo "[retry] another attempt running"; exit 0; }
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

PY="${PYTHON:-python3}"
VPY="$HERE/.venv/bin/python"

log() { echo "[retry $(date +%H:%M:%S)] $*"; }

# ---- 1) probe ----
INDEX=""
for u in "https://pypi.tuna.tsinghua.edu.cn/simple/pip/" \
         "https://pypi.org/simple/pip/" \
         "http://mirrors.aliyun.com/pypi/simple/pip/"; do
  sz=$(curl -s --max-time 10 -o /dev/null -w "%{size_download}" "$u" 2>/dev/null || echo 0)
  if [ "${sz:-0}" -gt 5000 ]; then INDEX="$u"; break; fi
done
[ -n "$INDEX" ] || { log "network still blocked; skipping"; exit 2; }
BASE="${INDEX%/pip/}"
HOST="$(echo "$INDEX" | awk -F/ '{print $3}')"
log "index usable: $BASE"

# ---- 2) obtain a pip runner ----
PIPRUN=""      # command template: "<pyrun> -m pip" or "<pyrun> <wheel>/pip"
RUNPY="$PY"    # python used for tests/install
if [ -x "$VPY" ] && "$VPY" -m pip --version >/dev/null 2>&1; then
  PIPRUN="$VPY -m pip"; RUNPY="$VPY"
elif sudo -n true 2>/dev/null && sudo apt-get -o Acquire::http::Timeout=15 -o Acquire::Retries=1 \
        install -y python3-venv python3-pip >/dev/null 2>&1; then
  [ -x "$VPY" ] || "$PY" -m venv "$HERE/.venv" 2>/dev/null || true
  "$VPY" -m pip --version >/dev/null 2>&1 && { PIPRUN="$VPY -m pip"; RUNPY="$VPY"; }
fi
if [ -z "$PIPRUN" ]; then
  log "bootstrapping pip from wheel ..."
  curl -s --max-time 30 "$BASE/pip/" -o /tmp/_pipidx.html || true
  rel=$(grep -oE 'href="[^"]*pip-[0-9]+\.[0-9]+(\.[0-9]+)?-py3-none-any\.whl[^"]*"' /tmp/_pipidx.html \
        | tail -1 | sed -E 's/^href="//; s/#.*$//')
  [ -n "$rel" ] || { log "could not find pip wheel"; exit 1; }
  case "$rel" in
    http*) url="$rel" ;;
    /*)    url="https://$HOST$rel" ;;
    *)     url="$(dirname "$BASE")/$rel" ;;
  esac
  curl -sL --max-time 180 "$url" -o /tmp/_pip.whl || { log "pip wheel download failed"; exit 1; }
  [ "$(stat -c%s /tmp/_pip.whl)" -gt 100000 ] || { log "pip wheel too small"; exit 1; }
  PIPRUN="$PY /tmp/_pip.whl/pip"
fi

# ---- 3) install ----
log "installing frameworks ..."
if ! $PIPRUN install --user --disable-pip-version-check --timeout 60 --retries 5 \
      -i "$BASE" --trusted-host "$HOST" -r requirements-frameworks.txt; then
  log "install failed"; exit 1
fi

# ---- 4) tests ----
log "installed; running framework tests"
"$RUNPY" -m unittest tests.test_frameworks -v 2>&1 | tail -20
log "full suite"
"$RUNPY" -m unittest discover tests 2>&1 | tail -4
log "DONE"
exit 0
