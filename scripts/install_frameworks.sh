#!/usr/bin/env bash
# Best-effort installer for the optional LangChain / LangGraph adapters.
# Tries a few indexes because some environments block PyPI/CDN hosts.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

PY="${PYTHON:-python3}"
if [ ! -d .venv ]; then
  echo "creating venv (.venv) ..."
  "$PY" -m venv .venv || { echo "venv failed; need python3-venv"; exit 1; }
fi
VPY=".venv/bin/python"
PIP="$VPY -m pip"

INDEXES=(
  "https://pypi.org/simple"
  "https://pypi.tuna.tsinghua.edu.cn/simple"
  "https://mirrors.aliyun.com/pypi/simple"
  "https://mirrors.ustc.edu.cn/pypi/web/simple"
)

for idx in "${INDEXES[@]}"; do
  echo "== trying index: $idx"
  if ! $VPY -m pip --version >/dev/null 2>&1; then
    echo "   pip missing in venv (install python3-venv / python3-pip)"; exit 1
  fi
  if $PIP install --disable-pip-version-check --timeout 30 --retries 3 \
        -i "$idx" --trusted-host "$(echo "$idx" | awk -F/ '{print $3}')" \
        -r requirements-frameworks.txt; then
    echo "== installed from $idx"
    echo "run tests with: .venv/bin/python -m unittest discover tests -v"
    exit 0
  fi
  echo "   failed from $idx"
done

echo "all indexes failed (network blocked?). The adapters remain install-guarded;"
echo "offline tests still pass. Retry later or from a network that can reach PyPI."
exit 1
