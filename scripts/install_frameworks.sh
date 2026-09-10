#!/usr/bin/env bash
# 尽力而为地安装可选的 LangChain / LangGraph 适配层。
# 之所以轮询多个索引：某些环境会封禁 PyPI/CDN 主机，换镜像才装得上。
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

# 框架只装进独立 venv，避免污染系统 Python
PY="${PYTHON:-python3}"
if [ ! -d .venv ]; then
  echo "creating venv (.venv) ..."
  "$PY" -m venv .venv || { echo "venv failed; need python3-venv"; exit 1; }
fi
VPY=".venv/bin/python"
PIP="$VPY -m pip"

# 索引按「官方 → 国内镜像」排序，逐个失败再换下一个
INDEXES=(
  "https://pypi.org/simple"
  "https://pypi.tuna.tsinghua.edu.cn/simple"
  "https://mirrors.aliyun.com/pypi/simple"
  "https://mirrors.ustc.edu.cn/pypi/web/simple"
)

# --trusted-host 取 URL 的 host 部分：镜像站多为 http/证书不全，不跳过校验会直接失败
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

# 全部失败不算致命：适配层有 import 守卫，离线测试仍可跑；之后再重试
echo "all indexes failed (network blocked?). The adapters remain install-guarded;"
echo "offline tests still pass. Retry later or from a network that can reach PyPI."
exit 1
