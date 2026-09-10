#!/usr/bin/env bash
# 等网络可用时安装 LangChain/LangGraph，然后跑真正的框架测试。
# 面向「apt/PyPI 都被部分封禁」的环境，逐级降级：
#   1. 轻量连通性探测（被封时镜像会截断响应，不能只看状态码），
#   2. 依次尝试 venv 里的 pip → apt 装 pip → 直接下载 pip wheel 自举，
#   3. 装依赖，4. 跑测试。
#
# 退出码：0 已安装并测完 | 2 网络仍不可用 | 1 安装失败。
# 用 mkdir 锁避免并发重复执行（后台轮询与 cron 可能同时触发）。
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"
LOCK="$HERE/.install_frameworks.lock"
mkdir "$LOCK" 2>/dev/null || { echo "[retry] another attempt running"; exit 0; }
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

PY="${PYTHON:-python3}"
VPY="$HERE/.venv/bin/python"

log() { echo "[retry $(date +%H:%M:%S)] $*"; }

# ---- 1) 探测可用索引：被墙时镜像会返回 200 但内容被截断，所以按实际下载字节数判断 ----
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

# ---- 2) 拿到一个可用的 pip 执行方式（venv → apt → 直接下 wheel） ----
PIPRUN=""      # 命令模板："<pyrun> -m pip" 或 "<pyrun> <wheel>/pip"
RUNPY="$PY"    # 装依赖 / 跑测试实际使用的 python
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

# ---- 3) 安装依赖（--user 避免动系统包；镜像同样要 --trusted-host） ----
log "installing frameworks ..."
if ! $PIPRUN install --user --disable-pip-version-check --timeout 60 --retries 5 \
      -i "$BASE" --trusted-host "$HOST" -r requirements-frameworks.txt; then
  log "install failed"; exit 1
fi

# ---- 4) 先跑框架测试，再跑全量测试（都只留尾部输出，避免日志刷屏） ----
log "installed; running framework tests"
"$RUNPY" -m unittest tests.test_frameworks -v 2>&1 | tail -20
log "full suite"
"$RUNPY" -m unittest discover tests 2>&1 | tail -4
log "DONE"
exit 0
