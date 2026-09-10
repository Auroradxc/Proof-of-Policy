#!/usr/bin/env bash
# 重试安装 Foundry（anvil/forge），好让 P7-c 的链上锚定 e2e 能跑。
# 本机网络时断时续：所以网络不通时快速失败，且可反复执行（有锁文件，不会留下半成品）。
#
# 退出码：0 已安装并验证 | 2 网络仍不可用 | 1 尝试过但失败
#
# 用法：  bash scripts/retry_install_foundry.sh [--check]
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$HERE/.install_foundry.lock"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

log() { echo "[foundry $(date +%H:%M:%S)] $*"; }

# 已经装好了就直接退出（幂等）
if command -v anvil >/dev/null 2>&1 && command -v forge >/dev/null 2>&1; then
  log "already installed: $(anvil --version 2>&1 | head -1)"
  exit 0
fi
# 装在 ~/.foundry 但没进 PATH 的情况也要认
for c in "$HOME/.foundry/bin/anvil" "$HOME/.foundry/bin/forge"; do
  [ -x "$c" ] && export PATH="$HOME/.foundry/bin:$PATH"
done
if command -v anvil >/dev/null 2>&1 && command -v forge >/dev/null 2>&1; then
  log "already installed (~/.foundry): $(anvil --version 2>&1 | head -1)"
  exit 0
fi

# ---- 网络探测：必须真的抓到内容才算通（网络抖动时主机根路径返回 200/302 是假阳性）----
probe() {
  # 先试最小且最可靠的：API 元数据，再试安装脚本本身
  for u in "https://api.github.com/repos/foundry-rs/foundry/releases/latest" \
           "https://raw.githubusercontent.com/foundry-rs/foundry/master/foundryup/install" \
           "https://foundry.paradigm.xyz"; do
    sz=$(curl -sL --max-time 12 -o /dev/null -w "%{size_download}" "$u" 2>/dev/null || echo 0)
    if [ "${sz:-0}" -gt 200 ]; then echo "$u"; return 0; fi
  done
  return 1
}
SRC="$(probe)" || { log "network blocked; nothing to do"; exit 2; }
log "network up via $SRC"
[ "$CHECK_ONLY" = "1" ] && exit 0

mkdir "$LOCK" 2>/dev/null || { log "another attempt running"; exit 0; }
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

install_script() {
  # 先试官方安装脚本，失败再走 gh-proxy 镜像拿同一份脚本
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

# 安装脚本只装 foundryup，二进制还得再跑一次 foundryup 才下载
export PATH="$HOME/.foundry/bin:$PATH"
if ! command -v foundryup >/dev/null 2>&1; then log "foundryup missing after install"; exit 1; fi
log "foundryup (downloading binaries) ..."
foundryup >/tmp/foundryup.log 2>&1 || { log "foundryup failed"; tail -8 /tmp/foundryup.log; exit 1; }

if command -v anvil >/dev/null 2>&1 && command -v forge >/dev/null 2>&1; then
  log "DONE: $(anvil --version 2>&1 | head -1) | $(forge --version 2>&1 | head -1)"
  exit 0
fi
log "installed but anvil/forge not on PATH"; exit 1
