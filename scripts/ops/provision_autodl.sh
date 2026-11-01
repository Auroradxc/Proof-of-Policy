#!/usr/bin/env bash
# AutoDL 云机装配：把 X1（P0-06/07/08）要的东西一次装齐，并在**动手之前**
# 把「这台机器根本跑不出 groth16」这件事挡住。
#
# 为什么要有它（与 provision_cloud.sh 的分工）：
#   * provision_cloud.sh 是**通用清单**，只打印、不执行，且每行都带 sudo；
#   * 本文是**AutoDL 专用**，真的执行，并处理这个平台特有的三个坑：
#       1. 容器里没有 sudo（你本来就是 root）；
#       2. `/proc/meminfo` 可能报的是宿主内存，64 GiB 闸门会假 PASS；
#       3. 系统盘只有 30 GB，编译产物必须落到数据盘 /root/autodl-tmp。
#   平台背景与选型见 docs/ops-autodl.md。
#
# 用法：
#   bash scripts/ops/provision_autodl.sh            # 体检 + 安装（可反复执行）
#   bash scripts/ops/provision_autodl.sh --check    # 只体检，不动环境，秒级
#   bash scripts/ops/provision_autodl.sh --force    # 内存不达标也继续装（不推荐）
#
# 退出码：0 装好且体检通过 | 2 硬件不达标（**没装任何东西**）| 1 安装过程失败
#
# 环境变量：
#   POP_CLOUD_MEM_GIB   最低内存（GiB），默认 64 —— 与 bench_scale.py 的
#                       MODE_MIN_MEM_MB["groth16"] 同口径，别自己调低
#   CARGO_TARGET_DIR    编译产物目录；缺省自动指向数据盘
set -uo pipefail

# 仓库根：从本文件向上找**同时含** policydsl/ 与 circuits/ 的目录
# （与 scripts/_bootstrap.py、install_ezkl.sh 用同一对标记）。
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [ ! -d "$HERE/policydsl" ] && [ "$HERE" != "/" ]; do HERE="$(dirname "$HERE")"; done
[ -d "$HERE/circuits" ] || { echo "找不到仓库根（从 ${BASH_SOURCE[0]} 向上）" >&2; exit 1; }

CHECK_ONLY=0; FORCE=0
for a in "$@"; do
  case "$a" in
    --check)   CHECK_ONLY=1 ;;
    --force)   FORCE=1 ;;
    -h|--help) sed -n '2,23p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数：$a（--help 看用法）" >&2; exit 1 ;;
  esac
done

NEED_MEM_GIB="${POP_CLOUD_MEM_GIB:-64}"
DATA_DISK="/root/autodl-tmp"

log()  { echo "[provision $(date +%H:%M:%S)] $*"; }
warn() { echo "[provision $(date +%H:%M:%S)] ⚠  $*" >&2; }

# ---------------------------------------------------------------------------
# 1. 硬件体检：先读 cgroup，再读 /proc/meminfo
#
# 为什么 cgroup 优先：容器里 /proc/meminfo 常常报**宿主**内存（几百 GB），
# 于是 check_wave2_env.py 与 bench_scale.py 的 64 GiB 闸门会**假 PASS**，
# 而你在真实的 60 GB 配额上跑到第 40 分钟收一个 SIGKILL。两者不一致时，
# 以 cgroup 为准，并把两个数都打出来（那个不一致本身就是结论）。
# ---------------------------------------------------------------------------
cfgb() {  # 读 cgroup 内存上限（字节）。读不到 / 无上限 → 空
  local v=""
  if [ -r /sys/fs/cgroup/memory.max ]; then
    v="$(cat /sys/fs/cgroup/memory.max 2>/dev/null)"
  elif [ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
    v="$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null)"
  fi
  case "$v" in ''|max|*[!0-9]*) return 1 ;; esac
  # cgroup v1 的「无上限」是一个巨大的哨兵值，按「读不到」处理
  [ "$v" -lt 1500000000000 ] 2>/dev/null || return 1
  echo "$v"
}

meminfo_bytes() {
  awk '/^MemTotal:/ {printf "%.0f\n", $2*1024; exit}' /proc/meminfo 2>/dev/null
}

CG_BYTES="$(cfgb || echo '')"
MI_BYTES="$(meminfo_bytes || echo '')"
MEM_BYTES="${CG_BYTES:-$MI_BYTES}"
MEM_GIB="$(awk -v b="${MEM_BYTES:-0}" 'BEGIN{printf "%.1f", b/1073741824}')"
MI_GIB="$(awk -v b="${MI_BYTES:-0}" 'BEGIN{printf "%.1f", b/1073741824}')"
# CPU 同理：容器里 nproc 报的是**宿主**核数（AutoDL 上常见 128），
# 真实可用的只有 cpu.max 配额。这个数决定 cargo/SP1 该开几个 worker，
# 直接用 128 会严重超卖，编译反而更慢。
cgroup_cpus() {
  [ -r /sys/fs/cgroup/cpu.max ] || return 1
  local q p
  read -r q p < /sys/fs/cgroup/cpu.max || return 1
  [ "$q" = "max" ] && return 1
  [ "$p" -gt 0 ] 2>/dev/null || return 1
  awk -v q="$q" -v p="$p" 'BEGIN{c=q/p; printf "%.0f\n", (c<1?1:c)}'
}
HOST_CPU="$(nproc 2>/dev/null || echo '?')"
CPU="$(cgroup_cpus || echo "$HOST_CPU")"

log "CPU      : ${CPU} 核"
log "内存     : ${MEM_GIB} GiB（按 cgroup 计）"
if [ -n "$CG_BYTES" ] && [ -n "$MI_BYTES" ] \
   && [ "$(awk -v a="$CG_BYTES" -v b="$MI_BYTES" 'BEGIN{print (b>a*1.5)?"1":"0"}')" = "1" ]; then
  warn "/proc/meminfo 报 ${MI_GIB} GiB，cgroup 只有 ${MEM_GIB} GiB —— 这就是那个「假 PASS」陷阱"
  warn "bench_scale.py 读的是 /proc/meminfo；它判 PASS 不等于真装得下，一切以 cgroup 为准"
fi
if [ "$HOST_CPU" != "?" ] && [ "$HOST_CPU" != "$CPU" ]; then
  warn "nproc 报 ${HOST_CPU} 核（宿主），cgroup 配额只有 ${CPU} 核 —— 并行度一律按 ${CPU} 设"
fi

if ! awk -v m="$MEM_GIB" -v n="$NEED_MEM_GIB" 'BEGIN{exit !(m+0 >= n+0)}'; then
  cat >&2 <<EOF

================================================================
 这里停下：内存 ${MEM_GIB} GiB < ${NEED_MEM_GIB} GiB
================================================================
 groth16 的闸门（bench_scale.py:MODE_MIN_MEM_MB）读的就是这个数，
 差 1–2 GiB 不是「慢一点」，是**整档被跳过**（skipped），而 groth16
 正是这次租机的唯一目的。详见 docs/ops-autodl.md §1。

 60 / 62 GB 的机器同样过不了 —— 按 ≥90 GB 挑，留 1.4 倍余量。
 确实要在不合规的机器上装（例如只做探测）：加 --force，但结果不能
 当 T1 的交付物。

 换机器后重跑本脚本即可；本脚本未改动任何环境。
================================================================
EOF
  [ "$FORCE" = "1" ] || exit 2
  warn "--force：继续安装，但 groth16 大概率跑不出结论"
fi

# 磁盘：系统盘 30 GB 放不下编译；数据盘是唯一的落点
if [ -d "$DATA_DISK" ]; then
  FREE_GIB="$(df -BG --output=avail "$DATA_DISK" 2>/dev/null | tail -1 | tr -dc '0-9')"
  log "数据盘   : ${DATA_DISK} 可用 ${FREE_GIB:-?} GiB"
  if [ -n "${FREE_GIB:-}" ] && [ "$FREE_GIB" -lt 40 ]; then
    warn "数据盘只剩 ${FREE_GIB} GiB —— rustup + cargo-prove + circuits/target 约 25 GB，余量太小"
  fi
else
  warn "没有 $DATA_DISK（不是 AutoDL 实例？）—— 编译产物会落在系统盘，注意 30 GB 上限"
fi

# Miniconda / conda 镜像里 python 不在 /usr/bin，PATH 得自己补
for d in "$HOME/miniconda3/bin" /root/miniconda3/bin /opt/conda/bin; do
  if [ -x "$d/python3" ]; then
    export PATH="$d:$PATH"
    log "Python   : $("$d/python3" -V 2>&1)（$d）"
    break
  fi
done

if [ "$CHECK_ONLY" = "1" ]; then
  log "--check：只体检，未改动环境"
  exit 0
fi

# ---------------------------------------------------------------------------
# 2. 系统包
#
# AutoDL 容器里你是 root，`sudo` 常常根本不存在 —— provision_cloud.sh 打印的
# `sudo apt-get …` 会直接 command not found。这里按身份决定加不加 sudo。
# ---------------------------------------------------------------------------
if [ "$(id -u)" = "0" ]; then SUDO=""; else
  command -v sudo >/dev/null 2>&1 || { log "非 root 且没有 sudo —— 无法装系统包"; exit 1; }
  SUDO="sudo"
fi

# --- 国内取源 ---
# 在 AutoDL 上实测（2026-11-01）：apt 走华为云很快；但 github.com 超时、
# go.dev 握手失败、static.rust-lang.org 单文件 12 s。所以 rustup 走清华、
# Go 走 golang.google.cn、cargo 走 rsproxy。POP_CN_MIRROR=0 可关掉。
if [ "${POP_CN_MIRROR:-1}" = "1" ]; then
  export RUSTUP_DIST_SERVER="${RUSTUP_DIST_SERVER:-https://mirrors.tuna.tsinghua.edu.cn/rustup}"
  export RUSTUP_UPDATE_ROOT="${RUSTUP_UPDATE_ROOT:-https://mirrors.tuna.tsinghua.edu.cn/rustup/rustup}"
  GO_URL_BASE="${GO_URL_BASE:-https://golang.google.cn/dl}"
  GO_VERSION_URL="${GO_VERSION_URL:-https://golang.google.cn/VERSION?m=text}"
  log "取源：rustup→清华、Go→golang.google.cn、cargo→rsproxy"
else
  GO_URL_BASE="${GO_URL_BASE:-https://go.dev/dl}"
  GO_VERSION_URL="${GO_VERSION_URL:-https://go.dev/VERSION?m=text}"
fi

# tzdata/keyboard 之类会在无人值守时卡住等输入，必须非交互
export DEBIAN_FRONTEND=noninteractive

log "apt-get update + 装 build-essential / pkg-config / libssl-dev / git / curl / jq / cmake / libclang-dev"
if ! { $SUDO apt-get update -y && $SUDO apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev git curl jq cmake libclang-dev ca-certificates; }; then
  log "系统包安装失败 —— 看上面的 apt 输出"; exit 1
fi

# ---------------------------------------------------------------------------
# 3. Rust
# ---------------------------------------------------------------------------
export PATH="$HOME/.cargo/bin:$HOME/.sp1/bin:/usr/local/go/bin:$PATH"
if command -v cargo >/dev/null 2>&1; then
  log "Rust 已装：$(cargo --version)"
else
  log "装 Rust（rustup，用户级）"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y >/dev/null \
    || { log "rustup 安装失败"; exit 1; }
  export PATH="$HOME/.cargo/bin:$PATH"
  log "Rust：$(cargo --version)"
fi

# cargo 源替换：crates.io 的 API 在国内不稳，索引能连但下载经常卡住。
# rsproxy 只换下载源，校验和仍按原 crates.io 的，产物不受影响。
if [ "${POP_CN_MIRROR:-1}" = "1" ] && [ ! -f "$HOME/.cargo/config.toml" ]; then
  mkdir -p "$HOME/.cargo"
  cat > "$HOME/.cargo/config.toml" <<'TOML'
# 由 scripts/ops/provision_autodl.sh 写入；删掉本文件即回到官方源
[source.crates-io]
replace-with = "rsproxy-sparse"

[source.rsproxy-sparse]
registry = "sparse+https://rsproxy.cn/index/"
TOML
  log "已写 ~/.cargo/config.toml（crates → rsproxy）"
fi

# ---------------------------------------------------------------------------
# 4. SP1 工具链
#
# 版本以 circuits/Cargo.lock 为准（本仓对齐 v6.7.0）。`cargo prove install`
# 装的是 latest，所以这里**先报出版本**，对不上时明确警告而不是静默继续 ——
# 版本错会让 proof 的 vkey 与仓库里固化的那套对不上，错误要到验证时才暴露。
# ---------------------------------------------------------------------------
#
# 这里有四个坑，2026-11-01 在北京B区 570 机上逐个踩过：
#   1. `curl -L https://sp1.succinct.xyz | bash` 只装 sp1up **本身**，
#      不装 cargo-prove。第二步得跑 `sp1up -v <tag>`。
#   2. 配套 Rust 工具链（~385 MB）官方用 `cargo-prove prove install-toolchain`
#      从 GitHub Releases 取，实测 **~2 KB/s**。
#   3. `install-toolchain` **不复用**已下载的文件：它会把
#      ~/.sp1/rust-toolchain-<triple>.tar.gz 截断重下。先下好再跑没用。
#   4. **不要给这一步开 AutoDL 学术加速**：那个代理做 TLS 中间人，系统 CA
#      里有它的根证书，curl 认、Rust 的 rustls 不认，报错是
#      "Fetching GitHub releases failed" —— 而同一 URL 用 curl 是 200，
#      很容易误判成「GitHub 被墙」。
#
# 所以：**手工下载 + 解包 + rustup toolchain link** 是主路径，不是兜底。
SP1_VERSION="${POP_SP1_VERSION:-v6.7.0}"
SP1_TRIPLE="$(uname -m)-unknown-linux-gnu"
MIRROR_PREFIX="${POP_GH_MIRROR:-https://ghfast.top}"

have_sp1_toolchain() { rustup toolchain list 2>/dev/null | grep -q '^succinct'; }

if command -v cargo-prove >/dev/null 2>&1; then
  log "cargo-prove 已装：$(cargo prove --version 2>/dev/null)"
else
  log "装 sp1up"
  curl -fsSL https://sp1.succinct.xyz | bash >/dev/null 2>&1 || warn "sp1up 安装脚本返回非零"
  export PATH="$HOME/.sp1/bin:$PATH"
  [ -x "$HOME/.sp1/bin/sp1up" ] || { log "sp1up 没装上（PATH=$PATH）"; exit 1; }
  log "sp1up -v ${SP1_VERSION}（拉 cargo-prove 本体）"
  "$HOME/.sp1/bin/sp1up" -v "$SP1_VERSION" || warn "sp1up 返回非零（工具链那半通常在这步失败，下面单独装）"
fi

if have_sp1_toolchain; then
  log "SP1 Rust 工具链已就绪：$(rustup toolchain list | grep '^succinct' | head -1)"
else
  # 版本号直接问二进制要，比猜 tag 可靠
  SP1_TAG="$(strings "$HOME/.sp1/bin/cargo-prove" 2>/dev/null \
    | grep -oE 'succinct-[0-9]+\.[0-9]+\.[0-9]+-64bit' | sort -u | tail -1)"
  SP1_TAG="${SP1_TAG:-succinct-1.94.0-64bit}"
  SP1_URL="https://github.com/succinctlabs/rust/releases/download/${SP1_TAG}/rust-toolchain-${SP1_TRIPLE}.tar.gz"
  TB="$HOME/rust-toolchain-${SP1_TRIPLE}.tar.gz"

  unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
  log "下载工具链 ${SP1_TAG}（走镜像 ${MIRROR_PREFIX}，约 3 分钟）"
  curl -fL -C - --retry 20 --retry-delay 2 --connect-timeout 20 \
    -o "$TB" "${MIRROR_PREFIX}/${SP1_URL}" \
    || { curl -fL -C - --retry 10 -o "$TB" "https://gh-proxy.com/${SP1_URL}" \
         || warn "镜像都没下成功"; }

  if [ -s "$TB" ]; then
    log "解包并 link（约 1 GB 落盘）"
    rm -rf "$HOME/.sp1/toolchain"; mkdir -p "$HOME/.sp1/toolchain"
    if tar -C "$HOME/.sp1/toolchain" -xzf "$TB" && rustup toolchain link succinct "$HOME/.sp1/toolchain"; then
      log "已 link succinct → $HOME/.sp1/toolchain"
    else
      warn "解包/link 失败，退回官方 install-toolchain（会很慢）"
      "$HOME/.sp1/bin/cargo-prove" prove install-toolchain || warn "install-toolchain 也失败"
    fi
  else
    warn "工具链包没下到，退回官方 install-toolchain（会很慢）"
    "$HOME/.sp1/bin/cargo-prove" prove install-toolchain || warn "install-toolchain 也失败"
  fi
fi
log "SP1：$(cargo prove --version 2>/dev/null || echo '未就绪') | 工具链：$(rustup toolchain list 2>/dev/null | grep '^succinct' | head -1 || echo 无)"

LOCKED_SP1="$(grep -oE 'sp1-(sdk|prover)-[0-9]+\.[0-9]+\.[0-9]+' "$HERE/circuits/Cargo.lock" 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
GOT_SP1="$(cargo prove --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
if [ -n "${LOCKED_SP1:-}" ] && [ -n "${GOT_SP1:-}" ] && [ "$LOCKED_SP1" != "$GOT_SP1" ]; then
  warn "cargo-prove 是 ${GOT_SP1}，circuits/Cargo.lock 锁的是 ${LOCKED_SP1} —— 不要用 latest 顶替"
fi

# ---------------------------------------------------------------------------
# 5. Go ≥ 1.24（SP1 的 gnark 包装器要）
# ---------------------------------------------------------------------------
GO_NEED=1.24
need_go() {
  command -v go >/dev/null 2>&1 || return 0
  local v; v="$(go version | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | tr -d 'go')"
  awk -v a="$v" -v b="$GO_NEED" 'BEGIN{exit !(a+0 < b+0)}'
}
if need_go; then
  log "装 Go ${GO_NEED}（apt 自带的通常不够新）"
  GO_TGZ="$(curl -sL "${GO_VERSION_URL}" 2>/dev/null | head -1 | tr -d '[:space:]')"
  case "$GO_TGZ" in go1.*) ;; *) GO_TGZ="go1.24.0"; warn "取不到最新 Go 版本号，退回 ${GO_TGZ}" ;; esac
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  curl -fsSL "${GO_URL_BASE}/${GO_TGZ}.linux-amd64.tar.gz" -o "$TMP/go.tgz" \
    || { log "Go 下载失败（网络？）"; exit 1; }
  $SUDO rm -rf /usr/local/go && $SUDO tar -C /usr/local -xzf "$TMP/go.tgz" \
    || { log "Go 解包失败"; exit 1; }
  export PATH="/usr/local/go/bin:$PATH"
  command -v go >/dev/null 2>&1 && log "已写入 PATH：/usr/local/go/bin —— 请自行加进 ~/.bashrc"
else
  log "Go 已装：$(go version)"
fi

# go mod 默认走 proxy.golang.org（国内 i/o timeout），而 sp1-recursion-gnark-ffi
# 的 build.rs 要现编 gnark —— 不设这个，宿主构建会挂在 gnark 上。
if command -v go >/dev/null 2>&1; then
  go env -w GOPROXY="${GOPROXY_CN:-https://goproxy.cn,direct}" >/dev/null 2>&1 || true
  log "GOPROXY=$(go env GOPROXY)"
fi

# ---------------------------------------------------------------------------
# 6. 编译产物落盘：系统盘 30 GB 装不下，必须指到数据盘
# ---------------------------------------------------------------------------
if [ -d "$DATA_DISK" ]; then
  WANT="$DATA_DISK/cargo-target"
  mkdir -p "$WANT"
  export CARGO_TARGET_DIR="$WANT"
  if ! grep -qs 'CARGO_TARGET_DIR=.*autodl-tmp' "$HOME/.bashrc"; then
    printf '\n# AutoDL：系统盘只有 30 GB，编译产物落数据盘（scripts/ops/provision_autodl.sh 写入）\nexport CARGO_TARGET_DIR=%s\n' "$WANT" >> "$HOME/.bashrc"
    log "已写入 ~/.bashrc：export CARGO_TARGET_DIR=$WANT"
  fi
  log "CARGO_TARGET_DIR=$WANT"
fi

# ---------------------------------------------------------------------------
# 7. 收尾体检：与云机 runbook 同一个判据
# ---------------------------------------------------------------------------
log "跑环境体检（check_wave2_env.py）"
cd "$HERE" || exit 1
if python3 scripts/ops/check_wave2_env.py --require P0-06_groth16; then
  cat <<EOF

----------------------------------------------------------------
 装好了。下一步（务必先进 tmux，编译 1–2 小时）：
   tmux new -s wave2
   cd $HERE
   export SP1_PROVER=cpu
   cargo build --release -p pop-script          # 或按 circuits/README 的入口
   /usr/bin/time -v python3 bench/bench_scale.py \\
     --out bench/results/scale-probe.json \\
     --proof-modes groth16 --lengths 200 --rules 1

 探测通过后**不用换机**，直接接着跑全量：
   bash scripts/ops/run_wave2_cloud.sh --stage all --budget-min 600
----------------------------------------------------------------
EOF
  exit 0
fi

warn "体检没过（见上面的 ⛔ 行）。常见原因：cargo-prove 没进 PATH —— 开新 shell 或 source ~/.bashrc 再试"
exit 1
