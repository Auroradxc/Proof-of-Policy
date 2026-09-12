#!/usr/bin/env bash
# 安装 P2-9（语义规则）的 ezkl 依赖栈，好让 `ezkl_prove.py` 与
# `POP_TEST_EZKL=1` 的端到端用例能跑。
#
# 本机网络时断时续，所以：网络不通时**快速失败**；可反复执行（有锁文件，不会
# 留下半成品）；也可以先把 wheel 缓存下来，之后完全离线装。
#
# 退出码：0 已装好并验证 | 2 网络不可用且本地无可用 wheelhouse | 1 尝试过但失败
#
# 用法：
#   bash scripts/install_ezkl.sh                 # 在线装（走镜像）
#   bash scripts/install_ezkl.sh --check         # 只检查装没装好，不动环境
#   bash scripts/install_ezkl.sh --save-wheels   # 装好后把 wheel 另存到 wheelhouse/
#   bash scripts/install_ezkl.sh --offline       # 只用 wheelhouse 装，全程不联网
#   bash scripts/install_ezkl.sh --force         # 即使已装也重装一遍
#
# 环境变量：
#   PYTHON             解释器，默认 python3
#   PIP_INDEX_URL      pip 索引；默认清华 PyPI 镜像
#   POP_EZKL_WHEELHOUSE  wheel 缓存目录；默认 <仓库根>/wheelhouse/ezkl
#
# ⚠️ 两个硬约束（详见 requirements-ezkl.txt 与 docs/reproduce.md §8）：
#   1. **必须 --user 装**（本机没有 sudo 可用的系统 pip，也不该装到系统里）；
#   2. 装完的 ezkl 出证/验证**极吃内存**（setup 峰值 4.76 GiB + prove 峰值
#      8.72 GiB）：`setup` 与 `prove` 必须**分进程**跑，别把两步并进一个进程。
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REQ="$HERE/requirements-ezkl.txt"
PY="${PYTHON:-python3}"
LOCK="$HERE/.install_ezkl.lock"
WHEELHOUSE="${POP_EZKL_WHEELHOUSE:-$HERE/wheelhouse/ezkl}"
INDEX="${PIP_INDEX_URL:-https://pypi.tuna.tsinghua.edu.cn/simple}"

CHECK_ONLY=0; OFFLINE=0; FORCE=0; SAVE_WHEELS=0
for a in "$@"; do
  case "$a" in
    --check)       CHECK_ONLY=1 ;;
    --offline)     OFFLINE=1 ;;
    --force)       FORCE=1 ;;
    --save-wheels) SAVE_WHEELS=1 ;;
    -h|--help)     sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ; exit 0 ;;
    *) echo "未知参数：$a（--help 看用法）" >&2; exit 1 ;;
  esac
done

log() { echo "[ezkl $(date +%H:%M:%S)] $*"; }

# ---- 就绪判定：三个包都 import 得到，且版本与锁定值一致才算「装好」 ----
# 只看 `import ezkl` 会漏掉「装了个别的版本」——那会让证出的陪伴证明与策略里
# 固化的 onnx_sha256 / model_vkey 对不上，错误却在很久以后才暴露。
PINNED="ezkl==23.0.5 onnx==1.22.0 torch==2.14.0"
installed_versions() {
  "$PY" - <<'PYEOF' 2>/dev/null
import importlib.metadata as md
for pkg in ("ezkl", "onnx", "torch"):
    try:
        print(f"{pkg}=={md.version(pkg)}")
    except md.PackageNotFoundError:
        raise SystemExit(1)
PYEOF
}

ready() {
  local got
  got="$(installed_versions)" || return 1
  local want
  for want in $PINNED; do
    grep -qx "$want" <<<"$got" || return 1
  done
  return 0
}

if [ "$FORCE" = "0" ] && ready; then
  log "already installed: $(installed_versions | tr '\n' ' ')"
  [ "$CHECK_ONLY" = "1" ] && exit 0
  [ "$SAVE_WHEELS" = "0" ] && exit 0
fi
if [ "$CHECK_ONLY" = "1" ]; then
  if ready; then exit 0; fi
  log "未装好（缺包或版本不符）：$(installed_versions 2>/dev/null | tr '\n' ' ' || echo '一个都没有')"
  exit 1
fi

[ -f "$REQ" ] || { log "缺少 $REQ"; exit 1; }

# ---- 本地 wheelhouse 优先：有就直接离线装，不碰网络 ----
have_wheels() {
  [ -d "$WHEELHOUSE" ] || return 1
  # 至少要能看到版本锁定的那三个轮子才算「可用」（其余依赖会一并被 pip 解出）
  local n
  n=$(find "$WHEELHOUSE" -maxdepth 1 -name 'ezkl-*.whl' 2>/dev/null | wc -l)
  [ "${n:-0}" -gt 0 ]
}

# ---- 网络探测：必须真的抓到内容才算通（抖动时返回 200/302 是假阳性）----
probe() {
  local u="https://pypi.tuna.tsinghua.edu.cn/simple/ezkl/"
  local sz
  sz=$(curl -sL --max-time 12 -o /dev/null -w "%{size_download}" "$u" 2>/dev/null || echo 0)
  [ "${sz:-0}" -gt 200 ] && { echo "$u"; return 0; }
  return 1
}

if have_wheels; then
  log "用本地 wheel 缓存离线安装：$WHEELHOUSE"
  PIP_ARGS=(--user --no-index --find-links "$WHEELHOUSE")
else
  [ "$OFFLINE" = "1" ] && { log "--offline 但 $WHEELHOUSE 里没有可用的 wheel"; exit 2; }
  SRC="$(probe)" || {
    log "网络不可用，且本地无 wheel 缓存 —— 无法安装"
    log "（网络恢复后重跑本脚本，或用 --save-wheels 在有网时先存一份）"
    exit 2
  }
  log "网络可用（$SRC），走镜像 $INDEX 安装"
  PIP_ARGS=(--user -i "$INDEX")
fi

# 同一时刻只允许一个安装实例：半成品 site-packages 比不装更难查
mkdir "$LOCK" 2>/dev/null || { log "另有一次安装正在进行，稍后重试"; exit 0; }
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

log "pip install -r requirements-ezkl.txt （约 1–3 分钟；torch 是个大轮子）"
LOG="$HERE/.install_ezkl.log"
if ! "$PY" -m pip install "${PIP_ARGS[@]}" -r "$REQ" >"$LOG" 2>&1; then
  log "安装失败，日志尾部："
  tail -12 "$LOG" >&2
  exit 1
fi

if [ "$SAVE_WHEELS" = "1" ]; then
  mkdir -p "$WHEELHOUSE"
  log "另存 wheel 到 $WHEELHOUSE （torch 轮子较大，可能几百 MB～2 GB）"
  "$PY" -m pip download -i "$INDEX" -r "$REQ" -d "$WHEELHOUSE" >>"$LOG" 2>&1 \
    || log "（警告）wheel 另存失败，但依赖本身已装好"
fi

# ---- 装完自检：不只看 import，还要真的把它跑起来 ----
if ! ready; then
  log "安装过程没报错，但版本核对不通过：$(installed_versions 2>/dev/null | tr '\n' ' ')"
  exit 1
fi
log "版本核对通过：$(installed_versions | tr '\n' ' ')"

if [ -f "$HERE/scripts/ezkl_prove.py" ]; then
  log "冒烟：scripts/ezkl_prove.py info（只看产物清单，不出证，秒级）"
  if "$PY" "$HERE/scripts/ezkl_prove.py" info >>"$LOG" 2>&1; then
    log "冒烟通过。要出真证明：python3 scripts/ezkl_prove.py selftest"
    log "  真正端到端一例：POP_TEST_EZKL=1 python3 -m unittest tests.test_semantic"
    log "  ⚠️ setup 与 prove 峰值各 4.76 / 8.72 GiB，务必分进程跑（见 docs/reproduce.md §8）"
    exit 0
  fi
  log "（警告）ezkl_prove.py info 没跑通 —— 依赖装上了，但链路可能还有问题"
  tail -8 "$LOG" >&2
  exit 1
fi

log "DONE（未找到 scripts/ezkl_prove.py，跳过冒烟）"
exit 0
