#!/usr/bin/env bash
# 一条命令复现 PoP 的纯 Python 参考层 + 证书/验证链路（宿主 fast 模式）。
#
# 用法：
#   bash scripts/ops/reproduce_artifact.sh
#   bash scripts/ops/reproduce_artifact.sh --out-dir /tmp/pop-artifact
#   bash scripts/ops/reproduce_artifact.sh --no-build    # 缺 pop-script 时直接报错，不自动构建
#
# 做什么（按顺序）：
#   1. 编译策略包 → ConstraintSpec（打印 policy_hash）
#   2. scripts/demo/demo_all.sh --out-dir … ：8 条支路走宿主校验（不产生 SP1 证明）
#   3. scripts/verify/verify_session.py ：只用公开产物做第三方独立验证
#   4. tests.test_policy_commit + tests.test_doc_links ：纯 Python 冒烟
#
# 不做什么（刻意划界）：
#   · 不出 SP1 / groth16 / compressed 证明 —— 出证需要 ~10 GiB 内存与数分钟；
#   · 不调用真实 LLM —— demo 缺省是离线桩（终端会写 `fake (offline)`）；
#   · 不覆盖云机规模 / 真实 LLM 的猜测熵 k —— 见 docs/runbook-wave2.md。
#
# 前置：
#   · Python 3.10+
#   · 宿主驱动 circuits/target/release/pop-script（脚本会在缺失时自动构建；
#     构建需要 Rust + SP1 工具链，但**不出证**。只想跑纯 Python 的话用 Dockerfile）。
#   · demo 支路①需要框架依赖：python3 -m pip install -r requirements-frameworks.txt
#
# 退出码：0 = 全部步骤通过；非 0 = 失败（demo 里的 SKIP 不算失败，例如缺 ezkl/foundry）。

set -euo pipefail

# 仓库根：按标记向上找（与 scripts/_bootstrap.py / demo_all.sh 相同的一对标记）。
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$HERE"
while [ ! -d "$REPO/policydsl" ] && [ "$REPO" != "/" ]; do REPO="$(dirname "$REPO")"; done
[ -d "$REPO/circuits" ] || { echo "找不到仓库根（从 $HERE 向上）" >&2; exit 1; }
cd "$REPO"

OUT_DIR="${OUT_DIR:-$REPO/scripts/examples/out/artifact}"
BUILD=1
while [ $# -gt 0 ]; do
  case "$1" in
    --out-dir)
      shift
      [ $# -gt 0 ] || { echo "--out-dir 需要参数" >&2; exit 2; }
      OUT_DIR="$1" ;;
    --no-build) BUILD=0 ;;
    -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

# 转成绝对路径：demo_all.sh 会自己 cd，相对路径会指到别处。
case "$OUT_DIR" in
  /*) ;;
  *) OUT_DIR="$REPO/$OUT_DIR" ;;
esac
mkdir -p "$OUT_DIR"

step() { printf '\n=== %s ===\n' "$*"; }
ok()   { printf '[OK] %s\n' "$*"; }

# ---------------------------------------------------------------- 预检 ----
python3 - <<'PY' || exit 2
import sys
if sys.version_info < (3, 10):
    raise SystemExit("需要 Python >= 3.10，当前 %s" % sys.version.split()[0])
PY

DRIVER="$REPO/circuits/target/release/pop-script"
if [ ! -x "$DRIVER" ]; then
  if [ "$BUILD" = 0 ]; then
    echo "缺宿主驱动：$DRIVER" >&2
    echo "先构建（需要 Rust + SP1 工具链；只构建宿主驱动，不出证）：" >&2
    echo "  cd circuits && cargo build --release -p pop-script" >&2
    exit 2
  fi
  echo "未找到宿主驱动，开始构建 pop-script（首次较慢；只构建 host 驱动，不出证）..."
  ( cd "$REPO/circuits" && cargo build --release -p pop-script )
fi
[ -x "$DRIVER" ] || { echo "构建后仍缺 $DRIVER" >&2; exit 2; }

# demo 支路①会实例化 LangChain 的离线桩；缺框架依赖时提前给一条可执行的命令，
# 而不是让 demo 半路 FAIL。
if ! python3 -c "import langchain_core" >/dev/null 2>&1; then
  echo "demo 支路①需要 langchain-core。先装：" >&2
  echo "  python3 -m pip install -r requirements-frameworks.txt" >&2
  exit 2
fi

# ------------------------------------------------- 1) 编译策略（Python 层）--
step "1/4 编译策略（Python 参考层）"
SPEC="$OUT_DIR/policy.spec.json"
python3 -m policydsl compile policy_packs/eu_ai_act_v1.json > "$SPEC"
POLICY_HASH=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "$SPEC")
ok "ConstraintSpec → $SPEC"
echo "     policy_hash = $POLICY_HASH"

# ------------------------------------------------- 2) demo_all fast（无证明）--
step "2/4 全链路 demo（fast：宿主校验，不出 SP1 证明）"
DEMO_DIR="$OUT_DIR/all"
if ! bash scripts/demo/demo_all.sh --out-dir "$DEMO_DIR"; then
  echo "demo 有步骤 FAIL —— 日志在 $DEMO_DIR/logs/*.log" >&2
  exit 1
fi
ok "demo 报告 → $DEMO_DIR/REPORT.md"

# ------------------------------------------------- 3) 第三方独立验证 --------
step "3/4 第三方独立验证（只用公开产物复算）"
SESSION="$DEMO_DIR/policy/session.json"
[ -f "$SESSION" ] || {
  echo "缺 $SESSION —— demo 的「公开模式主干」没有产出 session.json" >&2
  exit 1
}
if ! python3 scripts/verify/verify_session.py --session "$SESSION"; then
  echo "verify_session 未通过" >&2
  exit 1
fi

# ------------------------------------------------- 4) 纯 Python 冒烟 --------
step "4/4 纯 Python 冒烟（证书承诺 + 文档链接）"
python3 -m unittest tests.test_policy_commit tests.test_doc_links
ok "单元测试通过"

# ---------------------------------------------------------------- 汇总 ----
step "完成"
cat <<EOF
模式        : host-fast / no-prove（证书 proof_mode=unproven）
未生成      : SP1 / groth16 / compressed 证明；未调用真实 LLM
产物        :
  $SPEC
  $DEMO_DIR/REPORT.md
  $SESSION
  $DEMO_DIR/logs/*.log
复现边界    : 不含 groth16、真实 LLM 的猜测熵 k、云机规模（见 docs/runbook-wave2.md）
RESULT: PASS
EOF
