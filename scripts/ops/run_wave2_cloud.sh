#!/usr/bin/env bash
# Wave 2 X1：云机上的证明任务编排（P0-06 → P0-07/P0-08）。
#
# 设计约束（与 bench_scale.py 的文档一致）：
#   * 出证**必须串行**：每个证明进程固定地板 ~10.15 GiB，groth16 更高；
#     并发只会互相推向 OOM 并污染峰值内存读数。本脚本用 flock 拒绝并发。
#   * 续跑：bench_scale.py 自带续跑；中断后重跑同一条命令即可。
#   * 预算闸：--budget-min 超时后把剩余点标成「未跑（预算用尽）」，不假装跑完。
#   * 不自动 sudo：安装依赖见 scripts/ops/provision_cloud.sh。
#
# 用法：
#   bash scripts/ops/run_wave2_cloud.sh --stage groth16
#   bash scripts/ops/run_wave2_cloud.sh --stage scale --budget-min 600
#   bash scripts/ops/run_wave2_cloud.sh --stage surface --timeout 3600
#   bash scripts/ops/run_wave2_cloud.sh --stage all --budget-min 600
#
# 产物：
#   bench/results/scale-cloud.json / .md          （P0-06/P0-08）
#   bench/results/privacy_surface.json / .md      （P0-07）
set -euo pipefail

cd "$(dirname "$0")/../.."
REPO="$(pwd)"

STAGE="all"
BUDGET_MIN="600"
TIMEOUT="3600"
OUT="bench/results/scale-cloud.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage) STAGE="$2"; shift 2 ;;
    --budget-min) BUDGET_MIN="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '1,40p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

echo "== Wave 2 X1 =="
echo "repo        : $REPO"
echo "stage       : $STAGE"
echo "budget(min) : $BUDGET_MIN"
echo "timeout(s)  : $TIMEOUT"
echo "out         : $OUT"
echo ""

# 1) 起飞前的资源闸：groth16 / scale / surface 都要求 ≥64 GiB + cargo-prove
python3 scripts/ops/check_wave2_env.py --require P0-06_groth16
echo ""

# 2) 串行锁：同一台机器上不允许两个证明编排同时跑
LOCK="/tmp/pop-wave2-cloud.lock"
exec 9>"$LOCK"
if ! flock -n 9; then
  echo "[FAIL] 另一个 Wave 2 云机任务正在跑（$LOCK）。出证必须串行。" >&2
  exit 1
fi

run_groth16() {
  echo "== P0-06: groth16 首轮（3 档长度 × 3 档规则）=="
  SP1_PROVER=cpu python3 bench/bench_scale.py \
    --out "$OUT" \
    --proof-modes groth16 \
    --lengths 200,2000,10000 \
    --rules 1,2,3 \
    --budget-min "$BUDGET_MIN"
}

run_scale() {
  echo "== P0-08: 全矩阵（core+groth16，含 50k 长度）=="
  SP1_PROVER=cpu python3 bench/bench_scale.py \
    --out "$OUT" \
    --proof-modes core,groth16 \
    --lengths 200,2000,10000,50000 \
    --rules 1,2,3,6 \
    --budget-min "$BUDGET_MIN"
}

run_surface() {
  echo "== P0-07: 隐私面探针（core+groth16）=="
  SP1_PROVER=cpu python3 bench/bench_privacy_surface.py \
    --tiers core,groth16 \
    --timeout "$TIMEOUT" \
    --out-dir bench/results
}

case "$STAGE" in
  groth16) run_groth16 ;;
  scale)   run_scale ;;
  surface) run_surface ;;
  all)
    run_groth16
    run_surface
    run_scale
    ;;
  *) echo "unknown stage: $STAGE（可用 groth16|scale|surface|all）" >&2; exit 2 ;;
esac

echo ""
echo "== 完成 =="
echo "scale          : $OUT 与 ${OUT%.json}.md"
echo "privacy surface: bench/results/privacy_surface.{json,md}"
echo ""
echo "下一步：把结果文件拷回主仓库；不要在云机上跑全量 unittest。"
