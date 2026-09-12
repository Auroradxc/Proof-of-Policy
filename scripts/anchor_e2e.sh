#!/usr/bin/env bash
# P7-c 一条命令跑通「链上锚定」端到端：
#
#   起本地 Anvil → 部署 contracts/Anchor.sol → 跑 agent 会话 demo（每张证书上链）
#   → 第三方 verify_session --rpc 独立核对（含反例对照）
#
# 用法：
#   bash scripts/anchor_e2e.sh                 # 默认不生成 SP1 证明（快，~10s）
#   SP1_PROVER=cpu bash scripts/anchor_e2e.sh --prove   # 附带真实 Core 证明（本机实测 3:10 / 峰值 10.2 GiB）
#   RPC=http://127.0.0.1:8545 bash scripts/anchor_e2e.sh   # 复用已在跑的节点
#   bash scripts/anchor_e2e.sh --keep           # 结束后不关闭 anvil
#
# 退出码：0 全部 PASS；1 任一步骤失败。
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

RPC="${RPC:-http://127.0.0.1:8545}"
PORT="${PORT:-8545}"
OUT_DIR="${OUT_DIR:-$HERE/scripts/examples/out/chain}"
PROVE=0; KEEP=0
for a in "$@"; do
  case "$a" in
    --prove) PROVE=1 ;;
    --keep)  KEEP=1 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done

log()  { echo -e "\n\033[1m[anchor-e2e]\033[0m $*"; }
fail() { echo -e "\033[31m[anchor-e2e] FAIL:\033[0m $*" >&2; exit 1; }

# ---- 0) foundry ----
export PATH="$PATH:$HOME/.foundry/bin"
command -v anvil >/dev/null || fail "anvil not found (bash scripts/retry_install_foundry.sh)"
command -v cast  >/dev/null || fail "cast not found (bash scripts/retry_install_foundry.sh)"
log "foundry: $(anvil --version 2>&1 | head -1)"

ANVIL_PID=""
started_node=0
cleanup() {
  if [ -n "$ANVIL_PID" ] && [ "$KEEP" = "0" ]; then
    kill "$ANVIL_PID" 2>/dev/null && log "stopped anvil (pid $ANVIL_PID)"
  fi
}
trap cleanup EXIT

# ---- 1) 节点（没有就自己起一个） ----
if cast block-number --rpc-url "$RPC" >/dev/null 2>&1; then
  log "reusing node at $RPC (chain-id $(cast chain-id --rpc-url "$RPC"))"
else
  log "starting local anvil on port $PORT ..."
  anvil --port "$PORT" --silent >/tmp/anchor_e2e_anvil.log 2>&1 &
  ANVIL_PID=$!
  started_node=1
  for _ in $(seq 1 40); do
    cast block-number --rpc-url "$RPC" >/dev/null 2>&1 && break
    sleep 0.25
  done
  cast block-number --rpc-url "$RPC" >/dev/null 2>&1 || { tail -5 /tmp/anchor_e2e_anvil.log; fail "anvil did not come up"; }
  log "anvil up (pid $ANVIL_PID), chain-id $(cast chain-id --rpc-url "$RPC")"
fi

# ---- 2) 部署 Anchor 合约（字节码来自入库的 contracts/Anchor.json） ----
log "deploying Anchor.sol ..."
DEPLOY_JSON="$OUT_DIR/deploy.json"
python3 scripts/deploy_anchor.py --rpc "$RPC" --out "$DEPLOY_JSON" || fail "deploy failed"
CONTRACT=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['address'])" "$DEPLOY_JSON")
echo "contract = $CONTRACT"

# ---- 3) agent 会话 demo：每张证书锚定（链上 + 本地账本） ----
DEMO_ARGS=(--out-dir "$OUT_DIR" --rpc "$RPC" --contract "$CONTRACT")
[ "$PROVE" = "1" ] || DEMO_ARGS+=(--no-prove)
log "running demo (prove=$PROVE) → $OUT_DIR"
SP1_PROVER=cpu python3 scripts/demo_e2e.py "${DEMO_ARGS[@]}" || fail "demo failed"
[ -f "$OUT_DIR/session.json" ] || fail "session.json missing"

# ---- 4) 第三方独立核对（仅凭公开产物 + RPC） ----
log "independent verification (verify_session --rpc) ..."
python3 scripts/verify_session.py --session "$OUT_DIR/session.json" \
        --rpc "$RPC" --contract "$CONTRACT" || fail "verify_session reported FAIL"

# ---- 5) 反例对照：未登记的摘要必须读回 0（证明上面的 PASS 不是恒真） ----
UNKNOWN="0x8f2a1c4e6b9d0f3a5c7e1b4d6f8a0c2e4b6d8f0a1c3e5b7d9f0a2c4e6b8d0f3a"
UNKNOWN_TS=$(cast call --rpc-url "$RPC" "$CONTRACT" "anchoredAt(bytes32)(uint256)" "$UNKNOWN")
log "negative control: unknown digest anchoredAt = $UNKNOWN_TS (expected 0)"
[ "${UNKNOWN_TS%% *}" = "0" ] || fail "negative control failed: unknown digest reads back non-zero"

log "ALL PASS ✅"
echo "  session : $OUT_DIR/session.json"
echo "  contract: $CONTRACT  (rpc $RPC)"
if [ -n "$ANVIL_PID" ] && [ "$KEEP" = "1" ]; then echo "  anvil   : still running (pid $ANVIL_PID)"; fi
