#!/usr/bin/env bash
# 全链路 demo：把项目的**各条支路**依次跑一遍，合成一份报告。
#
# 为什么需要它：本项目有若干条端到端支路，每条都有自己的驱动脚本，但没有任何
# 一个入口能把它们串起来看一遍 —— `demo_e2e.py` 只走「公开模式主干」这一条，
# 其余支路各自为政。第一次读仓库的人跑完 demo_e2e 会以为链路已经全覆盖了。
# 本脚本不重新实现任何东西，只是**按依赖顺序调用既有驱动**并如实汇总结果：
# 哪条跑了、哪条跳过了（为什么）、耗时与峰值内存、以及**哪几条是 stand-in**。
#
# 用法：
#   bash scripts/demo_all.sh                # 快速模式：走宿主校验，不出真证明（约半分钟）
#   bash scripts/demo_all.sh --prove        # 出真证明（每条支路数分钟、峰值 ~10 GB，约 25–30 分钟）
#   bash scripts/demo_all.sh --out-dir DIR  # 产物与报告落 DIR
#   bash scripts/demo_all.sh --list         # 只列支路，不跑
#
# 退出码：0 = 所有**应有**的步骤都 PASS；1 = 有步骤 FAIL。
# 跳过（缺依赖）不算失败，但会在报告里单列 —— 跳过与通过必须能分开看，
# 否则「全绿」会变成一句没法核对的话。

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

PROVE=0
LIST=0
OUT_DIR="$HERE/scripts/examples/out/all"
while [ $# -gt 0 ]; do
  case "$1" in
    --prove)   PROVE=1 ;;
    --list)    LIST=1 ;;
    --out-dir) shift; OUT_DIR="$1" ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

export PATH="$PATH:$HOME/.foundry/bin"
[ "$PROVE" = "1" ] && export SP1_PROVER=cpu

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLD=$'\033[1m'; RST=$'\033[0m'
ok()   { printf '%s' "$GRN"; }
warn() { printf '%s' "$YEL"; }

# printf 的 %-Ns 按**字节**补齐，中文列会参差不齐（`公开模式主干` 是 18 字节 12 列，
# `私有模式` 是 12 字节 8 列 —— 都补到 18 字节，右边却差了 6 列）。这里按**显示宽度**
# 补（CJK/全角记 2 列），让 --list 和汇总表在终端里真的对齐。
pad() {  # pad <字符串> <目标显示宽度>
  python3 -c '
import sys, unicodedata
s, n = sys.argv[1], int(sys.argv[2])
w = sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)
sys.stdout.write(s + " " * max(0, n - w))' "$1" "$2"
}

# 同一条同时进终端与 REPORT.md —— 报告才是会被单独读的那份产物，
# 只打在终端上，只读报告的人就看不到（去色后再落盘）。
emit() {
  echo "$1"
  GAPS+=("$(printf '%s' "$1" | sed 's/\x1b\[[0-9;]*m//g')")
}

# ---------------------------------------------------------------- 支路定义 --
#
# 每条支路：`key|中文名|驱动脚本|说明`。顺序即执行顺序（有依赖的排在被依赖者之后）。
LANES=(
  "policy|公开模式主干|scripts/demo_e2e.py|LangChain 流式(含早停) + MCP 工具(参数/结果) + 真 SP1 证明 + 挑战绑定 + 公私模式对比 + 账本"
  "private|私有模式|scripts/private_demo.py|响应承诺 + 逐违规证据承诺 + 脱敏证明(mask_covered) + 证据开示"
  "semantic|语义规则(P2-9)|scripts/ezkl_prove.py|ezkl 陪伴证明：确定性特征图 + 阈值判定，验证方与 SP1 结论**合取**"
  "compose|组合证明(P1-6)|scripts/compose_proof.py|策略半 ∧ 推理半，两个 guest 两个 vkey → 一张组合证书"
  "session|会话聚合(P2-10)|scripts/prove_session.py|一组证书的 Merkle 根 + 三条义务(policy_hash 全同/链无缝/覆盖完整)"
  "multiparty|多证明者(P2-11)|scripts/prove_multiparty.py|按规则类切三段，各角色用自己的键对**自己那段**出证"
  "anchor|链上锚定(P7-c)|scripts/anchor_e2e.sh|起 anvil → 部署 Anchor.sol → 14 张证书摘要上链 → 第三方 --rpc 核对"
  "verify|第三方独立验证|scripts/verify_session.py|只用公开产物(session.json + ledger + proof)复算全部结论"
)

if [ "$LIST" = "1" ]; then
  printf '%s %s %s\n' "$(pad key 12)" "$(pad 中文名 18)" "驱动"
  for l in "${LANES[@]}"; do
    IFS='|' read -r k name drv desc <<<"$l"
    printf '%s %s %s\n' "$(pad "$k" 12)" "$(pad "$name" 18)" "$drv"
    printf '%s %s   %s\n' "$(pad '' 12)" "$(pad '' 18)" "$desc"
  done
  exit 0
fi

rm -rf "$OUT_DIR"; mkdir -p "$OUT_DIR/logs"
SOLO="$OUT_DIR/_solo"     # 供不走 out-dir 参数的驱动（private_demo）用
mkdir -p "$SOLO"

# ---------------------------------------------------------------- 计时工具 --
# 用 /usr/bin/time 量墙钟与峰值 RSS。缺了就退化成 date，并如实标注「未量到内存」。
TIME_BIN=""
if [ -x /usr/bin/time ]; then TIME_BIN=/usr/bin/time; fi

declare -a ROWS=()
declare -a GAPS=()
FAILED=0

run_step() {  # run_step <key> <name> <驱动> <依赖key为空的必要条件> -- <命令...>
  local key="$1" name="$2" drv="$3"; shift 3
  local log="$OUT_DIR/logs/$key.log" tlog="$OUT_DIR/logs/$key.time"
  local t0 t1 wall peak exit_code status

  t0=$(date +%s.%N)
  if [ -n "$TIME_BIN" ]; then
    "$TIME_BIN" -f "%M" -o "$tlog" "$@" >"$log" 2>&1
    exit_code=$?
    # 命令失败时 GNU time 会先往 -o 文件写一行 "Command exited with non-zero
    # status N"，再写统计值 —— 所以取**最后一行**，且只认纯数字。
    peak=$(tail -1 "$tlog" 2>/dev/null)
    case "$peak" in ''|*[!0-9]*) peak="" ;; esac
  else
    "$@" >"$log" 2>&1
    exit_code=$?
    peak=""
  fi
  t1=$(date +%s.%N)
  wall=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')

  if [ "$exit_code" -eq 0 ]; then status="PASS"; else status="FAIL"; FAILED=1; fi
  ROWS+=("$key|$name|$drv|$status|$wall|${peak:--}|$exit_code")
  printf '  %-6s %s %6ss  peak %s\n' "$status" "$(pad "$name" 18)" "$wall" "${peak:-?}KB"
  return 0
}

skip_step() {  # skip_step <key> <name> <驱动> <原因>
  ROWS+=("$1|$2|$3|SKIP|0.0|-|$4")
  printf '  %-6s %-18s %s\n' "SKIP" "$2" "$4"
}

echo "${BLD}全链路 demo${RST}  模式=$([ "$PROVE" = 1 ] && echo 'prove（出真证明）' || echo 'fast（宿主校验，不出证明）')"
echo "  产物：$OUT_DIR"
echo

# 依赖探测：缺什么就如实跳过，不假装通过。
HAVE_EZKL=0
python3 -c "import ezkl" >/dev/null 2>&1 && HAVE_EZKL=1
HAVE_SRS=0
[ -f semantic/artifacts/kzg.srs ] && [ -f semantic/artifacts/model.compiled ] && HAVE_SRS=1
HAVE_ANVIL=0
command -v anvil >/dev/null 2>&1 && command -v cast >/dev/null 2>&1 && HAVE_ANVIL=1

# ---- 1) 公开模式主干 -------------------------------------------------------
PROVE_ARG=(); [ "$PROVE" = 0 ] && PROVE_ARG=(--no-prove)
# anchor_e2e.sh 的旗标是 --prove（没有 --no-prove），所以要单独转一次 —— 漏了这一步
# 的话，--prove 模式下这一条会**悄悄不出证**（日志里 `running demo (prove=0)`），
# 而汇总表仍然报 PASS：正是本脚本要拦的那种「说法 ≠ 产物」。
ANCHOR_ARG=(); [ "$PROVE" = 1 ] && ANCHOR_ARG=(--prove)
run_step policy "公开模式主干" "scripts/demo_e2e.py" \
  python3 scripts/demo_e2e.py "${PROVE_ARG[@]}" --out-dir "$OUT_DIR/policy"
SESSION_JSON="$OUT_DIR/policy/session.json"

# ---- 2) 私有模式 -----------------------------------------------------------
run_step private "私有模式" "scripts/private_demo.py" \
  python3 scripts/private_demo.py "${PROVE_ARG[@]}"

# ---- 3) 语义规则（P2-9）---------------------------------------------------
if [ "$HAVE_EZKL" = 0 ]; then
  skip_step semantic "语义规则(P2-9)" "scripts/ezkl_prove.py" "未装 ezkl（python3 -c 'import ezkl' 失败）"
elif [ "$HAVE_SRS" = 0 ]; then
  skip_step semantic "语义规则(P2-9)" "scripts/ezkl_prove.py" "缺 semantic/artifacts/{kzg.srs,model.compiled}，先跑 ezkl_prove.py setup"
else
  # selftest 是四条文本的端到端自检（含同形异义反例），比单条 prove 更能说明问题。
  run_step semantic "语义规则(P2-9)" "scripts/ezkl_prove.py" \
    python3 scripts/ezkl_prove.py selftest
fi

# ---- 4) 组合证明（P1-6）---------------------------------------------------
run_step compose "组合证明(P1-6)" "scripts/compose_proof.py" \
  python3 scripts/compose_proof.py \
    --pack policy_packs/eu_ai_act_v1.json \
    --response scripts/examples/eu_agent_reply.txt \
    "${PROVE_ARG[@]}" --out-dir "$OUT_DIR/compose"

# ---- 5) 会话聚合（P2-10）—— 依赖上一轮的 session.json ---------------------
if [ ! -f "$SESSION_JSON" ]; then
  skip_step session "会话聚合(P2-10)" "scripts/prove_session.py" \
    "缺 $SESSION_JSON（依赖「公开模式主干」的产物，那一步没有成功产出）"
else
  run_step session "会话聚合(P2-10)" "scripts/prove_session.py" \
    python3 scripts/prove_session.py --session "$SESSION_JSON" \
      "${PROVE_ARG[@]}" --out-dir "$OUT_DIR/session"
fi

# ---- 6) 多证明者（P2-11）---------------------------------------------------
run_step multiparty "多证明者(P2-11)" "scripts/prove_multiparty.py" \
  python3 scripts/prove_multiparty.py \
    --pack policy_packs/eu_ai_act_v1.json \
    --response scripts/examples/eu_agent_reply.txt \
    "${PROVE_ARG[@]}" --out-dir "$OUT_DIR/multiparty"

# ---- 7) 链上锚定 -----------------------------------------------------------
if [ "$HAVE_ANVIL" = 0 ]; then
  skip_step anchor "链上锚定(P7-c)" "scripts/anchor_e2e.sh" "未装 foundry（anvil/cast 不在 PATH），先跑 scripts/retry_install_foundry.sh"
else
  run_step anchor "链上锚定(P7-c)" "scripts/anchor_e2e.sh" \
    env OUT_DIR="$OUT_DIR/anchor" bash scripts/anchor_e2e.sh "${ANCHOR_ARG[@]}"
fi

# ---- 8) 第三方独立验证（闭环）---------------------------------------------
if [ ! -f "$SESSION_JSON" ]; then
  skip_step verify "第三方独立验证" "scripts/verify_session.py" "缺 $SESSION_JSON"
else
  run_step verify "第三方独立验证" "scripts/verify_session.py" \
    python3 scripts/verify_session.py --session "$SESSION_JSON"
fi

# ---------------------------------------------------------------- 汇总报告 --
echo
echo "${BLD}=== 支路汇总 ===${RST}"
printf '%s %s %-6s %8s %10s  %s\n' "$(pad key 12)" "$(pad 支路 18)" \
  "$(pad 结果 6)" "墙钟(s)" "峰值(KB)" "驱动"
printf '%.0s-' {1..92}; echo
for r in "${ROWS[@]}"; do
  IFS='|' read -r k name drv status wall peak extra <<<"$r"
  if [ "$status" = "PASS" ]; then ok; elif [ "$status" = "SKIP" ]; then warn; else printf '%s' "$RED"; fi
  printf '%s %s %-6s %8s %10s  %s\n' "$(pad "$k" 12)" "$(pad "$name" 18)" \
    "$status" "$wall" "$peak" "$drv"
  printf '%s' "$RST"
  [ "$status" = "SKIP" ] && printf '%s %s   ↳ 跳过原因：%s\n' "$(pad '' 12)" "$(pad '' 18)" "$extra"
done

# ------------------------------------------------- 三处「演示印象 ≠ 事实」--
# 这三条不是给人看的免责声明，而是**从产物/源码里现推**的 —— 它们不会随
# 文档更新而漂移。放在报告里是因为跑完上面这些步骤，最容易得到的三个错误
# 结论恰好就是它们。
echo
emit "=== 跑完这份报告后，最容易得到的三个错误结论 ==="

# ① 链上到底验证了什么：从合约 ABI 里数函数名，而不是抄文档。
ABI=contracts/Anchor.json
if [ -f "$ABI" ]; then
  FNS=$(python3 - "$ABI" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
abi = doc["abi"] if isinstance(doc, dict) else doc     # forge 产物把 ABI 放在 "abi" 下
fns = sorted(e["name"] for e in abi
             if isinstance(e, dict) and e.get("type") == "function")
print(", ".join(fns))
PY
)
  emit "① ${YEL}链上只锚定「证书摘要」，不验证证明。${RST}"
  emit "   实测合约函数：$FNS"
  emit "   → 没有 anchorWithProof / verifyProof。链上得到的是「该摘要某时刻已存在」，"
  emit "     不是「已证明的结论」。对外说「链上可验证」是过度声明（见 docs/plan-p0p1p2.md §P1-7）。"
else
  emit "① ${YEL}链上只锚定「证书摘要」，不验证证明${RST}（未找到 $ABI，未能现推函数表）。"
fi

# ② 流式那半用的是不是真模型：从 demo 源码里读它 import 了什么。
FAKE=$(grep -o "GenericFakeChatModel" scripts/demo_e2e.py | head -1)
if [ -n "$FAKE" ]; then
  emit "② ${YEL}流式路径的「LLM」是假的。${RST}"
  emit "   实测 scripts/demo_e2e.py 用的是 LangChain 的 $FAKE（响应写死）。"
  emit "   → 真实的是 **callback 管线**（PoPCallbackHandler 确实跑在 LangChain 流式管线上），"
  emit "     不是模型。接真 LLM 后还会多出两个接口问题：流式分片的切分口径、早停时半截响应的界定。"
fi

# ③ 推理半是不是「某真实 LLM 跑过」的证据：从安全模型里摘它自己的话。
STANDIN=$(grep -o "那是 stand-in，\*\*不是\*\*\"某真实 LLM 跑过\"的证据" docs/security-model.md | head -1)
if [ -n "$STANDIN" ]; then
  emit "③ ${YEL}组合证明里的「推理」是 stand-in。${RST}"
  emit "   docs/security-model.md 原话：$STANDIN（确定性 MLP 前向，非 zkAgent）。"
  emit "   → 组合那一步验收的是**组合机制**（两个 vkey 的键分离），不是推理的成本结构。"
  emit "     这个项目的非目标里就写着「T 确由某个真实 LLM 产出」不在任何层。"
fi

echo
emit "  另有几条与「跑通了」无关、但决定能不能落地的硬约束："
emit "   · 出证的内存地板 ~10.15 GiB、一份 core 证明数分钟 → 出证只能**异步**，"
emit "     不是请求链路里的东西。见 bench/results/proofs.md。"
emit "   · core 证明**不是**零知识，响应内容隐藏对低熵 T 有上界（可被猜测—验证还原）。"
emit "     能主张的是「策略零知识」。见 docs/sp1-zk-audit.md §4。"

# 验证方要花多少钱：从 verify 那条支路**自己的输出**里读，别抄文档。
# 关键区分：真正「验」的耗时 vs 把验证器拉起来的成本 —— 前者常被后者淹没，
# 只看上表那 30 多秒 / 7 GiB 会得出「验证很贵」的错误结论。
if [ -s "$OUT_DIR/logs/verify.log" ]; then
  V_COST=$(python3 - "$OUT_DIR/logs/verify.log" <<'PY'
import re, sys
t = open(sys.argv[1], encoding="utf-8", errors="replace").read()
s = re.search(r'"setup_seconds":\s*([\d.]+)', t)
v = re.search(r'"verify_times_seconds":\s*\[\s*([\d.]+)', t)
print(f"{float(s.group(1)):.1f} {float(v.group(1)):.3f}" if s and v else "")
PY
)
  if [ -n "$V_COST" ]; then
    V_SETUP=${V_COST%% *}; V_ONE=${V_COST##* }
    # core 证明没有 compressed 边车时，verify_session 会退回 `pop-script --verify`
    # ——那是**证明器**二进制，这正是「判定只要 0.1s、却要 7 GiB」的来源。
    V_BIN=$(grep -o 'pop-verify\|pop-script' "$OUT_DIR/logs/verify.log" | head -1)
    V_WALL=-; V_PEAK=-
    for r in "${ROWS[@]}"; do
      IFS='|' read -r k _ _ _ w p _ <<<"$r"
      [ "$k" = "verify" ] && { V_WALL="$w"; V_PEAK="$p"; }
    done
    case "$V_PEAK" in ''|*[!0-9]*) V_GIB="?" ;; *) V_GIB=$(awk -v k="$V_PEAK" 'BEGIN{printf "%.1f", k/1048576}') ;; esac
    emit "   · 第三方验证的**判定**极便宜（每份证明 ${V_ONE}s），但这条支路实测 ${V_WALL}s /"
    emit "     峰值 ${V_GIB} GiB —— 大头不是「验」，是**把验证器拉起来**：SP1 客户端装载 ${V_SETUP}s，"
    emit "     且这次走的是 \`${V_BIN:-?}\`（core 证明没有 compressed 边车时的回退路径）。"
    emit "     要只带验证器（免证明器状态），走 compressed + pop-verify，见 docs/reproduce.md §11。"
  fi
fi

# ---------------------------------------------------------------- 落盘 ----
REPORT="$OUT_DIR/REPORT.md"
{
  echo "# 全链路 demo 报告"
  echo
  echo "模式：\`$([ "$PROVE" = 1 ] && echo prove || echo fast)\`　生成时间：$(date -Iseconds)"
  echo "机器：$(nproc) 核 · $(awk -F': ' '/model name/{print $2; exit}' /proc/cpuinfo) · 内存 $(awk '/MemTotal/{printf "%.1f", $2/1024/1024}' /proc/meminfo) GiB"
  echo
  echo "| 支路 | 驱动 | 结果 | 墙钟(s) | 峰值(KiB) | 日志 |"
  echo "|---|---|---|---:|---:|---|"
  for r in "${ROWS[@]}"; do
    IFS='|' read -r k name drv status wall peak extra <<<"$r"
    if [ "$status" = "SKIP" ]; then
      echo "| $name | \`$drv\` | **SKIP** — $extra | - | - | - |"
    else
      echo "| $name | \`$drv\` | **$status** | $wall | $peak | \`logs/$k.log\` |"
    fi
  done
  echo
  echo "> **fast 模式下的所有 PASS 都不是「已出证」**：各驱动在 \`--no-prove\` 下只做"
  echo "> Python ↔ Rust 宿主对拍。要真证明加 \`--prove\`（每条支路数分钟、峰值 ~10 GB）。"
  echo
  echo "## 跳过与失败的分辨"
  echo
  echo "SKIP = 缺依赖（未装 ezkl / foundry / 上游产物缺失），不代表功能不存在；"
  echo "FAIL = 该步骤真的失败了。二者必须分开看。"
  # 上面那几段「演示印象 ≠ 事实」同样落进报告 —— 只读 REPORT.md 的人不该漏掉它们。
  # （它们是从产物/源码现推的，所以这份报告不会随文档更新而漂移。）
  if [ "${#GAPS[@]}" -gt 0 ]; then
    echo
    echo "## 上面那些 PASS 之外：最容易得到的几个错误结论"
    echo
    echo '```text'
    printf '%s\n' "${GAPS[@]}"
    echo '```'
  fi
} > "$REPORT"

echo
if [ "$FAILED" = 0 ]; then
  echo "${GRN}汇总：没有 FAIL${RST}（SKIP 的条数与原因见上表）"
else
  echo "${RED}汇总：有步骤 FAIL${RST} —— 看 $OUT_DIR/logs/*.log"
fi
echo "报告：$REPORT"
exit "$FAILED"
