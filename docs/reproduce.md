# 复现指南：一次合规证明（README → 复现）

> 目标：在**本机（WSL2/Linux，无需 GPU）**从零复现 PoP 的完整链路：
> 策略 → 电路 → **真实 SP1 证明** → 验证 → 证书 → 第三方独立验证。
> 预计：环境齐全后，单次证明 ~70s；全流程首次约 20–40 分钟（含编译）。

---

## 0. 环境要求

| 项 | 要求 | 备注 |
|---|---|---|
| OS | Ubuntu/WSL2 x86_64 | 本项目在 WSL2 验证 |
| 内存 | **≥12GB**（CPU Core 证明的**固定地板 ~10.15 GiB**，见 [`bench/results/proofs.md`](../bench/results/proofs.md)） | 7.6GB 会 OOM（killer 日志：`Killed process fibonacci`）；**12GB 也只够证小策略**，边界见下方注 |
| Rust + SP1 | Rust stable；`cargo-prove` **v6.7.0** + succinct 工具链 | `curl -L https://sp1.succinct.xyz \| bash` → `sp1up` → `sp1up` |
| Go | ≥1.24（`sp1-sdk` 的 `native-gnark` 需要） | 走 `GOPROXY=https://goproxy.cn,direct` |
| C/系统依赖 | `build-essential clang pkg-config libssl-dev cmake protobuf-compiler` | protoc 供 sp1-prover-types |
| Python | 3.10+（stdlib 即可跑参考层与测试） | 框架适配需 `requirements-frameworks.txt` |

**网络对策（本环境实测）**：`github.com` / `crates.io` HTTPS 常被限流，PyPI 多数镜像受限。
- git 克隆：`gh-proxy` 镜像（仓库**局部** `insteadOf`，勿设全局）；
- cargo：`rsproxy` sparse 镜像（`~/.cargo/config.toml`）；
- Go：`goproxy.cn`；Python 包：清华 PyPI `https://pypi.tuna.tsinghua.edu.cn/simple`（apt 不可用时可用 pip wheel 引导）。

---

## 1. 复现：参考层（秒级，无需 Rust）

```bash
cd Proof-of-Policy/03_代码仓库/zk-policy     # 仓库根（目录曾名为“方向二”，已重命名）
python3 -m unittest discover tests -v          # 期望 581 passed（15 skip：2 个 compressed fixture + 3 个 POP_TEST_PROOF 门控 + 1 个 POP_TEST_EZKL 门控 + 5 个 POP_TEST_COMPOSE 门控 + 1 个 POP_TEST_SESSION 门控 + 1 个 POP_TEST_MULTIPARTY 门控 + 1 个 POP_TEST_LLM 门控 + 1 设计内）
python3 -m policydsl compile policy_packs/eu_ai_act_v1.json | head    # 编译出 ConstraintSpec
```

## 2. 复现：电路构建（首次较慢）

```bash
cd circuits/program && cargo prove build                        # 生成 guest ELF
cd ../script && cargo build --release -p pop-script             # 宿主驱动
```
> 需要 `SP1_PROVER=cpu` 出证；`native` 非法（会 `unreachable` 崩溃），`light` 不能出证。
> `sp1-prover` 6.7.0 依赖上游 tempfile 缺失的 `TempDir::keep()` → 仓库内 `circuits/patches/tempfile` 已 vendored（`[patch.crates-io]`）。

## 3. 复现：一次透明模式合规证明（最小）

```bash
SP1_PROVER=cpu python3 scripts/prove_policy.py \
  --pack policy_packs/eu_ai_act_v1.json \
  --response scripts/examples/eu_agent_reply.txt \
  --out-dir scripts/examples/out/eu --expect pass
```
期望输出（关键行）：
```
[PASS] check passed golden=True sp1=True  rules golden=[] sp1=[]
--- proving eu-ai-act-v1 (SP1, ~1 min) ---
[PASS] prove passed golden=True sp1=True  rules golden=[] sp1=[]
RESULT: PASS
```

## 4. 复现：双端一致性（Python golden ↔ SP1）

```bash
SP1_PROVER=cpu python3 scripts/cross_validate.py      # 期望 host 19/19 · prove 19/19（prove 约 45 min，见下方注）
```

> 真实证明默认**分块**（`--chunk 4`；19 条向量 = 5 个 `pop-script` 进程）。原因很实际：
> 本机（11.9 GB RAM）把全部向量塞进一个进程时，会在第 6~7 个证明处被内核
> OOM-kill（峰值 10.65 / 10.82 GB）。分块不改变交给电路的输入，只是让每个进程
> 从干净状态开始；`--chunk 0` 可恢复单进程（需 ≥16 GB 机器）。
> 2026-09-12 那次 19 向量的整批重跑用的是 `--chunk 2`（10 个子进程，约 45 min）。

> ⚠️ **一台 12 GB 机器的证明侧天花板**（P2-12 实测，[`bench/results/proofs.md`](../bench/results/proofs.md)）：
> 别指望换更大的策略再跑一遍 —— 峰值常驻的**固定地板就是 ~10.15 GiB**
> （200 字符 × 1 条规则这种最小配置已经 10,389 MB），往上只剩很窄的一条缝：
>
> | 策略规模 | 能否出证 |
> |---|---|
> | 1 条规则，≤10k 字符 | ✅ |
> | 2 条规则，~200 字符 | ✅ |
> | 3 条规则及以上（含 `pattern_block`） | ❌ OOM |
> | 1 条规则，20k 字符 | ❌ OOM |
>
> 卡的是**内存不是 CPU**：周期表（[`bench/results/cycles.md`](../bench/results/cycles.md)）
> 能扫到 100k 字符 × 6 规则，因为那只跑 zkVM 执行不出证。想证更大的策略要么加内存，
> 要么换证明模式（`compressed` 需 ≥16 GB，见 §11）。
>
> **换机器就能把这张表拉长** —— 具体怎么跑见下面 §4½。

## 4½. 云机 runbook：P1-7 的 groth16 + P2-12 的全矩阵

本机够不着的两件事共用**同一次租机窗口**（登记见 [`plan-p0p1p2.md`](plan-p0p1p2.md) §9 待办 **T1**）。
一台机器、两个用途，但**内存需求差一个量级**：

| 用途 | 内存 | 性质 |
|---|---|---|
| **P1-7** groth16 出证 + 验证合约测通 | **≥64 GB** | **硬需求、实测**（本机 12 GB 上 compressed/groth16 分别峰值 11.0 / 11.07 GB 被 OOM 杀，递归包装的固定开销就超了） |
| **P2-12** core 全矩阵 | ~16 GB（**粗估，未实测**） | **顺带**，不阻塞任何东西；做不完不影响 P1 段收尾 |

**到机后按此顺序做**（前一件做完再做后一件）：

**① P1-7：groth16 证明 + 链上验证**（唯一的硬需求，先做）

```bash
cd contracts && forge build && cd ..          # solc 0.8.24 已在 ~/.svm 缓存，可离线编译
SP1_PROVER=cpu ./scripts/anchor_e2e.sh --onchain-verify
```

**② P2-12 全矩阵（`core`）**：`20k / 50k / 100k` × `1 / 2 / 3 / 6` 规则，
**再把本机那 6 个点用同一套参数重跑一遍**，两张表才拼得起来。

```bash
# 新补的 12 格（本机全部 OOM 的那一半）
SP1_PROVER=cpu python3 bench/bench_proofs.py \
  --out bench/results/proofs-cloud.json \
  --points "20000,1 20000,2 20000,3 20000,6 50000,1 50000,2 50000,3 50000,6 100000,1 100000,2 100000,3 100000,6"

# 本机那 6 格，同参数复核（注意 --out 仍指向 proofs-cloud.json，别覆盖本机的表）
SP1_PROVER=cpu python3 bench/bench_proofs.py \
  --out bench/results/proofs-cloud.json \
  --points "200,1 200,2 2000,1 10000,1 200,3 20000,1"
```

**③ `compressed` 对照**：这是本机**完全量不到**的一格，也是 [`security-model.md`](security-model.md)
里「groth16/plonk 是唯一可能隐藏见证的模式，本机未实测」那句话的补测。只在少数点上跑：

```bash
SP1_PROVER=cpu python3 bench/bench_proofs.py \
  --out bench/results/proofs-cloud-compressed.json \
  --proof-mode compressed --points "200,1 2000,1"
```

⚠️ **跨机口径（入库前必读）**：

1. **云机的数字不能与本机 12 GB 那张表并列读数。** SP1 的证明耗时随 CPU 核数与型号走、
   可行域随内存走 —— 同一组采样点换台机器就是**另一张表**。所以：
   - 结果**另存**为 `proofs-cloud*.json/.md`，与本机的 `proofs.{json,md}` **并列呈现，不合并**；
   - `bench_proofs.py` 从 2026-09-12 起会把**核数 / CPU 型号 / 内存 / hostname** 与
     `proof_mode` 一并写进 JSON、并在 `.md` 顶部打出来 —— 云机结果因此**自带硬件标注**，
     这正是为这批数字加的（否则入库后无从解释）；
   - 论文/文档里引用跨机数字时**连着机器一起引**（形如「本机 12 GB / 24 核」vs「云机 N GB / M 核」）。
2. **`--proof-mode` 之间同样不可比。** 递归包装的固定开销差很多，`compressed`/`groth16` 在
   本机必然 OOM；云机上 core 与 compressed 的耗时/内存/体积要分成两张表读，别混行。
3. **多个采样点要引号包住整体**：`--points "200,1 200,2"`。`--points` 只吃一个参数，
   点之间用空格或 `;` 分隔；不加引号时第二个点会被 argparse 判为多余的位置参数而报错。
4. **出证必须串行**：同一台机器上不要并行跑两个 `bench_proofs.py` / `cross_validate.py` ——
   每个进程的固定地板就是 ~10.15 GiB，并行只会互相把对方推向 OOM，并污染峰值内存的读数。

## 5. 复现：私有模式（承诺 + 选择性披露 + 证据开示）

```bash
SP1_PROVER=cpu python3 scripts/private_demo.py
# 期望：check/prove 与 golden 一致；leak/binding/challenge/opening 全 PASS；redaction.mask_covered=true
#      （challenge 行： (T',nonce)_opens=True wrong_T'_rejected=True wrong_nonce_rejected=True domain_separated=True）
```

**只想看公/私差别**：不必单跑这一条 —— 主 demo 的**第 4 步**就会拿同一条 T、
同一个 nonce 在两种模式下各出一张证书，把「验证方分别看得见什么」**现读**成一张
并排表（公开模式证据是明文、私有模式只有承诺），再演示证据选择性开示与篡改被拒。
见 [`../README.md`](../README.md) 的「公私模式对比」一节，或 `--no-contrast` 关掉它。

> 主 demo 那一步的两张证书**默认只做宿主校验**（标 `unproven`）：本 demo 的
> `agent_content_v1` 这条策略在**私有模式**下本机证不了（实测 `anon-rss` 10.391 GiB
> 被 OOM-kill，天花板约 10.385 GiB）。**这一节才是私有模式真证明的落点** ——
> 这里的策略更小，实测峰值 10.383 GiB，是能过的那一档。

## 6. 复现：合规证书 + 第三方验证

```bash
SP1_PROVER=cpu python3 scripts/issue_cert.py \
  --pack policy_packs/eu_ai_act_v1.json --response scripts/examples/eu_agent_reply.txt \
  --out-dir scripts/examples/out/cert_public          # 默认 --nonce auto：现场出一个 32 字节挑战值
SP1_PROVER=cpu python3 scripts/verify_cert.py \
  --cert scripts/examples/out/cert_public/cert.json --pack policy_packs/eu_ai_act_v1.json \
  --ledger scripts/examples/out/ledger.jsonl --proof scripts/examples/out/cert_public/proof.bin \
  --response scripts/examples/eu_agent_reply.txt      # ← 送达的 T′，用来核对响应绑定
# 期望 9 项全 PASS（签名 / proof_mode / policy_hash / response_binding / 锚定 / SP1 证明 / outcome / vkey / proof_sha256）
```

> **`--response` 是 P0-2 的验收点**：加上它，验证器会现场重算 `SHA256("pop-bind-v1"‖len‖nonce‖T′)`
> 并与证明公开值里承诺的绑定比对，报告里出现
> `[PASS] response_binding — 送达的 T′ 就是被证明的 T`。
> 把 `--response` 换成**另一条**响应，这一项应变成 `[FAIL] … 对不上` 且 `RESULT: FAIL`
> —— 这正是「中间人换响应」被拦下的样子。不带 `--response` 时该项只做证书内部自洽比对，
> 报告会写明来源仅来自证书本身。

## 7. 复现：组合证明（P1-6，可选）

```bash
# 策略半 + 推理半各出一份真实证明（两个 guest 程序 → 两个 vkey），再合成一张组合证书
SP1_PROVER=cpu python3 scripts/compose_proof.py \
  --pack policy_packs/eu_ai_act_v1.json --response scripts/examples/eu_agent_reply.txt \
  --out-dir scripts/examples/out/compose
# 期望：RESULT: PASS 且 组合义务(Compose): PASS
```

**两次出证各 ~2 分钟、峰值 ~10.5 GiB，且必须分进程**（同进程连出两份会在第二份 setup 被 OOM；
两半的分项数字见 [`../bench/results/compose.md`](../bench/results/compose.md)）。
改过 `policydsl/compose.py` 后想重跑合成与验证时，加 `--reuse-proofs` 沿用已有证明（秒级），
不必再花几分钟出证。`--no-prove` 只跑宿主校验（两端判定逻辑对齐 + Rust↔Python 逐位一致），
**不产组合证书**。

**为什么是两份证明**：组合义务 `Compose = (推理完整性 ∧ 策略合规)` 要求「模型确实算出了这条响应」
与「这条响应满足策略」两件事各自被证明，且证明**来自不同程序**（不同 vkey）——
否则「这份证明属于哪一半」无从判断。⚠️ 推理那一半在当前仓库是**代理**（确定性定点 MLP），
不是 zkAgent；见 [`security-model.md`](security-model.md) 引理 L6 与 `bench/results/compose.md`。

---

## 7½. 复现：会话聚合证明（P2-10，可选）

```bash
# 先有一个端到端会话包（旧的在盘 bundle 不带 seal，会被义务③如实拒掉）
python3 scripts/demo_e2e.py --no-prove --out-dir scripts/examples/out/e2e

# 秒级：只看「一个 run 的证书集能否聚合」（Python ↔ Rust 对拍，不出证）
python3 scripts/prove_session.py --session scripts/examples/out/e2e/session.json --no-prove
# 期望：每个 run 两行 [ ok ]，末行 RESULT: PASS

# 真实出证 + 独立验证（3 张证书的 run：~2.5 分钟、峰值 ~10 GiB）
SP1_PROVER=cpu python3 scripts/prove_session.py \
  --session scripts/examples/out/e2e/session.json --run 1 \
  --nonce-hex 00112233445566778899aabbccddeeff \
  --proof-out scripts/examples/out/session/run1.proof
```

**它会如实分开报两件事**（2026-09-12 实测的尾行）：

```
  [ ok ] verify   Merkle 根与交付的 3 张证书相符; … ; 只核对了 count/trace_root；未给网关公钥，seal 签名未验
  **不合规**：这张聚合证明本身是真的，它覆盖的轨迹不满足策略
RESULT: PASS
```

—— `demo_e2e` 的第二个 run 里有两张证书是**如实记录了违规**的，所以聚合证明**为真**而轨迹
**不合规**：`ok`（这次聚合是真的）与 `satisfied`（被覆盖的证书都 passed）必须分开读。
不给 `--keyring` 时那行会明说「seal 签名未验」—— 电路内没有网关公钥，**别把这一行读成已核过**。

改一条证书再喂进去（换一张 / 挖掉链尾一张 / 换个 nonce），`verify` 一行会变 `[FAIL]`：
**尾截断只有 Merkle 根拦得住**（前缀的 `index`/`prev` 依然连续），理由见
[`security-model.md`](security-model.md) 引理 L8。

---

## 8. 复现：语义规则（P2-9，可选，重依赖）

`semantic_bound`（「回复的有害概率不得高于阈值」这类**学不出形式证明**的规则）
**不在 SP1 电路内判定**：电路只把「这条被委托了」登记进公开值 `delegated[]`，
判定由一条 **ezkl/halo2 陪伴证明**补上，验证方必须**合取**二者。因此这一段是**独立的一条链**，
需要 `requirements-ezkl.txt` 里的那套依赖（torch / onnx / ezkl），且 `semantic/artifacts/` 会占 ~3 GB
（`pk.ezkl` 2.92 GiB 与 `kzg.srs` 32 MiB 可重算、不入库；`vk.ezkl` 802 KiB 入库）。

```bash
bash scripts/install_ezkl.sh             # 装依赖栈（幂等；--check 只看装没装好）
python3 scripts/ezkl_prove.py info       # 只看产物清单与规模（秒级，不出证）
python3 scripts/ezkl_prove.py selftest   # 四条文本端到端自检（含同形异义反例）
POP_TEST_EZKL=1 python3 -m unittest tests.test_semantic   # 真·端到端一例（~61 s / 峰值 ~9 GiB）
```

`install_ezkl.sh` 做的事就是 `python3 -m pip install --user -r requirements-ezkl.txt`
（网络对策见 §0），外加**版本核对**（`ezkl==23.0.5 / onnx==1.22.0 / torch==2.14.0`，
装错版本会让陪伴证明与策略里固化的 `onnx_sha256` / `model_vkey` 对不上）和一次
冒烟（`ezkl_prove.py info`）。网络不通时会**快速失败**（退出码 2），不会留下半成品；
也可以在有网时先 `--save-wheels` 存一份 wheel 到 `wheelhouse/`（**不入库**，torch
一个大轮子就几百 MB），之后用 `--offline` 全程离线装。

**这两条命令必须分进程**：ezkl 的 `setup` 与 `prove` 峰值叠加会在 12 GB 机器上 OOM
（setup 4.76 GiB + prove 8.72 GiB，见 `bench/results/semantic.md`）——`scripts/ezkl_prove.py`
本身就是分阶段跑的，别把两步并进一个进程。

⚠️ **三条硬边界**（论证见 [`design-semantic-rules.md`](design-semantic-rules.md) 的**引理 L7**）：

1. **`passed=true` 且 `delegated` 非空 ≠ 策略被满足**。`verify_cert.py` 因此打印**两行**：
   `RESULT:` 说这张证书真不真，`合规:` 说策略满足没满足。带 `--semantic-dir` 时它会核
   `{system, model_vkey, onnx_sha256, threshold_bp, direction}` 与陪伴证明的公开实例是否逐字段相等。
2. **语义规则只支持公开模式** —— `encode` 在词表上单射，公开实例可反查原文；策略含语义规则时
   私有模式**直接 panic**（fail closed）。
3. **随包模型是演示用小模型**，不构成任何语义安全保证（与 §4.2 的 `tokens` 口径同一类诚实标注）。

> 最值得跑的一条是 `selftest`：它先演示现有 `keyword_block` 被同形异义字（`wеaponize` 的西里尔 `е`）
> **绕过**，再展示语义规则把同一句拦下 —— 这是论文里那条绕过实验的可复现版本。
>
> 那条绕过**现在还有第二个解法**，而且不需要 ezkl/torch：`normalized_keyword_block`（P2-9b）在
> **SP1 电路内**先把响应折叠回 ASCII 再做同样的子串判定，秒级、零额外依赖。两者的取舍见
> [`modules/01`](modules/01-policy-dsl.md) §2：一个管「字面变体」（确定性、可解释），
> 一个管「改写」（统计、需要模型）。跑这一条不需要本节的重依赖：
>
> ```bash
> python3 -m unittest tests.test_normalize tests.test_rules_incircuit   # 后者需先编 pop-script
> python3 scripts/cross_validate.py --no-prove                          # 19 条向量里 5 条是折叠规则
> ```

---

## 9. 复现：一键端到端 demo + 截图

> **想一次看全所有支路**（不只下面这条主干），跑总入口：
>
> ```bash
> bash scripts/demo_all.sh            # fast：宿主校验，约 20 秒
> bash scripts/demo_all.sh --prove    # 真出证，本机实测 26–27 分钟、峰值 ~10 GB
> ```
>
> 它把 8 条支路（公开模式 / 私有模式 / 语义规则 / 组合 / 会话聚合 / 多证明者 /
> 链上锚定 / 第三方验证）依次跑一遍，汇总成 `scripts/examples/out/all/REPORT.md`，
> 并标出每条是 PASS / FAIL / SKIP（跳过原因）与耗时、峰值内存。
> 见 [`modules/07-cli-scripts.md`](modules/07-cli-scripts.md) §3。

```bash
SP1_PROVER=cpu python3 scripts/demo_e2e.py                 # 真实会话 + 真实 SP1 证明（加 --no-prove 秒级）
python3 scripts/verify_session.py --session scripts/examples/out/e2e/session.json
python3 scripts/make_shots.py --run-demo                   # 生成 docs/demo/*.html/svg/png
```
期望：`verify_session` 全 PASS；`docs/demo/session_report.html`、`session_summary.png`、`verify_result.png` 生成。

> 第 4 步（公私对比）默认开着：它会让**同一个响应**再走一次公开、一次私有，
> 各出一张证书并并排打印「验证方分别看得见什么」，然后演示证据选择性开示与篡改被拒。
> 这两张证书**默认只做宿主校验**（`unproven`，≈秒级）—— 本 demo 的策略私有模式
> 本机证不了，理由见 §5 的注；`--contrast-prove`（≥16 GB）才会给它们也出真证明。
> 不想看就 `--no-contrast`。
> 两张对比证书同样进 `session.json`，所以上面那条 `verify_session` 的
> `zk` 条数会是 **3**（主干 1 + 对比 2）而不是 1，`certificates` 总数也相应多 2；
> `zk_proof` 那一行会印成 `SP1 proof verified (pop-script) + unproven (host-check only)×2`。

## 10.（可选）框架适配

```bash
bash scripts/install_frameworks.sh     # langchain / langgraph / mcp；装好后真实框架测试自动启用
```

## 11.（可选）审计路径：verifier-only（免构造证明器）

```bash
# a) 生成 compressed 证明（默认 core 不变；此命令额外产出验证边车 .bytes/.pv/.vkh/.verify.json）
SP1_PROVER=cpu python3 scripts/issue_cert.py \
  --pack policy_packs/eu_ai_act_v1.json --response scripts/examples/eu_agent_reply.txt \
  --out-dir scripts/examples/out/cert_audit --proof-mode compressed

# b) 仅验证器（不构造证明器，无 ~10 GB 证明器状态）
./circuits/target/release/pop-verify \
  --meta scripts/examples/out/cert_audit/proof.bin.verify.json

# c) 第三方验证会自动走快路径（存在边车 + pop-verify 已构建时）
python3 scripts/verify_cert.py --cert .../cert.json --pack policy_packs/eu_ai_act_v1.json \
  --ledger .../ledger.jsonl --proof .../proof.bin
```

> ⚠️ **内存**：`compressed` 证明需 **≥16 GB**（本机 12 GB 实测 OOM，峰值 anon-RSS 11.0 GB；Core 仍需 ~10 GB）。
> 需要 fixture 时运行 `SP1_PROVER=cpu bash scripts/make_audit_proof.sh`（生成后 `tests/test_verifier_only.py` 的用例自动启用）。

## 12.（可选）链上锚定：真跑本地 Anvil

把每张**证书摘要**（`cert_digest` = 证书载荷的 SHA-256）登记进 `contracts/Anchor.sol`，
得到一条公共、带时间戳、与本地账本无关的存在性证明。链上只存 32 字节摘要，不存响应内容。

```bash
# 前置：foundry（anvil/cast）
bash scripts/retry_install_foundry.sh          # 网络可用时安装；成功后 anvil/forge/cast 1.8.1

# 一键端到端：起 anvil → 部署合约 → 会话 demo（每张证书上链）→ 第三方 --rpc 核对（含反例对照）
bash scripts/anchor_e2e.sh                     # 默认不生成 SP1 证明（秒级）
SP1_PROVER=cpu bash scripts/anchor_e2e.sh --prove   # 附带真实 Core 证明（本机实测 3:10 / 峰值 10.2 GiB）
```

期望输出（末段）：

```
[PASS] ledger_chain / certificates_signature / certificates_policy_hash / certificates_anchored
[PASS] certificates_proof_mode / certificates_vkey_label    # P0-4 的两条诚实性不变量，互为姊妹
[PASS] stream_chains 2 run(s)
[PASS] zk_proof      SP1 proof verified (pop-script)      # --no-prove 时为 unproven (host-check only)
[PASS] chain_anchored 14/14 digests on chain 0x5fbdb231… (14 cross-checked)
negative control: unknown digest anchoredAt = 0 (expected 0)
ALL PASS ✅
```

手动分步（等价，便于接到自备节点/测试网）：

```bash
anvil &                                             # 或任意 EVM RPC 端点
python3 scripts/deploy_anchor.py --rpc http://127.0.0.1:8545 \
        --out .anchor_deploy.json                   # 打印 POP_ANCHOR_RPC / POP_ANCHOR_CONTRACT
python3 scripts/demo_e2e.py --no-prove \
        --rpc http://127.0.0.1:8545 --contract 0x5FbDB2315678afecb367f032d93F642f64180aa3
python3 scripts/verify_session.py --session .../session.json \
        --rpc http://127.0.0.1:8545 --contract 0x5FbDB2315678afecb367f032d93F642f64180aa3
```

要点：

- **部署不需要 solc/forge**：字节码来自入库的 `contracts/Anchor.json`（abi + bytecode），运行期只需要 `cast` + RPC。
- 锚定**幂等**：同一摘要重复登记不再发交易（合约对重复登记 revert，后端先查询/兜底为 `already_anchored`）。
- 链上成功后，`tx_hash`/区块号/链上时间戳会写进本地账本条目的 `meta.on_chain`（哈希链仍自洽）。
- `verify_session` 的 `chain_anchored` 会做**交叉核对**：本地记录的区块时间戳 == 链上 `anchoredAt`，并且该区块的时间戳与登记时间戳一致。
- 反例对照确保该检查不是恒真：未登记的摘要读回 `0`。

---

## 验收判据（复现成功）

- `python3 -m unittest discover tests` → **581 passed（15 skip）**（2026-09-13 复跑；skip：2 = compressed 审计 fixture 待 ≥16 GB 机器生成，3 = `POP_TEST_PROOF` 门控的用例（证明层 2 例 + 证明服务的真 vkey 出证 1 例），1 = `POP_TEST_EZKL` 门控的真实 ezkl 出证用例，5 = `POP_TEST_COMPOSE` 门控的组合证明端到端用例（真出两份证明），1 = `POP_TEST_SESSION` 门控的会话聚合证明端到端用例，1 = `POP_TEST_MULTIPARTY` 门控的多证明者端到端用例（真出两份切片证明），1 = `POP_TEST_LLM` 门控的真 provider 用例（需要真 API key + 网络；同模块里走本地 SSE 桩的那 4 例**默认就跑**），1 = 设计内「依赖已装」用例）；
- `scripts/prove_policy.py` → **RESULT: PASS**；
- `SP1_PROVER=cpu python3 scripts/cross_validate.py` → **`RESULT: host 19/19  prove 19/19  PASS`**（2026-09-12 **整批重跑**：19 条向量各出一份真 core 证明，`--chunk 2` 切到 10 个独立子进程，约 45 min，见 `modules/08-tests-bench.md` §5）
  （真实证明分块跑：默认 `--chunk 4`，那次重跑用 `--chunk 2` = 10 块，见 §4 的说明；`--no-prove` 时跳过真实证明）；
- `verify_cert.py`（带 `--response T′`）/ `verify_session.py` → **RESULT: PASS**（含 SP1 证明密码学验证与响应绑定核对）；
- `bash scripts/anchor_e2e.sh` → **ALL PASS**（链上锚定 14/14 + 反例对照，见 §12）；
  `--prove` 变体（2026-09-12 本机实测重跑）→ **ALL PASS ✅**，含真 Core 证明：
  `[PASS] zk_proof SP1 proof verified (pop-script) + response binding`、`[PASS] chain_anchored 14/14`，
  整条命令 **3:10 墙钟 / 峰值 10.18 GiB**（`/usr/bin/time -v`）；
- `python3 scripts/ezkl_prove.py selftest` → **四条文本全 PASS**（含同形异义反例，见 §8）；
- `POP_TEST_EZKL=1 python3 -m unittest tests.test_semantic` → **OK**（真·端到端一例，~61 s）。

## 故障排查

| 现象 | 原因 | 处理 |
|---|---|---|
| 证明进程被杀、无输出 | 内存不足（WSL 默认 ~7.6GB） | 宿主 `C:\Users\<你>\.wslconfig` 设 `memory=12GB`，`wsl --shutdown` 后重启 |
| `cross_validate --prove` 跑到第 6~7 个向量就被 kill | 单进程跑 19 个证明会累积内存（峰值 10.8 GB） | 用默认的 `--chunk 4`（本来就默认分块）；别改成 `--chunk 0` |
| `bench_proofs.py` 的某个点被 kill（退出码 137） | 该点超出本机证明侧天花板（固定地板 ~10.15 GiB） | **这是结论不是故障**：脚本会把它如实记进 `rows[].error` 并继续后面的点；换更小的点（减规则数 / 减长度），边界见 [`bench/results/proofs.md`](../bench/results/proofs.md) |
| `cargo prove ... unreachable` | `SP1_PROVER=native` 非法 | 用 `SP1_PROVER=cpu` |
| 出证报 “light prover cannot prove” | light 只能执行/验证 | 用 `cpu` |
| sp1-prover 编译报 `no method named keep` | 上游 tempfile 3.x 无 `TempDir::keep()` | 勿删 `circuits/patches/tempfile` 与 `[patch.crates-io]` |
| `git clone` / `cargo fetch` / pip 卡住 | 网络限流 | 用 gh-proxy / rsproxy / 清华 PyPI 镜像（见 §0） |
| `protoc` 找不到 | 缺 protobuf-compiler | `sudo apt-get install -y protobuf-compiler` |
| 缺少 `libsp1gnark.a` 构建失败 | 无 Go | 安装 Go ≥1.24 且设置 `GOPROXY` |

> 安全/边界说明：证书签名为 **Ed25519**（`policydsl/cert.py` + `policydsl/keys.py`，P0-3）——验证方只持公钥、无法伪造；
> 第三方验签用 `verify_cert.py --keyring <公钥>`（或证书同目录的 `key.json`）。**HSM/KMS 托管仍待补**；
> 锚定默认走**文件账本**（离线可验），也可 `--rpc/--contract` 真上链（见 §12，本地 Anvil 端到端 PASS）；
> 上链交易用明文私钥参数（demo 用 Anvil 公开测试键），生产应换 keystore/HSM。
