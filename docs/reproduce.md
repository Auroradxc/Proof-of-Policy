# 复现指南：一次合规证明（README → 复现）

> 目标：在**本机（WSL2/Linux，无需 GPU）**从零复现 PoP 的完整链路：
> 策略 → 电路 → **真实 SP1 证明** → 验证 → 证书 → 第三方独立验证。
> 预计：环境齐全后，单次证明 ~70s；全流程首次约 20–40 分钟（含编译）。

---

## 0. 环境要求

| 项 | 要求 | 备注 |
|---|---|---|
| OS | Ubuntu/WSL2 x86_64 | 本项目在 WSL2 验证 |
| 内存 | **≥12GB**（CPU Core 证明峰值 ~9–10GB） | 7.6GB 会 OOM（killer 日志：`Killed process fibonacci`） |
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
python3 -m unittest discover tests -v          # 期望 348 passed（11 skip：2 个 compressed fixture + 2 个 POP_TEST_PROOF 门控 + 1 个 POP_TEST_EZKL 门控 + 5 个 POP_TEST_COMPOSE 门控 + 1 设计内）
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
SP1_PROVER=cpu python3 scripts/cross_validate.py      # 期望 host 19/19（prove 见下方注）
```

> 真实证明默认**分块**（`--chunk 4`，共 4 个 `pop-script` 进程）。原因很实际：
> 本机（11.9 GB RAM）把 14 个向量塞进一个进程时，会在第 6~7 个证明处被内核
> OOM-kill（峰值 10.65 / 10.82 GB）。分块不改变交给电路的输入，只是让每个进程
> 从干净状态开始；`--chunk 0` 可恢复单进程（需 ≥16 GB 机器）。

## 5. 复现：私有模式（承诺 + 选择性披露 + 证据开示）

```bash
SP1_PROVER=cpu python3 scripts/private_demo.py
# 期望：check/prove 与 golden 一致；leak/binding/challenge/opening 全 PASS；redaction.mask_covered=true
#      （challenge 行： (T',nonce)_opens=True wrong_T'_rejected=True wrong_nonce_rejected=True domain_separated=True）
```

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

## 8. 复现：语义规则（P2-9，可选，重依赖）

`semantic_bound`（「回复的有害概率不得高于阈值」这类**学不出形式证明**的规则）
**不在 SP1 电路内判定**：电路只把「这条被委托了」登记进公开值 `delegated[]`，
判定由一条 **ezkl/halo2 陪伴证明**补上，验证方必须**合取**二者。因此这一段是**独立的一条链**，
需要 `requirements-ezkl.txt` 里的那套依赖（torch / onnx / ezkl），且 `semantic/artifacts/` 会占 ~3 GB
（`pk.ezkl` 2.92 GiB 与 `kzg.srs` 32 MiB 可重算、不入库；`vk.ezkl` 802 KiB 入库）。

```bash
python3 -m pip install --user -r requirements-ezkl.txt   # 网络对策见 §0
python3 scripts/ezkl_prove.py info       # 只看产物清单与规模（秒级，不出证）
python3 scripts/ezkl_prove.py selftest   # 四条文本端到端自检（含同形异义反例）
POP_TEST_EZKL=1 python3 -m unittest tests.test_semantic   # 真·端到端一例（~61 s / 峰值 ~9 GiB）
```

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

```bash
SP1_PROVER=cpu python3 scripts/demo_e2e.py                 # 真实会话 + 真实 SP1 证明（加 --no-prove 秒级）
python3 scripts/verify_session.py --session scripts/examples/out/e2e/session.json
python3 scripts/make_shots.py --run-demo                   # 生成 docs/demo/*.html/svg/png
```
期望：`verify_session` 全 PASS；`docs/demo/session_report.html`、`session_summary.png`、`verify_result.png` 生成。

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
SP1_PROVER=cpu bash scripts/anchor_e2e.sh --prove   # 附带真实 Core 证明（~66s / ~10 GB）
```

期望输出（末段）：

```
[PASS] ledger_chain / certificates_signature / certificates_policy_hash / certificates_anchored
[PASS] stream_chains 2 run(s)
[PASS] zk_proof      SP1 proof verified (pop-script)      # --no-prove 时为 unproven (host-check only)
[PASS] chain_anchored 12/12 digests on chain 0x5fbdb231… (12 cross-checked)
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

- `python3 -m unittest discover tests` → **348 passed（11 skip）**（skip：2 = compressed 审计 fixture 待 ≥16 GB 机器生成，2 = `POP_TEST_PROOF` 门控的证明层用例，1 = `POP_TEST_EZKL` 门控的真实 ezkl 出证用例，5 = `POP_TEST_COMPOSE` 门控的组合证明端到端用例（真出两份证明），1 = 设计内「依赖已装」用例）；
- `scripts/prove_policy.py` → **RESULT: PASS**；
- `SP1_PROVER=cpu python3 scripts/cross_validate.py` → **`RESULT: host 19/19  prove 19/19  PASS`**（**prove 未重跑**：向量 14 → 19 后只做过 host 全量 + `norm_homoglyph` 单条真实证明，整批 prove 须 `--chunk`，见 `modules/08-tests-bench.md` §5）
  （真实证明分 4 块跑，见 §4 的说明；`--no-prove` 时跳过真实证明）；
- `verify_cert.py`（带 `--response T′`）/ `verify_session.py` → **RESULT: PASS**（含 SP1 证明密码学验证与响应绑定核对）；
- `bash scripts/anchor_e2e.sh` → **ALL PASS**（链上锚定 12/12 + 反例对照，见 §12）；
- `python3 scripts/ezkl_prove.py selftest` → **四条文本全 PASS**（含同形异义反例，见 §8）；
- `POP_TEST_EZKL=1 python3 -m unittest tests.test_semantic` → **OK**（真·端到端一例，~61 s）。

## 故障排查

| 现象 | 原因 | 处理 |
|---|---|---|
| 证明进程被杀、无输出 | 内存不足（WSL 默认 ~7.6GB） | 宿主 `C:\Users\<你>\.wslconfig` 设 `memory=12GB`，`wsl --shutdown` 后重启 |
| `cross_validate --prove` 跑到第 6~7 个向量就被 kill | 单进程跑 14 个证明会累积内存（峰值 10.8 GB） | 用默认的 `--chunk 4`（本来就默认分块）；别改成 `--chunk 0` |
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
