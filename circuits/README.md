# circuits/ —— SP1 证明层（Rust）

> 状态（2026-09-12 订正）：**Phase 0–5 全部完成**，本层对齐 SP1 **v6.7.0**。
> 原「Phase 0 占位 program」的说法已过期 —— 现在有**三个 guest**（策略 / 推理 / 会话三个域，
> 三个不同的 `vkey`）、一个驱动 `pop-script` 与一个 verifier-only 审计二进制。

## 结构（SP1 v6 workspace）

```
circuits/
├── Cargo.toml          # workspace(members=types,program,infer-program,session-program,script,verifier)
│                       #   + [patch.crates-io] tempfile
├── rust-toolchain      # channel = stable（宿主）
├── patches/tempfile    # vendored tempfile 3.19.1 + TempDir::keep()（见下）
├── types/              # pop-types：guest 与宿主**共用**的判定逻辑（no_std）
│                       #   evaluate / evaluate_private / nfa_match / folded_text（P2-9b 折叠）
├── program/            # guest · **策略域**：读 Job → 判定约束 → commit Outcome
│   └── src/main.rs     #   公开模式 Outcome::Public / 私有模式 Outcome::Private
├── infer-program/      # guest · **推理域**（P1-6）：只接 Job::Infer，承载推理完整性
├── session-program/    # guest · **会话域**（P2-10）：跨证书一致性
├── verifier/           # pop-verify：仅 `sp1-verifier`（免构造证明器）的审计快路径
└── script/             # host 驱动 pop-script：build.rs 编译 guest → prove / verify / execute
    ├── build.rs        # sp1_build::build_program_with_args("../program")
    └── src/main.rs     # --proof-mode {core,compressed,groth16,plonk}（默认 core）、--proof-out、--verify
```

> **三个 guest ⇒ 三个不同的 `vkey`** 是 L6（组合义务，P1-6）与 L9（多证明者，P2-11）的键分离依据 ——
> `program` 显式**拒绝** `Job::Infer`，推理全靠 `infer-program`，所以「换响应」与「换推理」各由一把键担责。

## 环境要求

- Rust stable + SP1 cargo-prove（v6）+ succinct 工具链（`cargo prove install-toolchain`）。
- **Go ≥1.24**：`sp1-sdk` 的 `native-gnark` 特征用 Go 编译 gnark 库（CPU 出证需要），构建时保证 `GOPROXY` 可用。
- **内存**：CPU Core 真实证明的峰值**固定地板约 10.15 GiB**（200 字符 × 1 条规则就已 10,389 MB），
  与 trace 长度、规则数基本无关；可行域是「**一个地板 + 两级台阶**」。本机 11.7 GiB 只放得下
  1 规则 ≤10k 字符 / 2 规则 ~200 字符；3 条规则与 20k 字符都 OOM。
  实测表与口径见 [`../bench/results/proofs.md`](../bench/results/proofs.md) —— **这张边界是内存的函数，不是 prover 的性质**。
  `compressed` / `groth16` 的递归包装固定开销更大（本机实测峰值 11.0 / 11.07 GB 即被 OOM），需 ≥64 GB 机器。
- **tempfile 补丁**：sp1-prover 6.7.0 调用上游 tempfile 3.x 不存在的 `TempDir::keep()`，故 vendored `patches/tempfile`；勿删 `[patch.crates-io]`。

## 构建与运行

二进制是 `circuits/target/release/pop-script`（guest ELF 由 `script/build.rs` 编进去）。
命令行只有开关、没有位置参数：

```
pop-script [--check | --execute] --vectors v.json [--out r.json] [--proof-out p.bin]
pop-script  --verify --proof p.bin [--job policy|infer|session]
           [--proof-mode core|compressed|groth16|plonk]   # 默认 core
```

```bash
# 1) 编译 guest（riscv64im-succinct-zkvm-elf）
cd program && cargo prove build

# 2) 出证 + 宿主验证 —— 手写 vectors.json 很啰嗦，直接用封装好的入口：
#    （--response 收的是**文件路径**；默认就出证，--no-prove 才跳过）
cd ../..
SP1_PROVER=cpu python3 scripts/prove_policy.py \
    --pack policy_packs/eu_ai_act_v1.json \
    --response scripts/examples/eu_agent_reply.txt \
    --out-dir scripts/examples/out/eu --expect pass

# 3) 不出证只算周期（快；bench_cycles.py 走的就是 --execute 这条路径）
python3 bench/bench_cycles.py
```

> 日常入口不用手敲 `pop-script`：`scripts/prove_policy.py` / `cross_validate.py` /
> `bench/bench_proofs.py` 都已封装好，并处理了分块（`--chunk`）与硬件记录（`host` / `proof_mode`）。
> **`--proof-out` 的 sidecar 现在对 core 也会写**，`pop-verify` 据此选择是否走 verifier-only 快路径
> （`policydsl/verifier.py::prefer_verifier_only`）。

> `SP1_PROVER=cpu`（v6 合法值 cpu/cuda/mock/light/network）。Windows/WSL 的对策见
> [`docs/dev-plan.md`](../docs/dev-plan.md) §4。

## Phase 1–5 交付（逐条对应 [`docs/dev-plan.md`](../docs/dev-plan.md) §2）

1. ✅ **Phase 1 已完成**：program 读 `ProofRequest`(serde) 并对 keyword_block/length_bound 判定、commit `ProofOutput`；
   共享类型在 `circuits/types`；与 Python golden 交叉验证 `scripts/cross_validate.py`（**当时 5/5**）。
2. ✅ **Phase 2 已完成**：`PatternBlock` 入电路——`policydsl.nfa` 编译 pattern→NFA spec，`pop-types::nfa_match`
   (no_std Pike VM) 判定；PII 规则(`policydsl/pii.py`)+`pii_redaction_v1` 包；**当时 host 7/7 + 真实证明 7/7**。
3. ✅ **Phase 3 已完成（透明模式 MVP）**：`policydsl.serialize` 映射 ConstraintSpec→ProofRequest；`scripts/prove_policy.py`
   对 `eu-ai-act-v1`(pass) / `finance-redaction-v1`(violate) 真实出证并验证，与 golden 一致（MVP 验收见 docs/dev-plan.md）。
4. ✅ **Phase 4 已完成（私有模式 + 边界增强）**：`Job/Outcome` 双模式；`PrivateOutput` 只公开响应承诺 + 证据承诺 +
   脱敏证明（`redaction_ok` 且 **`mask_covered`：掩码 ⊆ 电路内验证的真实命中**）；`scripts/private_demo.py` 通过
   host 比对 + 真实证明 + 泄露/绑定/**证据开示**实验。
5. ✅ **Phase 5 已完成（合规证书 + 独立验证）**：`pop-script --proof-out` 保存证明、`--verify` 独立验证；
   `policydsl/cert.py`（DSSE 证书）、`anchor.py`（防篡改账本）、`agent.py`（Agent 钩子）；
   `scripts/issue_cert.py` / `verify_cert.py` 端到端（第三方验证全 PASS，含 SP1 证明密码学验证）。

> **Phase 5 之后的工作不在本文件**：P0 绑定收紧、P1 轨迹/组合/链上/形式化、P2 语义/会话/多证明者/规模评测
> 见 [`docs/plan-p0p1p2.md`](../docs/plan-p0p1p2.md)（当前权威计划）。上面几条的向量数（5/5、7/7）
> 是**当时的集**；当前是 **19 向量，host 19/19 · prove 19/19**（`docs/reproduce.md` §验收判据）。
