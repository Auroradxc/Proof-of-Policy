# circuits/ —— SP1 证明层（Rust）

> 状态（2026-09-10）：**Phase 0 已完成**，本层对齐 SP1 **v6.7.0**，占位 program 可出证+验证。

## 结构（SP1 v6 workspace）

```
circuits/
├── Cargo.toml          # workspace(members=program,script) + [patch.crates-io] tempfile
├── rust-toolchain      # channel = stable（宿主）
├── patches/tempfile    # vendored tempfile 3.19.1 + TempDir::keep()（见下）
├── program/            # SP1 zkVM 程序（guest）：读 ProofRequest → 判定约束 → commit
│   └── src/main.rs     # Phase 0 占位：读 u32 → commit（Phase 1-3 换成真判定）
└── script/             # SP1 驱动（host）：build.rs 编译 guest → prove → verify
    ├── build.rs        # sp1_build::build_program_with_args("../program")
    └── src/main.rs     # 占位驱动：SP1_PROVER=cpu 出证并验证
```

## 环境要求

- Rust stable + SP1 cargo-prove（v6）+ succinct 工具链（`cargo prove install-toolchain`）。
- **Go ≥1.24**：`sp1-sdk` 的 `native-gnark` 特征用 Go 编译 gnark 库（CPU 出证需要），构建时保证 `GOPROXY` 可用。
- **内存**：CPU Core 真实证明峰值约 9–10GB，建议 ≥12GB（本项目 WSL 已配 12GB）。
- **tempfile 补丁**：sp1-prover 6.7.0 调用上游 tempfile 3.x 不存在的 `TempDir::keep()`，故 vendored `patches/tempfile`；勿删 `[patch.crates-io]`。

## 构建与运行（Phase 0 验证）

```bash
# 1) 编译 guest（riscv64im-succinct-zkvm-elf）
cd program && cargo prove build

# 2) 出证 + 宿主验证（占位程序，输入 n）
cd ../script
SP1_PROVER=cpu cargo run --release --bin pop-script -- 42
# → Successfully generated proof! / Successfully verified proof!
```

> `SP1_PROVER=cpu`（v6 合法值 cpu/cuda/mock/light/network）。Windows/WSL 见仓库外备忘 `docs/dev-plan.md` 第 4 节。

## Phase 1-3 路线（对应 docs/dev-plan.md）

1. ✅ **Phase 1 已完成**：program 读 `ProofRequest`(serde) 并对 keyword_block/length_bound 判定、commit `ProofOutput`；
   共享类型在 `circuits/types`；与 Python golden 交叉验证 `scripts/cross_validate.py`（5/5 通过）。
2. ✅ **Phase 2 已完成**：`PatternBlock` 入电路——`policydsl.nfa` 编译 pattern→NFA spec，`pop-types::nfa_match`
   (no_std Pike VM) 判定；PII 规则(`policydsl/pii.py`)+`pii_redaction_v1` 包；host 7/7 + 真实证明 7/7。
3. ✅ **Phase 3 已完成（透明模式 MVP）**：`policydsl.serialize` 映射 ConstraintSpec→ProofRequest；`scripts/prove_policy.py`
   对 `eu-ai-act-v1`(pass) / `finance-redaction-v1`(violate) 真实出证并验证，与 golden 一致（MVP 验收见 docs/dev-plan.md）。
