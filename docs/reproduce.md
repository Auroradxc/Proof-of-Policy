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
cd 方向二/03_代码仓库/zk-policy
python3 -m unittest discover tests -v          # 期望 101 passed（1 skip=设计内）
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
SP1_PROVER=cpu python3 scripts/cross_validate.py      # 期望 host 7/7 + prove 7/7
```

## 5. 复现：私有模式（承诺 + 选择性披露 + 证据开示）

```bash
SP1_PROVER=cpu python3 scripts/private_demo.py
# 期望：check/prove 与 golden 一致；leak/binding/opening 全 PASS；redaction.mask_covered=true
```

## 6. 复现：合规证书 + 第三方验证

```bash
SP1_PROVER=cpu python3 scripts/issue_cert.py \
  --pack policy_packs/eu_ai_act_v1.json --response scripts/examples/eu_agent_reply.txt \
  --out-dir scripts/examples/out/cert_public
SP1_PROVER=cpu python3 scripts/verify_cert.py \
  --cert scripts/examples/out/cert_public/cert.json --pack policy_packs/eu_ai_act_v1.json \
  --ledger scripts/examples/out/ledger.jsonl --proof scripts/examples/out/cert_public/proof.bin
# 期望 7 项全 PASS（签名 / policy_hash / 锚定 / SP1 证明 / outcome / vkey / proof_sha256）
```

## 7. 复现：一键端到端 demo + 截图

```bash
SP1_PROVER=cpu python3 scripts/demo_e2e.py                 # 真实会话 + 真实 SP1 证明（加 --no-prove 秒级）
python3 scripts/verify_session.py --session scripts/examples/out/e2e/session.json
python3 scripts/make_shots.py --run-demo                   # 生成 docs/demo/*.html/svg/png
```
期望：`verify_session` 全 PASS；`docs/demo/session_report.html`、`session_summary.png`、`verify_result.png` 生成。

## 8.（可选）框架适配

```bash
bash scripts/install_frameworks.sh     # langchain / langgraph / mcp；装好后真实框架测试自动启用
```

## 9.（可选）审计路径：verifier-only（免构造证明器）

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

---

## 验收判据（复现成功）

- `python3 -m unittest discover tests` → **101 passed（1 skip）**；
- `scripts/prove_policy.py` / `cross_validate.py` → **RESULT: PASS**；
- `verify_cert.py` / `verify_session.py` → **RESULT: PASS**（含 SP1 证明密码学验证）。

## 故障排查

| 现象 | 原因 | 处理 |
|---|---|---|
| 证明进程被杀、无输出 | 内存不足（WSL 默认 ~7.6GB） | 宿主 `C:\Users\<你>\.wslconfig` 设 `memory=12GB`，`wsl --shutdown` 后重启 |
| `cargo prove ... unreachable` | `SP1_PROVER=native` 非法 | 用 `SP1_PROVER=cpu` |
| 出证报 “light prover cannot prove” | light 只能执行/验证 | 用 `cpu` |
| sp1-prover 编译报 `no method named keep` | 上游 tempfile 3.x 无 `TempDir::keep()` | 勿删 `circuits/patches/tempfile` 与 `[patch.crates-io]` |
| `git clone` / `cargo fetch` / pip 卡住 | 网络限流 | 用 gh-proxy / rsproxy / 清华 PyPI 镜像（见 §0） |
| `protoc` 找不到 | 缺 protobuf-compiler | `sudo apt-get install -y protobuf-compiler` |
| 缺少 `libsp1gnark.a` 构建失败 | 无 Go | 安装 Go ≥1.24 且设置 `GOPROXY` |

> 安全/边界说明：证书签名当前为 **HMAC-SHA256 demo signer**（`policydsl/cert.py`），生产应换 Ed25519/HSM；链上锚定当前为**文件账本**（离线可验），RPC 后端见 `anchor_on_chain` 钩子。
