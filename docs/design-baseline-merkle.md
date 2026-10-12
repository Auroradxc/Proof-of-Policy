# 设计说明：签名 Merkle 基线臂（WP9）

本文件是 `bench/results/baseline.{json,md}` 的**配套说明**，不是第二份规格。
规格在 `docs/tdsc-plan.md` §WP9（本节只讲「这条臂怎么搭、复用谁、故意不做什么」）。

## 它是什么

一条**非 ZK** 对照臂（brivora / VAOL 风格）：对 `(π, T, nonce)` 三元组

1. 用 `policydsl.check`（参考评估器）得到 `passed`；
2. 用 `policydsl.privacy.commit` 算 `response_commitment` / `response_binding`；
3. 对签名体 `{policy_hash, response_commitment, nonce, passed, ts}` 用 **Ed25519**
   （`policydsl.evidence.cert.Ed25519Signer` 的 `sign_payload`，类 DSSE 信封）签名；
4. 把证书摘要追加进**仅追加 Merkle 日志**并出包含证明。

量：签名时间、Merkle 追加时间、包含证明大小、核验时间、证书大小（均取重复中位数）。

## 复用谁（不另写语义）

| 环节 | 出处 |
|---|---|
| 判定 `J(π,T)` | `policydsl.core.evaluate.check`（`from policydsl import check`） |
| 承诺 / 绑定 / nonce | `policydsl/privacy/commit.py`、`policydsl/privacy/challenge.py` |
| 签名 / 信封 / keyring | `policydsl/evidence/cert.py`（`Ed25519Signer`、`sign_payload`、`verify_envelope`） |
| Merkle | `policydsl/proofs/session.py`（`MERKLE_NODE_DOMAIN` / `merkle_root` / `merkle_proof` / `verify_merkle_proof`） |
| 机器记录 | `bench_proofs.host_info()`（与 `proofs.md` 同一口径）+ Python / OS 版本 |

`cert.py` 用的是仓库既有的 `cryptography` 依赖（网关签发工具回执的同一套），
没有引入新依赖。

## 承重的那条不变量：不对称是**机器校验**的

签名 Merkle 日志的核验链是「验签 → 验日志包含 → **重跑 `J(π,T)`**」。前两步只需
公开数据，第三步**必须同时持有 π 与 T 的明文** —— 这是签名范式的结构性后果。
为了不让它停在注释上，`bench_baseline.py` 提供两条**都被真实调用/测量**的路径：

- `verify_public_only(...)`：验签 + 验包含；`passed` 恒为 `None`、`honest` 恒为 `False`；
- `verify_by_reexecution(policy, response, ...)`：额外重跑参考评估器，并把「签名者
  写的 `passed`」与「重跑结果」逐位对齐；π 或 T 缺失时**抛 `BaselineError`**。

`require_honest(result)` 供调用方把「拿公开结果当诚实核验」变成一条异常。
脚本跑完前会断言六条（`asymmetry` 字段）：公开路径确实能验签/验包含、它确实回答
不了 `passed`、误用会抛、缺明文会抛、**签名有效但内容为假的证书公开路径同样全绿**、
给了明文才允许说「诚实核验过」。任一条不绿即 `SystemExit`，不入库。

## 故意不做的事

- **不做增量 Merkle**：`MerkleLog.append` 每次重算整棵树的根（`Θ(n)`），所以
  `baseline.md` 的「Merkle 追加」一栏要按「重算根」读，不是增量追加的摊销价。
- **不写任何 ZK / SP1 数字**：ZK 成本列一律「见 WP1 / `bench/results/proofs.md`」。
  交叉点数据在 WP1 的云机落地前缺一半（§WP9.1 的诚实边界）。
- **不进 `tests/test_bench_views.py` 的 `VIEWS`**：该闸门的通用不变量假定 proofs 表
  形状的 `rows`（`ok` / `peak_rss_mb`），本臂没有内存采样；与 `verify`/`streaming`/
  `compose`/`semantic`/`cycles`/`ablation` 同样是「入库但未申报」。本脚本自带
  `--render-only`，`.md` 始终可由 `.json` 重渲染。

## 复跑

```bash
python3 bench/bench_baseline.py                       # → bench/results/baseline.{json,md}
python3 bench/bench_baseline.py --reps 2000 --log-size 4096
python3 bench/bench_baseline.py --render-only         # 不重采数据，仅重渲染 .md
```
