# SP1 v6.7.0 健全性与零知识性核查（P0-4）

> 结论先行：**健全性成立；`core` / `compressed` 证明不满足零知识性。**
> 并且——这是更重要的发现——**即使换成 Groth16/Plonk，本项目的私有模式仍不是内容隐藏的**，
> 因为它发布了对低熵 `T` 可离线枚举的承诺。详见 §4。

核查日期：2026-09-11 · 版本：**SP1 v6.7.0**（`circuits/Cargo.lock` 全系列锁定）
方法：**两类独立证据** —— ① 官方文档/安全模型/审计报告；② 本机源码级审计
（`~/.cargo/registry` 中 v6.7.0 的全部 `sp1-*` / `slop-*` crate）。二者得出同一结论。
另附若干实测作**佐证**（`proof.bin` 中无响应明文窗口等）；实测本身不构成 ZK 判据，理由见 §2.2。

---

## 1. 健全性（Soundness）：成立

SP1 的健全性是官方明确主张、且被第三方审计覆盖的性质：

| 证据 | 内容 |
|---|---|
| 官方安全模型 | 「SP1 Hypercube 不依赖 proximity gap 猜想，而是依赖 (eprint 2020/654) 的 proximity gap **定理**，且在 unique decoding regime 下运行」；假设递归不带来安全损失；septic 曲线提供 ≥100 bit 安全性 |
| Zellic 审计 | 《Hypercube Protocol Cryptographic Security Assessment》，2025-12-23，193 页，3 Critical / 7 High —— **全部是健全性/绑定类**（如「Jagged PCS 不绑定证明者到 round 划分」「padding 操纵破坏 jagged PCS 的绑定性」） |
| 安全公告 | 已发布 5 条 advisory 全为健全性/绑定；最近一条 V6 的是 `GHSA-63x8-x938-vx33`（Recursion Circuit Row-Count Binding Gap，2026-04-11，High） |
| 本项目实测 | `tests/test_policy_binding.py` 的「真证明 + 假哈希必须被拒」、`cross_validate` 违规向量 `passed=false` —— 均 PASS |

**本项目依赖的正是这一条**：§3 的「违反策略的轨迹无法通过验证」归约到 zkVM 健全性 + SHA-256 抗碰撞。
这条依赖是**成立的**，无须修改。

---

## 2. 零知识性（Zero-knowledge）：`core` / `compressed` **不满足**

### 2.1 官方明文（决定性）

SP1 安全模型页（`docs.sp1/security/security-model`）原文：

> "While our implementations of Groth16 and PLONK are zero-knowledge,
> **individual STARK proofs in SP1 do not currently satisfy the zero-knowledge property.**"

Succinct 官方博客（VEIL 发布文，2026-05-01）说得更直白：

> "Modern proof systems like SP1 are designed for succinctness. … But these systems
> **are not natively zero-knowledge (ZK) and offer no privacy guarantees**, ruling out
> use cases dealing with sensitive data…"

### 2.2 源码独立验证（同一结论）

在 v6.7.0 的**全部** `sp1-*` / `slop-*` crate 上重跑盲化搜索，结果为空：

| 检查 | 位置 | 结果 |
|---|---|---|
| 盲化/隐藏/随机化/掩码行 | `slop-{commit,merkle-tree,jagged,whir,basefold,fri,uni-stark}` 的 `src/` | **命中 0** |
| 承诺是否带 opening randomness | `sp1-hypercube/src/prover/shard.rs:462 commit_traces` | `pcs_prover.commit_multilinears(message)` —— **只吃轨迹值，无随机参数** |
| `ShardProof` 暴露面 | `sp1-hypercube/src/verifier/proof.rs:47-60` | `main_commitment`（轨迹 Merkle 根）+ `opened_values`（注释原文 "The values of the traces at the final random point"）**明文在证明里** |
| WHIR 配置参数 | `slop-whir/src/config.rs WhirProofShape` | 全是**可靠性**参数（`starting_ood_samples`、`num_queries`、`*_pow_bits`…），**无隐藏参数** |
| `zk` feature flag | 所有 manifest | 无 |
| 全树 "zero-knowledge" 字样 | 仅 2 处 | `sp1-verifier/src/{plonk,groth16}/mod.rs` 的 gnark 包装器注释 |

唯一真正的 CSPRNG 是 `sp1-prover/src/utils.rs:148 generate_nonce()`（128-bit `OsRng`），
它注入 `proof_nonce` 并级联进所有 Fiat–Shamir 挑战。**这是 transcript 随机化，不是见证盲化**——
它让重复证明逐字节不同（实测：同一输入两次出证差异 2671109 字节），但不改变「轨迹开值明文可得」这一事实。
*（顺带纠正一个易犯的推理：不能用「两次证明是否相同」当 ZK 判据。确定性 ⇒ 非 ZK 成立，但非确定性 ⇏ ZK，此处正是反例。）*

原生 ZK 的路线图是 **VEIL**（eprint 2026/683，Succinct 作者群）：`slop-veil` crate 已随 v6.7.0 发布，
但**没有被任何证明路径依赖**（`slop/README.md` 自称 experimental / 未经审计；0 反向依赖）。
即 **v6.7.0 的证明管线里没有可用的 ZK 路径**。

### 2.3 `groth16` / `plonk`：包装器层面的 ZK，但有三个保留

结构上是**唯一**隐藏内部 STARK 证明的模式（`sp1-prover/src/build.rs:350-381`）：

- 私有见证：`template_input.write(&mut witness)` —— 完整的 `ShardProof`
- 公开输入：只有 5 个 —— `VkeyHash` / `CommittedValuesDigest` / `ExitCode` / `VkRoot` / `ProofNonce`
  （`sp1-recursion-gnark-ffi/go/sp1/utils.go:63-90`，与 `#3 PublicInputs[5]` 一致）

但：

1. **这是包装器层面的声明，不是被审计的性质**。Zellic 审计里 "zero-knowledge" 只出现在
   Succinct 自己提供的营销描述与 Zellic 的公司模板里，**没有任何 finding 把「隐藏见证」当作被评估性质**。
2. **不是后量子**（依赖 BN254 上的 Groth16/Plonk 椭圆曲线假设）。
3. **本机出不了**：该模式需 ≥16 GB（本机 12 GB 会 OOM，见 `docs/dev-plan.md`），因此
   本仓库**无法在本机产出或回归测试**这条路。

---

## 3. 对本项目的直接影响

| 项 | 现状 | 判定 |
|---|---|---|
| §3 健全性论证（A1/A4/A6） | 依赖 zkVM 健全性 | ✅ **不受影响**，论证成立 |
| 私有模式的「公开值不含明文」 | 证书公开值只有 64-hex 承诺，Leak 实验可测 | ✅ 成立 |
| 私有模式的「证明工件不泄露见证」 | 默认走 `core` | ❌ **不成立** |

`core` 模式给对手的额外能力（相对「只能猜承诺」）：

- **重放式猜测-验证**：`main_commitment` 是 guest 确定性执行的轨迹 Merkle 根。
  对手对猜到的 `T′` 重放 guest 执行即可复现该根并比对——比出证便宜得多的猜测-验证通道。
- **聚合轨迹暴露**：`opened_values` 是轨迹在挑战点上的真实开值（无掩码）。
  多次出证（同一策略、不同 `T`）之间的相关性可被利用，例如粗粒度地识别响应长度/分支走向。

---

## 4. 更重要的发现：**绑定与隐藏对低熵 `T` 不可兼得**

即使把证明换成真正的 ZK（Groth16），本项目的私有模式**仍然不是内容隐藏的**，根因不在 SP1 而在设计：

```
response_binding = SHA256(BIND_DOMAIN ‖ u32_be(len(n)) ‖ n ‖ T)
response_commitment = SHA256(T)
```

两者都**公开**（进公开值、进证书）。P0-2 要求 `response_binding` **必须可由任意持 `(n, T′)` 的一方
离线重算** —— 这正是它的价值所在（验证者不信出证方也能核对）。而「公开的、可离线重算的 `T` 的函数」
**就是**一个离线猜测-验证 oracle：

> 对任意候选 `T′`，算一遍 `SHA256(…‖T′)` 比对即可判定 `T′ == T`。

自然语言响应的熵远低于 SHA-256 的 256 bit（一句话 T 的信息量通常在 ~10²–10³ bit 量级，
且高度受上下文约束），因此**枚举是可行的**。

这不是本文档新发现的缺陷——§2 的「内容隐私」论证其实一直写得很诚实：
「拿到 `V` 的人能做的只是**猜测—验证**」。问题在于**叙事**：「零知识合规证明」这个说法会被读成
「证明 `T` 合规，且 `T` 不可恢复」，而后者对低熵 `T` 在密码学上做不到。

**推论（可写进论文的干净结论）**：在绑定必须由验证者独立重算的前提下，
「响应绑定」与「响应内容隐藏」对低熵输入**在信息论上互斥**。要两者兼得，只能：
① 让 `n` 保密（则验证者无法独立核对，退化为信任出证方）；
② `T` 高熵（如带密钥的 MAC 输出，但那就不是自然语言响应了）；
③ 接受「隐藏」只对**不在验证者候选集内**的 `T` 成立。

---

## 5. 结论与建议动作

**已核实**（替换 `docs/security-model.md` §5 假设 1 的 ⚠️ 待核实块）：

1. 健全性成立 → 现有安全论证不变。
2. `core` / `compressed` **不满足零知识性**（**两类独立证据**：Succinct 官方安全模型明文 + 本机源码审计；
   实测仅作佐证 —— 证明里找不到响应明文窗口，但这**不是** ZK 判据，见 §2.2 的推理纠正）。
3. `groth16` / `plonk` 是唯一可能隐藏见证的模式，但属包装器层面声明、非审计性质、非后量子、本机不可出证。
4. **私有模式当前的准确定义是「公开值不泄露明文」，不是「证明工件不泄露见证」，更不是「`T` 不可恢复」。**

**建议**：

- [x] **文档口径**：§2「内容隐私 Content privacy」已正名为「**承诺隐私 Committed-value privacy**」，
      并显式写明它**不**防御对低熵 `T` 的离线枚举（§4 的互斥结论）。
      *已同步*：`security-model.md` §2/§5、`architecture.md`、`quadrant.md`、`bench/comparison_zkagent.md` §4.4、
      `modules/05-zk-circuits.md`、`plan-p0p1p2.md`（P0-4 行 + 风险登记册 + §9 进度）、`policydsl/commit.py` 文档串。
- [x] **证书诚实标注**：`binding.proof_mode` 字段（`core`/`compressed`/`groth16`/`plonk`/`unproven`）
      已写进载荷并进 `cert_digest`，`cert.proof_hiding()` 给出该档的隐藏程度（**未知模式返回
      `"unknown"`，不猜**）。验证侧：`verify_cert.py` 逐证书与**工件自报的模式**（边车
      `*.verify.json` / `*.meta.json` / 验证器输出）比对，无工件却自称某档即 `[FAIL] proof_mode`；
      `verify_session.py` 再加一层会话级双条件核对。验收见
      `tests/test_cert.py::TestProofModeLabeling` 与
      `tests/test_policy_binding.py::TestProofModeOverclaimRejected`。
- [x] **叙事收紧**：论文摘要/README 里「零知识合规证明」已限定为
      「**策略零知识**」（策略合规性可证而不暴露违规内容）+ 明确说明响应内容的隐藏上界。
      *已同步*：`README.md` 首段、`方向二_README.md`、`paper/proof-of-policy.md` 标题/摘要/§2.1/§5/§8.1、
      `docs/plan-p0p1p2.md` §3 标题。
      *注：这其实正是本系统真正成立的强项——`policy_hash` 三方绑定 + 违规只暴露证据承诺。*
- [ ] **可选强化**（非阻塞）：若要真正的见证隐藏，需在 ≥16 GB 机器上用 `groth16` 模式出证并回归；
      同时**分离两个承诺**：`response_binding`（无盐、可重算、用于绑定）与
      `response_commitment`（改为带盐/带密钥、用于隐藏，不再公开可验证）。
- [ ] **本机限制如实记录**：groth16/plonk 路线在本环境**不可验证**，只能标注为「设计上可行，未实测」。

---

**相关**：安全模型 → [`security-model.md`](security-model.md) §2 / §5；
电路与承诺 → [`modules/05-zk-circuits.md`](modules/05-zk-circuits.md)；
隐私原语 → [`modules/02-privacy-commitment.md`](modules/02-privacy-commitment.md)；
计划 → [`plan-p0p1p2.md`](plan-p0p1p2.md) P0-4。
