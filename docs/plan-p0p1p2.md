# PoP 补足计划：P0 / P1 / P2

> 依据：`docs/security-model.md`、`paper/proof-of-policy.md`、`bench/comparison_zkagent.md`
> 与对 `circuits/`+`policydsl/` 的逐行复核（含一个已**实跑复现**的健全性破坏）。
> 本计划是**可执行**的：每个任务给出改动文件、接口签名、验收测试与前置依赖。

---

## 0. 现状基线（2026-09-10）

| 项 | 值 |
|---|---|
| 测试 | 143 passed / 3 skipped |
| 电路 | `pop-types` 615 行 + guest 26 行 + 驱动 308 行 + verifier 125 行 |
| 公开值 | **仅 `Outcome{passed, violations}`——不含策略、不含响应绑定、不含轨迹绑定** |
| 本机 | 24 核 / **12 GB**（groth16/plonk 需 ≥32 GB → P1-7 的硬约束） |
| 可用库 | `cryptography` 3.4.8 ✅（Ed25519 可用）；`ezkl`/`nacl`/`eth_account` ❌ |
| 签名 | HMAC + **公开常量密钥** `DEMO_KEY`（`policydsl/cert.py:31`）→ 任何人可伪造 |

### 已确认的健全性破坏（P0-1 要修的）

`circuits/program/src/main.rs:21` 把含 `constraints` 的 `Job` 读为**私有输入**，只 `commit(&out)`。
`Outcome`（`circuits/types/src/lib.rs:132,467`）不含策略。

实跑证据（`pop-script --check`，同一条含 `weaponize` 的响应）：

```
honest_eu_policy         passed=False  violations=[{keyword_block, banned_terms, weaponize}]
attacker_trivial_policy  passed=True   violations=[]        ← constraints: []
```

而 `scripts/verify_cert.py:74` 的策略绑定是 `payload["policy_hash"] == spec["sha256"]` ——
**纯字符串比对**。攻击者填入真策略哈希即可全绿。结论：证明的义务是
「**存在** π′ 使 J(π′,T).passed」，不是「J(π,T).passed」。

---

## 1. 决策点（已拍板，2026-09-10）

| # | 决策 | **结论** | 影响 |
|---|---|---|---|
| **D1** | P1-6「与 zkAgent 联合证明」如何落地？zkAgent 是 SJTU 的 C++ 系统，代码未公开 | ✅ **形式化组合引理 + 代理推理证明**：同 zkVM 内做一个确定性小模型（MLP）前向的推理完整性证明作为 stand-in，实测组合成本；论文如实写成「组合框架 + 代理实验」 | §4 P1-6 按分支 A 执行，**不阻塞**；若日后拿到 zkAgent 代码，只需替换 prover |
| **D2** | P1-7 链上验证算力从哪来？本机 12 GB，groth16/plonk 必然 OOM | ✅ **租一次性 ≥64 GB 云机**：产出 groth16 证明 + 测通验证合约；结果入库后本机离线复核 | §4 P1-7 需要一个云机窗口（约数小时），提前排期 |
| **D3** | P2-9「语义级规则」做到什么深度？ | ✅ **完整 ezkl 集成**（非可判定子集） | **P2 从 4 周扩到 6 周**；新增 ZK 机器学习栈与信任边界设计；前置依赖见 §8.0（pip 缺失） |

> D3 的选择使 P2-9 从「1 周可判定子集」升级为**独立的 2–3 周工作流**，且引入了本项目此前没有的一类新依赖
> （torch / onnx / ezkl 及其 halo2 后端）。§5.1 给出完整拆分与信任边界论证。

---

## 2. 路线图

```
W1    W2    W3    W4    W5    W6    W7    W8    W9    W10
├P0─┤
│绑定+Ed25519+口径
      ├──── P1（轨迹绑定 → M1 → 链上 → 形式化）────┤
                                                  ├──── P2 ────┤
                   └── P2-9 ezkl 前置（pip/依赖）──┘  └ P2-9 主线 ┘
                     可与 P1 并行，提前启动以吃满工期
```

| 阶段 | 周 | 交付 | 验收 |
|---|---|---|---|
| **P0** | 1 | 策略入公开值、挑战-响应绑定、Ed25519、文档口径 + ZK 性质查证 | 攻击测试**必须失败**；新测试全绿 |
| **P1** | 3 | 轨迹绑定、M1 组合、链上证明验证、形式化安全模型 | 端到端全 PASS + 反例对照；游戏式定义 + 归约 |
| **P2** | **6** | ezkl 语义规则（**含依赖栈打通**）、跨证书一致性、多证明者、真实规模评测 | 新模块 + 新 bench 表 + 论文 §7 重写 |

> **并行建议**：P2-9 的前置（§8.0 恢复 pip、装 torch/onnx/ezkl）与 P1 无耦合，
> **建议 W1 就并行启动**，否则 2–3 周的依赖栈调试会串行吃掉 P2 的全部预算。

---

## 3. P0：让「策略零知识证明」这个声明成立（1 周）

> **标题口径（2026-09-11 核查后收紧）**：原文为「零知识合规证明」。P0-4 查证确认 SP1 的
> `core`/`compressed` 证明**并非零知识**，且响应内容隐藏对低熵 `T` 有明确上界（见 [`sp1-zk-audit.md`](sp1-zk-audit.md)）。
> 因此本节的「零知识」限定为**策略零知识** —— 合规性可证而**违规内容不泄露**（违规只以证据承诺披露）；
> 响应内容隐藏只承诺「公开值不含明文」。本节各项的**技术目标不变**，仅口径收紧。

### P0-1 策略进公开值 ⭐ 关键路径 —— ✅ 已完成（2026-09-10）

> **状态**：代码已落地、编译通过、163 项单测全绿、`cross_validate --no-prove` 14/14
> 保持、真实 SP1 证明的 cert_public 工件已按新 ELF 重新生成并端到端验证通过。
> 攻击回归测试见 `tests/test_policy_binding.py`（三层 + 一层 opt-in）。
>
> **与下方设计稿的偏差（以实现为准）**
> 1. `spec_canonical` 用 `String`（规范字节是**纯 ASCII**，见 `canonical_spec_text`），
>    不是 `Vec<u8>` —— 让 `serde_json` 的 vectors 文件保持可读，且 `decode/encode("utf-8")`
>    是恒等变换，哈希逐字节一致。
> 2. `response_binding` 属于 P0-2，本步未加。
> 3. **新增** `circuits/verifier/src/main.rs`：`pop-verify` 过去只把公开值哈希一遍，
>    证书里的 `outcome`/`policy_hash` 与它**没有任何可核对的联系**（同一类脱钩，
>    只是上移了一层）。现在它把公开值解回 `Outcome` 并输出，验证方才能做真正
>    的三方比对。摊平逻辑 `pop_types::outcome_value` 由 `pop-script` 与 `pop-verify`
>    **共用**，形状不可能漂移。
> 4. `tests/test_serialize.py` 从「枚举映射测试」改写为「**契约字节性质**测试」
>    （确定性与紧凑性、纯 ASCII、`sha256(字节) == spec["sha256"]` 恒等式、
>    未知 kind 原样携带）。
>
> **验收证据**（本机实跑）
> ```
> python3 -m unittest discover tests                     → Ran 163 tests, OK (skipped=4)
> python3 scripts/cross_validate.py --no-prove           → host 14/14  PASS
> SP1_PROVER=cpu python3 scripts/verify_cert.py ... --proof .../proof.bin
>   [PASS] policy_hash  5b5fd101…[cert] == 5b5fd101…[cert.outcome]
>                       == 5b5fd101…[recompiled] == 5b5fd101…[proof]
>   RESULT: PASS
> POP_TEST_PROOF=1 python3 -m unittest tests.test_policy_binding.TestProofLevelBinding
>   → 2 tests OK（含「真证明 + 假哈希必须被拒」）
> ```

**核心设计：把「规范 JSON 字节」作为唯一真相源，guest 从同一段字节里同时得到「哈希」和「要判定的约束」。**
这样「哈希覆盖的约束」与「实际判定的约束」在构造上不可分离——攻击者无法再解耦。

```rust
// circuits/types/src/lib.rs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstraintSpec {          // Python 规范 JSON 的直接映射
    pub spec_version: String,
    pub policy_id: String,
    pub policy_version: String,
    pub semantic: String,
    pub constraints: Vec<SpecConstraint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]   // ← 内部标签，直接吃 Python 形状
pub enum SpecConstraint {
    KeywordBlock { name: String, keywords: Vec<String> },
    LengthBound { name: String, min: u32, max: u32 },
    PatternBlock { name: String, patterns: Vec<String>, nfa: NfaBlock,
                   #[serde(default)] mode: PatternMode },
    FormatCheck { name: String, format: FormatKind },
    ToolArgGuard { name: String, #[serde(default)] tools: Vec<String>,
                   forbidden_fields: Vec<String> },
    BudgetBound { name: String, budget: u32, unit: BudgetUnit },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NfaBlock { pub compiled: Vec<NfaSpec> }
```

请求体改成携带**规范字节**：

```rust
pub struct ProofRequest {
    pub spec_canonical: Vec<u8>,   // ← 新增：唯一真相源（Python 产出）
    pub response: String,
    #[serde(default)] pub nonce: Vec<u8>,        // P0-2
    #[serde(default)] pub receipts: Vec<ToolReceipt>, // P1-5
}
```

guest（`circuits/program/src/main.rs`）变为：

```rust
pub fn main() {
    let job: Job = io::read();
    let out: Outcome = run_job(&job);   // run_job 内部：
    //   let spec: ConstraintSpec = serde_json::from_slice(&req.spec_canonical)?;
    //   let policy_hash = sha256_hex(&req.spec_canonical);   ← 与判定同源
    //   判定用 spec.constraints；policy_hash 填入 ProofOutput/PrivateOutput
    io::commit(&out);
}
```

公开值新增字段：

```rust
pub struct ProofOutput    { pub policy_hash: String, pub response_binding: String,
                            pub passed: bool, pub violations: Vec<Violation> }
pub struct PrivateOutput  { pub policy_hash: String, pub response_binding: String,
                            pub passed: bool, /* ...既有... */ }
```

Python 侧：

```python
# policydsl/compile.py
def canonical_spec_bytes(spec: Dict) -> bytes:
    """规范 JSON 字节（与 _canonical_hash 完全一致）。"""
    stable = {k: spec[k] for k in ("spec_version","policy_id","policy_version",
                                   "semantic","constraints")}
    return json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")

def _canonical_hash(obj): return hashlib.sha256(canonical_spec_bytes(obj)).hexdigest()
```

**改动清单**

| 文件 | 改动 |
|---|---|
| `circuits/types/src/lib.rs` | 新增 `ConstraintSpec`/`SpecConstraint`/`NfaBlock`；`ProofRequest`/`PrivateRequest` 用 `spec_canonical`；`ProofOutput`/`PrivateOutput` 加 `policy_hash`；`evaluate` 改吃 `&[SpecConstraint]` |
| `circuits/program/src/main.rs` | 解析 + 哈希 + 提交 |
| `circuits/script/src/main.rs` | `VectorIn` 改字段；`outcome_json` 带上 `policy_hash` |
| `policydsl/compile.py` | `canonical_spec_bytes` |
| `policydsl/serialize.py` | ✅ `spec_to_rust_constraints` **已删除**，改导出 `spec_canonical_text(spec)` + `vector_entry(...)`（20 个调用点已机械替换） |
| 20 个调用点 | `scripts/{prove_policy,cross_validate,private_demo,issue_cert,demo_e2e}.py`、`tests/{test_rules_incircuit,test_ablation,test_serialize}.py`、`bench/*.py` |
| `scripts/verify_cert.py` | 策略绑定改**四方比对**（证书声明 / 证书 outcome 内嵌 / 重编译 / 证明公开值），并把证明校验**提到绑定之前**（绑定要用到证明公开值） |
| `scripts/verify_session.py` | 同上；`zk` 循环补上「证明公开值」这一路 |
| `circuits/verifier/src/main.rs` | 解码公开值为 `Outcome` 并输出（新增 `pop-types` 依赖）；解码失败即判 `verified=false`（fail-closed） |
| `policydsl/verifier.py` | 新增 `check_policy_binding` / `committed_policy_hash` / `outcome_without_meta` |

**验收测试** `tests/test_policy_binding.py`（新，分三层 + 一层 opt-in）：

```python
def test_empty_policy_commits_empty_hash_not_real(self):
    """攻击的第一半成立、第二半不成立：空策略确实 passed=true，
    但电路承诺的哈希是**空策略**的哈希，不是真策略的。"""
    out = run_check(spec_canonical_text(compile_policy(EMPTY)), VIOLATING)
    self.assertTrue(out["passed"])
    self.assertEqual(out["policy_hash"], hash_of(EMPTY))
    self.assertNotEqual(out["policy_hash"], hash_of(REAL))
```

- `TestAttackIsDead`：Rust 侧实跑 `--check`，不变量「`passed=true` 且 `policy_hash==真实策略哈希`」
  对**真策略会拒绝**的响应永不成立（前提逐例实测，不假设）。
- `TestFailsClosed`：未知 `kind` 必须让 guest **产不出证明**，而不是静默跳过。
- `TestThreeWayBinding`：三方比对判定逻辑 + **反空洞断言**（来源少于两个一律失败，
  否则「三方比对」退化成恒真）。
- `TestVerifierEndToEnd`：对一张**签名有效**的伪造证书跑 `verify_cert.py` → 必须 FAIL
  （诚实证书作正向对照）。
- `TestProofLevelBinding`（`POP_TEST_PROOF=1`，约 74 s）：真证明 + 假哈希必须被拒；
  证明本身仍 `[PASS] proof_verify`，断在 `[FAIL] policy_hash`。

> **风险**：20 个调用点的机械替换 + `test_serialize.py` 重写。属可控工程量，但必须一次性完成，避免两套序列化并存。

---

### P0-2 挑战-响应绑定 —— ✅ 已完成（2026-09-10）

> **状态**：电路与参考层两侧都落地，`tests/test_binding.py` 19 项全绿（四种 nonce
> 长度与 Python golden 逐字节对齐），全部工件按新 ELF 重新生成并端到端验证通过。
>
> **与下方设计稿的偏差（以实现为准）**
> 1. **绑定公式加了长度前缀**：`SHA256(BIND_DOMAIN ‖ u32_be(len(nonce)) ‖ nonce ‖ T_utf8)`。
>    没有它，`(nonce=b"ab", T="cd")` 与 `(nonce=b"abcd", T="")` 会哈希成同一个值 ——
>    拼接的经典歧义。挑战值通常定长，但把无歧义性寄托在调用方自觉上不是好买卖。
>    代价是 4 字节；收益是 `(nonce, T) → 字节串` 恒为单射。
> 2. `BIND_SCHEME = "pop-bind-v1"` 一并写进证书的 `challenge` 块，便于将来换代时
>    验证方**从证书本身**看出该用哪套算法，而不是猜。
> 3. `ProofOutput` **和** `PrivateOutput` 都加 `response_binding`（原设计只提私有模式）。
>    公开模式下 T 同样是证明的私有输入、证书里也不出现 T，同样需要这一绑定。
> 4. `response_commitment` **保留原义**（`SHA256(T)`，即「存在某条通过判定的 T」），
>    没有被「升级」成绑定值 —— 二者回答的是不同的问题，合并会让「这到底是哪条 T」
>    这个区分消失。会话绑定由 `response_binding` 单独承担。
> 5. `challenge.py` 多了一个 `NonceStore`（追加式「已用 nonce」记录）。一次性是协议
>    使用方的责任，给个语义正确、离线可跑的最小参考比只写一句注释强。
> 6. `cert.ai_act_claims` 增加 `art12_response_bound`，**如实**反映本证书是否带
>    challenge 块 —— 没有它时不能默认成 True。
>
> **验收证据**（本机实跑）
> ```
> python3 -m unittest discover tests                     → Ran 184 tests, OK (skipped=5)
> python3 -m unittest tests.test_binding -v              → Ran 19 tests, OK
> python3 scripts/cross_validate.py --no-prove           → host 14/14  PASS
> python3 scripts/private_demo.py                        → challenge (T',nonce)_opens=True
>                                                          wrong_T'_rejected=True
>                                                          wrong_nonce_rejected=True
>                                                          domain_separated=True
> python3 scripts/verify_cert.py ... --response T.txt    → [PASS] response_binding
>                                                          — 送达的 T′ 就是被证明的 T
> python3 scripts/verify_session.py --session …/session.json
>                                                        → [PASS] certificates_response_binding
>                                                          [PASS] zk_proof … + response binding
> ```
>
> 反例对照（同一条命令，只把 `--response` 换成另一条响应）：
> ```
> [PASS] policy_hash     …四路一致…
> [FAIL] response_binding MISMATCH: fceb8f96…[cert.challenge] == fceb8f96…[cert.outcome]
>                         == 8ea38633…[response] — 送达的 T′ 与被证明的 T 对不上
> RESULT: FAIL
> ```
> 这一正一反是 P0-2 的验收实质：换 T′ 后**只有**响应绑定那一卡变红，其余照旧 ——
> 说明它确实在独立地承担「T′ == T」这件事，而不是搭便车。

---

> ### ↓ 以下是原始设计稿（保留备查，以本节开头的实现为准）

**问题**：证明的 T ≠ 送达的 T′；私有模式下验证者永远看不到 T，无法自证绑定。

**设计**：客户端出 `nonce`，电路内承诺 `response_binding = SHA256("pop-bind-v1" ‖ nonce ‖ T_utf8)`，
公开值携带该绑定。持 T 与 nonce 的一方可**离线**核对。

```python
# policydsl/commit.py
BIND_DOMAIN = b"pop-bind-v1"
def response_binding(nonce: bytes, response: str) -> str:
    return hashlib.sha256(BIND_DOMAIN + nonce + response.encode("utf-8")).hexdigest()
def verify_binding(nonce: bytes, response: str, binding: str) -> bool:
    return hmac.compare_digest(response_binding(nonce, response), binding)
```

```python
# policydsl/challenge.py（新）
def new_nonce() -> bytes:   # 32 字节 CSPRNG，一次性
    return secrets.token_bytes(32)
```

- ~~私有模式下 `response_commitment` 语义升级为「绑定到本次会话的承诺」；保留 `commitment(T)` 供兼容。~~
  （**未采纳**，见开头偏差 4：两个字段并置而非合并。）
- `scripts/issue_cert.py` / `demo_e2e.py` 接受 `--nonce`；`verify_cert.py` 加 `--response` / `--nonce` 做核对
  （`verify_session.py` 不做重算，只对会话内证书做自洽比对）。
- `scripts/demo_e2e.py` 走真实挑战流程（客户端生成 → 传 → 验证）。

**验收** `tests/test_binding.py`：① 正确 (nonce,T) 通过；② 换 T 失败；③ 换 nonce 失败（**重放防护**）；④ 空 nonce 与带 nonce 的绑定不同（域分离）。

**验证方怎么用**：`verify_cert.py --cert ... --response T.txt` —— 新增的第 3b 卡做
四路比对（`challenge` 块 / outcome 内嵌 / 证明公开值 / 由 T′ 与 nonce 现场重算），
与策略绑定同构（同样要求 ≥2 个来源，缺失来源如实列出）。不给 `--response` 时那一路
记为 `absent`，报告不会假装做过完整核对。

**这一层**解决的是「送达的 T′ 是不是被证明的 T」。**不**解决的（留 P1-5）：
`tool_calls` / `token_count` 仍是证明者自填的私有输入，工具轨迹的真伪不在绑定范围内。

---

### P0-3 Ed25519 替换 demo HMAC

```python
# policydsl/cert.py  签名器协议
class Signer(Protocol):
    keyid: str
    def sign(self, data: bytes) -> bytes: ...
    def verify(self, data: bytes, sig: bytes) -> bool: ...

class Ed25519Signer:   # 生产：cryptography.hazmat.primitives.asymmetric.ed25519
    keyid = "ed25519:<pubkey_fingerprint>"
class HmacSigner:      # 仅测试；keyid 前缀 "test-hmac-sha256"
```

- `verify_envelope(env, keyring)` 按 `keyid` 前缀**分发**；默认 keyring **不含** HMAC → 旧证书不再被接受。
- `policydsl/keys.py`（新）：`load_or_create(path)`、`POP_SIGNING_KEY` 环境变量、PEM/PKCS8。
- `scripts/gen_key.py`（新）：生成密钥对 + 指纹。
- 改动调用点：`issue_cert.py`、`verify_cert.py`、`demo_e2e.py`、`verify_session.py`、`tests/test_cert.py`。
- `scripts/demo_e2e.py` / `anchor_e2e.sh` 默认生成临时密钥对并打印公钥。

**验收**：① 错密钥签名被拒；② 篡改 payload 被拒；③ **负例**——用旧 `DEMO_KEY` 签出的信封**必须被拒**（证明这次替换不是恒真）。

---

### P0-4 口径一致 + ZK 性质声明

| 位置 | 现状 | 改为 |
|---|---|---|
| `paper §4.2` | 「keyword/length/pattern 入电路」 | 统一为 6 类（与 §5 一致） |
| `paper §6` | 「102 全绿(1 skip)」 | 实跑值（P0 后会变） |
| `docs/security-model.md:65` | `host/prove 7/7` | ✅ 已改为 `14/14`（2026-09-10） |
| `docs/eu-ai-act-mapping.md` | 工具路径「`zk:false`」 | 已入电路（P1-5 后语义再更新） |
| **全仓库** | **未声明 ZK 性质** | ✅ **已查证（2026-09-11）**，结论见 [`sp1-zk-audit.md`](sp1-zk-audit.md)：**core/compressed 不满足零知识性**（两类独立证据：Succinct 安全模型明文 + 本机 SLOP 栈源码零盲化命中；另有实测佐证）；`groth16`/`plonk` 是唯一可能隐藏见证的模式（包装器层面声明、未被审计评估、非后量子、本机 12 GB 出不了证）；原生 ZK 的 `slop-veil` 已发布但未被任何证明路径依赖。**后果**：私有模式口径收紧为「公开值不泄露明文」，不再宣传「证明工件不泄露见证」；证书待加 `binding.proof_mode` 诚实标注（列为后续动作，非阻塞） |

> P0-4 的最后一条是**调研任务**，不是文书任务，但它决定 §4.3（双隐私模式）能否成立，优先级等同 P0-1。
> **已查证（2026-09-11）**：健全性成立；零知识性对 `core`/`compressed` **不成立**。
> 私有模式**仍然成立**，但成立的是「承诺隐私」（公开值不含明文）这一较弱性质；
> 另外核查还发现一个**与 SP1 无关的设计层结论**——对低熵 `T`，「响应绑定」与「响应内容隐藏」互斥
> （`response_binding` 必须公开可重算 ⇒ 必然是一个离线猜测-验证 oracle）。详见 `sp1-zk-audit.md` §4。

---

## 4. P1：从「合规原语」到「可验证 agent」（3 周）

### P1-5 轨迹绑定 —— 把「证明者的声明」变成「可验证的事实」

**问题**：`tool_calls` 与 `token_count` 是 `ProofRequest` 里由证明者自填的私有输入
（`circuits/types/src/lib.rs:112-119,390`）。`tool_arg_guard`/`budget_bound` 因此**语义上不健全**。

**设计**：引入**工具回执链**。回执由**工具网关**（不是 agent）签发；agent 只能转发。

```python
# policydsl/trace.py（新）
@dataclass
class ToolReceipt:
    seq: int; tool: str
    args_digest: str        # H(canonical(args))
    result_digest: str      # H(result_text)
    ts: str
    prev: str               # 前一条回执的 digest（"genesis" 起始）
    sig: str                # 网关签名，覆盖上述全部字段
    keyid: str

def chain_digest(receipts) -> str: ...        # 链尾摘要
def verify_chain(receipts, keyring) -> bool:  # 序号连续 + prev 链接 + 每条验签
```

**电路内**（新增 `Job` 字段 `receipts: Vec<ToolReceipt>`，独立于 `constraints`）：
1. `verify_receipt_chain(receipts)`：序号连续、`prev` 链接正确（**签名在链下由网关钥验，链内验结构**——
   或把网关公钥作为公开输入，链内验 Ed25519；后者更强但代价高，建议**先做结构链 + 链下验签**，论文如实标注）；
2. `tool_arg_guard` / `budget_bound(calls)` 改为对 **receipts** 判定，而非 `tool_calls`；
3. `token_count` 改为**电路内自算**：把 `unit: "tokens"` 的语义定义为
   「按策略声明的确定性分词规则（UTF-8 空白分隔 run 数）在电路内计数」——
   **语义变了但变得可证**；论文必须在 §4.2 显式写明这一定义。

**接线**：`MCPGuard.call_tool`（`policydsl/mcp_adapter.py`）在**执行后**产出回执（
结果摘要 + 参数摘要 + 网关签名），使 demo 里的回执**真的由网关产生**而非 agent 自填。

**验收** `tests/test_trace.py`：① 完整链通过；② 删/换/重排一条 → 失败；③ **负例**——伪造一条
「参数不含被禁字段」的回执但仍带违规参数 → 验签失败；④ 旧路径（自填 `tool_calls`）**不再被接受**。

> 这是与 zkAgent 差距最大的地方，也是本计划**最有论文价值**的一段：把轨迹完整性做进同一份证明。

---

### P1-6 M1 联合证明（受 D1 影响）

**分支 A（推荐，可立即执行）**：
1. **形式化层**：定义组合义务 `Compose = (推理完整性 ∧ 策略合规)`，给出「键分离 + 两次验证 ⇒ 组合成立」的引理（写进 P1-8）。
2. **代理实验**：在现有 zkVM 内加 `Job::Infer` 模式，证明一个**确定性小模型前向**
   （固定权重、量化整数、`circuits/types` 内实现）确实产生了被承诺的输出。
3. **组合驱动** `scripts/compose_proof.py`（新）：分别产证 → 联合验证 → 输出 `CompositeCertificate`
   （含两个 proof digest + 两个 vkey + 组合义务声明）。
4. **成本表**：证明「组合成本 ≈ 两者之和，且由推理证明主导」这一假设是否成立。

**分支 B（若拿到 zkAgent 代码）**：把 2 换成真实 zkAgent prover，其余不变。

**验收**：`tests/test_compose.py` + `bench/results/compose.md`；**反例**——替换任一子证明必须被拒。

---

### P1-7 链上证明验证（受 D2 影响）

现状 `contracts/Anchor.sol` 只存 `bytes32` 摘要 —— **链上不验证证明**，「链上可验证」是过度声明。

**设计**：锚定**以验证为前提**。

```solidity
// contracts/Anchor.sol
ISP1Verifier public immutable verifier;
bytes32 public immutable programVKey;
mapping(bytes32 => uint64) public anchoredAt;

function anchorWithProof(bytes32 digest, bytes calldata proof, bytes calldata publicValues)
        external returns (uint64) {
    verifier.verifyProof(programVKey, publicValues, proof);   // ← 先验证
    bytes32 committed = abi.decode(publicValues, (bytes32));
    require(committed == digest, "digest != committed policy/outcome");
    // 再落链：首次即最终
}
```

**前置**：① 拉取 SP1 `SP1VerifierGateway`/`SP1VerifierGroth16` artifact 入库（与 `Anchor.json` 同策略）；
② **≥64 GB 机器**产出 groth16 证明（本机 12 GB 必 OOM）；
③ `scripts/anchor_e2e.sh --onchain-verify`。

**验收**：有效证明 → 锚定成功 + `anchoredAt>0`；**反例**——篡改 publicValues → `verifyProof` revert；
未验证证明直接调 `anchor()` → 路径被移除/拒绝。

---

### P1-8 形式化安全模型 v2

`docs/security-model.md` 重写为**游戏式定义 + 归约**：

| 定义 | 内容 |
|---|---|
| `Sound_{π}(A)` | A 对 `T ⊭ π` 产出被接受公开值 |
| `Bind_{resp}(A)` | A 使一个被接受证明绑定到 T′ ≠ 送达的 T |
| `Bind_{trace}(A)` | A 使被接受证明绑定到伪造回执链 |
| `Priv(A)` | 区分 `V(T₀)` 与 `V(T₁)` |
| `Redact(A)` | A 用掩码隐藏非真实命中的内容 |

**引理链**：L1 策略绑定（P0-1 构造 ⇒ 归约到 SHA-256 抗碰撞）、L2 响应绑定（P0-2）、
L3 轨迹绑定（P1-5）、L4 脱敏健全性（`redaction_ok ∧ mask_covered`）、L5 账本完整性。

**主定理**：`Adv^Sound ≤ Adv^ZKVM + Adv^CR_SHA256 + Adv^Sig`。

> 这是把本项目从「一个 zkVM 应用」提升为「一篇论文」的分水岭。

---

## 5. P2：拉开差距（6 周；D3 选全量 ezkl 后由 4 周扩至 6 周）

### P2-9 语义级规则：完整 ezkl 集成（2–3 周）⭐ D3 选定

**空位论证**：TEE 只证「护栏跑过」，形式化方法对学习型规则不可用，纯正则子集被
`wеaponize`（西里尔 е）这类同形异义字绕过。**学习型规则的可验证判定是本项目最大的差异化空位。**

#### 9.0 信任边界 —— 先定清楚，否则做出来是另一个 P0-1

语义规则的健全性有三个**必须同时满足**的条件，缺一个就退化成「证明者声明」：

| 条件 | 不满足的后果 | 本项目对策 |
|---|---|---|
| ① 模型权重被承诺 | 证明者可换一个「永远判安全」的模型 | ONNX 文件 sha256 绑定进约束，且经 ezkl `compile` 后由 **vk** 唯一确定 |
| ② **特征由 T 确定性派生** | 证明者可声明任意特征 → **与 P0-1 完全同构的漏洞** | 特征提取必须**在图内**（或电路内），不能是图外预计算 |
| ③ 输入与响应绑定 | 证明可复用自另一条响应 | ezkl 公开输入携带 P0-2 的 `response_binding` |

> ②是最容易做错的一条。若把「先用大模型算 embedding，再送 ezkl 证 head」，
> **embedding 就是证明者声明的**——等于白做。这决定了下面的架构。

#### 9.1 架构：全管线入图

```
T ──▶ [确定性特征：字符 n-gram 哈希桶计数 + 归一化]  ──▶ [小 head：Linear/MLP] ──▶ logit
       无学习参数 / 参数入模型                            ← 全部在一张 ONNX 图内
```

- **特征**：字符 2/3/4-gram，哈希到 `D=512` 桶，计数后 L2 归一化。**无学习参数**，纯确定性算术。
- **head**：`Linear(512→32) → ReLU → Linear(32→1)`，离线训练，权重**入库并承诺**。
- **ezkl 证**：`logit = f(T)` 且电路约束 `logit < threshold_bp`（定点整数）。
- **若 ezkl 无法表达 n-gram 哈希**（见 §9.6 回退）：特征改在 **SP1 电路内**算，
  ezkl 只证 head，两侧公开值都携带 `H(features)` 做交叉绑定——**这个回退方案同样健全**，且分工更清晰。

#### 9.2 子任务

| # | 子任务 | 交付 | 验收 |
|---|---|---|---|
| **9.1** | **依赖栈打通**：恢复 pip（§8.0）→ `torch`/`onnx`/`ezkl`（halo2 后端）；锁定版本写进 `requirements-ezkl.txt`；**离线 wheel 缓存入库** | 可复现的 `scripts/install_ezkl.sh` | `import ezkl` + 一次自带示例的 prove/verify 通过 |
| **9.2** | **模型与特征**：`semantic/train.py`（数据 + 训练 + 导出 ONNX）；权重与 ONNX 入库，`semantic/MODEL.sha256` | `semantic/model.onnx` + 训练脚本 | ONNX 导出**逐位确定**（同权重两次导出 sha256 相同） |
| **9.3** | **ezkl 编译与出证**：`scripts/ezkl_prove.py` —— `gen_settings → compile → setup → prove → verify`；产出 `vk` + `proof` | `semantic/artifacts/{vk.json,proof.json}` | `ezkl verify` 通过；记录**出证时间/大小/内存**（进 `bench/`） |
| **9.4** | **策略规则**：新增 `semantic_bound` kind，贯通 `model.py → compile.py → serialize.py → pop-types` | `Constraint::SemanticBound { name, model_vkey, onnx_sha256, threshold_bp, direction }` | `tests/test_semantic.py::test_compile_semantic`；契约哈希稳定 |
| **9.5** | **组合与绑定**：ezkl 公开输入塞入 `response_binding`；PoP 证书引用 `{ezkl_vk, ezkl_proof_sha256, onnx_sha256}`；验证方核对三者一致 | 扩展 `policydsl/cert.py` + `verify_cert.py` | 见 9.7 反例 |
| **9.6** | **信任边界论证**：`docs/design-semantic-rules.md` —— 为什么权重必须承诺、为什么特征必须图内、与 zkML 工作的关系 | 设计文档 | 与 §P1-8 的形式化模型对接（新增引理 L6） |
| **9.7** | **验收 + 反例** | `tests/test_semantic.py` | 见下 |

#### 9.3 验收测试（每条都必须有反例 —— 正向检查容易写成恒真）

```python
# tests/test_semantic.py
test_benign_text_passes              # 正向：正常文本 logit < 阈值 → 通过
test_harmful_text_blocked            # 正向：语义有害文本 → 违规
test_homoglyph_bypass_now_blocked    # 绕过演示：wеaponize（西里尔 е）→ 仍被拒
test_swapped_onnx_rejected           # 反例：换一个「永远判安全」的 ONNX → onnx_sha256 不匹配 → 拒绝
test_swapped_threshold_rejected      # 反例：改阈值 → policy_hash 变 → 拒绝
test_replayed_ezkl_proof_rejected    # 反例：把 A 响应的 ezkl 证明用在 B 响应 → response_binding 不匹配 → 拒绝
test_declared_features_rejected      # 反例：图外预计算的特征 → 图内 H(features) 不匹配 → 拒绝
```

> `test_homoglyph_bypass_now_blocked` 同时是**论文的实验素材**：先演示现有 `keyword_block`
> 可被绕过（真实、可复现），再展示语义规则将其拦下。

#### 9.4 风险

| 风险 | 概率 | 缓解 |
|---|---|---|
| ezkl 依赖栈（torch/onnx/halo2）版本地狱，2 周调不通 | **高** | §8.0 提前在 W1 并行启动；离线 wheel 缓存；**回退方案见 9.1** |
| ezkl 不支持 n-gram 哈希所需的 ONNX op | 中 | 回退：特征在 SP1 内算，ezkl 只证 head（同样健全） |
| 训练数据获得与标注 | 中 | 复用公开的毒性/有害内容数据集；规模只需支撑 demo，不追求 SOTA |
| ezkl 出证时间远超 SP1（可能分钟级） | 中 | 如实测量并进 `bench/`；本规则**标为可选**，策略可按需启用 |

---

### P2-9b 同形异义折叠（顺带交付，全电路内）

即使 ezkl 全量集成完成，**易混淆字符折叠仍值得作为独立的原生规则**：它零依赖、成本极低、
全电路内可证，且能覆盖 ezkl 模型可能漏掉的确定性绕过。

- 新增 `Constraint::NormalizedKeywordBlock { name, keywords, fold: FoldingSpec }`
- `policydsl/normalize.py`：西里尔/希腊同形字映射、全角→半角、去零宽字符（`U+200B/200C/200D/FEFF`）
- 电路内先折叠再匹配；`tests/test_semantic.py::test_homoglyph_bypass_now_blocked` 覆盖

**验收**：折叠前 `passed=True`、折叠后 `passed=False`（证明修复非恒真）。

### P2-10 跨证书策略一致性

`policydsl/session.py` + 新 guest 模式 `Job::Session`：证「一组证书 ①`policy_hash` 全同；
②流式链无缝拼接无缺口；③覆盖完整轨迹」。用 Merkle 根把 N 张证书摘要聚合进一次证明。

**验收**：`tests/test_session.py` —— 混入一张异策略证书 → 失败；挖掉一张 → 失败。

### P2-11 多证明者

`policydsl/multiparty.py`：模型方 / 工具网关 / 部署方各自持钥、各证一段策略切片；
输出 `CompositeCertificate`（N 签名 + 聚合证明）。基于 P1-5 的回执设施 + P1-6 的组合驱动。

**验收**：缺任一角色签名 → 拒绝；单角色策略切片被换 → 拒绝。

### P2-12 真实规模评测

- `bench_cycles.py`：长度扩到 `10k / 50k / 100k`；拟合成本模型 `cycles ≈ a·|T|·rules + b`（当前只有
  「~4.2k cycles/字符」一个点）。
- `bench_proofs.py`：加入 10k/50k 采样（每点 ~2 分钟 + ~10 GB，需 ≥32 GB 机器跑 groth16 变体）。
- **真实轨迹**：从 `demo_e2e` 会话抓真实 agent 轨迹回放，替掉纯合成输入。
- 重跑后**同步** `README.md`、`paper §7`、`docs/reproduce.md` 的硬编码数字。

---

## 6. 风险登记册

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| P0-1 的 20 个调用点替换引入回归 | 中 | 高 | 一次性完成 + `cross_validate` 作为总闸门（改判定逻辑后第一件事） |
| ~~SP1 core proof 非 ZK → 私有模式不成立~~ | **已查证** | **降级：中** | **已核实（2026-09-11）**：core/compressed 确实非 ZK（见 [`sp1-zk-audit.md`](sp1-zk-audit.md)），但**私有模式不因此不成立**——它本来成立的就是较弱的「承诺隐私」（公开值不含明文，Leak 实验可测），而非「见证隐藏」。风险从「致命」降为「叙事风险」：须收紧口径 + 证书加 `proof_mode` 标注。真正需要 groth16 的场景（对**高熵** `T` 的见证隐藏）本机无法验证，标注为未实测 |
| **ezkl 依赖栈调不通（D3 已选全量集成）** | **高** | **高** | §8.0 提前 W1 并行启动；离线 wheel 缓存；§9.1 的回退方案（特征在 SP1 内算，ezkl 只证 head）同样健全 |
| **语义规则的「特征」被证明者声明** | 中 | **致命** | §9.0 的②：特征必须图内/电路内派生；`test_declared_features_rejected` 锁死 |
| groth16 需 ≥64 GB，本机不可达 | 高 | 高 | D2 已定：云机一次性产出，结果入库 |
| zkAgent 源码不可得 | 高 | 中 | D1 已定：分支 A（形式化 + 代理推理证明），论文如实标注 |
| 电路内 token 计数语义变更引起口径争议 | 中 | 中 | P1-5 中显式定义写进论文 §4.2 |
| P2 由 4 周扩到 6 周挤压投稿窗口 | 高 | 中 | P2-9 与 P1 并行；P2-10/11/12 可裁剪（P2-9 是 D3 的必保项） |

---

## 7. 每个阶段结束时的验收判据

| 阶段 | 判据 |
|---|---|
| P0 | ① `tests/test_policy_binding.py::test_empty_policy_cannot_certify_real_policy` 通过；② `test_binding.py` 4 例；③ 旧 `DEMO_KEY` 信封被拒；④ `cross_validate` host/prove 14/14 仍绿；⑤ 全量测试无回归 |
| P1 | ① `test_trace.py` / `test_compose.py` / `test_anchor_chain.py` 全绿 + 各自反例；② `anchor_e2e.sh --onchain-verify` 全 PASS；③ 安全模型 v2 落盘且引理与代码一一对应 |
| P2 | ① `test_semantic.py` **7 例全绿含 5 条反例**（§9.3）；② `test_session.py`；③ `test_multiparty.py`；④ `bench/results/` 新增三张表（含 ezkl 出证成本）且文档数字同步；⑤ `docs/design-semantic-rules.md` 落盘并与引理 L6 对接 |

---

## 8. 环境准备（开工前）

### 8.0 ⚠️ 本机当前没有可用的 pip（已实测，D3 的硬前置）—— ✅ 已解决（2026-09-10）

> **已执行**：走「路 A」免 sudo 引导成功。
> ```
> pip 26.2.1 from /home/dong/.local/lib/python3.10/site-packages/pip (python 3.10)
> ```
> 注意装到了 `~/.local/bin`，**不在 PATH 上** —— 用 `python3 -m pip` 调用即可，
> 或把 `$HOME/.local/bin` 加进 PATH。
>
> 另外写了用户级镜像配置 `~/.config/pip/pip.conf`（`index-url` = 清华镜像，
> 不设 `extra-index-url` —— 设了会让 pip 并行查两个源，反而拖慢解析）：
> ```
> [global]
> index-url = https://pypi.tuna.tsinghua.edu.cn/simple
> timeout = 120
> retries = 5
> ```
> 这是 **pip** 的配置，与「git 镜像 `insteadOf` 必须保持仓库局部」那条约束无关。

```
python3 -V                     → Python 3.10.12
python3 -m pip --version       → No module named pip
ensurepip                      → 缺失
apt-get install python3-pip    → 有候选(22.0.2)，但 sudo 需要密码 → 需你执行
```

现有框架（`langchain_core 1.6.2` 等）装在 `~/.local/lib/python3.10/site-packages`，
说明**历史上曾有 pip**，现已不可用。`scripts/install_frameworks.sh` 建的 `.venv` 也不存在。

**要装 ezkl，必须先恢复 pip。** 两条路，推荐第一条（不需要 sudo）：

```bash
# 路 A（推荐，免 sudo）：get-pip 引导到 --user
#   已实测可达：pypi.tuna.tsinghua.edu.cn → 200，bootstrap.pypa.io → 200
curl -sSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
python3 /tmp/get-pip.py --user -i https://pypi.tuna.tsinghua.edu.cn/simple

# 路 B（需要你输密码执行）
sudo apt install -y python3-pip python3-venv
```

> 磁盘不是问题（`/` 剩余 **939 GB**）。此步骤与 P1 无耦合，**建议 W1 就并行做完**。

### 8.1 其余准备

**进度（2026-09-10）**：第 5 项 ✅ 已完成并冒烟验证；第 1/3/4 项待办。

```bash
# 1) 签名库 —— ✅ 已完成
#    实测：Ed25519 在原来的 3.4.8 上**本来就可用**（`Ed25519PrivateKey.generate()`
#    签名/验证通过），所以它从来不是 P0-3 的阻塞项。仍按建议升到了 50.0.1
#    （`--user`，在 ~/.local/lib/python3.10/site-packages，import 优先级高于系统的
#    /usr/lib/python3/dist-packages，已验证生效）。166 项单测不受影响。
python3 -m pip install --user -U "cryptography>=41"

# 2) Rust 侧新增依赖（pop-types 需解析规范 JSON 字节）
#    ✅ 已满足：circuits/types/Cargo.toml 里
#       serde_json = { version = "1", default-features = false, features = ["alloc"] }
#       （P0-1 已落地并编译通过；circuits/verifier 另加了 pop-types 依赖）

# 3) ≥64 GB 云机窗口（P1-7 的 groth16；本机 12 GB 必 OOM）
#    ⏳ 待办。届时 SP1_PROVER=cpu，结果入库后本机可离线复核

# 4) SP1 验证合约 artifact 入库（与 contracts/Anchor.json 同策略）
#    ⏳ 待办：contracts/SP1VerifierGateway.json

# 5) ezkl 依赖栈（P2-9）—— ✅ 已完成
python3 -m pip install --user -r requirements-ezkl.txt
```

**第 5 项实测结果**（`requirements-ezkl.txt` 锁定版本）：

| 包 | 版本 | 备注 |
|---|---|---|
| ezkl | 23.0.5 | PyO3/abi3 wheel；API 用 `compile_circuit` 而非早期文档的 `compile` |
| onnx | 1.22.0 | |
| torch | 2.14.0+cu130 | 拉入了 nvidia CUDA 依赖，`~/.local` 占 **5.6 GB**（磁盘 930 GB 剩余，无压力） |
| numpy | 2.2.6 | |

冒烟测试（本机实跑，约 5 秒）：

```
[OK] export onnx / gen_settings / calibrate_settings / compile_circuit (logrows=15)
[OK] gen_srs / setup / gen_witness / prove / verify
verify() -> True     proof 21.3 KB     RESULT: SMOKE PASS
```

> **P2-9 必须避开三个坑**（实测踩到）：
> 1. 导出 ONNX **不能带 `dynamic_axes`** —— 符号维度会让 tract 前端报
>    `Undetermined symbol in expression: <Sym0>`。所有维度必须常量。
>    这与 P2-9「特征在图中派生」的设计恰好一致（输入形状固定）。
> 2. **`ezkl 23.0.5` 的 `create_evm_verifier()` 在本机直接抛
>    `RuntimeError: no running event loop`**（pyo3 绑定的问题，Python 侧调用边界
>    就炸，没有 Rust 栈帧；塞进 asyncio 事件循环也一样）。注意 Pipeline 的其余
>    8 步（settings → 编译 → SRS → setup → witness → prove → verify）**全部正常**，
>    所以这不影响 P2-9 的电路/证明部分，只影响**链上验证器生成**。
>    待办：换 `ezkl 12.x`（PyPI `info.version` 认的那个版本）或直接调 Rust 库试试。
>    ezkl **没有装 CLI**（`~/.local/bin` 下没有 `ezkl` 可执行文件），所以没有
>    "改用命令行" 这条退路。
> 3. `solc` 需要手工装：`~/.local/bin/solc` 已放好 0.8.24
>    （`https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-v0.8.24+commit.e11b9ed9`，
>    实测可达 200；forge 自带的 `solar` 不顶用，`~/.svm` 是空的）。
>    ⚠️ **`~/.local/bin` 不在 PATH 上**，调用时要显式加前缀：
>    `PATH="$HOME/.local/bin:$PATH" python3 ...`
>    （长期办法是把 `~/.local/bin` 加进 PATH —— 那能顺带消掉 pip 反复报的
>    "scripts installed in ~/.local/bin which is not on PATH" 警告；但这属于改
>    你的 shell 配置，留给你决定。）

```bash
# 6) git 镜像配置保持仓库局部（勿设 --global）—— 已确认本机 local/global 均无 insteadOf
```


---

## 9. 下一步

**进度（2026-09-11）**：`P0-1` ✅ → `P0-2` ✅ → **`P0-4` 的 ZK 性质查证 ✅ 已完成**
（结论见 [`sp1-zk-audit.md`](sp1-zk-audit.md)：健全性成立；`core`/`compressed` **非 ZK**；
私有模式口径收紧为「承诺隐私」，`docs/security-model.md` §2/§5 已同步更新）。

下一步是 **`P0-3` Ed25519**（`cryptography` 已升到 50.0.1，随时可开工），
随后 `P0-4` 剩余的口径一致项（`paper §4.2/§6` 数字）与证书 `binding.proof_mode` 标注。

原关键路径：`P0-1`（改动小、可验证、且直接产出论文的「绑定引理」）→ `P0-4`（ZK 性质查证，决定私有模式是否成立）
→ `P0-2` → `P0-3` → `P1-5` → …

**并行启动**（与 P1 无耦合，越早越好）：
- `§8.0` 恢复 pip —— 不需要 sudo，两条命令，实测源可达；
- `§9.1` ezkl 依赖栈 —— 这是 D3 选全量集成后**最大的进度风险**，必须提前吃满工期。

```bash
# 现在就能做的两件事
curl -sSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
python3 /tmp/get-pip.py --user -i https://pypi.tuna.tsinghua.edu.cn/simple
python3 -m pip install --user torch onnx ezkl -i https://pypi.tuna.tsinghua.edu.cn/simple
```

> 完成 P0 后，我在评估中**已实跑复现**的那个攻击（空策略证明 + 真策略哈希 → 全绿）
> 会被 `tests/test_policy_binding.py` 永久锁死——这是本计划第一个可交付、可验证的里程碑。
