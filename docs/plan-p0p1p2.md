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
| 签名 | ~~HMAC + **公开常量密钥** `DEMO_KEY` → 任何人可伪造~~ → **P0-3 ✅**：Ed25519，私钥留在出证方（`policydsl/keys.py`），旧信封被结构性拒绝 |

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
> **2026-09-11 状态**：该前置里最后一块未知数（§9.1 的 ezkl EVM 验证器接口）已解（见待办 T2），
> P2-9 自身已无已知硬阻塞；P1 段剩下的唯一障碍是 **T1 的租机**（见 §9 待办）。

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
> python3 -m unittest discover tests                     → Ran 220 tests, OK (skipped=5)
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

**这一层**解决的是「送达的 T′ 是不是被证明的 T」。**不**解决的（已由 P1-5 补上，见下）：
`tool_calls` / `token_count` 当时是证明者自填的私有输入，工具轨迹的真伪不在绑定范围内。

---

### P0-3 Ed25519 替换 demo HMAC ✅（2026-09-11 完成）

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

- `verify_envelope(env, keyring)` 按 `keyid` 前缀**分发**（白名单只有 `ed25519` 与 `test-hmac-sha256`）。
  `demo-hmac-sha256` 在**查表之前**就被否掉 —— 所以「把配对密钥放进 keyring」也没用，
  拒绝是**结构性**的，不是配置疏漏。
- `policydsl/keys.py`（新）：`load_or_create(path)` / `signer_from_env` / `ephemeral_signer`、
  `POP_SIGNING_KEY`（+ `_PASSPHRASE`）环境变量、PKCS#8 PEM（`0600`、不覆盖）、
  公钥导出（hex/PEM/keyid）与验证方入口 `load_keyring` / `public_record`。
- `scripts/gen_key.py`（新）：生成密钥对 + 指纹；`--show` / `--pubkey` 只碰公钥。
- 改动调用点：`agent.py`、`langchain_adapter.py`、`issue_cert.py`、`verify_cert.py`、
  `verify_session.py`、`demo_e2e.py`、5 个测试文件。
- `demo_e2e.py` 默认生成**临时**密钥对（不落盘），把**公钥**写进 `session.json` 的
  `signers` 字段；`issue_cert.py` 把公钥写进 `<out-dir>/key.json`。
- 失败语义收紧：`verify_envelope` 失败一律返回 `(False, None)`（此前返回载荷）——
  调用方拿不到未经验签的载荷。与 `docs/modules/03-certificate.md` 的原文档一致。

**验收**（全部通过，逐条对应测试与命令）：
| # | 判据 | 证据 |
|---|---|---|
| ① | 错密钥签名被拒 | `test_cert.py::test_wrong_key_fails`；`verify_cert.py --keyring <别人的公钥>` → `[FAIL] signature` |
| ② | 篡改 payload 被拒 | `test_cert.py::test_tampered_payload_fails`；CLI 复制 `cert.json` 改 `outcome.passed` → `[FAIL] signature` |
| ③ | 旧 `DEMO_KEY` 信封必须被拒 | `test_cert.py::TestSchemeDispatch`（含「配对密钥在 ring 里仍被拒」+「`test-hmac-sha256` 同结构仍通过」证明**非恒真**）；CLI 旧信封 → `[FAIL] signature` |

---

### P0-4 口径一致 + ZK 性质声明

| 位置 | 现状 | 改为 |
|---|---|---|
| `paper §4.2` | 「keyword/length/pattern 入电路」 | 统一为 6 类（与 §5 一致） |
| `paper §6` | 「102 全绿(1 skip)」 | 实跑值（P0 后会变） |
| `docs/security-model.md:65` | `host/prove 7/7` | ✅ 已改为 `14/14`（2026-09-10） |
| `docs/eu-ai-act-mapping.md` | 工具路径「`zk:false`」 | ✅ 已入电路；「轨迹未绑定」一条已随 P1-5 改写为「链路可证 + 身份可验」 |
| **全仓库** | **未声明 ZK 性质** | ✅ **已查证（2026-09-11）**，结论见 [`sp1-zk-audit.md`](sp1-zk-audit.md)：**core/compressed 不满足零知识性**（两类独立证据：Succinct 安全模型明文 + 本机 SLOP 栈源码零盲化命中；另有实测佐证）；`groth16`/`plonk` 是唯一可能隐藏见证的模式（包装器层面声明、未被审计评估、非后量子、本机 12 GB 出不了证）；原生 ZK 的 `slop-veil` 已发布但未被任何证明路径依赖。**后果**：私有模式口径收紧为「公开值不泄露明文」，不再宣传「证明工件不泄露见证」；证书的 `binding.proof_mode` 诚实标注**已落地**（`verify_cert.py` 逐证书与工件自报模式比对，无工件只能标 `unproven`） |

> P0-4 的最后一条是**调研任务**，不是文书任务，但它决定 §4.3（双隐私模式）能否成立，优先级等同 P0-1。
> **已查证（2026-09-11）**：健全性成立；零知识性对 `core`/`compressed` **不成立**。
> 私有模式**仍然成立**，但成立的是「承诺隐私」（公开值不含明文）这一较弱性质；
> 另外核查还发现一个**与 SP1 无关的设计层结论**——对低熵 `T`，「响应绑定」与「响应内容隐藏」互斥
> （`response_binding` 必须公开可重算 ⇒ 必然是一个离线猜测-验证 oracle）。详见 `sp1-zk-audit.md` §4。

---

## 4. P1：从「合规原语」到「可验证 agent」（3 周）

### P1-5 轨迹绑定 ✅（2026-09-11 完成）—— 把「证明者的声明」变成「可验证的事实」

> **落地结果**（下面的设计稿保留作对照，实现与原稿的差异见文末「与设计稿的差异」）：
> `policydsl/trace.py`（回执/网关/链校验）+ `pop-types` 镜像 + 三个适配器接线 + `tests/test_trace.py`
> （四条验收 + 六例第三方核对，29 例全绿；**P1-5b 落地后同文件增至 39 例**，见 T4 行）
> + `cross_validate.py` 全部向量改为回执驱动（host 14/14、prove 14/14）。

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

**与设计稿的差异**（实现时改动，均有理由）：

1. **参数放明文，不是 `args_digest`**：摘要**没办法**支撑 `forbidden_fields` —— 电路拿
   `H(canonical(args))` 无从判断某次调用的参数里有没有 `password` 这个键。要么规则改判一个证明者
   同样能编的字段（自欺），要么把参数放进回执。回执是**私有输入**、不进公开值，放明文不额外泄露；
   防篡改靠签名，不靠保密。
2. **`verify_chain` 返回 `(bool, str)` 而非 `bool`**：失败原因要作为违规证据进证书（两端口径一致）。
3. **链不自洽 → fail-closed**：原稿只写"验结构"，没说验不过怎么办。实现选择：工具规则记
   `trace_unbound` 并**不通过**，且若策略里没有工具类规则，末尾补一条合成违规（`rule="<trace>"`）——
   杜绝"读不出来 = 零次调用"。
4. **`trace_root` 进公开值**（原稿未提）：与 `response_binding` 对称，让"证明绑的是哪条链"可被
   验证方离线核对；否则链与证明之间没有可见的拴点。
5. **驱动层也 `deny_unknown_fields`**：只在 `ProofRequest` 上标不够 —— `VectorIn` 不加的话，
   旧向量会在驱动层被静默丢字段，退化成"零次调用"照样出证（验收项 ④ 就落空了）。
6. **分词空白集取死为 6 个 ASCII 字节**，明确**不**用 Unicode White_Space（随 Unicode 版本漂移）。
7. **每调用证书的判定范围是整条链**：`passed` 的含义是「会话进行到这次调用为止一直合规」，
   链上任何一条违规都会让后续证书继续判失败 —— 保守取向，`passed=true` 绝不出现在脏轨迹上。

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
**均已达**：`POP_TEST_COMPOSE=1 python3 -m unittest tests.test_compose` → **Ran 47 tests … OK**（563.5 s，
无一 skip）；`bench/results/compose.{json,md}` 已跑出；全套 `python3 -m unittest discover -s tests -t .`
→ **348 passed / 11 skipped**。反例的「替换任一子证明必须被拒」在真产物上单独跑过
（`test_swapping_either_subproof_is_rejected`）。

**记要（分支 A ✅ 2026-09-12 完成）**：

| 步 | 落点 |
|---|---|
| 1 形式化 | **引理 L6** 写进 [`security-model.md`](security-model.md) §3（组合义务、键分离、四方 `response_binding`），含「不保证」三条与成本结论的如实标注 |
| 2 代理实验 | 新增 guest `circuits/infer-program`（包 `pop-infer`）；`pop-types` 加 `Job::Infer` / `InferRequest` / `run_infer` 与 `job_domain`；**两个 guest 入口各断言一次域**，把键分离钉进电路。模型是 16→32→4 定点（Q16）MLP，权重由编译期常量种子生成 ⇒ **模型就是程序**，被 vkey 承诺（比 P2-9 的 ezkl 委托更强）。Python 参考实现 `policydsl/infer.py` 与 Rust 逐位一致 |
| 3 组合驱动 | `policydsl/compose.py`（8 步验证）+ `scripts/compose_proof.py`（两次独立进程出证 → 合成 → 独立验证）。**必须分进程**：同进程连出两份证明会在第二份 setup 被 OOM |
| 4 成本表 | `bench/bench_compose.py` → **已跑出** `bench/results/compose.{json,md}`：策略半 127.3 s / 64.4 万周期 / 峰值 10.2 GiB，推理半 110.8 s / 8.3 万周期 / 峰值 10.0 GiB；组合层合成 5.0 ms、联合验证 53.8 s（主导是两次 vkey setup）。两半**分进程** ⇒ 峰值取 max 而非相加 |
| 反例 | `tests/test_compose.py`（48）：换证明文件/缺失、同 vkey/非期望 vkey、换模型/换输入、两半绑不同 T/送达 T′ 不符、形状/模式/域/policy_hash 重编译 —— 全部被拒 |
| 驱动接线 | 真出证明才暴露的 4 处（`kind`≠`--job` 旗标、`outcome_without_meta` 连 `mode` 一起剥、`--reuse-proofs` 必须还原同一个 nonce、`_verify_one` 漏给 `--out` 会在仓库根落 `results.json`）已修并各自补了回归用例（`TestDriverWiring`）—— 绑定层全绿但驱动一跑就炸，这个教训写进了测试注释 |

⚠️ **假设检验的结论要如实看**：`bench/results/compose.md` 逐条报了计划里那句
「组合成本 ≈ 两者之和，**且由推理证明主导**」——**前半成立，后半不成立**。代理模型太小，
两半都被 zkVM 固定开销（setup 与证明器启动）主导，看不出成本结构。**这份实验验证的是
组合机制，不是成本结构**；换上真 prover 才轮到「推理主导」。论文按此口径写。

**改动 ELF 的后果**：`infer-program` 与 `pop-program` 都是 guest，任一重编译都会改变 vkey；
`scripts/examples/out/` 下**本机生成**的证明工件随之失效（该目录被 `.gitignore` 忽略，
不入库）。唯一会用到它们的是 `POP_TEST_PROOF` 打开的那个测试，默认 skip；
要用就先重新生成：跑一次
`SP1_PROVER=cpu python3 scripts/issue_cert.py --pack policy_packs/eu_ai_act_v1.json --response scripts/examples/eu_agent_reply.txt --out-dir scripts/examples/out/cert_public`
（该用例读的就是这个目录）。

---

### P1-7 链上证明验证（受 D2 影响）—— ⛔ **未开始：等外部算力**

> **本项卡在硬件上，代码侧推不动。** 前置 ② 要求 **≥64 GB 内存的外部机器**产出 groth16 证明
> —— 本机 12 GB 实测**必 OOM**（compressed 与 groth16 均在峰值 ~11.0 GB 被 OOM killer 终止，
> 见 [`plan-p7.md`](plan-p7.md) §A）。这不是"再优化一下就行"的余量问题：递归包装的**固定开销**
> 就超过本机内存，`SHARD_SIZE` / `MEMORY_LIMIT` 对它无效。**须人工租一台一次性 ≥64 GB 云机**
> （约数小时窗口），产物入库后本机可离线复核。登记见 **§9 待办 T1**。
>
> 代码侧可以先行、不受影响的部分：`contracts/Anchor.sol` 的 `anchorWithProof` 骨架、
> `scripts/anchor_e2e.sh --onchain-verify` 的驱动与反例用例 —— 这些在 §P7-C 已有可运行基础
> （真实 Anvil 上端到端 PASS），本项只差 **groth16 证明工件**入不了库。

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
② **≥64 GB 机器**产出 groth16 证明（本机 12 GB 必 OOM）—— **见 §9 待办 T1（需人工租机，建议与 P1-5 并行排期）**；
③ `scripts/anchor_e2e.sh --onchain-verify`。

**验收**：有效证明 → 锚定成功 + `anchoredAt>0`；**反例**——篡改 publicValues → `verifyProof` revert；
未验证证明直接调 `anchor()` → 路径被移除/拒绝。

---

### P1-8 形式化安全模型 v2 —— ✅ 已完成（2026-09-11）

> **状态**：`docs/security-model.md` 已重写为 v2（§0 记号/参与方/信任边界/口径纪律 → §1 假设 A1–A7 →
> §2 游戏 G_Sound / G_Bind_pol / G_Bind_resp / G_Bind_trace / G_Priv / G_Redact / G_Ledger →
> §3 引理链 L1–L6 → §4 主定理 → §5 诚实边界 → §6 代码落点对照表 → §7 实验对照）。
>
> **与下方设计稿的偏差（以实现为准）**
> 1. 游戏从 5 个扩到 **7 个**：补 `Bind_pol`（策略绑定，P0-1 的构造性论证不能只算在 Sound 里）
>    与 `Ledger`（账本完整性），并显式记 `Redact`。
> 2. 主定理拆项写全：`Adv^Sound_π ≤ Adv^sound_zkVM + Adv^CR_SHA256 + Adv^EUF-CMA_Ed25519`，
>    并把**截尾**作为独立项 `+ Pr[截尾攻击](A)` 单列 —— 见 §5.3。
> 3. 新增**口径纪律 D1–D3**（不主张未证之事 / 不把链下步骤算作电路内 / 「公开值无明文」≠「内容不可恢复」）。
> 4. **本次工作产出一个新的健全性发现**：P1-5 回执链存在**截尾缺口**，已实跑复现、钉成用例
>    （当时用例名 `test_tail_truncation_is_a_known_gap`）并登记为待办 **T4**（对策：网关会话末端 seal）。
>    这正是「先写形式化模型」的价值 —— 缺口是形式化过程发现的，不是事后补的。**该待办已于
>    2026-09-11 关闭**（seal 落地，用例翻转为 `TestVerifyCertTraceBinding::test_tail_truncation_is_rejected`），
>    见上方 T4 行。

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
| **9.0** | **EVM 验证器接口**（原 T2 阻塞）—— ✅ **已完成（2026-09-11）** | `policydsl/ezkl_evm.py` + `tests/test_ezkl_evm.py` | 裸调用抛错已定位并绕开；一次性/可复用验证器与 VK artifact 均产出，10 例全绿 |
| **9.1** | **依赖栈打通**：恢复 pip（§8.0）→ `torch`/`onnx`/`ezkl`（halo2 后端）；锁定版本写进 `requirements-ezkl.txt`；**离线 wheel 缓存入库** | 可复现的 `scripts/install_ezkl.sh` | `import ezkl` + 一次自带示例的 prove/verify 通过 |
| **9.2** | **模型与特征**：`semantic/train.py`（数据 + 训练 + 导出 ONNX）；权重与 ONNX 入库，`semantic/MODEL.sha256` | `semantic/model.onnx` + 训练脚本 | ONNX 导出**逐位确定**（同权重两次导出 sha256 相同） |
| **9.3** | **ezkl 编译与出证**：`scripts/ezkl_prove.py` —— `gen_settings → compile → setup → prove → verify`；产出 `vk` + `proof` | `semantic/artifacts/{vk.json,proof.json}` | `ezkl verify` 通过；记录**出证时间/大小/内存**（进 `bench/`） |
| **9.4** | **策略规则**：新增 `semantic_bound` kind，贯通 `model.py → compile.py → serialize.py → pop-types` | `Constraint::SemanticBound { name, model_vkey, onnx_sha256, threshold_bp, direction }` | `tests/test_semantic.py::test_compile_semantic`；契约哈希稳定 |
| **9.5** | **组合与绑定** —— ✅ **已完成（2026-09-12）** | `policydsl/semantic.py::verify_companion/companion_entry`、`cert.build_payload(semantic=)`、`scripts/{issue_cert,verify_cert}.py` | 见 9.7 反例；**两处与原文不同，理由见 9.5 记要** |
| **9.6** | **信任边界论证** —— ✅ **已完成（2026-09-12）** | [`design-semantic-rules.md`](design-semantic-rules.md) | 与 §P1-8 的形式化模型对接：新增**引理 L7**（**不是 L6 —— 那号已被 P1-6 占用**，见记要） |
| **9.7** | **验收 + 反例** —— ✅ **已完成（2026-09-12）** | `tests/test_semantic.py`（29 例 / 6 条反例） | 见下；全套 **348 passed / 11 skipped**（2026-09-12 复跑） |

> **9.1–9.4 的完成状态补记（2026-09-12 审计）** —— 这四行此前没打勾，实物其实都在，逐条对账如下。
> 其中 **9.1 有一处未按计划交付**，如实记下：
>
> | # | 计划交付 | 实际 | 判定 |
> |---|---|---|---|
> | 9.1 | `scripts/install_ezkl.sh` + **离线 wheel 缓存入库** | ❌ 二者都**没做** | 安装路径已由 `requirements-ezkl.txt`（含版本锁定与冒烟说明）+ §8 的一行 `python3 -m pip install --user -r requirements-ezkl.txt` 覆盖；wheel 缓存当时没触发（镜像一直可用），且要入库 ~2 GB 二进制。**这是一处主动偏差，不是遗漏** —— 若要真离线，再补 `install_ezkl.sh` 与 wheelhouse |
> | 9.2 | `semantic/model.onnx` + 训练脚本 + `MODEL.sha256` | ✅ `semantic/{train.py,features.py,dataset.py,model.onnx,head.weights.json,MODEL.sha256}` | 导出逐位确定由 `test_two_processes_same_sha256` 锁死 |
> | 9.3 | `scripts/ezkl_prove.py` + `semantic/artifacts/{vk,proof}` | ✅ 同名脚本（`setup/prove/verify/selftest/info` 五个子命令）+ `semantic/artifacts/{vk.ezkl,proof.json}`（manifest 见 `MANIFEST.json`） | 成本已进 `bench/results/semantic.md`（setup 48.2 s / prove 76.6 s） |
> | 9.4 | `semantic_bound` 贯通四层 + `test_compile_semantic` | ✅ `model.py`（校验阈值/方向）→ `compile.py`（固化 `onnx_sha256` + `model_vkey`）→ `serialize.py` → `pop-types` | 契约哈希稳定由编译测试与 `policy_hash` 三方比对共同保证 |

> **9.0 记要（T2 的结论，2026-09-11）** —— 原文把这件事记成「先试 ezkl 12.x；或绕开该 API
> 手写 Solidity verifier」，两条**都不需要**。真因是**调用方式**，不是版本也不是依赖：
>
> ezkl 23.0.5 的 `create_evm_verifier()` / `create_evm_vka()` 是 pyo3 的 `#[pyfunction]`，
> 签名里全是 `str`/`bool`、`__doc__` 也只见 "you will need solc installed"，**看起来完全同步**；
> 但内部走 `pyo3-async-runtimes`，调用时**立刻**向 Python 事件循环注册回调并返回
> `asyncio.Future`。没有运行中的事件循环时，它内部的 `pyo3_async_runtimes::get_running_loop()`
> 转发到 CPython 的 `asyncio.get_running_loop()`，于是抛
> `RuntimeError: no running event loop`。
>
> 该报错把人引向"缺组件"是**必然**的 —— 那个字符串来自 CPython 的 asyncio，
> **不在** `ezkl.abi3.so` 里（`strings | grep` 零命中）；二进制里能查到的真调用点是
> `pyo3_async_runtimes::get_running_loop`。解法只有一种：**在事件循环内调用并 await 那个
> Future**，`policydsl/ezkl_evm.py::run` 把它包成同步调用。
>
> 顺带纠正两处：① **这条路径不需要 solc** —— docstring 那么写，实测（含把 `PATH` 剥空）
> 都不调用它，只是把 Halo2 模板常量填好写文件，~0.1 s；② **`reusable=True` 对电路规模敏感**
> —— 实测 logrows=12 时 ezkl 内部 panic（`ezkl-verifier/src/codegen/pcs.rs: The bit counter for
> the pairing input computations exceeds 256 bits`），17 通过；`create_evm_vka` 产出的
> `vka.json` **不是 JSON**（bincode 序列化的 VkArtifact），部署时别 `json.load`。

> **9.5–9.7 记要（2026-09-12）—— 三处与计划原文不同，逐条记下**
>
> ① **引理编号是 L7，不是 L6。** 计划 §9.6 写"新增引理 L6"，但 `L6` 早已分配给了
> P1-6 的跨证明组合义务（`docs/security-model.md` §3）。两条引理层面不同 ——
> L6 是**横向拼接**（多份证明合成一次会话结论）、L7 是**纵向下沉**（一次证书内，
> 部分判定被委托给另一个证明系统）—— 所以没有合并，而是新增 L7 并保留 L6 原义。
>
> ② **绑定方式与原文不同。** 原文是"ezkl 公开输入塞入 `response_binding`"，
> 实际做法是把 **`encode(T)` 的 id 序列本身**放进公开实例，验证方拿 `T′` 现场重算
> 逐位比对。原因：`response_binding` 是 `H(n,T)`，而 ezkl 图吃的是 id，
> 若把哈希塞进输入，图内根本无法消费它（哈希不可微、也不构成合法 id）。
> 现行做法更强 —— 它绑的是**送到图里的那份输入**，而不只是"某条文本的哈希"。
> **代价**：`encode` 对收录字符单射 ⇒ 公开实例可反查 `VOCAB` 恢复原文 ⇒
> 含语义规则的策略**只支持公开模式**（私有模式电路内 panic，fail closed）。
> 这条诚实地写进了 `design-semantic-rules.md` §3.③ 与安全模型 §5.4。
>
> ③ **特征实现与 §9.1 不同**（`D=64` 的常数投影表 + 圆周移位，而非 `D=512` 的
> n-gram 哈希桶），且**未采用**"特征在 SP1 内算"的回退。理由是实测的算子代价：
> `one_hot(idx) @ A` 的等价写法编译出 ~73 万行、`pk.ezkl` 9.46 GB，本机出不了证；
> 换成 `F.embedding`（图内即 `Gather`）后降到 13.1 万行。详细对照见
> `design-semantic-rules.md` §4。
>
> ④ **另一处实测发现（最容易踩空的一处）**：ezkl 的算子对定点口径**不一致** ——
> 消费下标的算子（`Gather`/`OneHot`）拿**缩放后**的值，算术算子拿**解量化后**的值。
> 故 `run_args.input_scale` **必须为 0**（= 1，缩放值就是 id）。用常见的 7 会让
> `Cast` 把小数截断成 0、全序列变 PAD，模型输出一个常数 —— **证明照样验证通过**，
> 症状看起来像"训练失败"。`semantic.patch_settings` 强制它，`check_settings` 在
> 验证方侧再核一遍。

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
| ~~SP1 core proof 非 ZK → 私有模式不成立~~ | **已查证** | **降级：中** | **已核实（2026-09-11）**：core/compressed 确实非 ZK（见 [`sp1-zk-audit.md`](sp1-zk-audit.md)），但**私有模式不因此不成立**——它本来成立的就是较弱的「承诺隐私」（公开值不含明文，Leak 实验可测），而非「见证隐藏」。风险从「致命」降为「叙事风险」：须收紧口径 + 证书加 `proof_mode` 标注（**两项均已完成**：口径见 `security-model.md` §2/§5，标注见 `cert.py` / `verify_cert.py`）。真正需要 groth16 的场景（对**高熵** `T` 的见证隐藏）本机无法验证，标注为未实测 |
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
| P0 | ① `tests/test_policy_binding.py::test_empty_policy_cannot_certify_real_policy` 通过；② `test_binding.py` 4 例；③ 旧 `DEMO_KEY` 信封被拒（**已达成**，见 P0-3 验收表）；④ `cross_validate` host/prove 14/14 仍绿；⑤ 全量测试无回归（2026-09-12 复跑：**348 全绿 / 11 skip**，skip 见 §7 说明） |
| P1 | ① `test_trace.py` ✅（**P1-5 已完成**：39 例含四条验收 + P1-5b 的 seal/截尾，`cross_validate` host/prove 14/14）/ `test_compose.py` ✅（**P1-6 分支 A 已完成**：48 例含 5 组反例 + 四条驱动接线回归）/ `test_anchor_chain.py` 全绿 + 各自反例；② `anchor_e2e.sh --onchain-verify` 全 PASS；③ 安全模型 v2 落盘且引理与代码一一对应（**L6 已从「规划中」改为已证**） |
| P2 | ① `test_semantic.py` **29 例全绿含 6 条反例**（§9.3；✅ 2026-09-12）；② `test_session.py`；③ `test_multiparty.py`；④ `bench/results/` 新增表格（含 ezkl 出证成本 ✅ `semantic.md`）且文档数字同步；⑤ `docs/design-semantic-rules.md` 落盘并与引理 **L7** 对接（**L6 已被 P1-6 占用**，见 §9.2 记要） |

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

**进度（2026-09-11）**：`P0-1` ✅ → `P0-2` ✅ → `P0-3` ✅ → `P0-4` ✅（ZK 性质查证 + 口径改写）
—— **P0 四项全部完成**。`P0-4` 结论见 [`sp1-zk-audit.md`](sp1-zk-audit.md)：
健全性成立；`core`/`compressed` **非 ZK**；私有模式口径收紧为「承诺隐私」，
对外表述统一为「策略零知识（合规性可证而不暴露违规内容）+ 响应内容隐藏有明确上界」，
`docs/security-model.md` §2/§5、`paper` §2.1/§5/§8.1 已同步更新。

**P0 遗留的小项（`binding.proof_mode` 诚实标注）也已完成** —— 字段进载荷
（`cert.PROOF_MODE_HIDING` / `proof_hiding()`，「未知模式返回 `unknown`，不猜」）、
进 `cert_digest`、由 `issue_cert.py`/`demo_e2e.py` 从工件元信息如实填写、
由 `verify_cert.py` 与 `verify_session.py` 与**工件自报的模式**交叉核对
（无工件却自称 `core` ⇒ FAIL；P0-4 之前的旧证书如实跳过），
验收见 `tests/test_cert.py::TestProofModeLabeling` 与
`tests/test_policy_binding.py::TestProofModeOverclaimRejected`。
至此 P0 无遗留项。

**同日真实工件复验**（不是单测，是拿真证明跑）：

| 复验项 | 命令 | 实测结果 |
|---|---|---|
| 标注与工件自报一致 | `verify_cert.py --cert <zk 证书> --proof <2.7 MiB 真证明> --keyring <公钥>` | `[PASS] proof_mode  cert=core (hiding: none); core[sidecar] == core[meta]`，连同签名/证明/三方策略绑定/响应绑定/锚定共 **9/9 PASS**（23 s） |
| 真实证明全量对拍 | `SP1_PROVER=cpu cross_validate.py`（默认 `--chunk 4`） | **`RESULT: host 14/14  prove 14/14  PASS`**，14 个真实 core 证明，24:00 墙钟，峰值 10.97 GB |
| guest ELF ↔ vkey 正向 | 上一条的每次 `--verify` 都会**从当前 ELF 重新 `setup` 推导 vkey** | 证书/工件里的 `0x00e314…` == 现 ELF 推导值 ⇒ 三者一致 |
| guest ELF ↔ vkey 反向 | `pop-script --verify --proof <改 `types` 之前的旧证明>` | 被拒：`pc_start != vk.pc_start`，`EXIT=101` —— 旧 ELF 的证明**无法**在新 ELF 下验通 |

> 顺带查出一个真实缺陷：把 14 个向量交给**一个** `pop-script` 进程会在第 6~7 个证明处被
> OOM-kill（峰值 10.65→10.82 GB，内存逐证明累加不回落）。`cross_validate.py` 因此改为默认
> 分块（`--chunk 4`），结果按原序合并；此前文档里写的「prove 14/14」在本机**跑不出来**，
> 现在才是可复现的判据。

原关键路径：`P0-1`（改动小、可验证、且直接产出论文的「绑定引理」）→ `P0-4`（ZK 性质查证，决定私有模式是否成立）
→ `P0-2` → `P0-3` → `P1-5` → …

**并行启动**（与 P1 无耦合，越早越好）：
- `§8.0` 恢复 pip —— ✅ 已完成（2026-09-10）；
- `§9.1` ezkl 依赖栈 —— 依赖已装并冒烟通过；`create_evm_verifier()` 的
  `RuntimeError: no running event loop` **已解**（2026-09-11，见下方待办 T2 与 §P2-9 的 9.0 记要），
  **P2-9 目前无已知硬阻塞**。

### 待办登记（需要外部资源或人工动作，代码侧推不动）

| # | 待办 | 阻塞谁 | 前置/成本 | 状态 |
|---|---|---|---|---|
| **T1** | **租一台一次性 ≥64 GB 云机**（**外部资源，人工动作**），产出 groth16 证明 + 测通验证合约（D2 已拍板） | `P1-7` 链上证明验证的**硬前置**：**本机 12 GB 必 OOM**（compressed 与 groth16 实测都在峰值 ~11.0 GB 被 OOM killer 终止 —— 递归包装的固定开销就超了本机内存，`SHARD_SIZE`/`MEMORY_LIMIT` 无效），groth16/plonk 出不来 | 需要人工租机（约数小时窗口）+ 一次环境搭建（Rust/SP1 工具链或直接搬 `circuits/` 目标目录）；产出入库后本机可离线复核 | ⬜ **未开始（阻塞中）** —— P1-5 完成后，本项是 **P1 段内唯一剩余任务**，也是唯一的外部阻塞；**不解决它，P1 段无法收尾**。建议立即排期租机 |
| **T2** | 解开 ezkl `create_evm_verifier()` 的 `RuntimeError: no running event loop` | `P2-9`（D3 选定的全量 ezkl 集成）的最后一个阻塞 | 先试 ezkl 12.x；或绕开该 API，直接由编译产物手写 Solidity verifier | ✅ **已完成（2026-09-11）** —— 两条预设备选都不需要：真因是**调用方式**（API 内部走 `pyo3-async-runtimes`，须在事件循环内调用并 await 其返回的 Future），非版本、非依赖。解见 `policydsl/ezkl_evm.py` + `tests/test_ezkl_evm.py`（10 例）、记要见 §P2-9 子任务表 9.0 |
| **T3** | 真实 SP1 证明的**全量**回归改为「出证 + 验证」两条腿都在 CI 之外定期跑 | 论文 §7 的证明时间/内存数字 | 单次 `cross_validate --prove` ≈ 24 分钟；本机跑即可 | ⬜ 未开始 |
| **T4** | **P1-5b：堵住回执链的「截尾」缺口**（做 P1-8 时发现，见 [`security-model.md`](security-model.md) §5.3） | `P1-5` 的**健全性缺口**：把链尾那条违规回执**整条删掉**后，剩下的仍是一条结构自洽、逐条签名有效的**真链**，`trace_binding`（证书绑的链 == 送检的链）与 `receipt_chain`（逐条验签）**双双 PASS**；**当链与证书由出证方一起转交时，违规尾巴可被静默截掉**。**这不是「再比一次」能补的** —— 任何只看交付链的检查都无从知道「后面还有没有」 | **网关对会话末端做一次承诺**：`ToolSeal{count, trace_root, ts, keyid, sig}`（域分隔 `pop-trace-seal-v1`），验证方核对 `len(chain) == seal.count ∧ trace_root(chain) == seal.trace_root` + 验签。截尾者只剩两条路：拿原 seal 配截断链（`count` 对不上）或为截断链新签一条（无网关私钥） | ✅ **已完成（2026-09-11，纯代码）** —— 见 `tests/test_trace.py::TestSeal`（9 例）与 `::TestVerifyCertTraceBinding::test_tail_truncation_is_rejected`（原 seal / 伪造 seal / 不带 seal 三路 + 正对照）。改动面：`policydsl/trace.py`（`ToolSeal`/`verify_seal`/`ToolGateway.seal`）+ `cert.build_payload`（载荷**顶层** `trace_seal`）+ `verify_cert.py` **3d** + 各适配器出证点。**两点与原设想的偏离，如实登记**：① **没有做「电路内对 seal 的结构校验」** —— 链尾摘要本就在电路内算并进公开值，「证明绑的是哪条链」已有电路保证；seal 要补的是「网关说这条链到此为止」，那是一个**签名**问题，按本项目「结构入电路、签名在链下」的既有分工放在链下；② **seal 放载荷顶层而不是 `outcome`** —— `outcome` 是证明公开值的镜像（验证方逐字段比对），放进去会让每一张带真实证明的证书都对不上。**残留边界**：验证方须持网关公钥（`--gateway-key`）才拿得到这个保证；只给 `--receipts` 而没给公钥时，3d 记 `PASS + 「截尾不可排除」(skipped)`；且 seal 仍是**网关的**陈述（A4），它把信任挪向网关而非消除信任 |

> **T2 已于 2026-09-11 关闭**（理由见上表与 §P2-9 的 9.0 记要）。
> **T1 仍开着，且现在没有别的并行项了** —— 它是 P1 段收尾的唯一障碍，也是**外部队列**
> （要人工去租机、等机器就绪），**越早排队越好**：租机窗口本身可能就要等，
> 而它一到手，P1-7 的代码侧工作（§P7-C 已有可运行基础）就能立刻接上。

**T4 已于 2026-09-11 关闭**（纯代码落地，见上表）。它不阻塞 `P1-7`，也不阻塞 `P2`。

```bash
# 现在就能做的两件事
curl -sSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
python3 /tmp/get-pip.py --user -i https://pypi.tuna.tsinghua.edu.cn/simple
python3 -m pip install --user torch onnx ezkl -i https://pypi.tuna.tsinghua.edu.cn/simple
```

> 完成 P0 后，我在评估中**已实跑复现**的那个攻击（空策略证明 + 真策略哈希 → 全绿）
> 会被 `tests/test_policy_binding.py` 永久锁死——这是本计划第一个可交付、可验证的里程碑。

**P0 收尾提交**：`538c6d8`（37 files，+2029/−227），工作区干净，P0 四项全部完成。
