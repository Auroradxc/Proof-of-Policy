# 03 · 合规证书

> 覆盖 `policydsl/cert.py`、`policydsl/agent.py`。
> 这一板块回答：**一次判定结果怎么变成一张第三方可独立核验的证书。**

---

## 1. 职责

证书把「一次 agent 响应/工具调用的合规结论」绑定到五个**可重算的哈希**上：

| 绑定项 | 值 | 第三方怎么验 |
|---|---|---|
| 策略 | `policy_hash` = `compile_policy(π)["sha256"]` | **重新编译**策略包并比对 |
| 程序 | `binding.vkey_hash`（SP1 验证密钥哈希） | 从 ELF 重新 setup 推导，或读证明边车 |
| 证明工件 | `binding.proof_sha256` | 对 `proof.bin` 求 SHA-256 |
| **证据档位** | `binding.proof_mode`（P0-4） | 与证明工件自报的模式（边车/元信息）比对；无工件的证书只能标 `unproven` |
| 承诺的公开值 | `binding.public_values_sha256` | 读证明的 public values 求哈希（verifier-only 路径用） |
| **本次响应** | `challenge.response_binding`（P0-2） | **用送达的 T′ 与 `nonce` 现场重算**并比对 |

`cert.py` 提供信封格式与签名；`agent.py` 提供**框架无关的两个钩子**，把「判定 → 出证」串起来。

**不负责**：策略编译（`01`）、隐私原语（`02`）、账本与上链（`04`）、框架接线（`06`）。

---

## 2. 证书载荷（payload）

由 `cert.build_payload(...)` 组装，结构确定（同一输入 ⇒ 同一字节 ⇒ 同一摘要）：

```jsonc
{
  "cert_version": "v1",
  "policy": {"id": "eu-ai-act-v1", "version": "0.1.0"},
  "policy_hash": "<64hex>",
  "mode": "public",                       // public | private | tool-call
  "outcome": {                            // 即 SP1 承诺的 ProofOutput / PrivateOutput
    "response_binding": "<64hex>",        // P0-2：SHA256("pop-bind-v1"‖len‖nonce‖T)
    "passed": true,
    "violations": [{"rule": "...", "kind": "...", "evidence": "..."}]
  },
  "binding": {
    "vkey_hash": "<hex>",                 // "unproven" 表示未附证明（仅链下判定）
    "proof_sha256": "<64hex>|null",
    "public_values_sha256": "<64hex>|null", // verifier-only 校验用
    "proof_mode": "core"                  // P0-4 诚实标注：见下
  },
  "ai_act": { /* 见 §4 */ },
  "challenge": {                          // 可选（P0-2），见下
    "scheme": "pop-bind-v1",
    "nonce": "<64hex>",                   // 一次性挑战值（公开）
    "response_binding": "<64hex>"         // 必须与 outcome 内嵌的那个逐字节相同
  },
  "ts": "2026-09-10T12:00:00Z",
  "streaming": { /* 可选，见 §5 */ }
}
```

`payload` 中的 `streaming` 等注解由 `extra` 参数注入（`build_payload(..., extra=...)`）。

### 挑战块（`challenge`）—— P0-2

没有它，证书只证明「**存在**某条 T 通过了 π」：证明的 T 是私有输入，公开值里只有
它的承诺，验证者手上的 T′ 与它**无任何联系**（中间人换一条 T′ 送达，证书照样全绿）。

修法是把验证者出的一次性 `nonce` 也喂进电路，让电路承诺
`response_binding = SHA256(BIND_DOMAIN ‖ u32_be(len(nonce)) ‖ nonce ‖ T_utf8)`
（域分隔见 `02` §5b）。`challenge` 块就是把这个承诺连同 `nonce` 一起写进证书，
于是**持 T′ 与 nonce 的任何一方都能离线核对** `commit.verify_binding(nonce, T′, binding)`，
不需要相信出证方。

> 三个关键点：①`challenge.response_binding` 与 `outcome.response_binding` 必须一致
> —— `verify_cert` 会把它们**连同证明公开值、连同现场重算值**做 ≥2 来源比对
> （`verifier.check_response_binding`，全局不变量 I7）；
> ②`nonce` 的**一次性**是协议使用方的责任，密码学只保证绑定不保证不复用
> （`challenge.NonceStore` 是最小参考实现）；
> ③不带 `--nonce` 出证 / 不附 `challenge` 的旧路径**不报错也不假装绑定了**：
> `verify_cert` 显式打印 `not challenge-bound — skipped`，`ai_act` 里对应字段为 `false`。

### 证明模式标注（`binding.proof_mode`）—— P0-4

`vkey_hash` 只说「这条证书绑定了一个程序」，**不说这个程序产出的证明隐藏了什么**。
而 SP1 的 `core`/`compressed` 证明是**普通 STARK，不是零知识证明**（`groth16`/`plonk`
只在包装层隐藏，内层 STARK 仍作为私有见证进入 gnark 电路，未审计、非后量子；
完整证据见 [`../sp1-zk-audit.md`](../sp1-zk-audit.md)）。不标注，第三方就无法判断
「响应内容被隐藏」这句话到底成不成立 —— 于是证书里多一个**如实的档位声明**：

| `proof_mode` | 含义 | 对见证的隐藏 |
|---|---|---|
| `unproven` | 没有证明工件（仅链下判定 / host-check） | `n/a` |
| `core` / `compressed` | SP1 STARK（**非零知识**） | `none` |
| `groth16` / `plonk` | STARK + gnark 包装 | `wrapper-only` |
| 其它/缺省 | —— | `unknown`（**不猜**） |

三条性质（由 `cert.proof_hiding()` 与验证方共同锁住）：

1. **没有工件只能自称 `unproven`**：既不传 `proof_mode` 也不传 `proof_sha256` 时
   `build_payload` 自动填 `unproven`；反过来，`verify_cert.py` 会拒绝一张
   「自称 `core` 却拿不出工件」的**过度声明**证书。
2. **未知模式一律 `"unknown"`**：`proof_hiding("stark-recursive")` 不会退回某个
   看似合理的档位 —— 把「未知」说成「已知」正是这条标注要防的事。
3. **它是稳定字段**：进 `cert_digest`，所以事后改写档位会破坏锚定。

> ⚠️ 这是**出证方的自我声明**，其可信度来自第 1 条与验证方的交叉核对
> （`verify_cert.py` 拿它跟证明工件的边车/元信息比对，多来源必须指向同一档），
> 而不是来自「证书自己说了什么」。

### 信封（DSSE 风格）

```jsonc
{
  "payloadType": "application/vnd.proof-of-policy+json",
  "payload": "<base64(canonical(payload))>",
  "signatures": [{"keyid": "ed25519:<sha256(原始公钥)>", "sig": "<base64(Ed25519 签名)>"}]
}
```

- **规范序列化** `canonical(obj)` = `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`。
  这是「独立重算哈希」的前提：任何实现只要按同一规则序列化，就能得到同一 `cert_digest`。
- 签名覆盖的是 **payload 字节**（不是 JSON 文本的另一种编码）。Ed25519 在规范内部先哈希，
  因此对任意长度载荷都只需一次 64 字节签名，不需要预先哈希。

#### 签名方案：按 `keyid` 前缀分发（P0-3）

`keyid` 冒号前的部分是**方案前缀**，`verify_envelope` 据此分发：

| 方案前缀 | 实现 | 用途 |
|---|---|---|
| `ed25519` | `Ed25519Signer` | **生产**（非对称，提供不可否认性） |
| `test-hmac-sha256` | `HmacSigner` | 仅测试/演示（对称） |
| 其它任何前缀 | —— | **直接拒绝** |

> ⚠️ **历史遗留**：P0-3 之前用一把**硬编码在源码里的公开密钥** `DEMO_KEY` 做 HMAC
> （`keyid = "demo-hmac-sha256"`）。对称密钥的根本问题是**不提供不可否认性** ——
> 验证方持有同一把密钥，所以任何能验签的人也能伪造签名，而「记录不可否认」正是审计
> 证书的全部意义。现在该方案**不在任何 keyring 里**：`verify_envelope` 在查表**之前**
> 就按前缀把它否掉，所以即便把配对的密钥放进 keyring 也一样被拒 ——
> **旧证书不可能再通过**（`tests/test_cert.py::TestSchemeDispatch` 锁住这一点）。
> `DEMO_KEY`/`DEFAULT_KEYID` 仅为兼容引用与负例测试保留，**不要在新代码里使用**。

**密钥从哪来**（`policydsl/keys.py`）：

- 出证方：`keys.load_or_create()` 读 `$POP_SIGNING_KEY`（缺省 `.pop-keys/signing.key`，
  已 gitignore，`0600`、不覆盖已有文件），没有就生成一把；`scripts/gen_key.py` 是它的 CLI。
- 验证方：`keys.load_keyring(path_or_text)` 把 `key.json` / `*.pub.hex` / `*.pub.pem` /
  公钥十六进制读成 `{keyid: 公钥}`，交给 `verify_envelope`。**从头到尾不需要私钥。**

---

## 3. 函数级 API（`cert.py`）

| 函数 | 签名 | 说明 |
|---|---|---|
| `canonical(obj)` | `-> bytes` | 规范 JSON 字节（键排序、紧凑分隔符、UTF-8） |
| `sha256_hex(data)` | `-> hex` | 字节的 SHA-256 |
| `utc_now()` | `-> "2026-09-10T12:00:00Z"` | 证书时间戳格式 |
| `ai_act_claims(mode, challenge_bound=False)` | `-> dict` | EU AI Act Art.12/13 声明（§4）；`challenge_bound` 决定 `art12.response_bound` |
| `build_payload(...)` | `-> dict` | 组装载荷；`ts` 缺省取当前时间 |
| `cert_digest(payload)` | `-> hex` | `SHA256(canonical(payload))` —— **锚定值** |
| `sign_payload(payload, signer, keyid=…)` | `-> dict` | 包成签名信封；`signer` 是任意 `Signer`，也可以是 `bytes`（旧式 HMAC，仅测试） |
| `envelope_payload(env)` | `-> dict` | 从信封解出载荷（不验证签名） |
| `envelope_keyid(env)` | `-> str?` | 第一个签名的 keyid |
| `envelope_scheme(env)` | `-> str` | keyid 的方案前缀（无签名则空串） |
| `verify_envelope(env, keyring)` | `-> (bool, dict?)` | 按方案前缀分发验签；失败返回 `(False, None)` |
| `proof_hiding(proof_mode)` | `-> "none"/"wrapper-only"/"n/a"/"unknown"` | 该档证据对见证的隐藏程度；**未知模式返回 `"unknown"`，不猜** |
| `PROOF_MODE_UNPROVEN` / `PROOF_MODE_HIDING` | 常量 | 「未证明」的取值与档位→隐藏程度映射表 |
| `keyring(*signers)` | `-> {keyid: 验签器}` | 由签名器/公钥构造 keyring |
| `Ed25519Signer` | 类 | `.keyid` / `.public_key` / `.public_hex` / `.generate()` / `.sign()` / `.verify()` |
| `HmacSigner` | 类 | **仅测试**（方案前缀 `test-hmac-sha256`） |
| `ED25519_SCHEME` / `HMAC_TEST_SCHEME` / `PAYLOAD_TYPE` / `CERT_VERSION` | 常量 | |
| `DEFAULT_KEYID` / `DEMO_KEY` | 常量 | **历史遗留**，仅为兼容引用与负例测试保留 |

`cert.py` 里**没有**密钥生成或落盘逻辑 —— 那在 `policydsl/keys.py`（见 §2 末）：
`key_path` / `load_or_create` / `signer_from_env` / `ephemeral_signer` /
`public_hex` / `load_public` / `load_keyring` / `public_record`。

`build_payload` 的完整签名：

```python
build_payload(policy_id, policy_version, spec, mode, outcome,
              vkey_hash, proof_sha256=None, ts=None,
              extra=None, public_values_sha256=None,
              challenge=None, proof_mode=None) -> dict
```

`challenge`（P0-2）与 `proof_mode`（P0-4）都是**末位可选参数**，这样更早的所有
位置参数调用点（`agent.py` 的第 8 位 `ts`、测试里的 `"TS"`）都无需改动。传了
`challenge`，载荷才多出上面那个 `challenge` 块，`ai_act.art12_record_keeping.response_bound`
才为 `true`；`proof_mode` 缺省时按 `proof_sha256` 是否为空推断（空 ⇒ `unproven`）。

---

## 4. EU AI Act 声明（`ai_act_claims`）

证书内嵌两条自我声明，把技术动作映射到监管条款（详见 [`../eu-ai-act-mapping.md`](../eu-ai-act-mapping.md)）：

```jsonc
"art12_record_keeping": {            // 记录留存
  "per_call_record": true,           // 每次调用一条记录
  "policy_hash_bound": true,         // 记录绑定策略哈希
  "response_bound": true,            // P0-2：记录绑定本次响应（有 challenge 块才为 true）
  "anchored": true                   // 已锚定（防篡改）
},
"art13_transparency": {              // 透明度
  "policy_disclosed": true,          // 策略公开
  "mode": "public",                  // 响应公开 or 仅承诺
  "outcome_disclosed": true          // 判定结果公开
}
```

> 这些是**声明字段**，不是被证明的断言；它们的可信度来自「证书其余部分可核验」。
> 例如 `anchored: true` 的实际依据是 `cert_digest` 真的在账本里（`04` 的 `find_anchor`）。

---

## 5. 流式（增量）证书与早停

流式生成时，`PoPCallbackHandler` 可以在**每个 token 之后**对当前前缀做判定，并对**判定翻转的时刻**
签发一张部分证书。这种证书靠 `streaming` 注解串成哈希链：

```jsonc
"streaming": {
  "partial": true,                      // 前缀判定（非权威结论）
  "tokens": 7,
  "chain": {"index": 3, "prev": "<上一张证书的 cert_digest|'genesis'>"}
}
```

早停证书额外携带：

```jsonc
"streaming": {"partial": false,
              "stop": {"reason": "violation", "at_index": 3, "chain_head": "<64hex>"}}
```

**健全性要点**：部分证书只是「前缀结论」，仅供早告警/早停，**权威结论始终是 `on_llm_end` 的那一张**
（见 [`../security-model.md`](../security-model.md) 「流式早停健全性」）。链的校验由
`langchain_adapter.verify_chain` 完成（序号连续 + `prev` 链接，可检出重排/插入/篡改）。

---

## 6. `agent.py`：框架无关的插桩钩子

`AgentMonitor(policy, mode="public"|"private", key, keyid)` 在构造时**编译一次**策略并缓存 `self.spec`
（后续所有判定复用，避免每条消息重编译）。

| 方法 | 路径 | 说明 |
|---|---|---|
| `generate_outcome(response, mask=None, redacted=None, spans=None)` | 生成 | 算「承诺的判定结果」：public → `canonical_violations`；private → `private_output` |
| `on_generate(response, ts=None, vkey_hash="unproven", proof_sha256=None, mask=None, redacted=None, spans=None, extra=None, proof_mode=None)` | 生成 | 判定 + 出证（`mode` 沿用构造值） |
| `tool_call_outcome(name, args, response=None)` | 工具 | 用 `evaluate.check` 判定；结果含 `"zk": True` |
| `on_tool_call(name, args, ts=None, response=None, vkey_hash="unproven", proof_mode=None)` | 工具 | 判定 + 出证（`mode` 固定为 `"tool-call"`） |
| `mock_agent()` | — | 确定性、免 LLM 的会话生成器（先工具调用、后生成），供 demo/测试 |

关键语义：

- **`vkey_hash="unproven"` 是默认值**：表示这张证书**没有绑定真实证明**，只是链下判定。
  `verify_session` 会据此要求「证书也没声称有证明」（`proof_sha256 is None`）。
- 工具路径的 outcome 里 `zk: True` 表示「**该规则类型可证**」（六类规则都已入电路），
  与「这张证书附了证明」是两件事 —— 后者看 `binding.vkey_hash`。
- 工具路径的 `mode` 是 `"tool-call"`，生成路径是 `"public"`/`"private"`。这影响 `ai_act_claims` 的
  `mode` 字段取值。
- **`proof_mode` 与 `vkey_hash` 必须一起给**：只给 `vkey_hash` 等于说「绑了一个程序」却
  不说「这档证据隐藏了什么」。框架适配器（`06`）把它作为构造参数一路带到底，
  只是为了少写样板 —— 校验逻辑不认适配器，只认载荷里那个字段。

---

## 7. 不变量与边界

1. **载荷确定性**：除 `ts` 外全部字段由输入决定；`build_payload` 不注入随机数。
   `ts` 一旦生成即固定，`cert_digest` 因此稳定（锚定要求如此）。
2. **签名覆盖 payload 字节**，不覆盖 `payloadType`/`keyid` —— 与 DSSE 的常见做法一致，但要知道这一点。
3. **`verify_envelope` 失败即返回 `(False, None)`**，调用方必须先判 `ok` 再用 payload。
4. **`cert_digest` 是唯一锚定值**：改动 payload 任何一个字段（包括 `ts`）都会改变摘要，
   所以「同一张证书」在语义上包含其时间戳。
5. **`outcome` 直接来自证明的公开值**（`issue_cert.py` 从 `results.json` 里剥掉 `name`/`mode` 后原样放入），
   不是重新算的 —— 保证「证书里的结论 == 电路承诺的结论」。
6. **`extra` 只能新增顶层键**（`payload.update(extra)`），不要用它覆盖 `policy_hash`/`binding` 等绑定字段。
7. **`proof_mode` 不被"猜"**：`proof_hiding` 对任何不认识的取值返回 `"unknown"`，
   且 `build_payload` 只在「确实没有工件」时才推断出 `unproven` —— 缺省不是
   「最宽松的档位」，而是「什么都没说」。
8. **`challenge` 块本身不是证明**：它是电路公开值的一部分被**抄进**证书。单独看证书，
   它只是一句声明；可信度来自「与证明公开值一致」（`verify_cert` 的第 3b 步会拿证明去比）。
   没有 `--proof` 时若把 `--response` 也省了，就只剩证书内部两个来源 —— 照样会通过，
   但报告里会写明来源只来自证书本身，不构成对出证方的独立约束。

---

## 8. 测试对应

| 测试 | 覆盖 |
|---|---|
| `tests/test_cert.py::TestCertificate` | 载荷字段、`cert_digest` 稳定性、Ed25519 签名/公钥验证、篡改拒绝 |
| `tests/test_cert.py::TestSchemeDispatch` | **P0-3 验收**：错密钥/篡改被拒、旧 `demo-hmac-sha256` 信封被拒（且证明非恒真）、未知方案被拒、失败必返回 `(False, None)` |
| `tests/test_cert.py::TestProofModeLabeling` | **P0-4 验收**：无工件 ⇒ `unproven`；显式档位原样保留；改档位会改 `cert_digest`；隐藏程度映射；未知模式返回 `"unknown"`（不猜） |
| `tests/test_policy_binding.py::TestProofModeOverclaimRejected` | **P0-4 验收（验证方）**：诚实标 `unproven` 通过；自称 `core` 却无工件 ⇒ `[FAIL] proof_mode`；缺字段的旧证书如实跳过 |
| `tests/test_agent.py` | `AgentMonitor` 两条路径的 outcome 与证书、`mock_agent` 确定性 |
| `tests/test_frameworks.py`（流式部分） | `verify_chain`、早停证书形状 |
| `tests/test_binding.py::TestChallengedCertificateEndToEnd` | 挑战块进证书：送达 T′ 通过 / 换 T′ / 换 nonce 被拒 / 无挑战块诚实跳过 |
| `scripts/verify_cert.py` | 端到端 9 项检查（签名 / policy_hash / **response_binding** / **proof_mode** / 锚定 / 证明 / outcome / vkey / proof_sha256） |
| `scripts/verify_session.py` | 会话级：签名 + policy_hash + **response_binding** + **proof_mode**（逐证书 + 与工件自报模式交叉核对）+ 锚定 + 流式链 + zk 证明 |

---

## 9. 扩展指引

- **换签名算法**（Ed25519 已于 P0-3 落地）：新增一个带 `scheme` 的 `Signer` 子类，
  在 `verify_envelope` 的**方案白名单**里加上它的前缀，并让 `keys.load_keyring` 能识别
  对应的公钥编码。信封结构与 `payloadType`/`payload`/`signatures` 三字段不变，
  所以**换算法不会让已有锚定失效**（`keyid` 不进 `cert_digest`）。
- **密钥轮换**：新旧公钥同时放进 keyring 即可平滑过渡（一个 ring 可持多把密钥，
  `verify_envelope` 按信封的 `keyid` 选）。要**吊销**旧的，就在方案层面拒掉，
  或把该 keyid 从 ring 里移除 —— 注意后者只挡得住「按 keyid 找不到密钥」，
  与 `demo-hmac-sha256` 那种「方案本身不被接受」不是一回事。
- **接 HSM / KMS**：把 `keys.load_or_create` 换成取远程句柄，只要返回的对象满足
  `Signer` 协议（`keyid` + `sign`）即可；`Ed25519Signer` 只是一个实现，不是接口。
- **加新的证书字段**：优先走 `extra`（如流式注解就是这么加的）；若必须进**稳定字段**，
  要意识到它会改变 `cert_digest`，**旧证书的摘要会对不上**。
- **接新的证明模式**（如未来换成真正的 ZK 后端）：在 `PROOF_MODE_HIDING` 里加上
  它的档位与**实测**的隐藏程度，并让 `verifier.artifact_proof_modes` 能读到它的
  自报来源。**不要**在没实测的情况下把新档位写成 `"full"` —— 那正是 P0-4 审计
  揪出来的问题形态（`sp1-zk-audit.md` 记的是实测结论）。
- **加新路径**（如「模型加载路径」）：在 `AgentMonitor` 上加一对 `*_outcome` / `on_*`，
  并决定 `mode` 字符串 —— 它会进入 `ai_act_claims`。

---

**相关**：摘要如何被锚定 → [`04-anchoring-audit.md`](04-anchoring-audit.md)；
钩子如何接到真实框架 → [`06-frameworks.md`](06-frameworks.md)。
