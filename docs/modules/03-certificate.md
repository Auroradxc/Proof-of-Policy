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
    "public_values_sha256": "<64hex>|null"   // verifier-only 校验用
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

### 信封（DSSE 风格）

```jsonc
{
  "payloadType": "application/vnd.proof-of-policy+json",
  "payload": "<base64(canonical(payload))>",
  "signatures": [{"keyid": "demo-hmac-sha256", "sig": "<base64(HMAC-SHA256)>"}]
}
```

- **规范序列化** `canonical(obj)` = `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`。
  这是「独立重算哈希」的前提：任何实现只要按同一规则序列化，就能得到同一 `cert_digest`。
- 签名覆盖的是 **payload 字节**（不是 JSON 文本的另一种编码），`verify_envelope` 用
  `hmac.compare_digest` 做**常量时间**比较，避免时序侧信道。

> ⚠️ **当前是 HMAC-SHA256 演示签名器**（`DEMO_KEY = b"proof-of-policy-demo-key"`，标准库实现）。
> 它只提供完整性/演示语义，**不提供不可否认性**（验证方持有同一密钥）。生产应换成 Ed25519/HSM ——
> **信封结构不变**，只换 `sign_payload` / `verify_envelope` 的签名实现。

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
| `sign_payload(payload, key, keyid=…)` | `-> dict` | 包成签名信封 |
| `envelope_payload(env)` | `-> dict` | 从信封解出载荷（不验证签名） |
| `envelope_keyid(env)` | `-> str?` | 第一个签名的 keyid |
| `verify_envelope(env, key)` | `-> (bool, dict?)` | 校验签名；失败返回 `(False, None)` |
| `CERT_VERSION` / `PAYLOAD_TYPE` / `DEFAULT_KEYID` / `DEMO_KEY` | 常量 | |

`build_payload` 的完整签名：

```python
build_payload(policy_id, policy_version, spec, mode, outcome,
              vkey_hash, proof_sha256=None, ts=None,
              extra=None, public_values_sha256=None,
              challenge=None) -> dict
```

`challenge` 是**末位可选参数**，这样 P0-2 之前的所有位置参数调用点
（`agent.py` 的第 8 位 `ts`、测试里的 `"TS"`）都无需改动。传了它，
载荷才多出上面那个 `challenge` 块，`ai_act.art12_record_keeping.response_bound` 才为 `true`。

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
| `on_generate(response, ts=None, vkey_hash="unproven", proof_sha256=None, mask=None, redacted=None, spans=None, extra=None)` | 生成 | 判定 + 出证（`mode` 沿用构造值） |
| `tool_call_outcome(name, args, response=None)` | 工具 | 用 `evaluate.check` 判定；结果含 `"zk": True` |
| `on_tool_call(name, args, ts=None, response=None, vkey_hash="unproven")` | 工具 | 判定 + 出证（`mode` 固定为 `"tool-call"`） |
| `mock_agent()` | — | 确定性、免 LLM 的会话生成器（先工具调用、后生成），供 demo/测试 |

关键语义：

- **`vkey_hash="unproven"` 是默认值**：表示这张证书**没有绑定真实证明**，只是链下判定。
  `verify_session` 会据此要求「证书也没声称有证明」（`proof_sha256 is None`）。
- 工具路径的 outcome 里 `zk: True` 表示「**该规则类型可证**」（六类规则都已入电路），
  与「这张证书附了证明」是两件事 —— 后者看 `binding.vkey_hash`。
- 工具路径的 `mode` 是 `"tool-call"`，生成路径是 `"public"`/`"private"`。这影响 `ai_act_claims` 的
  `mode` 字段取值。

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
7. **`challenge` 块本身不是证明**：它是电路公开值的一部分被**抄进**证书。单独看证书，
   它只是一句声明；可信度来自「与证明公开值一致」（`verify_cert` 的第 3b 步会拿证明去比）。
   没有 `--proof` 时若把 `--response` 也省了，就只剩证书内部两个来源 —— 照样会通过，
   但报告里会写明来源只来自证书本身，不构成对出证方的独立约束。

---

## 8. 测试对应

| 测试 | 覆盖 |
|---|---|
| `tests/test_cert.py::TestCertificate` | 载荷字段、`cert_digest` 稳定性、签名/验证、篡改拒绝 |
| `tests/test_agent.py` | `AgentMonitor` 两条路径的 outcome 与证书、`mock_agent` 确定性 |
| `tests/test_frameworks.py`（流式部分） | `verify_chain`、早停证书形状 |
| `tests/test_binding.py::TestChallengedCertificateEndToEnd` | 挑战块进证书：送达 T′ 通过 / 换 T′ / 换 nonce 被拒 / 无挑战块诚实跳过 |
| `scripts/verify_cert.py` | 端到端 8 项检查（签名 / policy_hash / **response_binding** / 锚定 / 证明 / outcome / vkey / proof_sha256） |
| `scripts/verify_session.py` | 会话级：签名 + policy_hash + **response_binding** + 锚定 + 流式链 + zk 证明 |

---

## 9. 扩展指引

- **换生产签名**：实现 `sign_payload` / `verify_envelope` 的 Ed25519 版本，保持返回结构与
  `payloadType`/`payload`/`signatures` 三字段不变；`keyid` 改成算法/密钥标识。
  注意 `cert.DEMO_KEY` 在 `agent.py`、`langchain_adapter.py`、各脚本里都有引用点。
- **加新的证书字段**：优先走 `extra`（如流式注解就是这么加的）；若必须进**稳定字段**，
  要意识到它会改变 `cert_digest`，**旧证书的摘要会对不上**。
- **加新路径**（如「模型加载路径」）：在 `AgentMonitor` 上加一对 `*_outcome` / `on_*`，
  并决定 `mode` 字符串 —— 它会进入 `ai_act_claims`。

---

**相关**：摘要如何被锚定 → [`04-anchoring-audit.md`](04-anchoring-audit.md)；
钩子如何接到真实框架 → [`06-frameworks.md`](06-frameworks.md)。
