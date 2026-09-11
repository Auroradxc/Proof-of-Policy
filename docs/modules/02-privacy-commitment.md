# 02 · 隐私与承诺（私有模式）

> 覆盖 `policydsl/commit.py`，依赖 `nfa.py` 的区间计算。
> 这一板块回答：**如何在不说出响应内容的前提下，证明「我判定过了，结论是这个」，
> 并且「我遮蔽掉的确实是我声称命中的内容」。**

---

## 1. 职责

透明模式公开响应全文；**私有模式**只公开五样东西：

1. `response_binding` —— 挑战-响应绑定，把 T 拴到本次会话的一次性 nonce 上（P0-2）；
2. `response_commitment = SHA256(T)` —— 响应承诺；
3. 每条违规的 `{rule, kind, evidence_commitment}` —— 违规定位（**不给证据明文**）；
4. 可选的**脱敏证明** `redaction`；
5. `passed` 布尔值。

> `response_binding` 与 `response_commitment` 回答的是**两个不同的问题**，缺一不可：
> 前者「是**这一条** T 吗」（会话绑定），后者「**存在某条** T 通过了吗」（内容承诺）。
> 只留后者的话，验证者拿到一条 T′ 却没有任何东西能把它与证明对上 —— 那正是 P0-2
> 之前的状态。所以没有把 `response_commitment`「升级」成绑定值，而是并置。

`commit.py` 就是这套原语的参考实现，语义与 Rust 侧 `pop-types::evaluate_private` **逐字节兼容**
（`scripts/private_demo.py` 逐字段比对 golden 与电路输出，含 `response_binding`）。

**不负责**：证书封装（`03`）、证明本身（`05`）。这里只定义「什么值该被提交」。
挑战值的**生成与生命周期**（一次性、重放记录）在 `policydsl/challenge.py`（本节 §5b）。

---

## 2. 关键数据结构

### 2.1 私有输入 `PrivateRequest`（Rust 侧同名）

| 字段 | 含义 |
|---|---|
| `spec_canonical` | 策略规范 JSON 字节（与公开模式同一份，唯一真相源） |
| `response` | 原始响应（**私密输入**，不进公开值） |
| `nonce: [u8]` | 一次性挑战值（P0-2）。空 = 未走挑战流程，绑定退化为「空挑战的承诺」 |
| `mask: [u32]` | 允许不同（置为 `*`）的字符下标 |
| `redacted: str?` | 要验证的候选脱敏串（可选） |
| `spans: [(u32,u32)]` | **见证区间**：声称「这些位置是真实模式匹配」的证据 |
| `tool_calls` / `token_count` | 轨迹类规则用 |

### 2.2 私有输出 `PrivateOutput`

```jsonc
{
  "response_binding": "<64hex>",         // SHA256("pop-bind-v1" ‖ len(nonce) ‖ nonce ‖ T)
  "response_commitment": "<64hex>",      // SHA256(T)
  "passed": false,
  "violations": [{"rule": "no_email", "kind": "pattern_block",
                  "evidence_commitment": "<64hex>"}],
  "redaction": {                         // 仅当提供了 redacted 时非 null
    "redacted_commitment": "<64hex>",
    "mask_count": 15,
    "redaction_ok": true,                // R 与 T 仅在掩码位不同
    "mask_covered": true                 // 每个掩码位都落在「真实完整匹配」的见证 span 内
  }
}
```

> 公开值里**没有任何明文**：`passed` 是布尔、其余全是 64 位十六进制承诺。这是「内容隐私」这一
> 安全目标的全部实现依据（见 `../security-model.md` 的 Leak 实验）。

---

## 3. 规范证据字符串（跨层一致的关键）

`commit.canonical_violations` **精确镜像** `pop-types::evaluate`，产出 `(rule, kind, evidence)` 三元组，
其 `evidence` 字符串必须与 Rust 侧**逐字节相同** —— 因为私有模式提交的是 `SHA256(evidence)`，
差一个字节两个承诺就对不上。

| kind | evidence 字符串 | 说明 |
|---|---|---|
| `keyword_block` | 命中的关键词本身 | 取 spec 顺序下**第一个**命中 |
| `length_bound` | `"len=<N>"` | 码点长度 |
| `pattern_block` | 命中的模式串 | 按编译顺序第一条命中 |
| `format_check` | `"<format>"`（如 `"json"`） | |
| `tool_arg_guard` | `"<tool>:<field>"` | 每个调用至多一条 |
| `budget_bound` | `"<unit>=<total>/<budget>"` | 如 `"calls=3/2"` |

注意这与 `evaluate.py` 的 `Violation.evidence`（结构化字典/列表）**不是一回事**：
透明模式走 `evaluate.py`，私有模式走 `commit.py`。两者的一致性由 `cross_validate` 与
`private_demo` 分别保证。

另一个必须逐字节一致的点：**ASCII 小写化**。

```python
def _ascii_lower(s):   # 不用 str.lower()！
    return "".join(chr(ord(c)+32) if "A" <= c <= "Z" else c for c in s)
```

Python 的 `str.lower()` 会折叠非 ASCII 字母，而 Rust 侧只折叠 ASCII —— 直接调用会导致
链下/链上对同一输入得出不同判定（全局不变量 I3）。

---

## 4. 可证明脱敏（这一板块的核心）

脱敏目标：把响应里命中的敏感片段替换成 `*` 后公开，**同时证明「被 `*` 掉的位置确实命中了规则」**，
防止作恶的证明者借掩码掩盖任意文本（例如把一段违规内容藏在一大片 `*` 后面）。

两个性质分开验证、缺一不可：

| 性质 | 函数 | 含义 | 电路内对应 |
|---|---|---|---|
| `redaction_ok` | `commit.redaction_ok(response, redacted, mask)` | 等长、掩码位恰为 `*`、非掩码位**完全不变**（VDR 式位选择器） | `types::redaction_ok` |
| `mask_covered` | `commit.mask_covered(mask, spans)` ∧ `commit.spans_valid(spec, text, spans)` | ① 每个 span 都是某条 pattern 的**真实完整匹配**；② 每个掩码下标都落在某个 span 内（`mask ⊆ spans`） | `types::spans_valid` + `mask_within_spans` |

`mask_covered` 的「真实完整匹配」由 `nfa.anchored_full_match` 判定：两端锚定、**至少消耗 1 个字符**
（长度为 0 的空匹配一律不认），这正是「不能拿空 span 糊弄」的地方。

**二者合取 ⇒ 脱敏只遮蔽真实命中内容。** 负例对照（`scripts/private_demo.py` 的 `badspan` 用例）：
构造 `spans=[[0,1]]` 而掩码并不落在真实匹配内 → 电路内 `mask_covered=false`。

### 掩码是怎么算出来的

```python
mask = commit.mask_from_patterns(patterns, response)   # 被命中区间覆盖的字符下标
spans = commit.spec_spans(spec, response)              # 合并所有 pattern_block 的匹配区间
redacted = commit.redact(response, mask)               # 掩码位替换成 "*"
```

`mask_from_patterns` → `nfa.mask_indices` → 对每个 spec 求 `find_spans`（每个起点的**最长**匹配，
排序合并）→ 取并集。`spec_spans` 走同样路径但保留区间（作为见证 `spans`）。
两者都由 `find_spans` 的确定性算法给出：**参考层用它构造掩码**，电路内则只**验证**它（不重算）。

---

## 5. 证据开示（对审计者的选择性披露）

私有模式的常态是「只给承诺」；当审计者有权查看时，证明者**开示**明文片段：

```python
bundle = commit.evidence_bundle(spec, response)
# [{"rule": "no_email", "kind": "pattern_block",
#   "evidence": "dev@example.com", "evidence_commitment": "<64hex>"}, ...]

commit.verify_bundle(bundle)          # 每条：SHA256(evidence) == evidence_commitment
commit.open_evidence(comm, fragment)  # 单条开示校验
```

安全性来自 SHA-256 的抗原像性：未持有原响应的人无法为任意承诺伪造出能通过校验的开示；
篡改开示会被 `verify_bundle` 拒绝。**bundle 里的承诺必须与证明输出里的承诺一致**，
`private_demo.evidence_experiment` 显式检查了这一点（`bound_to_proof`）。

---

## 5b. 挑战-响应绑定（`challenge.py` + `commit` 的两个函数）

**要修的问题**：证明说的是「某条 T 满足 π」。公开模式下 T 只是证明的私有输入、
证书里不出现；私有模式下更只有 `response_commitment`。于是「被证明的 T」与
「客户端收到的 T′」之间**没有任何联系** —— 中间人可以用一条合规的 T 去换一条
不合规的 T′ 送达，证明依然有效，因为它压根没提过 T′。

**做法**：让**验证者出题**。

```
客户端/验证者                    证明方                        验证者
     │ 1. nonce = new_nonce()      │                             │
     ├──────────── nonce ─────────►│                             │
     │                             │ 2. 电路承诺                  │
     │                             │  response_binding =         │
     │ 3. 收到 T′ ◄─────────────────┤  SHA256(domain‖len‖n‖T)     │
     │                             │                             │
     │ 4. commit.verify_binding(nonce, T′, binding) → True 才认账  │
```

```python
BIND_DOMAIN = b"pop-bind-v1"
def response_binding(nonce: bytes, response: str) -> str:
    # SHA256(BIND_DOMAIN ‖ u32_be(len(nonce)) ‖ nonce ‖ T_utf8)，小写十六进制
def verify_binding(nonce, response, binding) -> bool:   # hmac.compare_digest
```

`len(nonce)` 这个 4 字节大端前缀是**必需的**：没有它，
`(nonce=b"ab", T="cd")` 与 `(nonce=b"abcd", T="")` 会哈希成同一个值（拼接歧义）。
加了它，`(nonce, T) → 字节串` 恒为单射，任意长度都无歧义。
Python 侧与 `pop_types::response_binding` 必须逐字节一致 —— 否则验证方拿 Python
重算去核对会永远失败（或更糟：永远通过）；`tests/test_binding.py::TestPythonRustParity`
真跑 `pop-script --check` 钉死这一点。

`challenge.py` 提供：

| 成员 | 说明 |
|---|---|
| `NONCE_BYTES = 32` | 挑战值长度（256 bit CSPRNG） |
| `new_nonce()` | `secrets.token_bytes(32)` |
| `nonce_hex(b)` / `parse_nonce(s)` | 十六进制编解码；`parse_nonce` 拒绝奇数长度与非十六进制 |
| `challenge_block(nonce, binding)` | 证书里的 `challenge` 块：`{scheme, nonce, response_binding}` |
| `check_challenge(payload, response)` | 用证书自带的 `challenge` 块**离线**核对一条候选 T′ |
| `NonceStore(path=None)` | 追加式「已用 nonce」记录；`consume` 重复即抛 `ValueError` |

> **一次性是协议使用方的责任**，不是密码学的自动结果：nonce 是**公开**的（必须公开，
> 否则没人能核对），所以重放一条绑定了该 nonce 的合法证书在密码学上是成立的。它的危害
> 是「一次会话变成多次」，而不是「伪造的 T′ 通过」。`NonceStore` 是给不想自己造轮子的
> 调用方准备的最小参考 —— 真实部署会把它换成数据库一行或链上一次调用。

---

## 6. 函数级 API

| 函数 | 签名 | 说明 |
|---|---|---|
| `commitment(text)` | `str -> hex` | `SHA256(text.encode("utf-8"))` 小写十六进制 |
| `evidence_commitment(evidence)` | `str -> hex` | 同 `commitment`（语义别名，便于阅读） |
| `canonical_violations(spec, response, tool_calls=None, token_count=None)` | `-> list[dict]` | **镜像 Rust 判定**，返回 `(rule, kind, evidence)`；未知 kind 抛 `NotImplementedError` |
| `private_output(spec, response, mask=None, redacted=None, spans=None, nonce=b"", ...)` | `-> dict` | 组装 `PrivateOutput` golden（含脱敏证明与 `response_binding`） |
| `response_binding(nonce, response)` | `bytes,str -> hex` | `SHA256(BIND_DOMAIN ‖ u32_be(len) ‖ nonce ‖ T_utf8)`（P0-2；↔ `pop_types::response_binding`） |
| `verify_binding(nonce, response, binding)` | `-> bool` | 常量时间（`hmac.compare_digest`）核对绑定 |
| `BIND_DOMAIN` / `BIND_SCHEME` | `b"pop-bind-v1"` / `"pop-bind-v1"` | 域分隔前缀 / 证书 `challenge.scheme` 取值 |
| `mask_from_patterns(patterns, text)` | `-> [int]` | 命中区间覆盖的字符下标 |
| `spec_spans(spec, text)` | `-> [(lo,hi)]` | 合并所有 pattern_block 的匹配区间 |
| `spans_valid(spec, text, spans)` | `-> bool` | 每个区间都是真实完整匹配 |
| `mask_covered(mask, spans)` | `-> bool` | `mask ⊆ spans` |
| `redact(text, mask, char="*")` | `-> str` | 掩码位替换 |
| `redaction_ok(response, redacted, mask, char="*")` | `-> bool` | 等长 + 掩码位为 `char` + 其余不变；**下标越界返回 False** |
| `open_evidence(commitment_hex, fragment)` | `-> bool` | `SHA256(fragment) == commitment_hex` |
| `evidence_bundle(spec, response)` | `-> list[dict]` | 完整披露（明文 + 承诺） |
| `verify_bundle(bundle)` | `-> bool` | 逐条校验承诺 |
| `MASK_CHAR` | `"*"` | 掩码字符 |

---

## 7. 不变量与边界

1. **等长**：`redaction_ok` 先比 `len(response) != len(redacted)`（**码点长度**），不等直接 False。
2. **掩码下标合法**：负下标或越界（`i >= len`）返回 False —— 不允许「掩码指向不存在的位置」。
3. **空匹配不算数**：`anchored_full_match` 的 `start >= end` 直接 False。
4. **证据字符串必须逐字节一致**：改动 `canonical_violations` 里任何一个字符（比如 `len=` 前后空格）
   都会让**已有证书的证据承诺**对不上 —— 属于破坏性变更。
5. **`spans` 与 `mask` 是两个独立输入**：只给 `mask` 而不给能覆盖它的 `spans`，`mask_covered` 为 False。
6. **`passed` 由违规数量推出**（`len(vs) == 0`），不接受外部传入。
7. **`commit.py` 不做任何 I/O**，纯函数 —— 便于电路内复现同一语义。

---

## 8. 测试对应

| 测试 | 覆盖 |
|---|---|
| `tests/test_commit.py::TestCommitments` | 承诺的确定性、不同输入不同承诺 |
| `tests/test_commit.py::TestPrivateOutput` | 私有输出形状、`evidence_commitment` 与 `canonical_violations` 一致 |
| `tests/test_commit.py::TestMaskCoverage` | `spans_valid` / `mask_covered`（**伪造 span → `mask_covered=false`**） |
| `tests/test_commit.py::TestRedaction` | `redact` / `redaction_ok` 的等长、越界、篡改 |
| `tests/test_commit.py::TestEvidenceOpening` | 开示验证、篡改被拒 |
| `tests/test_binding.py::TestBindingPrimitive` | ①正确 `(nonce,T)` 通过 ②换 T 失败 ③换 nonce 失败 ④空 nonce 是独立域；`len` 前缀消除拼接歧义 |
| `tests/test_binding.py::TestReplayAndDomain` | `NonceStore` 拒绝重放、可持久化；`new_nonce` 32 字节且不重复 |
| `tests/test_binding.py::TestPythonRustParity` | 真跑 `pop-script --check` 比对 Python/Rust 绑定值（公开 + 私有模式，多种 nonce 长度） |
| `tests/test_binding.py::TestChallengedCertificateEndToEnd` | 出证 → `verify_cert --response`：送达的 T′ 通过、换 T′ / 换 nonce 被拒、无挑战块时诚实跳过 |
| `scripts/private_demo.py` | 端到端：host check ↔ golden 逐字段、负例、Leak、Binding、Evidence、真实证明 |
| `tests/test_rules_incircuit.py` | 私有输出在电路内与 golden 一致 |

---

## 9. 扩展指引

- **想让脱敏覆盖更多模式**：只需在策略包里增加 `pattern_block` 规则；掩码与见证区间会自动包含它
  （`spec_spans` 遍历所有 pattern_block）。
- **想加新的证据形状**：改 `canonical_violations` 的分支，**同时**改 `circuits/types/src/lib.rs`
  的 `evaluate` 对应分支，保持字符串完全一致，然后跑 `scripts/private_demo.py`。
- **想把校验位（IBAN MOD-97）纳入私有证明**：目前 `pii.iban_mod97` 是纯链下辅助函数，
  要入电路需要新增约束类型（见 `01` §7 的六步）。

---

**相关**：这些承诺如何进证书 → [`03-certificate.md`](03-certificate.md)；
同一套私有判定在电路里怎么跑 → [`05-zk-circuits.md`](05-zk-circuits.md) §4；
安全论证 → [`../security-model.md`](../security-model.md)。
