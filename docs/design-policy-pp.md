# P-PP 原型：策略签发前置条件（证书层）

> **状态**：2026-11-01，A2 原型落地。新增
> `policydsl/evidence/policy_registry.py`、`tests/test_policy_registry.py` 与
> `scripts/ops/policy_pp.py`；**未改** `cert.py` / `verify_cert.py` / 电路 / 论文。
> 本文说明它证明什么、不证明什么、依赖哪些假设，以及与带盐承诺、证明工件、
> `delegated` 披露的关系。定义与三方模型见
> [`security-model.md`](security-model.md) §4.6；带盐承诺见
> [`certificate-binding-framework.md`](certificate-binding-framework.md) §7 与
> [`../policydsl/privacy/policy_commit.py`](../policydsl/privacy/policy_commit.py)。

## 1. 问题：`policy_hash` 单独看是惰性的

私有策略模式下，证书公开值里只有 `policy_hash`，没有策略正文。于是第三方 `V`
能验出的只是：

> 「**某个**哈希为 `H` 的策略被这份证明判定了。」

它**验不出** `H` 是不是监管方/标准方规定的那条策略。证明者对任意策略 π′ 都能
出一张自洽证书，只要在证书里写 `H′ = SHA256(π′)`。这不是签名或零知识能补的：
要补就得让 `V` 看到 π，而那正是私有模式要藏的东西。

**补缺口的是签发行为，不是密码学原语。** 规范方 `R` 签发 π、把它的
`policy_hash` 登记进一份可被第三方读取的签发记录；`V` 只要确认「证书里的 `H`
在这份记录里、且记录是 `R` 签的」，就得到「某条**被签发的**策略被满足」。
这就是 P-PP（策略可问责）。没有它，私有策略模式的结论为空。

## 2. 三方模型与 P-PP 的位置

| 角色 | 诚实性 | 持有什么 | 在 P-PP 里的动作 |
|---|---|---|---|
| **规范方 `R`**（authority） | **诚实**（信任假设） | π 全文、盐、签发私钥 | 签发清单：算带盐 `policy_hash`，用 Ed25519 私钥签清单；审计时开示 `(π, nonce)` |
| **运营方 `O`**（operator） | **不可信** | π 全文、盐、出证密钥 | 用清单里的 `policy_hash` 出证；不得自选哈希 |
| **第三方 `V`** | 诚实 | 权威**公钥**、签发记录、证书公开产物 | 验清单签名 → 查哈希 → 核对证书的 `policy.id/version`；仍看不到 π |

P-PP 的作用可以写成一句可检验的检查链（实现：`
policydsl/evidence/policy_registry.py` 的 `verify_cert_policy`）：

1. 证书载荷里有 `policy_hash`；
2. 该哈希出现在签发记录（registry）里；
3. 对应清单字段完整、`authority_keyid` 与权威公钥一致、Ed25519 验签通过；
4. 载荷若带 `policy.{id,version}`，必须与清单一致（防「借 A 的哈希冒充 B 的
   id/version」）。

四条同时通过才返回 PASS；任何一条断掉都是 FAIL。

## 3. 清单字段与签名口径

```json
{
  "manifest_version": "v1",
  "policy_id": "agent-content-v1",
  "policy_version": "0.1.0",
  "policy_hash": "9f2c…（64 位小写十六进制，带盐承诺）",
  "issued_at": "2026-11-01T00:00:00Z",
  "authority_keyid": "ed25519:<sha256(权威公钥)>",
  "sig": "<base64(Ed25519(canonical_manifest_bytes(manifest)))>"
}
```

* **规范字节**：`canonical_manifest_bytes` 对除 `sig` 外的全部字段做
  「键排序 + 紧凑分隔符 + UTF-8」JSON 编码；`sig` 不能覆盖自身，故排除。
  `authority_keyid` 与 `issued_at` **在签名范围内**，改任何一个都验不过。
* **哈希来源**：`policy_hash = policy_commitment(pack)`，即
  `SHA256(canonical(π) ‖ policy_nonce)` —— 与证书里现有的 `policy_hash` 同一
  口径（见 `policydsl/privacy/policy_commit.py`）。
* **清单里刻意没有** `policy_nonce` 和策略正文（`rules` 等）。`verify_manifest`
  对这两个字段 **fail closed**：一旦出现就拒绝。否则清单本身会把带盐承诺的
  隐藏性抵消掉。
* **盐的流向**：权威生成盐、随策略包私下交给运营方；清单只公开哈希。审计时
  权威（或运营方）开示 `(π, nonce)`，验证者调 `verify_commitment` 重算即可。
* **registry** 是 `{policy_hash: manifest}` 的 JSON 容器，只按哈希查、只追加；
  同哈希不同内容会冲突报错，不静默覆盖。

CLI：`python3 scripts/ops/policy_pp.py issue|verify …`（见脚本 docstring）。
`issue` 用 `keys.signer_from_env` 取权威私钥；`verify` 只需要公钥文件/十六进制。

## 4. 证明什么

在 **P-PP + 既有绑定检查**成立时，第三方 `V` 得到：

> 证书载荷里的 `policy_hash` 是**一份被规范方签发的策略**的带盐承诺；
> 且证书声称的 `policy.id/version` 与那份签发记录一致。

更精确地说，`verify_cert_policy` 与既有证书验证合起来给出：

```text
∃ π*:  Issued(R, H(π*)) ∧ H(π*) = cert.policy_hash
       ∧ cert.policy.id/version = manifest.policy_id/version
```

其中 `H(·)` 是带盐承诺。**「Issued」是一次签名事件**，不是数学性质：
`V` 不需要看到 π 也能确认这个哈希被权威背过书。这与
[`security-model.md`](security-model.md) §4.6.3 能力表里 `V` 的第 ③ 条
（“`H` 出现在规范方的签发记录里”）是同一句话。

在既有绑定（证书签名 + SP1 公开值里的 `policy_hash` + 现场重编译）也通过时，
`V` 进一步知道：**证明实际判定的就是哈希为 `H` 的那条策略**，从而把
「某条被签发的策略被满足」落到具体的 `H` 上。

## 5. 不证明什么

必须写进论文，否则这张清单会被读成「合规证明」：

1. **不证明策略内容对第三方可见。** `V` 仍然不知道 π 有几条规则、是什么类型；
   P-PP 只给哈希一个签发背书，不披露正文。要披露需另走审计开示或
   `delegated`/披露层级。
2. **不证明「被签发的策略就是 `V` 心里那条」。** `V` 只能得到「是**某条已被
   签发**的规范」，除非它自己知道并核对了 `policy_id/version` 的语义。策略内容
   是否正确，最终取决于权威签了什么。
3. **不证明策略内容与行为一致。** 重执行 / 部署上下文推断那条通道与 P-PP 无关；
   盐只保护哈希，不保护行为。
4. **不关闭证明工件通道。** `core`/`compressed` STARK 的 trace 与
   `opened_values` 仍可能泄露 π（见 [`sp1-zk-audit.md`](sp1-zk-audit.md) 与
   [`certificate-binding-framework.md`](certificate-binding-framework.md) §7.3）。
   P-PP 是**认证哈希的出处**，不是 witness-hiding。
5. **不覆盖 `delegated` 的语义缺口。** 清单签的是整条策略的哈希；若本轮
   `delegated` 非空，那份 SP1 证明并没有判定委托约束，仍需陪伴证明 + fail closed
   （见 [`blockers/C1.md`](blockers/C1.md)）。P-PP 不能让「未判定的部分」变成
   「已签发所以已判定」。
6. **不提供新鲜度 / 撤销 / 过期。** 原型没有 expiry、revocation list 或单调序号；
   一份旧清单可以一直被引用。真正部署需要把 `issued_at` 纳入有效性策略，并定义
   撤销记录。
7. **不防重放/替换签发记录。** 若攻击者能让 `V` 用**自己的**公钥验清单，P-PP
   立刻退化成「运营方自签」。权威公钥必须**带外可信分发**。

## 6. 信任假设

| 假设 | 内容 | 不成立时 |
|---|---|---|
| **A4 类：权威诚实** | 规范方只签发它真正认可的 π；不会给 π′ 签 `policy_id` 冒充 π | `V` 得到「某条被签发的策略」，但那条可能不是规定的策略；P-PP 无法补救 |
| **权威公钥真实性** | `V` 手里的 `authority_keyid`/公钥确实属于规范方（带外、证书/公告板等） | 攻击者可自签清单，P-PP 退化为自证 |
| **私钥保密** | 权威 Ed25519 私钥不泄露；泄露即可伪造任意签发记录 | 所有历史/未来清单的不可否认性失效 |
| **哈希抗碰撞（A2）** | SHA-256 抗第二原像 | 可把已签发的 `H` 对应到另一条 π′ |
| **既有绑定成立** | 证书签名、证明公开值、`policy_hash` 三方比对通过 | P-PP 只说明「哈希被签发」，不说明「证明真的判定了它」 |
| **registry 完整性** | `V` 读到的签发记录没有被静默删改 | 删除只会导致误拒（fail closed），但替换内容会与签名冲突；新增伪造条目仍需权威私钥 |

注意：**「权威诚实」与 `security-model.md` §0.2 的「策略作者｜诚实」是同一条
假设**。P-PP 没有引入新的信任主体，只是把这条一直存在的前提绑定到私有策略
模式上，并把它变成一个可运行的检查。

## 7. 与带盐承诺、证明工件、`delegated` 的关系

```text
            隐藏性                          可问责性
   ┌────────────────────────┐      ┌────────────────────────────┐
   │ 带盐承诺 policy_nonce  │      │ P-PP：权威签发 policy_hash │
   │ 关的是「公开值可枚举」 │      │ 关的是「哈希出处不可考」   │
   └────────────────────────┘      └────────────────────────────┘
              │                                  │
              └────────── 正交，缺一不可 ────────┘
```

* **对带盐承诺**：P-PP **必须签带盐后的哈希**，且**不能**把盐放进清单。盐保证
  `V` 不能枚举策略；清单签名保证 `V` 知道这个不可枚举的哈希是谁背书的。两者
  解决的是不同问题：盐 = 隐藏，签发 = 问责。
* **对 `core` 证明工件泄露**：P-PP **不**减少 trace 泄露。即使哈希不可枚举、
  清单可验签，`core` 工件仍可能暴露 π。要关这条通道需 `groth16`/`plonk` 的
  witness-hiding（E1 任务）。
* **对 `delegated` 披露**：P-PP 签的是策略整体哈希，不改变 `delegated` 非空时
  「本轮未判定」的事实，也不改变「`delegated.name` 泄露规则名」这条通道。
  披露层级（L0/L1/L2）仍是证书层的另一件事；签发记录不应成为泄露规则名的
  新入口（原型因此拒绝 `rules`/`policy` 等字段进清单）。
* **对证书层边界**：P-PP 完全在**证书层之外**，不改变电路公开值、vkey 或证书
  字节。它只是给现有 `payload["policy_hash"]` 加一条外部可核验的出处。

## 8. 给论文 §4 的输入要点（可直接用）

> 论文当前编排里 §4 是 System（「双隐私模式」「合规证书与锚定」两小节）；
> 若章节号调整，以下段落按语义插入即可。

1. **定义（P-PP）**：私有策略模式下，策略可问责当且仅当 `policy_hash` 可追溯
   到规范方的一条签发记录。该前提不是可选加固，而是第三方结论的**存在条件**；
   没有它，`policy_hash` 是惰性的，验证者只能得到「某个哈希为 H 的策略通过了」。
2. **机制（证书层、无电路改动）**：权威对
   `{manifest_version, policy_id, policy_version, policy_hash, issued_at,
   authority_keyid}` 的规范 JSON 做 Ed25519 签名；第三方验签后查哈希，并核对
   证书的 `policy.id/version`。清单**不含**盐与策略正文，因此签发不抵消带盐
   承诺的隐藏性。原型：`policydsl/evidence/policy_registry.py` +
   `scripts/ops/policy_pp.py`。
3. **命题（可直接陈述）**：在权威诚实、权威公钥真实、A2 与既有证书绑定成立的
   条件下，`verify_cert_policy` 通过蕴含「证书声称的带盐承诺对应一条被规范方
   签发的策略，且证书的策略 id/version 与签发记录一致」。
4. **边界（必须与命题同时给出）**：P-PP **不**披露策略内容、**不**替代
   witness-hiding、**不**覆盖 `delegated` 的语义缺口、**不**提供新鲜度/撤销；
   它只把「哈希是谁签发的」变成可核验事实。权威不诚实（A4 类）时本层无能为力。
5. **与现有框架的接口**：P-PP 与带盐承诺（定理 D / §7）正交：盐关闭公开值
   枚举通道，签发关闭哈希出处通道；与披露层级（L0/L1/L2）正交：后者决定
   `V` 看到多少规则结构。三者可以独立开关，组合时才给出「隐藏 + 可问责 +
   可审计」的完整图景。

## 9. 原型边界（已知缺口）

* 无撤销/过期/单调序号；registry 的「只追加」语义目前由调用方保证，文件格式
  未带链式摘要。
* 无多权威/阈值签发；`authority_keyid` 单值。
* 无「策略包 ↔ 清单」的离线一致性检查：CLI `issue` 不持久化盐，运营方需自行
  保管 `(pack, nonce)`，否则无法出证。
* `payload` 只接受已解码的证书载荷；信封签名验证在 CLI 里是**可选**的
  `--operator-key`，完整证书检查仍由 `scripts/verify/verify_cert.py` 承担。
