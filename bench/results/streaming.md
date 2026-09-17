# 流式路径的代价：`Θ(L²)`

逐字符喂 `"z" * L`（对全部包都不命中 ⇒ 每个前缀都扫到底、判定不翻转），
走**真实**的 `PoPCallbackHandler.on_llm_new_token`，`stream_step_chars=1`。
不出证，只跑参考评估器。

| L | agent_content | agent_tool | eu_ai_act | finance_redaction | multiparty_demo | pii_redaction |
|---:|---:|---:|---:|---:|---:|---:|
| 500 | 54 ms | 9 ms | 163 ms | 101 ms | 9 ms | 349 ms |
| 1000 | 186 ms | 32 ms | 624 ms | 376 ms | 37 ms | 1,344 ms |
| 2000 | 699 ms | 110 ms | 2,421 ms | — ⚠️ 越界（>1500） | 131 ms | 4,911 ms |

## 每字符成本（ms/char）—— **看这一张**

| L | agent_content | agent_tool | eu_ai_act | finance_redaction | multiparty_demo | pii_redaction |
|---:|---:|---:|---:|---:|---:|---:|
| 500 | 0.1076 | 0.0179 | 0.3262 | 0.2013 | 0.0180 | 0.6983 |
| 1000 | 0.1858 | 0.0320 | 0.6244 | 0.3763 | 0.0367 | 1.3441 |
| 2000 | 0.3497 | 0.0552 | 1.2104 | — | 0.0653 | 2.4554 |

**读法**：L 拉长多少倍，每字符成本就跟着长多少倍 —— 下面每行都并排给出这两个倍率，直接对看即可。**若总代价是线性的，第二列那一栏应当基本不变**（每字符成本是常数）。它随 L 同步上升，就是 `Θ(L²)` 的样子。所以**不要把某个 L 上的「每字符」当常数去外推**。

- agent_content：L ×4.0，每字符成本 0.1076 → 0.3497 ms/char（×3.25）；拟合常数 0.429 → 0.350 µs/char²
- agent_tool：L ×4.0，每字符成本 0.0179 → 0.0552 ms/char（×3.08）；拟合常数 0.072 → 0.055 µs/char²
- eu_ai_act：L ×4.0，每字符成本 0.3262 → 1.2104 ms/char（×3.71）；拟合常数 1.302 → 1.210 µs/char²
- finance_redaction：L ×2.0，每字符成本 0.2013 → 0.3763 ms/char（×1.87）；拟合常数 0.804 → 0.752 µs/char²
- multiparty_demo：L ×4.0，每字符成本 0.0180 → 0.0653 ms/char（×3.63）；拟合常数 0.072 → 0.065 µs/char²
- pii_redaction：L ×4.0，每字符成本 0.6983 → 2.4554 ms/char（×3.52）；拟合常数 2.788 → 2.454 µs/char²

拟合常数 `c = 总耗时 / (L(L+1)/2)` 在各 L 上基本不变 —— 说明 `总耗时 ≈ c·L²/2` 这个模型站得住，二次性是量出来的、不是外推的。

**包间差也是真的**：同为 2000 字符，最贵的 `pii_redaction` 与最便宜的 `agent_tool` 差 **44×**（2.455 vs 0.0552 ms/char）。因为每个采样点要对**完整前缀**跑一遍**全部** pattern 的 NFA。所以「流式要多久」**没有单一答案，必须连着策略包说**。

**采样的上限逐包判，不是全表取最小**：前缀越过某个包的 `length_bound.max` 会翻转判定、多签一张证书，签发成本就混进被测路径 —— 那种 (包, L) **单点不测**，在表里标成「越界」并记进 `streaming.json` 的 `skipped`，**不是悄悄空着**。

| 越界的点 | 原因 |
|---|---|
| `finance_redaction_v1.json` @ 2000 | n > length_bound.max=1500 ⇒ 判定会在上界处翻转、多签一张证书 |

顺带一个事实：`agent_tool_v1` 与 `pii_redaction_v1` **没有 `length_bound`**，它们的代价**没有天花板** —— 而后者正是表里最贵的（见 R17a）。

## 流式路径跑不了的包（**边界，不是跳过**）

| 包 | 症状 | 原因 |
|---|---|---|
| `semantic_demo_v1.json` | `NotImplementedError: kind 'semantic_bound' not provable in-circuit yet` | canonical_violations 对 semantic_bound 抛 NotImplementedError（承诺镜像只覆盖 7 类入电路规则；该 kind 委托给 ezkl 陪伴证明） |

脚本把这一条**当断言跑**（`probe_unsupported`）：哪天它不再抛了，基准会当场失败，逼人把它挪进成本表 —— 而不是让它一直挂在「已知例外」的名下。

## 引用这份结果的文档

- `docs/modules/06-frameworks.md` §流式代价 —— 本表是那一段的数字来源
- `policydsl/adapters/langchain_adapter.py` —— `PoPCallbackHandler` docstring
- `docs/dev-plan.md` §5.7 —— R17b 的取证；P2 R9(b) 的前后对比基线

