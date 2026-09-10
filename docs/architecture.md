# 架构文档

> 本文只讲**分层与契约**（一页纸）。按板块深入代码请读 [`modules/`](modules/README.md)：
> 01 策略 DSL 与编译 · 02 隐私与承诺 · 03 合规证书 · 04 锚定与审计 ·
> 05 ZK 电路层 · 06 框架集成 · 07 CLI 与脚本 · 08 测试与评测。

## 双层架构

- **Python 层（链下）**：策略作者写 JSON 策略包 → `policydsl.compile()` 产出 **ConstraintSpec**（唯一的链上/链下契约）；`policydsl.evaluate()` 提供**参考判定**（golden），供单测与交叉验证使用。
- **Rust + SP1 层（证明）**：`circuits/program` 在 zkVM 内消费 ProofRequest（`response + ConstraintSpec`），重放约束判定并 `commit(passed, evidence)`；`circuits/script` 负责证明生成与验证（宿主机，可选链上）。

## ConstraintSpec 契约（v1）

```jsonc
{
  "spec_version": "v1",
  "policy_id": "eu-ai-act-v1",
  "policy_version": "0.1.0",
  "semantic": "and",
  "constraints": [
    {"kind": "keyword_block", "name": "...", "keywords": ["exploit", "weaponize", ...]},
    {"kind": "length_bound",  "name": "...", "min": 1, "max": 2000},
    {"kind": "pattern_block", "name": "...", "patterns": ["..."], "nfa": {"status": "compiled_in_circuit_wo3"}},
    ...
  ],
  "sha256": "<64 hex>"
}
```

- `sha256` = canonical hash of `{spec_version, policy_id, policy_version, semantic, constraints}`（排序键、紧凑分隔符）。用于策略溯源绑定（合规证书中的 `circuit_hash`/`policy_hash`）。
- 约束语义：`semantic="and"`，全部约束通过即合规。违规定位到具体约束（`violations[].kind`）。

## 数据流（完整）

```
策略作者                链下作者/编译                证明方(SP1)              验证方
policy_packs/a.json ──► policydsl.compile ──► ConstraintSpec ──► ProofRequest
                                                                    │
response.txt ──────────────────────────────────────────────────────┘
                                                                    │
                                      circuits/program 内重放约束判定 commit(passed)
                                                                    │
                                     host/链上 verify(passed, proof) ◄── 合规证书
```

## 安全模型

- **合规健全性**：不满足 π 的响应无法产出被接受的证明（证明者不能伪造通过）——**六类规则均已入电路**。
- **内容隐私**（私有模式）：验证者看不到响应全文，只看到承诺与违规定位（+ 可证明的脱敏）。
- **不可伪造**：无原响应的攻击者不能伪造「通过」证明；证据开示需 `SHA256(片段)=承诺`。
- **记录完整性**：哈希链账本 + 链上锚定（`cert_digest` 登记进 `contracts/Anchor.sol`）。

完整定义、归约论证与对应实验见 [`security-model.md`](security-model.md)；
实现层面的落点见 [`modules/03-certificate.md`](modules/03-certificate.md) 与
[`modules/04-anchoring-audit.md`](modules/04-anchoring-audit.md)。

## 与既有项目的关系

独立方向；SP1 仅作为通用证明基础设施使用，与既有私有面部认证项目无代码/数据依赖。
