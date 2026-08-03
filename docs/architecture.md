# 架构文档

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

## 安全模型（W7 填充）

- **合规健全性**：不满足 π 的响应无法产出被接受的证明（证明者不能伪造通过）。
- **内容隐私**（W5 私有模式）：验证者看不到响应全文，只看到承诺与违规定位。
- **不可伪造**：无原响应的攻击者不能伪造「通过」证明。
- 形式化定义将在 W7 写入 `docs/security-model.md`（扩展 VDR 的 Leak/Unforgeability 实验到多规则策略）。

## 与既有项目的关系

独立方向；SP1 仅作为通用证明基础设施使用，与既有私有面部认证项目无代码/数据依赖。
