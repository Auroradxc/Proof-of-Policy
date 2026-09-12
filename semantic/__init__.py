"""语义规则（P2-9，D3 选定的「完整 ezkl 集成」）。

本包是**模型侧**：确定性特征图（:mod:`semantic.features`）、demo 级数据
（:mod:`semantic.dataset`）、训练与导出（:mod:`semantic.train`）。

它与仓库其余部分的关系：

```
T ──▶ encode(T)  ──▶ [ONNX 图：固定投影 n-gram 特征 + 训练好的 head] ──▶ P(有害) ∈ [0,1]
                          ▲ 无学习参数（信任边界 ②）      ▲ 权重入库、sha256 承诺（①）
     └──────────────► ezkl 编译 → vk（唯一确定整张图）→ 证明（公开实例 = 输入 + 分数）
```

**本包不 import ezkl**（也不 import torch 于导入期）—— 「需要 torch/ezkl 才做得了的事」
都收在训练与出证两个入口里，这样 ``import semantic`` 在纯标准库环境里不会炸。

证明与验证在 :mod:`policydsl.semantic`（Python 侧契约）与
``scripts/ezkl_prove.py``（出证入口）。
"""
