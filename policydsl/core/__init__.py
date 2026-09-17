"""策略、跨层契约与 golden 判定。

这一层与 `circuits/types` 的 Rust 实现**逐字段对齐**：同一个 `ConstraintSpec` +
同一份输入，两侧必须得出同一个判定（由 `scripts/cross_validate.py` 交叉验证）。
改这里的规则语义，必须同步改 Rust 侧，否则 `cross_validate` 会红。

**本子包不 re-export 任何符号** —— 一个模块只有一个名字。要用什么就写全路径，
例如 `from policydsl.core.model import Policy`。
"""
