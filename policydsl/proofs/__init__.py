"""证明编排：组合证明、会话聚合、多证明者、语义规则委托。

与 `core` 的区别：`core` 决定「合不合规」，这里决定「**怎么把判定包成一份可验证的产物**」，
以及多个证明之间如何合成一个结论（引理 L6 / L7 / L8）。

**本子包不 re-export 任何符号**，用法示例见 `docs/security-model.md` §3 与
`docs/design-semantic-rules.md`。
"""
