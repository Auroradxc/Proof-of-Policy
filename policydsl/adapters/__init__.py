"""接到 agent 框架上：框架无关的 `agent`，各框架适配器，以及模型构造。

`agent.py` 是**唯一的**框架无关核心（生成路径 + 工具路径两个钩子）；
`langchain_adapter` / `langgraph_adapter` / `mcp_adapter` 都只是把框架的回调
转成它认识的形状，不含判定逻辑。

**本子包不 re-export 任何符号**，接新框架见 `docs/modules/06-frameworks.md` §8。
"""
