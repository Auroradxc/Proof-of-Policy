# 06 · 框架集成

> 覆盖 `policydsl/langchain_adapter.py`、`langgraph_adapter.py`、`mcp_adapter.py`，
> 以及被它们共同驱动的 `policydsl/agent.py`（钩子定义见 [`03-certificate.md`](03-certificate.md) §6）。
> 这一板块回答：**怎么把「判定 → 出证」挂到真实的 agent 框架上，且不要求改写框架。**

---

## 1. 总体设计：一个 monitor，两种路径，三个适配器

```
                      ┌──────────────── AgentMonitor ────────────────┐
                      │  on_generate()       on_tool_call()          │
                      │  生成路径             工具路径                 │
                      └───────▲──────────────────────▲──────────────┘
                              │                       │
     ┌────────────────────────┼───────────────────────┼──────────────────────┐
     │ LangChain              │ LangGraph             │ MCP                  │
     │ PoPCallbackHandler     │ PoPCallbackHandler    │ MCPGuard             │
     │ · on_llm_end           │ · 同一回调（共享基类） │ · check()   参数侧   │
     │ · on_llm_new_token     │ · guard_node() 包装    │ · judge_result() 结果侧│
     │ · on_tool_start/end    │ · astream_events 认证  │ · call_tool() 守护    │
     └────────────────────────┴───────────────────────┴──────────────────────┘
```

三条原则：

1. **不改框架**：适配器只做「事件 → 钩子」的翻译，策略判定与出证全在 `AgentMonitor` 里。
2. **可离线单测**：所有适配器在缺少对应框架时用**鸭子类型**回退，因此不需要装框架也能跑测试。
3. **真实框架也测**：装了框架后（`bash scripts/install_frameworks.sh`），真实端到端测试会自动启用。

---

## 2. LangChain / LangGraph 回调（`langchain_adapter.py`）

**一个 handler 同时插桩两者** —— 因为 LangChain 与 LangGraph 共享同一套回调系统
（`langchain_core.callbacks`）：

```python
handler = PoPCallbackHandler(content_monitor, vkey_hash="demo", stop_on_violation=True)
chain.invoke(x, config={"callbacks": [handler]})   # LangChain
graph.invoke(state, config={"callbacks": [handler]})  # LangGraph
handler.certificates           # 每个 LLM/工具事件一张证书
```

导入时探测：有 `langchain_core` 就继承真正的 `BaseCallbackHandler`，否则用极简鸭子类型回退。

### 2.1 回调映射

| 回调 | 动作 |
|---|---|
| `on_llm_new_token(token, **kw)` | 累积流式前缀；**判定翻转**时签发链式部分证书；`stop_on_violation` 时签早停证书并停止后续出证 |
| `on_llm_end(response, **kw)` | 签发**权威**证书（优先用流式缓冲的精确 token 流，回退到 `_extract_text` 结构提取） |
| `on_tool_start(serialized, input_str, **kw)` | 记录工具名与参数（供 `on_tool_end` 使用） |
| `on_tool_end(output, **kw)` | 签发工具调用证书 |

工具名/参数的提取做了兼容：`_tool_name` 从序列化信息或 kwargs 取；`_parse_args` 接受 dict、
`ast.literal_eval` 字面量字符串、或任意对象（兜底 `{"input": ...}`）。

### 2.2 流式（增量）证书与早停

```python
self._sbuf[run_id]      # 累积的流式前缀
self._scount[run_id]    # token 计数（stream_every 控制采样频率）
self._sverdict[run_id]  # 上一次判定（用于检测「翻转」）
self._sstopped[run_id]  # 是否已早停
```

判定逻辑：**只在判定发生变化时**（首次出现或翻转）签发部分证书 —— 避免每个 token 都出一张。
早停（`stop_on_violation=True`）在**首次** `verdict is False` 时额外签发一张
`streaming.stop = {"reason": "violation", "at_index", "chain_head"}` 的证书，并置位 `_sstopped`
（后续 token 直接 return）。

流式证书靠 `streaming.chain = {index, prev}` 串成哈希链，链接值是 `cert_digest(payload)`，
首张的 `prev` 为 `"genesis"`：

```python
def verify_chain(certs) -> bool      # 序号连续 + prev 链接
```

> 健全性提示：部分证书是**前缀判定**，仅供早告警/早停；**权威结论永远是 `on_llm_end` 那张**。
> 见 [`../security-model.md`](../security-model.md)「流式早停健全性」。

### 2.3 公开 API

| 名称 | 说明 |
|---|---|
| `PoPCallbackHandler(monitor, vkey_hash="unproven", proof_sha256=None, on_cert=None, stream_check=True, stream_every=1, on_stream_cert=None, stop_on_violation=False, on_early_stop=None)` | 回调处理器 |
| `handler.certificates` / `handler.stream_certificates` | 权威证书 / 流式（含早停）证书 |
| `handler.stream_chain(run_id)` | 该 run 的流式证书链的载荷摘要列表 |
| `verify_certificates(handler, key=DEMO_KEY)` | 截至目前所有**权威**证书都能验签 |
| `verify_chain(certs)` | 流式链完整性（序号 + prev） |
| `langchain_available()` / `langgraph_available()` | 依赖探测 |

---

## 3. LangGraph 原生集成（`langgraph_adapter.py`）

两种接线方式，都驱动同一个 `AgentMonitor`：

### 3.1 回调方式（不改图）

```python
handler = attach(monitor)                      # 返回 PoPCallbackHandler
graph.invoke(state, config={"callbacks": [handler]})
```

`attach(monitor, graph=None, **kw)` 接受 `graph` 参数**仅为可读性**，并不修改它
（编译后的 LangGraph 图不可变）。

### 3.2 节点包装（显式、框架原生）

```python
generate = guard_node(monitor, my_generate_node, kind="generate", key="output")
tool     = guard_node(monitor, my_tool_node,     kind="tool")
```

`guard_node` 返回的包装函数 = 原节点结果 + `certs_key`（默认 `"certificates"`）里的证书列表。

| `kind` | 从结果里读什么 |
|---|---|
| `"generate"` | `result[key]`（默认 `"output"`）作为响应文本 |
| `"tool"` | `result[tool_name_key]`（默认 `"name"`）与 `result[tool_args_key]`（默认 `"args"`） |

其他 `kind` 抛 `ValueError`。

`LangGraphGuard(monitor, **kw)` 是把上述工厂绑到一起的便捷包装：
`guard.callbacks()` / `guard.generate_node(node)` / `guard.tool_node(node)`。

### 3.3 事件流认证

`LangGraphEventCertifier(monitor, tool_monitor=None, vkey_hash="unproven", stream_handler=None)`
通过消费 `astream_events` **为整次运行**签发证书：

| 事件 | 动作 |
|---|---|
| `on_chat_model_stream` / `on_llm_stream` | 把分片喂给（可选的）`stream_handler` → 产出**流式**证书 |
| `on_chat_model_end` / `on_llm_end` | 生成路径证书 |
| `on_tool_end` | 工具路径证书 |

用法：`agenc = certifier.run(graph, inputs)`（异步）或 `run_sync(...)`（内部 `asyncio.run`）。
`certifier.events` 记录见过的事件名，便于可观测性。

`require_langgraph()` 在需要却缺失时抛带安装提示的 `RuntimeError`。

---

## 4. MCP 守护（`mcp_adapter.py`）

MCP（Model Context Protocol）的工具调用是**最重要的一道闸门**：参数侧可以在工具**执行前**拦截。

```python
guard = MCPGuard(tools_monitor, vkey_hash=vkey,
                 block_on_violation=True,          # 参数违规 → 飞行前拦截
                 result_monitor=content_monitor,   # 工具返回文本的独立策略
                 block_on_result_violation=False)
result, args_cert = await guard.call_tool(session, "search_kb", {"query": "refund"})
```

`call_tool` 的顺序是刻意的：

```
① check(name, args)          → 参数证书（tool_arg_guard / budget_bound）
② block_on_violation?        → 违规则抛 MCPBlocked(phase="args")，工具根本没被调用
③ await session.call_tool()  → 真正执行
④ judge_result(name, result) → 结果证书（内容策略，tool-result 路径）
⑤ block_on_result_violation? → 违规则抛 MCPBlocked(phase="result")
```

要点：

- **「飞行前」是可验证的**：`tests/test_mcp.py` 的 `FakeSession` 记录 `calls`，用例断言被拦截的调用
  **没有出现在 `calls` 里** —— 即拦截确实发生在执行之前。
- **结果侧证书是独立的**：`result_monitor` 是**另一个** `AgentMonitor`（内容策略包），
  `on_generate(..., extra={"tool": {"name": ..., "phase": "result"}})`，
  保证「工具的返回文本」也被内容策略判定。
- **对任何鸭子类型的会话都适用**：只要暴露 `async call_tool(name, args)`，
  真实 `mcp.ClientSession` 或测试 fake 都行。`call_tool_sync` 提供同步封装（内部 `asyncio.run`）。

`extract_result_text(result)` 从 `CallToolResult` / content 列表 / 普通值里提取文本，
兼容 dict 与对象两种 `content` 表示。

### 公开 API

| 名称 | 说明 |
|---|---|
| `MCPGuard(monitor, vkey_hash, block_on_violation=False, on_cert=None, result_monitor=None, block_on_result_violation=False, on_result_cert=None)` | 守护 |
| `guard.check(name, args)` | 只判定参数并出证（不调用工具） |
| `guard.judge_result(name, result)` | 只判定返回文本（未配 `result_monitor` 时返回 `None`） |
| `guard.call_tool(session, name, args)` / `call_tool_sync(...)` | 完整流程，返回 `(result, args_cert)` |
| `guard.certificates` / `guard.result_certificates` | 参数证书 / 结果证书 |
| `extract_result_text(result)` | 结果文本提取 |
| `MCPBlocked(tool, violations, phase)` | 拦截异常（`phase ∈ {"args", "result"}`） |

---

## 5. 三者的证书形态对照

| 适配器 | 路径 | 证书 `mode` | `kind`（demo_e2e 里） |
|---|---|---|---|
| `PoPCallbackHandler.on_llm_end` | 生成 | `public`（沿用 monitor 的 mode） | `llm` |
| `PoPCallbackHandler.on_llm_new_token` | 生成（流式） | `public` + `streaming` | `stream` |
| `PoPCallbackHandler.on_tool_end` | 工具 | `tool-call` | `tool-args` |
| `MCPGuard.check` | 工具 | `tool-call` | `tool-args` |
| `MCPGuard.judge_result` | 生成（结果侧） | `public` + `extra.tool` | `tool-result` |
| `LangGraphEventCertifier` | 两者 | 同上 | — |

`scripts/demo_e2e.py` 一次会话产出 **12 张证书**：流式（含早停）、LLM、MCP 参数 + 结果、zk 各若干。

---

## 6. 不变量与边界

1. **适配器不判定策略**：所有判定都在 `AgentMonitor`（→ `evaluate.check` / `commit`）。
   适配器只做事件翻译与状态管理。
2. **流式状态按 `run_id` 隔离**：`_sbuf`/`_scount`/`_sverdict`/`_sstopped` 都是 per-run 字典；
   `on_llm_end` 会清理该 run 的全部流式状态（避免长会话内存泄漏）。
3. **早停只影响「是否继续出证」**，不改变最终判定的健全性。
4. **`vkey_hash` 默认 `"unproven"`**：框架路径签发的证书默认**不绑定证明**；
   附证明的证书由 `scripts/issue_cert.py` / `demo_e2e.py` 的 zk 路径产出。
5. **工具路径的 `zk: True` 是「规则可证」**，不是「这张证书附了证明」（见 `03` §6）。
6. **缺失框架时的行为**：`PoPCallbackHandler` 回退到鸭子类型基类（可离线单测）；
   `require_langgraph()` 抛明确错误；`MCPGuard` 本身不 import mcp（对 fake 也适用）。
7. **不要翻译工具函数的 docstring**：`test_frameworks.py` 与 `mcp_echo_server.py` 里
   `@tool` 函数的 docstring 会被框架当作**工具描述**发给模型，属于功能性字符串而非注释。

---

## 7. 测试对应

| 测试 | 覆盖 | 真实框架缺失时 |
|---|---|---|
| `tests/test_agent.py` | `AgentMonitor` 两条路径 + `mock_agent` | 无依赖 |
| `tests/test_frameworks.py` | `PoPCallbackHandler`（含流式链/篡改/早停）、`guard_node`、`attach`、`LangGraphEventCertifier` | 离线用 duck-typed fake；已装框架时跑真实 LangChain/LangGraph |
| `tests/test_mcp.py` | `MCPGuard` 参数侧拦截、结果侧判定、`extract_result_text` | 离线用 `FakeSession`；已装 mcp 时跑真实 stdio（`tests/mcp_echo_server.py`） |
| `tests/test_demo_e2e.py` | 端到端会话（依赖齐全时才跑全部） | — |
| `scripts/demo_e2e.py` | 真实 LangChain 流式 + 真实 MCP stdio 的一键演示 | — |

安装框架：`bash scripts/install_frameworks.sh`（独立 venv + 镜像源；
装好后真实框架测试自动启用）。网络受限时用 `scripts/retry_install_frameworks.sh`。

---

## 8. 扩展指引

- **接一个新框架**（如 AutoGen / OpenAI Agents SDK）：写一个适配器，把该框架的
  「模型完成」事件接到 `monitor.on_generate`、「工具调用」事件接到 `monitor.on_tool_call`。
  参照 `langchain_adapter.py` 的 `_extract_text` / `_parse_args` 做**宽松提取**，
  并把缺失依赖做成「导入回退 + 离线 fake」，这样单测不需要装框架。
- **给工具路径加结果侧认证**：需要的不是新代码，而是给 `MCPGuard` / 新适配器传
  `result_monitor=<内容策略 monitor>`。
- **加流式早停的行为差异**：`stop_on_violation` 目前只是「停止出证 + 回调 `on_early_stop`」；
  如果框架支持真正的中断（如 LangChain 的 `raise_error` / 自定义异常），
  可以在 `on_early_stop` 回调里抛出 —— 但要注意这会改变控制流，需补测试。

---

**相关**：证书与信封结构 → [`03-certificate.md`](03-certificate.md)；
端到端 demo 怎么跑 → [`07-cli-scripts.md`](07-cli-scripts.md)。
