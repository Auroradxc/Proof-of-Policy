# 06 · 框架集成

> 覆盖 `policydsl/langchain_adapter.py`、`langgraph_adapter.py`、`mcp_adapter.py`、
> `llm.py`，以及被它们共同驱动的 `policydsl/agent.py`
> （钩子定义见 [`03-certificate.md`](03-certificate.md) §6）。
> 这一板块回答：**怎么把「判定 → 出证」挂到真实的 agent 框架上，且不要求改写框架。**
>
> 换个模型**只动这一层**：证书绑的是**一条具体的响应 `T`**，
> `ZK` / 证书 / 锚定 / 验证链一行都不用改。`llm.py` 是这句话的落地 ——
> 它只做「规格 → 一个 LangChain `BaseChatModel`」，
> 适配器与 `AgentMonitor` 都不知道对面是桩还是真模型。

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
handler = PoPCallbackHandler(content_monitor, vkey_hash=cert.VKEY_HASH_UNPROVEN,
                             stop_on_violation=True, hard_stop=True)
chain.invoke(x, config={"callbacks": [handler]})   # LangChain
graph.invoke(state, config={"callbacks": [handler]})  # LangGraph
handler.certificates           # 每个 LLM/工具事件一张证书
```

导入时探测：有 `langchain_core` 就继承真正的 `BaseCallbackHandler`，否则用极简鸭子类型回退。

### 2.1 回调映射

| 回调 | 动作 |
|---|---|
| `on_llm_new_token(token, **kw)` | 累积流式前缀；**判定翻转**时签发链式部分证书；`stop_on_violation` 时签早停证书并停止后续出证；`hard_stop` 时**抛出 `EarlyStop` 真掐断流**（见 §2.2） |
| `on_llm_end(response, **kw)` | 签发**权威**证书（优先用流式缓冲的精确 token 流，回退到 `_extract_text` 结构提取） |
| `on_tool_start(serialized, input_str, **kw)` | 记录工具名与参数（供 `on_tool_end` 使用） |
| `on_tool_end(output, **kw)` | 签发工具调用证书 |
| `on_llm_error(error, **kw)` | **失败也留痕**：照常签一张证书，并在载荷**顶层**附 `error` 块（见 §2.1.1）；`EarlyStop` 例外 —— 那是我们自己掐断的，直接返回，不重复出证 |
| `on_tool_error(error, **kw)` | 工具失败**也是这次调用的结果**：网关照常签回执，工具路径照常出证 + `error` 块 |

工具名/参数的提取做了兼容：`_tool_name` 从序列化信息或 kwargs 取；`_parse_args` 接受 dict、
`ast.literal_eval` 字面量字符串、或任意对象（兜底 `{"input": ...}`）。

#### 2.1.1 错误路径：为什么非签不可

真模型最常见的三件事是**超时、限流、内容拦截** —— 它们不是异常情况，是常态。而这套回调
此前只认「正常结束」：模型报错时**一张证书都不签**，于是产物上「会话失败了」与「会话干净」
长得一模一样。这正是 P0-4 要消灭的那类歧义，只不过这次藏在**「什么都没发生」**里。

`error_block(phase, error, tokens, text_len)`（`langchain_adapter.py`）构造的顶层块：

```json
"error": {"phase": "llm|tool", "type": "TimeoutError",
          "message_sha256": "…", "scope": "partial-prefix",
          "tokens": 12, "text_len": 43}
```

三个刻意的取舍：

- **只放类型名与消息的 SHA-256，不放消息原文** —— 异常消息里常有 prompt 片段、URL，偶尔
  还有密钥（HTTP 客户端报错尤其容易带上请求头）。要核对具体是哪次失败，让持有原文的一方
  自己算哈希来比。与证书其余部分「只放承诺、不放明文」同口径。
- **放载荷顶层，不进 `outcome`** —— `outcome` 是**证明公开值的镜像**，验证方会逐字段比对，
  而电路里没有 `error` 这个东西。放进去会让每一张带真实证明的证书都对不上（同 `trace_seal`
  与 `challenge` 的理由，见 `cert.build_payload`）。
- **`scope: "partial-prefix"`** —— 判的是**截断处的前缀**，不是「本次生成的全文」。一个 token
  都没收到时前缀是空串、判定自然「合规」，但那张证书**不是**在说「本次生成合规」；`scope`
  与 `text_len == 0` 一起把它读成「这次生成没有产出任何可判定的内容」。模型本会继续吐出的
  部分**不在**这张证书的判定范围内 —— 这个字段就是那句免责声明的可核对形式。

`handler.errors` / `certifier.errors` 另存一份异常清单：**只看 `certificates` 是分不出
「正常结束」与「带错结束」的**（两者都恰好一张证书），那正是这个分支要修的问题。

> 事件式插桩（`LangGraphEventCertifier`）不会自动继承这些分支 —— 它按事件名手写路由，
> 所以 `on_chat_model_error` / `on_llm_error` / `on_tool_error` 要**各自**认一遍。
> 用例见 `tests/test_frameworks.py::TestErrorCallbacksOffline` 与
> `::TestLangGraphErrorEventsOffline`，每条正向都配了非恒真对照。

### 2.2 流式（增量）证书与早停

```python
self._sbuf[run_id]      # 累积的流式前缀
self._scount[run_id]    # token 计数（stream_every 控制采样频率）
self._sverdict[run_id]  # 上一次判定（用于检测「翻转」）
self._sstopped[run_id]  # 是否已早停
```

判定逻辑：**只在判定发生变化时**（首次出现或翻转）签发部分证书 —— 避免每个 token 都出一张。
早停（`stop_on_violation=True`）在**首次** `verdict is False` 时额外签发一张
`streaming.stop = {"reason": "violation", "at_index", "chain_head", "scope"}` 的证书，并置位
`_sstopped`（后续 token 直接 return）。

> **`scope` 为什么是 `"partial-prefix"`**：这张证书写 `partial=false`，但那说的是
> 「这是本 run 的**结论**」，**不是**「判的是完整生成」—— 早停本来就停在中途。
> 它断言的是「**截至此点的前缀**违规」，读成「本次生成违规」是**过度声明**：模型
> 本会继续吐什么，谁都还没看见。字段口径与 `error_block` 的 `scope` 一致。

#### 软停 vs 真停（`hard_stop`）

上面那套只做到**软停**：不再出证，但**流照样把违规内容吐完**。对真模型这不是观感问题 ——
那些 token 照常计费，而早停本该是最直接的省钱手段。`hard_stop=True` 才是**真停**：

```python
handler = PoPCallbackHandler(content_monitor, stop_on_violation=True, hard_stop=True)
try:
    for chunk in model.stream("hi", config={"callbacks": [handler]}):
        ...
except EarlyStop as e:
    e.certificate          # 那张 streaming.stop 证书（先出证，后掐断）
```

要跨过两道**默认行为**，两道都不会报错、只会静默失效：

1. **回调抛异常默认被吞掉**。`BaseCallbackHandler.raise_error` 缺省 `False`，LangChain
   只记一条 `logger.warning("Error in X.y callback")` 就放过去了 —— 异常**根本出不了**
   回调系统。所以 `hard_stop=True` 时 handler 会把 `self.raise_error` 置 `True`。
2. **掐断会被路由成一次「失败」**。流被 `EarlyStop` 掐断后，LangChain 把它送进
   `on_llm_error`。那里必须**跳过** `EarlyStop`：它是我们自己干的，不是模型故障，而那份
   停止证书已经在 `error.certificate` 上了。不跳过的话，一次早停会产出**两张**证书，
   其中一张还把自伤记成模型错误 —— 既是误导，也让计数对不上。

顺序是**先出证，后掐断**：异常一旦抛出，这次调用的控制流就交还给调用方；反过来写的话，
那张 stop 证书就得建在异常处理里，而那时流式状态已经清了。

`hard_stop` **默认关**：它改变调用方的控制流，这类行为不能靠升级悄悄改掉既有集成。
打开后有一个**如实的后果**：被掐断的那次生成**没有** `on_llm_end`，因此**没有**权威的
`llm` 证书 —— 它的结论就是那张停止证书（`demo_e2e.py` 主路径即如此，见 [`07`](07-cli-scripts.md) §2.10）。

截断点比「软停」更靠前：LangChain **先跑回调再吐 chunk**，所以判出违规的那个分片本身
就被截住了。实测 `"Leak sk-abcdefghijklmnopqrstuvwxyz now"`（38 字符）在 `"Leak "`
（5 字符）处断掉，密钥**没有**到达调用方。

流式证书靠 `streaming.chain = {index, prev}` 串成哈希链，链接值是 `cert_digest(payload)`，
首张的 `prev` 为 `"genesis"`：

```python
def verify_chain(certs) -> bool      # 序号连续 + prev 链接
```

> 健全性提示：部分证书是**前缀判定**，仅供早告警/早停；**权威结论永远是 `on_llm_end` 那张**。
> 见 [`../security-model.md`](../security-model.md)「流式早停健全性」。
> `hard_stop=True` 时这次生成连权威证书都没有 —— 它被掐断了，这正是**如实**的。

### 2.3 公开 API

| 名称 | 说明 |
|---|---|
| `PoPCallbackHandler(monitor, vkey_hash="unproven", proof_sha256=None, on_cert=None, stream_check=True, stream_every=1, on_stream_cert=None, stop_on_violation=False, on_early_stop=None, proof_mode=None, gateway=None, hard_stop=False)` | 回调处理器 |
| `EarlyStop(RuntimeError)` | `hard_stop` 掐断流用的异常；`.certificate` = 那张停止证书 |
| `error_block(phase, error, tokens=0, text_len=0)` | 构造载荷顶层的 `error` 块（`scope` 固定 `"partial-prefix"`） |
| `handler.errors` | 本 handler 见到的异常清单（含 `EarlyStop`）—— 只看 `certificates` 分不出「正常结束」与「带错结束」 |
| `handler.certificates` / `handler.stream_certificates` | 权威证书 / 流式（含早停）证书 |
| `handler.stream_chain(run_id)` | 该 run 的流式证书链的载荷摘要列表 |
| `verify_certificates(handler, keyring=None)` | 截至目前所有**权威**证书都能验签；`keyring` 缺省用 handler 自己的签名器（自验签），第三方验证传**公钥** |
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

`LangGraphGuard(monitor, gateway=None, **kw)` 是把上述工厂绑到一起的便捷包装：
`guard.callbacks()` / `guard.generate_node(node)` / `guard.tool_node(node)`。
它持有**一把** `ToolGateway`（`guard.gateway`）并同时喂给三者 —— 不这样，
`callbacks()` 与 `tool_node()` 签出的证书会绑到两条不同的链上（#99）。
要接进外层已有的会话（例如 `MCPGuard` 那把），传 `gateway=`。

### 3.3 事件流认证

`LangGraphEventCertifier(monitor, tool_monitor=None, vkey_hash="unproven", stream_handler=None, proof_mode=None)`
通过消费 `astream_events` **为整次运行**签发证书：

| 事件 | 动作 |
|---|---|
| `on_chat_model_stream` / `on_llm_stream` | 把分片喂给（可选的）`stream_handler` → 产出**流式**证书 |
| `on_chat_model_end` / `on_llm_end` | 生成路径证书 |
| `on_tool_end` | 工具路径证书 |
| `on_chat_model_error` / `on_llm_error` | 生成路径**失败**证书（顶层 `error` 块，见 §2.1.1） |
| `on_tool_error` | 工具路径失败证书（照常签回执 + `error` 块） |

用法：`agenc = certifier.run(graph, inputs)`（异步）或 `run_sync(...)`（内部 `asyncio.run`）。
`certifier.events` 记录见过的事件名，便于可观测性。

`require_langgraph()` 在需要却缺失时抛带安装提示的 `RuntimeError`。

---

## 4. MCP 守护（`mcp_adapter.py`）

MCP（Model Context Protocol）的工具调用是**最重要的一道闸门**：参数侧可以在工具**执行前**拦截。

```python
gateway = trace.ToolGateway()                     # 一次会话**唯一**的那把（#99）
guard = MCPGuard(tools_monitor, vkey_hash=vkey,
                 block_on_violation=True,          # 参数违规 → 飞行前拦截
                 result_monitor=content_monitor,   # 工具返回文本的独立策略
                 block_on_result_violation=False,
                 gateway=gateway)
await guard.discover_tools(session)               # 工具清单**问服务器要**，不写死
result, args_cert = await guard.call_tool(session, "search_kb", {"query": "refund"})

# 生成路径**必须**接同一把 —— 否则两条链各指一条 trace_root，会话被劈成两条
handler = PoPCallbackHandler(content_monitor, gateway=gateway)
```

`call_tool` 的顺序是刻意的（**P1-5** 起工具**执行后**多一步「网关签发回执」）：

```
⓪ tool_names 检查            → 服务器没声明这个工具？存证为空、直接抛 MCPUnknownTool
① _screen(name, args)        → 飞行前筛查（**预览回执**，未签名、未入链）
② block_on_violation?        → 违规则存证 + 抛 MCPBlocked(phase="args")，工具根本没被调用
③ await session.call_tool()  → 真正执行
④ gateway.issue(...)         → 网关签发真回执（含结果摘要）并接到链尾
⑤ on_tool_call(receipt)      → 参数证书（tool_arg_guard / budget_bound）—— 判的是**回执**
⑥ judge_result(name, result) → 结果证书（内容策略，tool-result 路径）
⑦ block_on_result_violation? → 违规则抛 MCPBlocked(phase="result")
```

第 ⓪ 步在策略筛查**之前**：一个不存在的工具，判它参数合不合规没有意义 —— 该报的是
「这次调用根本不存在」（`phase="unknown-tool"`），不是「这次调用不合规」。

要点：

- **轨迹是网关签的，不是 agent 填的**：证书里判定用的输入是 `ToolReceipt`（网关在**执行后**签发、
  带 `seq`/`prev`/`sig` 的回执）。三个适配器（LangChain / LangGraph / MCP）共用同一个
  `ToolGateway`；`guard.receipts` 即当前链，交给生成路径一并出证（`trace_root` 进公开值）。
- **判定范围是整条链**：工具调用证书的 `passed` 意为「会话进行到这次调用为止一直合规」——
  链上任何一条违规都会让后续证书继续判失败，`passed=true` 不会出现在脏轨迹上。
- **「飞行前」是可验证的**：`tests/test_mcp.py` 的 `FakeSession` 记录 `calls`，用例断言被拦截的调用
  **没有出现在 `calls` 里** —— 即拦截确实发生在执行之前。被拦下的调用**不进链**（链只记录真的发生过
  的事），但仍会签出一张筛查证书存证 —— 「曾经试图调用」不该查无实据。
- **预览回执的诚实边界**：`_screen` 时工具还没执行，`result_digest` 无从谈起，所以那张证书（以及
  单独调用 `guard.check()` 得到的证书）里 `trace_root` 是**临时值**；随证明走的是第 ⑤ 步那张。
  同理它**天然没有 `trace_seal`**（P1-5b）：网关只对**真实发生过**的链签会话末端承诺 ——
  给预览配 seal 等于让网关为一次尚未发生的调用背书。验证方给了 `--gateway-key` 时，
  `verify_cert.py` 会对筛查证书报 `trace_seal` FAIL，这是**正确**的结论（它是预检告知，不是证据）。
- **结果侧证书是独立的**：`result_monitor` 是**另一个** `AgentMonitor`（内容策略包），
  `on_generate(..., extra={"tool": {"name": ..., "phase": "result"}})`，
  保证「工具的返回文本」也被内容策略判定。
- **工具清单问服务器要，不写死**（dev-plan §5.1.2 第 5 条）：`await guard.discover_tools(session)`
  走 MCP 的 `tools/list`，把名字排序后存进 `guard.tool_names`。写死的工具名在服务器改名之后
  **不会报错**，只会静默地跑成另一次调用 —— 那正是这个项目最反对的失败模式。
  注意清单**不是判定输入**（判定用的是策略包，与工具叫什么无关），它是「这次调用打不打得中」的前提。
  没问过服务器（`tool_names is None`）就**不做**存在性检查：把「还没问」当成「一个都没有」
  会把所有调用都拦掉，那是把缺省值当成了事实。
- **未声明的工具拦在执行之前，且不出证**：`MCPUnknownTool`（`phase="unknown-tool"`，继承
  `MCPBlocked` 以免改变调用方的 `except` 语义）在 `_screen` 之前就抛出，工具没被调用、
  `certificates` 里也不留东西 —— 拦的是一次**不存在**的调用，为它签一张「调用不合规」的证书
  是答非所问。
- **对任何鸭子类型的会话都适用**：只要暴露 `async call_tool(name, args)`
  （发现清单则要 `async list_tools()`，返回带 `.name` 的对象列表 —— 同真实 SDK 形状），
  真实 `mcp.ClientSession` 或测试 fake 都行。`call_tool_sync` 提供同步封装（内部 `asyncio.run`）。

`extract_result_text(result)` 从 `CallToolResult` / content 列表 / 普通值里提取文本，
兼容 dict 与对象两种 `content` 表示。

### 公开 API

| 名称 | 说明 |
|---|---|
| `MCPGuard(monitor, vkey_hash, block_on_violation=False, on_cert=None, result_monitor=None, block_on_result_violation=False, on_result_cert=None, proof_mode=None, gateway=None)` | 守护（`gateway` 缺省用进程内临时 Ed25519 钥的工具网关） |
| `guard.receipts` / `guard.gateway.seal()` | 当前回执链 / 会话末端承诺（P1-5b）。交给生成路径出证：`trace_root` 进 `outcome`、`seal` 进载荷顶层 `trace_seal` |
| `guard.discover_tools(session)` | 取服务器声明的工具名（`tools/list`），排序后存入 `guard.tool_names`；此后未声明的工具在执行前被拦 |
| `guard.tool_names` | 已发现的工具名；`None` = 还没问过 ⇒ 不做存在性检查 |
| `guard.check(name, args)` | 只判定参数并出证（不调用工具） |
| `guard.judge_result(name, result)` | 只判定返回文本（未配 `result_monitor` 时返回 `None`） |
| `guard.call_tool(session, name, args)` / `call_tool_sync(...)` | 完整流程，返回 `(result, args_cert)` |
| `guard.certificates` / `guard.result_certificates` | 参数证书 / 结果证书 |
| `extract_result_text(result)` | 结果文本提取 |
| `MCPBlocked(tool, violations, phase)` | 拦截异常（`phase ∈ {"args", "result"}`） |
| `MCPUnknownTool(tool, known)` | 调用了服务器**没声明**的工具（`phase="unknown-tool"`，`known` 为已知名单） |

---

## 4b. 真模型（`llm.py`）与 `demo_e2e.py --model`

**这一层唯一做的事**是把一个规格字符串变成一个 LangChain `BaseChatModel`：

```python
model = llm.build_chat_model("openai:gpt-4o-mini")   # 裸名按 openai
for chunk in model.stream(prompt, config={"callbacks": [handler]}):
    ...                                              # 回调层完全不知情
```

**回调层与 `AgentMonitor` 一行都不用改** —— `BaseChatModel.stream()` 会逐 chunk
派发 `on_llm_new_token`，与 `GenericFakeChatModel` 走的是同一条路。这是「换模型只动
适配器层」这句话的实测依据，而不是推断。

三个刻意的设计：

- **缺省不是真模型**：不传 `--model` 就走离线桩，因为 CI 与 `demo_all.sh` 不该依赖
  网络与 key。桩的那条路一行没动。
- **规格错就报错，绝不静默退回桩**：网络抖动退回桩还情有可原，**规格写错**退回桩
  则会让一份「真模型演示」的产物其实来自写死的字符串 —— 而且没人看得出来。
  未知 provider 也直接拒（猜一个 provider 比拒绝更糟，会把请求发到别处）。
- **不认 `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_BASE_URL`**：那是 Claude Code 自己的
  凭据。真模型调用该用使用者显式配的 key。

终端那行 `llm model : …` **永远**打印 —— 读产物的人不该去猜那段生成是不是真的。

### 离线怎么验「真客户端 + 真早停」

`tests/openai_sse_stub.py` 用标准库实现了 OpenAI 的**协议**（`/v1/chat/completions`
+ `text/event-stream`），于是**真的** `ChatOpenAI` 客户端能对着 `127.0.0.1:<port>/v1`
说话。验的是客户端与回调层的代码，不是某家 provider 的脾气 —— 所以这一段
**不需要网络与真 key，默认就跑**。

证据由**服务器侧**给出：桩数自己**真的写出去了**几片。客户端因 `EarlyStop` 提前
断开后，再写就会 `BrokenPipeError`，所以「写出去的片数 < 计划写的片数」证明切断
发生在**传输层**，而不是「我们这边不再往列表里 append 了」—— 这两件事的差别正是
早停在 Python 循环里"截断"与真的断开连接的区别。对照组是关掉 `hard_stop` 后每一片
都被写出去。

> 真 provider 那一条（`POP_TEST_LLM=1`）**只断言结构**（干净生成产出可验签的证书），
> **不**断言模型一定会违规 —— 那是赌 provider 的服从性。

---

## 5. 三者的证书形态对照

| 适配器 | 路径 | 证书 `mode` | `kind`（demo_e2e 里） | `trace_seal`（P1-5b） |
|---|---|---|---|---|
| `PoPCallbackHandler.on_llm_end` | 生成 | `public`（沿用 monitor 的 mode） | `llm` | 有（绑该时刻的链 + 网关 seal） |
| `PoPCallbackHandler.on_llm_new_token` | 生成（流式） | `public` + `streaming` | `stream` | 有（**签发那一刻**的快照；后续调用会让它作废 —— 这正是 `partial` 的含义） |
| `PoPCallbackHandler.on_tool_end` | 工具 | `tool-call` | `tool-args` | 有 |
| `MCPGuard.check` | 工具 | `tool-call` | `tool-args` | **无**（预检告知，见上） |
| `MCPGuard.judge_result` | 生成（结果侧） | `public` + `extra.tool` | `tool-result` | 有 |
| `PoPCallbackHandler.on_llm_error` | 生成（**失败**） | `public` + `error` | — | 有（绑报错那一刻的链） |
| `PoPCallbackHandler.on_tool_error` | 工具（**失败**） | `tool-call` + `error` | — | 有 |
| `LangGraphEventCertifier` | 两者 | 同上 | — | 有 |

`scripts/demo_e2e.py` 一次会话产出 **13 张证书**：流式（含早停）、LLM、MCP 参数 + 结果、zk 各若干。

---

## 6. 不变量与边界

1. **适配器不判定策略**：所有判定都在 `AgentMonitor`（→ `evaluate.check` / `commit`）。
   适配器只做事件翻译与状态管理。
2. **流式状态按 `run_id` 隔离**：`_sbuf`/`_scount`/`_sverdict`/`_sstopped` 都是 per-run 字典；
   `on_llm_end` 会清理该 run 的全部流式状态（避免长会话内存泄漏）。
3. **早停只影响「是否继续出证」**，不改变最终判定的健全性。软停（默认）不触碰控制流；
   `hard_stop=True` 会抛出 `EarlyStop` 改变控制流，且被掐断的那次生成**没有**权威证书
   （它的结论是那张停止证书）。两条路都不改变**已签发**证书的含义。
4. **生成路径也绑轨迹（P1-5b）**：`on_llm_end` / `on_llm_new_token` / `guard_node(generate)` /
   `LangGraphEventCertifier` 出的**内容**证书同样带 `receipts=gateway.receipts` 与
   `seal=gateway.seal()` —— 一张写着 `trace_root` 却没有 seal 的证书，验证方无从排除
   「链尾（乃至整条链）被删」。代价是内容证书的 `passed` 也**涵盖整条链**：脏轨迹上不会再
   出现 `passed=true` 的内容证书（与工具路径同一口径）。
4b. **一次会话只有一条轨迹（#99）**：内容链与工具链共用**同一把** `ToolGateway`，靠显式
   注入（`gateway=`）而不是各自缺省构造 —— 缺省构造会让每处各拿一把，`trace_root`
   各指一条链、`seal` 各封各的，会话被劈成两条。`LangGraphGuard` 持有一把并同时喂给
   `callbacks()` 与 `*_node()`（它此前每次调用都新建一把）。
   `zk_path` 的 zk 证书**不在此列**：它证的是「`T` 满足 `π`」，**不主张**工具轨迹，
   所以没有 `trace_seal` 是**如实**而非漏签（见 `dev-plan.md` §5.1.2 第 1 条）。
5. **`vkey_hash` 默认 `"unproven"`**：框架路径签发的证书默认**不绑定证明**；
   附证明的证书由 `scripts/issue_cert.py` / `demo_e2e.py` 的 zk 路径产出。
   `vkey_hash` 与 `proof_mode`（P0-4 的**证据档位诚实标注**）必须**成对**给出：
   只说「绑了哪个程序」而不说「这档证据隐藏了什么」，第三方就无从判断
   「响应内容被隐藏」是否成立。适配器把 `proof_mode` 作为构造参数（`guard_node`
   则作为关键字参数）一路带给 `build_payload`，缺省 `None` ⇒ 载荷按「未附工件」
   记 `unproven`。全部适配器的 `proof_mode` 语义见 [`03`](03-certificate.md) §2。
6. **工具路径的 `zk: True` 是「规则可证」**，不是「这张证书附了证明」（见 `03` §6）。
7. **缺失框架时的行为**：`PoPCallbackHandler` 回退到鸭子类型基类（可离线单测）；
   `require_langgraph()` 抛明确错误；`MCPGuard` 本身不 import mcp（对 fake 也适用）。
8. **不要翻译工具函数的 docstring**：`test_frameworks.py` 与 `mcp_echo_server.py` 里
   `@tool` 函数的 docstring 会被框架当作**工具描述**发给模型，属于功能性字符串而非注释。

---

## 7. 测试对应

| 测试 | 覆盖 | 真实框架缺失时 |
|---|---|---|
| `tests/test_agent.py` | `AgentMonitor` 两条路径 + `mock_agent` | 无依赖 |
| `tests/test_frameworks.py` | `PoPCallbackHandler`（含流式链/篡改/早停/`hard_stop`）、`guard_node`、`attach`、`LangGraphEventCertifier` | 离线用 duck-typed fake；已装框架时跑真实 LangChain/LangGraph（`TestRealHardStop` 证明流**确实**被掐断） |
| `tests/test_mcp.py` | `MCPGuard` 参数侧拦截、结果侧判定、`extract_result_text`、工具清单发现与未声明工具拦截 | 离线用 `FakeSession`；已装 mcp 时跑真实 stdio（`tests/mcp_echo_server.py`，`discover_tools` 也跑在真实 SDK 返回形状上） |
| `tests/test_real_llm.py` | `llm.parse_spec`/`build_chat_model` 的报错路径；**真实 `ChatOpenAI` 客户端 + 本地 SSE 桩**（`tests/openai_sse_stub.py`）下的真早停 —— 由服务器侧数它写出去了几片来证明**传输层**真的断了 | 规格与报错用例无依赖；客户端用例要 `langchain_openai`（已装则默认跑）；真 provider 用例由 `POP_TEST_LLM=1` 门控 |
| `tests/test_demo_e2e.py` | 端到端会话（依赖齐全时才跑全部）；`--model` 产物与离线桩**同形** | — |
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
- **流式早停的行为差异**：`stop_on_violation` 是「停止出证 + 回调 `on_early_stop`」，
  `hard_stop=True` 再加「抛出 `EarlyStop` 真掐断」。**换框架时这条要重做**：两道门槛
  （异常会不会被回调系统吞掉、掐断后走哪条错误路由）都是**框架特定**的，LangChain 的
  `raise_error` 换个框架就不存在了 —— 别以为抛个异常就完事。

---

**相关**：证书与信封结构 → [`03-certificate.md`](03-certificate.md)；
端到端 demo 怎么跑 → [`07-cli-scripts.md`](07-cli-scripts.md)。
