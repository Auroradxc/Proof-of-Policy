# 08 · 测试与评测

> 覆盖 `tests/`（42 个模块，783 个用例）与 `bench/`（7 个脚本，结果入库在 `bench/results/`）。
> 这一板块回答：**哪些性质被自动化守住了，论文里的数字是怎么测出来的。**

---

## 1. 测试套件总览

```bash
python3 -m unittest discover -s tests -t . -v   # 期望 783 passed, 15 skipped
```

| 模块 | 用例数 | 守护的性质 |
|---|---:|---|
| `test_trace` | 41 | **P1-5**：四条验收（①完整链通过 ②删/换/重排失败 ③伪造「参数干净」的回执验签失败 ④旧 `tool_calls` 向量被拒）；`trace_root` 与 Python **逐字节一致**（实测 `--check`）；编码层的长度前缀/键序/keyid 覆盖；链尾篡改**只有链下验签抓得住**的边界；**第三方核对**（`verify_cert.py --receipts [--gateway-key]` 7 例：摘要重算对齐 / 换链对不上 / 重排结构先炸 / 伪造链尾只被验签抓住 / 缺网关公钥时如实报「签名未验」/ 没有 `--receipts` 时仍单独核 seal / 截尾三路全拒）；**P1-5b 截尾对策**（`TestSeal` 9 例：确定性 / 空链 genesis / 四个字段都进签名原像 / 回执签名不能冒充 seal（域分隔）/ 三类失败形态 / 早期 seal 被后续调用作废 / 无公钥时如实报「签名未验」/ **seal 只进载荷顶层不进 outcome** / 缺 seal 的诚实口径）+ **`test_tail_truncation_is_rejected`**（原 seal+截断链 / 冒充 keyid 的伪造 seal / 索性不带 seal 三路全拒 + 「没截尾时全 PASS」的正对照；原「缺口」用例已翻转，见安全模型 §5.3 与待办 T4） |
| `test_dsl` | 33 | 领域模型、七类规则的通过/违规矩阵（含 P2-9b 的 `normalized_keyword_block`）、`PolicyError` 路径；**P1-5**：链坏 fail-closed、tokens 电路内自算（不可自填）；**R7**：`TestFromDictRejectsShape`（4 例）钉住「**不像策略包**的 JSON 只抛 `PolicyError`」——顶层不是对象 / 缺 `id` / `rules` 不是数组 / 规则项不是对象，四种形状原先各自漏 `KeyError`、`AttributeError`、`TypeError`，而调用方（11 份加载器、每个 CLI、常驻服务）**统统只接 `PolicyError`**，漏一个就是「用户把包写错了」表现成「工具崩了」（退出码 1 + 一坨 traceback，而不是退出码 2 + 一行 `error: …`）。两条**反向**用例同样重要：闸门不能反过来吞掉合法的包（空规则表合法、多余顶层字段允许）、形状对内容错仍须由 `Rule.validate` 报到**具体规则名**。见 `docs/dev-plan.md` §5.7.12 |
| `test_nfa` | 7 | 正则子集解析、NFA 构造、`match_search` 与 `re` 的行为对照、fail-fast |
| `test_pii` | 8 | 四个 PII 模式的命中/漏报、IBAN MOD-97 校验位 |
| `test_serialize` | 10 | serde 外部标签枚举形状、未知 kind 抛 `NotImplementedError`、`spec_canonical` 字节稳定 |
| `test_commit` | 12 | 承诺、私有输出、掩码覆盖、脱敏、证据开示 |
| `test_policy_binding` | 28 | **P0-1**：策略绑定三方比对；「空策略证明 + 真策略哈希」攻击回归；未入电路的 kind **fail-closed**；**P0-4**：夸大/低报证明模式的证书被判 FAIL（单证书层与会话层各一）、缺字段的旧证书如实跳过 |
| `test_binding` | 19 | **P0-2**：挑战-响应绑定（①正确对通过 ②换 T 拒 ③换 nonce 拒 ④空 nonce 独立域）、`NonceStore` 重放、Python↔Rust 逐字节对齐、带挑战证书端到端 |
| `test_cert` | 19 | 证书载荷、`cert_digest` 稳定性、签名与篡改拒绝；**P0-3**：按 keyid 方案前缀分发、旧 `demo-hmac-sha256` 结构性被拒、`load_keyring` 的三种公钥来源（路径拼错要报**真因**）；**P0-4**：`binding.proof_mode` 诚实标注与 `proof_hiding` 映射 |
| `test_cross_validate` | 6 | 真实证明分块（`--chunk`）：切开后拼回去逐一相等、顺序不变、`--chunk 0` 等价单进程、默认值刻意保守 |
| `test_agent` | 5 | `AgentMonitor` 两条路径、`mock_agent` 确定性、LangGraph 适配 |
| `test_frameworks` | 53 | LangChain 回调（流式链/篡改/早停/**真掐断**）、`guard_node`、`astream_events`；**P0-4**：`proof_mode` 贯通到回调与 `guard_node` 出的证书；错误回调（#96）与统一网关（#99，含**非恒真对照**：不共用网关时 seal 报截尾） |
| `test_mcp` | 15 | 参数侧飞行前拦截、结果侧判定、文本提取、**工具清单动态发现**（#98：未声明的工具在执行前被拦，附「声明过的照常放行」对照）；**P0-4**：`proof_mode` 同时落到参数侧与结果侧证书 |
| `test_real_llm` | 13 | **`--model` 真模型客户端**（#98）。三层：① 规格解析与报错（未知 provider / 空模型名 / 缺 key 都当场说清是哪一个，**刻意不认** Claude Code 自己的 `ANTHROPIC_AUTH_TOKEN`）② 真实 `langchain_openai` 客户端 + 本地 SSE 桩（`tests/openai_sse_stub.py`，**默认跑**，不需要网络与真 key）—— 由**服务器侧**数它写出去了几片，证明早停是在**传输层**真的断了连接，而非「我们这边不再 append」；对照组是关掉 `hard_stop` 后每一片都写出去 ③ 真 provider（`POP_TEST_LLM=1`）只断言结构，**不**赌模型一定会违规 |
| `test_anchor` | 7 | 账本读写、`verify_ledger`、篡改检出；**c6**：`TestUnconfiguredTypeConsistency`（3 例）钉住「要上链但没配」这一个条件在 `backend_from_env(require=True)` 与 `anchor_on_chain` 两处给出**同一种**异常 —— `test_same_type` 用 `assertIs(type(a),type(b))` 而非「都继承 RuntimeError」这种弱断言，`test_same_message` 断言消息一字不差，`test_not_implemented_error_would_not_be_caught` 是**反例对照**（证明前两条不是恒真的：原写法确实接不住） |
| `test_anchor_chain` | 28 | 合约 artifact、摘要编码、后端选择、RPC 后端离线（幂等/竞态）、cast 命令行、**账本尾部 O(1) 缓存**（`TestLedgerTail` 5 例：缺文件即 genesis / 追加后命中缓存 / **命中时一次 `read_ledger` 都不调**（数调用次数，这才是 O(1) 的真凭据）/ 外部追加使缓存失效 / 截短也失效）、anvil 端到端（含**服务层真的把摘要写进真链**：`ProofService(rpc_url=..., contract=...)` 走完一次作业，再由**独立只读客户端**读回核对 —— 假客户端测不出两层之间的接线错） |
| `test_normalize` | 28 | **P2-9b**：同形异义折叠（`pop-fold-v1`）。折叠表构造与 13 种非法声明（未知版本/未知键/超长表/非 ASCII或多字符替换值/自映射/重复 `from`/`map∩drop` …）全部 fail-closed；算法单遍**不链式**、`ascii_lower` 只碰 ASCII；**验收判据**是「折叠前 `passed=True`、折叠后 `passed=False`」这一对（并另断言 ASCII 那条被两条规则同时拦住，免得用例退化成恒真）；折叠表**进契约** → 改表即改 `policy_hash`。 |
| `test_rule_kinds` | 16 | **kind 分派的一致性**（`model._RULE_VALIDATORS` 是权威名单）：按 `kind` 分派的逻辑在项目里有**四份**（`model.Rule.validate` / `evaluate.check` / `compile.compile_constraints` / `commit.canonical_violations`）外加运行期枚举 `multiparty.KIND_OWNER`，漏改任一处**都是静默的**（没有异常、没有报错）。前两份用 `ast` 从裸 `if/elif` 链里抽字面量比对，`KIND_OWNER` 直接 import 不抄第二份；另有三条 fail-closed 用例，其中 **`test_unhashable_kind_is_policy_error_not_type_error`** 钉的是一条**真发生过的**回归 —— 校验从逐值比较改成查表后，不可哈希的 `kind`（JSON 里合法，如数组）会从可诊断的 `PolicyError` 退化成未捕获的 `TypeError`。**R6 加了第六件事**：`Violation.evidence_kind → rule.kind` 的翻译表（`evaluate.EVIDENCE_KIND_TO_RULE_KIND`，一度抄成**三份**，其中两份**各只有 7 项里的 3 项**）。两道闸门：① 表与 `check` 真正会产生的配对逐项相等 —— `ast` 只走 `if/elif rule.kind == …` 的**分支体**（`node.body`，不含 `orelse`；用 `ast.walk(if_node)` 会把整条 `elif` 链一起吞掉），取分支体内 `Violation(...)` 的第二个位置参数，剔除合成规则 `_TraceRule` 的 `trace_unbound`，并要求每个分支**恰好**一种；② 全仓不许再出现第二份（AST 找**含 ≥2 项本表配对**的字典字面量 —— 副本的实际形态，单个巧合配对不算），例外逐条申报、条数钉死。**防恒真**：扫描器与抽取器各喂一段已知样本；两条变异探针实测非恒真（把一份副本塞回 `prove_policy.py` → 报出该文件；从表里删掉一项 → 逐项比对报红）。**为什么不是「可读性问题」**：三份抄的**不一样长**，而今天不炸只是因为 7 个包用到的 `evidence_kind` 恰好落在那 3 项里；一旦有规则用上 `format`/`tool_arg`/`budget`/`normalized_keyword`，调用方的 `.get(k, k)` 会把 `"format"` 本身当 kind 交出去，而 guest 写的是 `format_check` —— 两边各自自洽，出证时才报「违规集合不同」 |
| `test_acceptance_baseline` | 3 | **等效替代的机械判据**（`scripts/verify/acceptance.py`）：现算七个可观察面并断言等于入库的 `tests/acceptance_baseline.json`（**1.3 s**）。七面 = 跨层契约（完整 `ConstraintSpec` 规范字节 + `policy_hash`）/ 两条判定路径在 7 包 × 24 条语料上的完整结论（含空·干净·脏·坏四档回执链）/ 20 种畸形包走「加载→校验→编译」三段各自的**异常类型与文案** / 畸形文件喂 CLI 的退出码与 stderr / 流式证书序列 / 两个 CLI 子命令 / `__all__` 导入面。另有 `test_baseline_covers_every_face` 防「基线被削成只剩一面时照样全绿」这类假绿。**它不判断该不该变，只保证变了一定有人看见** —— 分界与重新采集的步骤见 `docs/dev-plan.md` §5.7.4 |
| `test_rules_incircuit` | 13 | 七类规则在 `--check` 下与 Python golden 逐点对齐（**P1-5**：轨迹类规则判回执链，链坏两端都 fail-closed；**P2-9b**：`normalized_keyword_block` 7 组逐点对拍 + 私有模式下证据承诺与 Python 一致） |
| `test_ablation` | 7 | pike ≡ naive（Python 与 Rust 两侧）；**`TestBenchCorpusParsers`**（2 例）钉住基准脚本的采样点解析 —— 行为对（`--ns 100,200,400,800` 真能跑）+ 结构对（`bench_ablation` 与 `bench_cycles` 引用的是**同一个**函数对象，再抄一份出来就红）。守的是 R18 那个真 bug：私有副本把 `replace(",", " ")` 写成 `replace(";", " ")`，于是脚本 docstring 举的例子跑不过，而**没有测试**覆盖这两个函数 |
| `test_verifier_only` | 8 | `prefer_verifier_only` 三条件、core 不走近路；**P0-4**：`artifact_proof_modes` 收齐多来源、缺失不编默认值、来源不一致如实暴露 |
| `test_demo_e2e` | 5 | 端到端会话产物结构；**`--model` 与离线桩同构**（#98：真客户端跑出的会话与 fake 路径**逐条同形** —— 比的是两份会话的形状，不是一个写死的数字，因为写死的数字在假路径改动之后不会报错、只会静默地变成另一件事），外加「规格写错必须报错、绝不静默退回桩」；`TestDemoLanesMatchDoc`（1 例）把 `demo_all.sh` 的 `LANES` 数组与 `docs/demo/README.md` §3 的表格**逐字段机械比对** —— 这是同一个事实的两份抄写，分叉时不会有任何东西报错 |
| `test_ezkl_evm` | 10 | **T2**：`ezkl_evm.run` 对同步/异步/Future 三种可调用对象都成立（5 例，**不依赖 ezkl**）；真实 ezkl 下裸调用必抛 `no running event loop`（把上游坏行为钉死）、包一层即产出 `Halo2Verifier` 源码与 `verifyProof` ABI、连调互不影响、`reusable` 变体 + VK artifact（`vka.json` 实为 bincode，不是 JSON）、**剥空 `PATH` 也不调用 solc** |
| `test_semantic` | 30 | **P2-9**：语义规则（学习型规则）的委托与绑定，**含 6 条反例**（换 ONNX、换 vk、改阈值、翻转 `direction`、换证明文件/换响应、图外自算特征）与 fail-closed 四路（缺材料目录/缺陪伴证明/缺 `--response`/多带证明）；**分层**见下 —— 30 例中只有 1 例（`test_real_proof_verifies_and_binds`）需 ezkl 与 32 MiB `srs`，其余 29 例在本机实际执行 |
| `test_compose` | 48 | **P1-6**：组合证明 `Compose = (推理完整性 ∧ 策略合规)`。三层 —— ① 参考实现逐位一致（`pop-script --check --job infer` ↔ `policydsl/proofs/infer.py`：模型哈希/响应绑定/输入绑定/输出）② 组合绑定的 **5 组反例**（换证明文件·缺失、同 vkey·非期望 vkey、换模型·换输入、两半绑不同 T·送达 T′ 不符、形状·模式·域·policy_hash 重编译）③ **四条驱动接线回归**（`--job` 旗标 ≠ part 的 kind；`part_from_proof` 得把旗标而不是 kind 传下去；验证结果的 `mode` 不能被当展示元信息剥掉；`pop-script --verify` 必须显式给 `--out`，否则在仓库根落一个 `results.json`）——这几条对应 2026-09-12 真端到端跑出来的真 bug，单测当时全绿。真·端到端 5 例由 `POP_TEST_COMPOSE=1` 打开 |
| `test_session` | 38 | **P2-10**：跨证书一致性（`session` 域 = guest③）。三层 —— ① **Merkle 纯算术层**（单叶子即叶子本身；内部节点带 `pop-session-node-v1` 前缀；**奇数末位提升、绝不复制** ← 这条是「挖尾」防线的前提；n=1…9 的包含证明往返；篡改叶子与形状非法 fail-closed）② **两层对拍**（`pop-script --check --job session` ↔ `policydsl/proofs/session.py::run_session` 在链长 1/2/3/5/8 上**逐字段相等** —— 奇数链才会走到末位提升；Merkle 根跨层逐字节一致；nonce 改则 `session_binding` 改）③ **义务与反例**（混异策略 / 挖中间 / 换序 / 缺 `chain` / 缺 `seal` / 两条网关的 seal / 空集；验证侧的 happy path、**挖尾**、**整张换尾**、伪造根 / 伪造链尾承诺 / 伪造策略哈希、错域、现场重编译策略包、seal 签名与真回执）。**真·端到端 1 例**（`POP_TEST_SESSION=1`）对着真证明跑计划的两条验收判据（混异策略 + 挖尾），并核 `--nonce` 换一个即拒 |
| `test_multiparty` | 44 | **P2-11**：多证明者（模型方 / 工具网关 / 部署方各证一段策略切片）。三层 —— ① **切分层**（8 个 kind 的归属普查：每条规则恰属一个角色、切片两两不交且并集为全策略、三个角色**恒存在**（空切片也要签名）、未知 kind 在两处被拒、同名规则拒绝、`require_covering_length_bound` 只在整条策略上查一次、切片与整策同一份编译器、内容寻址确定性）② **绑定层**（happy path；缺 keyring 时如实标注「未验签名」；语义切片真实但需陪伴证明；JSON 往返；`plan_digest` 绑进**每一份**签名；**验收 ①** 缺任一角色签名 / 空签名表 / 缺 part / 重复 part；**角色密钥分离**；**验收 ②** 单角色切片被换（含该角色拿自己键重签、把切片谎报为空、单独改 plan、改 `plan_digest`）与**三方合谋改 plan**（不带策略包时而通过、带上 `policy_pack` 即被拒 —— 如实记下这条边界）；证明文件被换 / 张冠李戴 / 空切片带证明 / 非空切片不带证明 / 非 public 模式 / vkey 混用 / 非期望 vkey；换 T / 两半绑不同 T / 不同 `trace_root`；违规切片是**真证书但未满足**）③ **构造层**（缺角色键、一把键当两个角色、空策略无法出证、构建期缺证明、构建期 part 与策略不符）。真·端到端 1 例由 `POP_TEST_MULTIPARTY=1` 打开 |
| `test_proof_service` | 105 | **第二步（服务化）**：策略注册表（同名不同内容拒收、坏包**报告**而不吞掉）、**两段同形**（`host_outcome` 的键集与电路公开值逐字段相同；`violations` 镜像 `pop-types::evaluate`；两套推导打架就**停证** `VerdictMismatch`）、队列（第二个请求**排队**而非被拒、满了 429 且被拒的不吃队列位、作业炸了不带走工作线程、`stop()` drain）、`/v1/check` 的证书**真的验得过**（`verify_cert.py` → `RESULT: PASS` 含 `[PASS] trace_binding`，且账本里每条锚定摘要磁盘上都还在）、OOM 杀进程要被翻成一句「内存不足」（含 10.15 GiB 地板与 `dmesg` 核实法）、HTTP 层分得清 400/404/413（**413 不读正文**）、**鉴权层**（27 例：token 解析与三条拒收理由「短/含空白/重复标签或 secret」、**五处来源合并而非覆盖**、401 带 `WWW-Authenticate` 且**区分「格式错」与「token 错」**、报错**不回显**收到的值、`/v1/health` 快照**不含 secret**、令牌桶突发→429→回填、**按 token 分桶**（一个人打满不饿死另一个）、管理员豁免、**别人的作业返 404 且与「不存在」措辞逐字相同**、未鉴权不许提交）。、**账本 RPC 后端（29 例）**：`--rpc` 忘带 `--contract` **拒绝启动**（此前会静默退回文件账本）、配全了照样起（环境变量来源也算配全）、`/v1/health` 报 `anchor_backend` 且本地后端**不报** chain、链上后端报连通性、**链挂了如实报 unhealthy**、没有自检能力的后端报**「不知道」而不是 ok**、健康值走 TTL 缓存（5 次查询只探链 1 次）且**过期真的会重探**、锚定失败时磁盘上**没有** cert/payload/key/anchor 四个文件（并如实记下「工作目录会留下」这条边界）、作业 error 说清「没有签发证书」、**链已知断则当场拒收作业**（不吃队列位）、`/v1/check` 同样被拒（它也锚定）、HTTP 层 503 且两个入口的产物路径措辞各自正确。**配置写错=一句人话+退出码 2**（4 例：链上配一半 / 鉴权文件不存在 / `--require-auth` 无 token 都是干净拒绝，**不是 Python 回溯**；外加「配全了就真的起得来」的非恒真对照）。**真 vkey 出证 1 例由 `POP_TEST_PROOF=1` 打开**。**作业状态持久化（18 例）**：重启后 `GET /v1/attest/{job}` 照常答得出来（新对象读同一个 `--out-dir`）、提交人落盘后「别人的作业 404」口径不变、**三条重建规则各一条**（有证书就 `done` 哪怕记录停在 `proving` / 中间态不接回来当中间态而报「不会被执行」/ 记录说 `done` 而证书没了）、**两种记录-产物漂移各一条**（`payload.json` 被手改 ⇒ 记录摘要拦下；`cert.json` 里被签的那份被改 ⇒ 信封一致性拦下）、`job.json` 损坏或字段非法时**报错而不是 404**、`job_id` 形状不合法（含路径穿越形）**连文件系统都不碰**、记录写盘失败**不失败作业**但必须在 stderr 上喊、惰性按 id 加载（不启动扫盘）、`--pack` 少了一个包时作业仍在而 `verify_hint` 如实为 `null`、**换一个真进程**（子进程）读同一个 `--out-dir` 走 HTTP 再问一次。另记：**6 处变异测试**钉住这条线，并当场查出三件事 —— 两处是**测试自身**的毛病（信封校验的断言咬得太松，删掉那道校验测试照样绿；一条用例打的是全进程 `Path.write_text`，连工作线程写的产物一起打中，约 1/4 概率的假失败），一处是**产品 bug**（读回产物那段只捕 `(OSError, ValueError, KeyError)`，一个形状对但载荷不是字符串的 `cert.json` 抛 `TypeError` ⇒ **读取方自己崩、接口返 500**，改成捕 `Exception` 后修掉） |
| `test_generic_adapter` | 18 | **P3-a 框架无关参考适配器**（`GenericGuard`，把「接入契约」写成可跑的代码）。契约：生成/工具两条路径各出可验证证书、违规**如实记进证书**而不是藏起来（「证书为真」与「策略满足」是两件事）、一次会话**一把网关**、生成与工具**同一条 `trace_root`**、网关钥与出证方钥是**两把**、默认如实标 `unproven`。seal 时序：早期 seal 被后续调用作废并报「截尾」、每张证书带**自己那一刻**的 seal、无工具调用的会话 `seal.count=0`（而不是没有 seal）。该抛就抛：内容规则缺 `response` 抛 `PolicyError` 且**不留半张证书**、私钥绝不落盘。**第三方真脚本核对**（起子进程）：`verify_session.py` 全卡 PASS、`verify_cert.py` 连 `trace_binding`/`trace_seal` 都 PASS、**不给 `--receipts` 时 `trace_binding` 如实报 FAIL**（不是默认通过）、换别人的网关钥 `trace_seal` 必 FAIL。另记 **4 处变异**，其中一处一度**存活**：「把 `chain` 从整条网关链改成 `[receipt]`（等价于两条链）」时其余 17 例**全绿** —— `trace_root` 只取**最后一条**回执的摘要（链式性在每条回执的 `prev` 里），且只传当前那条时它 `seq` 不从 0 起、会先被判成 `trace_unbound`，于是 `passed` 与**规则名恰好都一样**，差别只在 `kind` 与「计到几条」。补了一条「第 2 次调用继承第 1 次的超预算」并断言咬在 `kind`/`evidence`（计到几条）上之后杀掉；另 3 处（丢网关公钥 / 不写 `receipts.json` / `generate` 不附 seal）均被杀。清单表与接新框架的步骤见 [`06-frameworks.md` §8](06-frameworks.md) |
| `test_regression_prove` | 16 | **c4 / T3 回归编排器**（`scripts/prove/regression_prove.py`）。**整轮跑的是替身驱动，一个字节的密码学都没算** —— 它证的是**编排层**，不是证明本身（真跑一次全量是 ≈45 min 且要 ~10.15 GiB 峰值，把编排的回归绑在那上面等于没有回归）。守护：**历史只追加不覆盖**（第二次跑完后第一次那条**逐字段没变**；`--dry-run` 一个字节都不写）、坏行不让 `--print` 崩且如实标 `UNREADABLE`；**成败归因**（出证腿挂了 → 验证腿记 `skipped` 且 `ok=False`，**绝不能因为「没跑」被算成通过**；验证腿自己挂了 → 只归因给验证腿，出证腿不被连坐）；**OOM 判据**（`POP_FAKE_FAIL=prove` 让替身**真的 `SIGKILL` 自己**，复刻 OOM killer 的无输出无末行，判 FAIL 且理由写明「没有 RESULT:」）；**失败记录留得下真因**（断言 `log_tail` 含 `CalledProcessError` 且**不含** `time -v` 的样板 —— 这里钉的是一个真踩过的坑：`time` 的报告打在子进程输出**之后**，「取末尾 30 行」会整段取到样板、把 traceback 挤掉，最需要证据的那种失败反而最看不见）；**留痕字段**（`git.sha`/`host.mem_total_mb`/驱动 `sha256` 都对着真文件重算核对）。另记 **6 处变异**，其中 M4 **存活且是等价变异**（如实登记）：把 `ok=(returncode==0 and verdict=="PASS")` 削成只看退出码 —— 当前两处证据总是同时成立，要证伪得让 `cross_validate` **自报 PASS 却非零退出**，那不是本模块能构造的状态；合取仍保留，防的是将来「印了末行之后才崩」 |
| `test_doc_links` | 4 | **文档里的仓库内链接必须指得到东西**（R1 的第三条闸门）。文档层是别的闸门都够不着的地方：把一个文件挪进 `docs/modules/`、删一节连同它的引用，编辑器不拦、review 也容易看漏，而读的人**不会看到报错** —— 他只会以为自己看错了路径。判据只覆盖「看起来就是仓库内路径」的链接（以 `./` `../` `/` 开头，或以已知后缀结尾），`http(s)://` / `mailto:` / 纯锚点一概跳过（外链断不断不是本仓能保证的事，更不该让 CI 连网）。实测 **47 份文档 / 274 条路径型链接 / 0 条指空**。防假绿有两层：`test_census_is_not_vacuous` 断言至少扫到 40 份文档与 200 条链接（正则写坏或 `rglob` 范围错了会当场红），`test_detects_a_dangling_link` 拿一份**已知含坏链接**的合成文档喂给同一个检查函数、要求它报出来（用临时目录里的真文件当好链接的靶子）| 
| `test_cross_layer_constants` | 6 | **跨层域分隔符逐字节相同**（R2）。域分隔符是「同一哈希在两个用途下不互相冒充」的**全部实现**，写错一个字符的后果不是报错，是**两侧各自自洽、合起来对不上**。比 5 条：`TRACE_DOMAIN`(pop-trace-v1) / `BIND_DOMAIN`(pop-bind-v1) / `INFER_DOMAIN`(pop-infer-v1) / `MERKLE_NODE_DOMAIN`(pop-session-node-v1) 四个 `&[u8]` 前缀、`INFER_DOMAIN_STR` 的 `&str` 形式、`FOLD_VERSIONS` 列表。**关键：它不需要 Rust 工具链** —— 比的是 `circuits/types/src/lib.rs` 里**声明的字面量**（正则抽取），所以进得了零依赖的那条 CI 通道，而 `skipUnless(POP_SCRIPT.exists())` 那些用例在缺驱动的机器上是**静默全绿**的。两条防退化：`test_a_missing_declaration_is_reported_not_ignored` 要求常量被改名/删掉时**报错而不是返回空串**（否则断言会拿 `b""` 去比、照样绿），`test_extractor_reads_the_declared_value_not_a_substring` 钉住「认声明、不认源码里出现过」，外加 `test_domains_are_distinct` 盯住域分离本身（两个域被合并成全同时，逐条比对**可能全部照样通过**）| 
| `test_scripts_layout` | 8 | **`scripts/` 分组的机械化保障**（见 `docs/dev-plan.md` §5.6）。存在理由很具体：每个脚本头部都自己写一行按**层数**算的 `sys.path.insert(…, parents[1])` 再 `from _bootstrap import` —— 脚本再搬一次家，这一行就**静默**指错，而它坏掉的是**跑 demo 才会走到**的路径，单测可能全绿（`policydsl/` 拆包时同一个毛病让 66 个用例一起红）。三件事：① **每个脚本都导入得动且 `REPO` == 仓库根**（16 个脚本逐个起子进程导入、不执行 `main`；另有 `test_at_least_one_script_and_five_groups` 防「空集合上全绿」——先断言至少发现 10 个脚本且组名恰是那 5 个）② **`_bootstrap` 是按标记搜索而不是数层数**（`test_finds_root_in_a_foreign_tree` 把它种进一棵陌生树仍找到根 ⇒ 是搜出来的不是写死的；`test_raises_loudly_when_markers_absent` 缺标记抛 `RuntimeError` 且消息里点名 `policydsl`/`circuits`；`test_raises_when_scripts_is_not_at_the_root` 把「嵌套 checkout 会接错树」这条自查本身变成被测行为；`test_bootstrap_is_idempotent_and_orders_repo_first` 在**子进程 + 临时 cwd** 里验连调两次不重复塞路径、且 `REPO` 排在脚本组**前面**）③ **组间不重名 + 根上不放计划外的东西**（5 个组目录是**并排**进 `sys.path` 的，同名文件会让 `import X` 取决于路径顺序 —— 这是 `bootstrap()` 成立的前提；另允许 `scripts/` 根上只有 `_bootstrap.py` + 5 组 + `examples/`，多出来的要么是误提交的产物要么是没想清楚放哪） |
| `test_nfa_cache` | 10 | **编译产物被共享之后，前提必须是显式的**（R3）。改之前 `compile_pattern` 每次返回一个**全新的**可变 dict，改之后同一个 pattern 永远返回**同一个对象** —— 这是本项目第一次出现「编译产物被多个调用方共享」，而它成立的前提是**谁都不改它**。这个前提今天成立（四个消费者都只读），但它是**隐式**的：将来谁往里写一行「顺手规整一下 `states`」不会报错，只会让**别人**手里那份悄悄变了 —— 于是判据变了、而没有任何一处响。所以钉成会红的断言：跑完 `match_search` / `find_spans` / `mask_indices` / `anchored_full_match` / `match_search_naive` 之后，与**新鲜编译**的那一份深度相等（`test_consumers_do_not_mutate_the_cached_spec`）。第二条是**序列化**：缓存对象是 dict 子类（为了挂 ε-闭包表），子类若改变规范字节，**跨层契约就变了、`policy_hash` 跟着变**，已入库的证明会集体对不上 —— 因此逐字节比一次，并在整条策略链上再比一次 `spec["sha256"]`（含「清掉缓存走冷路径」的对照）。另钉：闭包表记忆化命中的是**同一个**对象且等于现算、手工构造的普通 dict**不**被记忆化（不为性能改动对外行为面）、`deepcopy` 出来的确实独立。**防恒真**：四条变异探针实测 —— 往共享 spec 挂一个统计字段、把 ε-转移列表倒序（语义等价但内容变了）→ 两条都是 `failures` 而非崩溃；追加到共享闭包表 → 红；不注入 → 绿。`sorted(eps)` 那条探针**自己失效**（编译出来本就已序），如实记下：那是探针空转，不是用例失效 |
| `test_loader_parity` | 11 | **十一份策略加载器其实是同一件事 —— 这话得查出来，不能读出来**（P1-①，R7 的闸门）。同一个「包 JSON → `Policy`」的动作在仓库里抄了 11 份，长得很像但**像不等于同**：规则名兜底一份写 `r{i}`、一份写 `rule-{i}`；有的把 `semantic` / `description` 带进 `Policy`，有的丢掉（`semantic` **进**哈希，`description` **不进**）；有的用 `data["rules"]`（缺键 `KeyError`），有的用 `.get(..., [])`（缺键**静默变成空策略**，fail-open）。后果不是报错，是**同一个包被两份加载器编译出两个哈希** —— 出证方算一个、验证方算另一个，两边都自洽，证书在第三方手里才验不过。**顺序不能倒**：R7 要删的就是那 11 份，删完就再也比不了了，所以先采快照（`tests/loader_parity_baseline.json`）再动 R7。判据是**逐包的去重哈希集合与去重签名集合**（取「集合」而非「逐份记录」，才能让「11 份旧加载器」与「1 份收敛后的」逐路径可比），另加两条更严的：**两边都有的标签逐份比完整记录**（集合级判据不记「谁持哪种」，某一份从「丢」翻成「带」时集合不变、一条都不会红 —— 这个缺口是变异探针 A 暴露出来的）与**覆盖守卫**（每个包必须读到 `expected` 份，不足即拒绝出结果，比的是两堆空集合时集合级判据**是绿的**）。**采集结果**：7 包 × 11 份覆盖 77/77，`policy_hash` **每包恰好 1 种**，签名每包 2 种且分歧**只在 `description`**（3 份带、8 份丢成 `''`，含全部验证侧）—— 它不进哈希、不进证书、CLI 也不打印，对当前所有可观察输出是**惰性**的，所以 P0 的七面基线与它全都对不上。四条变异探针实测非恒真，其中一条**自身失效**（`version` 兜底的改动在 7 个包上走不到）已如实记下。**R7 落地后又加了一条**：收敛之后 8 份旧加载器丢掉的 `description` 由新的统一加载器**按包内声明**填回，这是 R7 唯一的**已声明归一**，所以 `test_the_live_delta_is_exactly_the_declared_normalization` 不只「把差异归一掉」，而是**反过来断言这处差异恰好就是申报的那一处**（逐 `(加载器, 包)` 比：变的集合恰是 8 份丢 description 的加载器 × 7 个包、顶层只许 `policy`/`policy_hash` 动、`policy_hash` 一个字都不许动、只有 `description` 值在变且恰好是 `'' → 包内声明值`）。归一**加上**这条断言，快照才不会退化成一张空白支票。见 `docs/dev-plan.md` §5.7.7、§5.7.12 |
| `test_driver_paths` | 9 | **驱动路径只能有一个出处 —— 把它钉成结构，而不是钉成一次普查**（R4）。`pop-script` / `pop-verify` 的字面量一度抄在 **26 个文件 / 33 行**里。抄得一字不差，所以从任何一处看都没问题 —— 问题在于「一字不差」是靠人抄对维持的，而抄错的后果恰好落在 `policydsl/paths.py` docstring 记的那类事故上：路径指向一个**不存在**的位置，且 26 处各自决定怎么办（抛 `FileNotFoundError` / `skipUnless` 静默跳过 / `raise SystemExit`），同一个故障有 26 种表现。闸门用 **AST** 扫，只认**恰好等于**驱动器名的字符串常量，并**排除 docstring**（那是在**叙述**，不是在**定位**）；另单扫**模块级别名**（`POP_SCRIPT = 别处.POP_SCRIPT` 照样是第二处出处 —— `policydsl/proofs/session.py:65` 与 `tests/test_session.py:44` 历史上就是）。例外**逐条申报、且条数钉死**：多一处要改数字、少一处也要改，于是例外既不会悄悄长大、也不会腐烂成「反正这个文件豁免」（对照 §5.7.7 的做法）。另钉三条：出处必须是**叶子**（只许 `import pathlib` / `from __future__` —— 出处若依赖重型模块，「读路径」这件事就付不起代价，正是它当初被抄的原因之一）；`cross_validate.py` 的 `$POP_SCRIPT` 覆盖**行为级**复测（两个子进程：缺省 = 出处、设了环境变量 = 该值，这是 R4 **必须保留**的能力，定时回归与单测靠它注入替身驱动）；`paths.POP_SCRIPT/POP_VERIFY` 确实解析在 `circuits/target/release/` 下。**防恒真**：扫描范围（≥100 个 `.py`，实测 106）与「确有模块从出处取路径」（≥25，实测 29）都有下限 —— 把 import 全删光不会全绿；两条变异探针实测非恒真（在**已被豁免**的文件里加一处 → 条数不符报红；在**未被豁免**的文件里加一处 → 红）。见 `docs/dev-plan.md` §5.7.9 |
| `test_artifact_digest` | 11 | **工件摘要只有一个口径，且这个口径没变过**（R5）。R5 之前，「对文件字节求 SHA-256」在仓库里写过 **7 份定义 + 1 段内联**（`proofs/compose.py`、`proofs/multiparty.py`、`runtime/service.py`、`scripts/prove/issue_cert.py`、`scripts/verify/verify_cert.py`、`scripts/verify/verify_session.py`、以及 `proofs/semantic.py` 那份带缓存的 `_sha256_of_file`，外加 `regression_prove.driver_fingerprint` 里一段**没有名字**的内联循环）。**为什么这不是「可读性问题」**：它们摘要的证明工件/公开值文件/驱动二进制会进证书的 `binding.proof_sha256` —— 出证方算一个值、验证方另算一个值，两处只要有一处口径变了（大写十六进制、按文本模式打开、少读一块），**两边各自自洽**，证书在第三方手里才验不过。这与 R4 的驱动路径是同一类事故：抄得一字不差，所以没有任何基线看得见。钉两件事：① **口径相同** —— 分块读（1 MiB）与 `read_bytes()` 在块的边界两侧（0 / 1 / 1 MiB−1 / 1 MiB / 1 MiB+1 / 2 MiB+12345 字节）给出**同一个**摘要，这是「收敛是等效替代」的全部内容；另钉小写十六进制（改大小写会让已入库证书集体对不上、且两边都「看起来对」）、`str`/`Path` 都收、失败模式（`FileNotFoundError`/`IsADirectoryError`）不变。② **口径只有一处** —— AST 扫全仓，除申报例外外谁都不许再定义摘要函数，**也不许再写那段流式读惯用法**（`driver_fingerprint` 当年就是没有名字的内联实现，只扫函数名的话整条漏掉）；例外逐条申报、条数钉死。两处**有意保留**：`core/model_fp.py` 的 `_sha256_of_file` 是**纯缓存壳**（mtime/size 是缓存键不参与计算，函数体只剩 `return sha256_file(path)`，另有「第二次真的命中缓存」的断言；它原先申报在 `proofs/semantic.py` 名下，**R14** 把模型指纹那组函数整体下沉时跟着搬了家 —— 名字与行为都没动，只是换了文件，申报路径跟着改）与 `tests/test_regression_prove.py::_sha256` 是**独立参照**（它验的是生产代码算出来的值，复用同一实现就成了自证 —— 对照本仓「两处独立算」的用法）。**防恒真**：扫描范围（≥100 个 `.py`）与「真有模块从出处取摘要」（≥8）都有下限，另有一条**给扫描器本身喂已知样本**的探针（认不出东西的扫描器与没有扫描器在结论上无法区分）。四条变异探针实测非恒真：别处新增一份 `def _sha256` / 口径改大写 / 每块漏读一个字节 / 缓存壳长回自己那份分块实现 → 各自报红。见 `docs/dev-plan.md` §5.7.10 |
| `test_nfa_transition_table` | 10 | **转移表的等效替代必须被证明，不能靠读代码点头**（R10）。`match_search` 是参考层判定 `pattern_block` 的那条路径，必须与电路侧逐条一致 —— 这里错一个字符，链下与链上就分叉，而分叉的表现是「证明验不过」而不是「这里报错」。R10 把它的最内层从「每条边调一次 Python 写的二分（`_point_in_ranges`）」换成预解包的 `bisect_right`（实测 `pii_redaction_v1` 的流式路径上它独占 **42%** 总耗时）。两把**独立的尺子**：`_match_search_pre_r10`（改动前实现的逐字副本，对**任何** spec 都成立，含畸形的手工 spec）与 `nfa.match_search_naive`（仓库已有、**算法不同**的 O(n²) 参考匹配器）—— 单比前者只证明「没改坏」，单比后者会把「新旧同错」读成通过。另有一条防**收益静默归零**：pattern 的区间若变成未排序或同边内相交，所有边会退回 `starts is None` 的慢分支，而上面那些对拍**依然全绿**（慢分支与旧实现逐字相同），所以另断言 6 条去重 pattern 的**每一行**都走快分支 |
| `test_bench_views` | 6 | **入库的基准视图必须恰好是它那份数据渲染出来的**（R11）。分工是：`bench/results/*.json` 是**数据**（跑基准时自动落盘），`*.md` 是**视图**（同一个 `dump()` 顺手渲染）。视图由数据完全决定 —— 这既是承诺，也是个可机械检查的性质；而它一旦破了**不会有人发现**：谁手工改了 `.md` 里一句措辞，下一次重跑基准就**静默**覆盖回去；反过来只提交 `.json` 忘了 `.md`，入库的就是过期的表（`.md` 恰恰是论文/文档/issue 里引的那一份）。**不用「跑一遍基准对拍」来测** —— 那要真出证十几分钟、还得撞 `proofs.json` 里那几个**故意留着的 OOM 点**；渲染是纯函数，直接调它：零成本、无副作用，红起来意思完全一样。查的**不是「数字对不对」**（数字是量出来的，本文件造不出），而是「入库的这份视图，是不是这份数据渲染的那个」。新增入库结果只要往 `VIEWS` 加一行。另钉：三张旋钮表**口径各不相同（默认矩阵 / 默认旋钮实验 / 旋钮 A/B），不要混读**；cliff 那张必须**每个点都在每个臂下量过**，且所探的点必须**真的是缺省会 OOM 的那些** —— 这一条是在「跨文件的同一份语料」被实测**证伪**之后改的（`demo` 语料是个 glob，其 sha256 随时间变，跨文件比它是**假命题**），改法是把**测量**本身换成一次 `--arms` 调用、两臂共用同一份装载好的语料 |
| `test_frontdoor` | 9 | **门面的 `__all__` 是一份承诺**（R12）。`from policydsl import Policy` 是本包对外的稳定面，而 `__all__` 出问题时**没有任何东西会报错**：**漏掉一个名字** → `from policydsl import *` 的使用者拿不到它，报错发生在**他的**代码里、不在本仓的 CI 里；**混进解析不了的名字**（拼错/被删/搬家没同步）→ `import *` 直接抛 `AttributeError`，而本包的测试若都点名导入就一个都碰不到；**重名** → `len(__all__)` 与实际导出的符号数对不上，而那个长度常被人当「门面有多大」读；**门面递出来的是另一个对象**（本地定义了个同名包装/别名）→ 名字还在、也解析得了，语义已经不是子包里的那一个。四条都不在「跑一遍看看」的射程里。与验收快照第 6 面（`6_import_surface`）分工明确：快照记名单的**内容**，变了要**人**确认后重采（那是「变更被承认」）；本文件记名单的**不变量**（不重不漏、能解析、与命名空间一致），名单**坏**了才红 —— 只有快照，改名单会退化成「反正重采一次就绿了」；只有不变量，名单被谁加了看不出来。**同名函数只要求「至少一处同一对象」**：仓库里合法地存在两个同名的 `verify_chain`（`evidence/trace.py` 收回执链、`adapters/langchain_adapter.py` 收证书表），而 `adapters` 只在别的用例 import 它时才进 `sys.modules` —— 早先「所有定义模块都必须一致」的写法因此**依赖执行顺序**（单跑绿、全量红），已改成「可调用物：至少一处是同一对象；常量：所有定义模块逐字相等」 |
| `test_layering` | 6 | **`core` 不许 import `proofs`**（R14）。`core` 是**判定层**（决定「合不合规」），`proofs` 是**出证编排层**（决定「怎么把判定包成一份可验证的产物」）；两层关系**单向** —— 出证层产出的东西要被判定层理解，判定层不该反过来依赖出证层。R14 之前这里是真倒置：`core/compile.py` 与 `core/evaluate.py` 为了取模型指纹写了四处 `from policydsl.proofs import semantic`，修法是把那组**纯契约**函数（模型指纹 / 路径口径 / 图的字符上限）下沉到 `core/model_fp.py`。门槛值得存在的理由很具体：倒置**能被重新引入**，而引入时**不会有任何东西变红**（多一条 import 而已，功能照跑）。**必须走 AST 不走正则**：被搬出来的 `core/model_fp.py` 的 docstring 里**就写着**那串字（作为反例说明），按文本扫会把它误判成违规；而只扫模块级又会漏掉 R14 修掉的**全部四处 —— 它们都在函数体里**，所以 `ast.walk` 走全树。门槛自己也要能被证伪（本仓反复记过的失败模式「**空集合上全绿**」）：一条断言扫描确实覆盖到 `core` 包（目录改了 / glob 写错会当场红），四条注入探针（模块级注入 / **函数级注入** / 换成 `core.model_fp` 不算违规 / docstring 里的文字不算 import）。**已实测非恒真**：往 `core/compile.py` 注入一句函数级 `from policydsl.proofs import semantic`，用例变红并指出 `(文件, 行号, 模块)`；恢复后工作区零 diff |
| **合计** | **783** | |

### 15 个 skip（都是设计内的）

| skip | 原因 | 怎么启用 |
|---|---|---|
| `test_verifier_only` 中 2 例 | `circuits/testdata/audit_proof/` 没有 compressed fixture | 在 ≥16 GB 机器上跑 `SP1_PROVER=cpu bash scripts/ops/make_audit_proof.sh` |
| `test_frameworks`（或 `test_mcp`）中 1 例 | 依赖已安装而用例本身是「缺依赖时的行为」 | 设计如此，装了框架就会 skip |
| `test_policy_binding` 中 2 例 | 「证明层」用例默认关闭（要 `scripts/examples/out/cert_public/` 下的工件与当前 guest ELF 匹配；改过 ELF 就得重新出证） | `POP_TEST_PROOF=1 python3 -m unittest tests.test_policy_binding`（**已实测通过**：Ran 22 … OK，67.1 s） |
| `test_multiparty` 中 1 例 | 「真·端到端」要给**两段**切片各出一份 SP1 证明（每段 ~2 分钟、峰值 ~10 GiB） | `POP_TEST_MULTIPARTY=1 python3 -m unittest tests.test_multiparty.TestMultipartyEndToEnd -v` |
| `test_semantic` 中 1 例 | 「真·端到端」要出一份 ezkl 证明（~61 s、峰值 ~9 GiB） | `POP_TEST_EZKL=1 python3 -m unittest tests.test_semantic`（已实测通过） |
| `test_compose` 中 5 例 | 「真·端到端」要出**两份** SP1 证明（各 ~2 分钟、峰值 ~10.5 GiB） | `POP_TEST_COMPOSE=1 python3 -m unittest tests.test_compose`（**已实测通过**：47 例全跑、无一 skip，563.5 s；加四条接线回归后共 48 例） |
| `test_session` 中 1 例 | 「真·端到端」要出一份 SP1 **会话聚合证明**（3 张证书，~2.5 分钟、峰值 ~10 GiB） | `POP_TEST_SESSION=1 python3 -m unittest tests.test_session.TestSessionEndToEnd -v`（**已实测通过**：Ran 1 … OK，152.5 s —— 含一次出证、一次独立验证与**四条**拒绝路径：换组证书 / 尾截断 / 混入异策略证书 / 错 nonce） |
| `test_proof_service` 中 1 例 | 「真 vkey 出证」要跑一次 SP1 core 证明（~2.5 分钟、峰值 ~10.2 GiB 的**固定地板**）。本机 11.7 GiB **装得下但没有余量**：2026-09-13 第一次与别的进程并跑时被 OOM killer 杀在 9.7 GiB 常驻（`dmesg` 有记录），**腾空后重跑通过**（171.1 s，`MemAvailable` 一度只剩 0.15 GiB 并靠 swap 撑住）。服务把这种失败翻成一句人话，见下 | `POP_TEST_PROOF=1 python3 -m unittest tests.test_proof_service.TestRealProofAttest -v`。**跑之前先让别的进程腾出内存**（本机实测：腾空即过、并跑即 OOM）；换 ≥16 GB 的机器则不必讲究 |
| `test_real_llm` 中 1 例 | 「真 provider」要一个真 API key + 网络 —— CI 不该依赖它 | `POP_TEST_LLM=1 POP_TEST_MODEL=openai:<model> python3 -m unittest tests.test_real_llm`。**注意**：同模块里那 4 例真客户端的用例（本地 SSE 桩）**默认就跑** —— 桩实现的是 OpenAI 的协议，所以「真实客户端接进回调层后早停还能不能掐断」不需要网络与真 key |

#### `test_semantic` 为什么敢把 ezkl 关在门外

六条反例在 `verify_companion` 的**第 1–5 步**就被挡住（指纹比对、证明文件哈希、
本地 `vk` 哈希、`encode(T′)` 逐位比对），而这几步不跑 ezkl 验证器 ——
所以 29 例在**没有 ezkl、没有 32 MiB `kzg.srs`** 的机器上也能全绿。
第 3 步之后才是"跑 ezkl 验证器"（`verify_proof=True`），它由那条默认关闭的端到端
用例覆盖。**把最后一颗钉子与整面墙分开**，是为了让反例能在 CI 上天天跑。

> `test_binding` 的 19 例**全部实际执行**：它靠 `pop-script --check`（秒级、不出证明）做
> Python↔Rust 逐字节比对，不需要真证明，因此不受 `POP_TEST_PROOF` 门控。

> 这是当前环境下的计数（`langchain`/`langgraph`/`mcp`、`pop-script`/`pop-verify`、
> 以及 `ezkl`/`torch` 均已安装，因此真实框架用例、Rust 路径用例与 ezkl 用例**实际执行**了，
> 而不是跳过）。**CI 上的 skip 数会更多（12 → 17）**：CI 不装 `ezkl`/`torch`，
> `test_ezkl_evm` 里需要真实 ezkl 的 5 例（`TestEzklEvmVerifier`）整组跳过，只有不依赖 ezkl 的
> `TestRunHelper` 5 例照跑 —— 这是设计内的，P2-9 的可选依赖不进 CI。

### 分层设计：为什么没装框架也能跑

所有框架适配器都遵循「**导入回退 + 离线 fake**」：

| 层次 | 手段 | 例子 |
|---|---|---|
| 真依赖存在 | 跑真实端到端 | `test_mcp.py` 起真 `stdio_client` 子进程；`test_frameworks.py` 用真 LangChain/LangGraph |
| 真依赖缺失 | 鸭子类型 fake | `test_mcp.py::FakeSession`（记录 `calls` 以证明「拦截发生在执行前」） |
| Rust 二进制缺失 | 用 `skipUnless` 跳过 | `test_rules_incircuit.py`、`test_ablation.py::TestRustNaivePath` |
| foundry 缺失 | 跳过 anvil e2e | `test_anchor_chain.py::TestAnvilEndToEnd` |

CI（`.github/workflows/ci.yml`）跑的是**最轻的一档**：Python 套件 + 锚定测试（离线 fake-RPC）
+ 一条文档卫生检查（禁止出现陈旧的绝对路径 `/home/*/方向二`）。**不跑证明、不依赖网络。**

---

## 2. 测试 ↔ 性质对照（安全模型）

把 `../security-model.md` 的定义映射到具体用例：

| 定义 | 对应用例/脚本 |
|---|---|
| Completeness | `scripts/prove/prove_policy.py`（eu pass）、`cross_validate.py` **host 19/19 · prove 19/19**（2026-09-12 整批重跑） |
| Soundness（入电路规则） | `cross_validate` 的 violate 向量、`private_demo` 的违规用例 |
| Content privacy | `test_commit.py::TestPrivateOutput`（无明文泄露）、`private_demo` 的 `leak` 实验 |
| Redaction soundness | `test_commit.py::TestMaskCoverage`（伪造 span → `mask_covered=false`） |
| Evidence unforgeability | `test_commit.py::TestEvidenceOpening`（篡改开示 → 失败） |
| Provenance | `scripts/verify/verify_cert.py` 的 `policy_hash`/`vkey`/`proof_sha256` 卡；`test_cert.py`；`test_policy_binding.py`（P0-1 攻击回归） |
| Response binding (A6) | `scripts/verify/verify_cert.py --response` 卡；`test_binding.py`（换 T′/换 nonce/域分离）；`demo_e2e` 的 challenge 实验 |
| 证据档位诚实标注 (P0-4) | `scripts/verify/verify_cert.py` 的 `proof_mode` 卡（与工件自报模式比对）；`verify_session.py` 的 `certificates_proof_mode`；`test_cert.py::TestProofModeLabeling`、`test_policy_binding.py::TestProofModeOverclaimRejected`（自称某档却无工件 ⇒ FAIL）、`test_verifier_only.py::TestArtifactProofModes` |
| vkey 诚实标注（同构的第二条） | `scripts/verify/verify_cert.py` 的 `vkey_label` 卡；`verify_session.py` 的 `certificates_vkey_label`；`test_policy_binding.py::TestVkeyLabelHonestyRejected`（**用 `demo_e2e.py` 写过的魔法值 `"demo"` 本身作反例**）+ `::TestSessionVkeyLabelHonesty`。此前 `vkey_hash` **一条不变量都没有**，那个字段可以被写成任意字符串而全绿通过 |
| Ledger integrity | `test_anchor.py`（链篡改检出）、`verify_session.py::ledger_chain` |
| Stream chain | `test_frameworks.py`（链路验证/篡改/早停） |
| 链上锚定 | `test_anchor_chain.py`（离线 fake + anvil e2e）、`anchor_e2e.sh` 的 `chain_anchored` 与反例 |
| End-to-end | `scripts/verify/verify_session.py` 全 PASS（含真实 SP1 证明） |

**关键的一类测试是「负例/反例」**：伪造 span、篡改开示、篡改账本条目、未登记摘要读回 0、
core 边车不得走快路径 —— 这些保证正向检查**不是恒真**的。

---

## 3. 评测（`bench/`）

**八个脚本**，覆盖八种成本：

| 脚本 | 测什么 | 用时不出证？ | 输出 |
|---|---|---|---|
| `bench_cycles.py` | **zkVM 周期数**（`pop-script --execute`） | 每点数秒 | `bench/results/cycles.{json,md}` |
| `bench_ablation.py` | **匹配器消融**：pike(NFA) vs 朴素回溯在病理输入下的退化 | 每点数秒 | `bench/results/ablation.{json,md}` |
| `bench_proofs.py` | **证明墙钟时间 + 工件大小 + 峰值内存** | 本机实测每点 **119–173 s** | `bench/results/proofs.{json,md}` |
| `bench_verify.py` | **验证成本**（冷启动 CLI / vkey setup / 纯验证） | 每次 ~20 s | `bench/results/verify.{json,md}` |
| `bench_semantic.py` | **ezkl 陪伴证明的成本**（setup / prove / verify） | 真出 ezkl 证明 | `bench/results/semantic.{json,md}` |
| `bench_compose.py` | **组合证明的成本**（两半各自 prove/verify + 组合层开销） | 真出两份 SP1 证明 | `bench/results/compose.{json,md}` |
| `bench_streaming.py` | **流式路径的 `Θ(L²)` 代价**（逐字符喂真实回调；6 个包 × 3 个长度） | 全程 **~9 s**（不出证） | `bench/results/streaming.{json,md}` |
| `bench_prover_knobs.py` | **SP1 prover 旋钮矩阵**（R11）：`SP1_WORKER_*` 能否压低那条 ~10.15 GiB 的地板；另有悬崖 A/B | 每个配置一次真证明 | `bench/results/prover_knobs{,_cliff}.{json,md}` |

```bash
python3 bench/bench_cycles.py
python3 bench/bench_ablation.py
python3 bench/bench_streaming.py
SP1_PROVER=cpu python3 bench/bench_proofs.py
SP1_PROVER=cpu python3 bench/bench_verify.py --proof <proof.bin>
SP1_PROVER=cpu python3 bench/bench_compose.py
SP1_PROVER=cpu python3 bench/bench_prover_knobs.py     # 旋钮无 CLI，全在 SP1_WORKER_* 环境变量
```

> `bench_proofs.py` 另有 `--proof-mode {core,compressed,groth16,plonk}`（默认 core）与
> `--points` 口径，写法见 [`bench/README.md`](../../bench/README.md)。量测机器与模式
> 会被一并写进 `proofs.json` 的 `host` / `proof_mode` 字段 —— **这张表只在它自己的机器上成立**。

**设计要点**（都写在 `bench/README.md`，改评测前先读）：

- **语料（P2-12）**：默认 `--corpus demo` —— 把仓库里**真跑出来的**工件的 `response`
  字段（`scripts/examples/out/**`）与示例回复汇总**去重**后当扫描对象，替掉以前那串纯
  合成的 `the quick brown fox jumps`。命中规则的段落**剔除并逐条记录**
  （真实轨迹里本来就有违规的：示例里那个 `sk-…` 凭据、含 `doxxing` 的回复都会命中），
  因为本基准量的是**扫到底**的最坏情况成本，命中即短路会让数字偏低。
  语料比采样点短（372 字符）时按**平铺重复**补齐，重复倍数如实写进结果 ——
  「一段 100k 的真实文本」和「372 字符铺 269 次」是两回事，不能含糊。
- 规则数 `1/2/3/4/6`（**刻意不是 `1/3/6`**）：那三个点对应的 `(n_kw, n_pat)` 是
  `(0,0)/(1,1)/(3,2)`，两个解释变量近似成比例，拟合出的单价一正一负 —— 这是**采样设计**
  问题，加长度救不了。走 `(0,0)/(1,0)/(1,1)/(2,1)/(3,2)` 才能把两类规则解耦。
- **消融**：`match_mode="naive"`（每个起点重跑 NFA，O(n²)）对照默认 `pike`。
  naive 只在 `length ≤ 2000` 上跑（>2000 在 zkVM 内过慢）。
- `bench_cycles` 走**子进程**调 `pop-script`（而不是 import），以测真实 CLI 路径的开销。
- **两条探针**（默认开，`--no-order-probe` 关）：**顺序探针**把同一批规则换个顺序再量；
  **边际探针**补上矩阵缺的「只有正则、没有关键词」那一格。它们不是补充材料 ——
  「成本不可按规则条数相加」这条结论的直接证据就是它们（见 §3.1 末）。
- `bench_proofs` 用 `/usr/bin/time` 抓峰值 RSS；每个点跑完顺手 `--verify` 确认证明有效。
  **每个点一个独立子进程**，且**量到一个点就落一次盘**：20k 的点随时可能被 OOM 杀掉，
  不能让前面几十分钟的数据跟着消失。

### 3.1 周期数矩阵（`bench/results/cycles.md`）

完整矩阵有 40 行（6 个长度 × 5 个规则数，naive 只到 2k），这里摘长度轴上的关键点：

| length | rules | pike | naive |
|---:|---:|---:|---:|
| 200 | 1 | 65,370 | 65,370 |
| 200 | 6 | 2,070,670 | 3,038,413 |
| 2,000 | 1 | 197,825 | 197,825 |
| 2,000 | 6 | 11,805,864 | 22,008,409 |
| 10,000 | 6 | 55,028,165 | — |
| 20,000 | 6 | 109,055,864 | — |
| 50,000 | 6 | 271,177,443 | — |
| 100,000 | 6 | 541,342,069 | — |

**读法一：固定策略时，cycles 对长度是精确线性的。** 每个规则集各自拿 6 个长度点拟合，
R² 全部 ≈ **1.0000**：

| 规则数 | keyword | pattern | 斜率 (cycles/字符) | 截距 |
|---:|---:|---:|---:|---:|
| 1 | 0 | 0 | 73.9 | 50,137 |
| 2 | 1 | 0 | 105.3 | 65,942 |
| 3 | 1 | 1 | 4,289.8 | 387,501 |
| 4 | 2 | 1 | 4,048.8 | 405,785 |
| 6 | 3 | 2 | 5,403.5 | 993,257 |

⇒ 扫描成本由 **NFA 正则主导**：一条 email 正则把每字符成本从 74 抬到 4,290
（**~58×**），而一条 keyword 规则只有 **~31 cycles/字符**。规则**条数**不是主因。

**读法二（重要）：成本不能按「单价 × 规则条数」相加。** 计划里那条
`cycles ≈ a·|T|·rules + b` 被数据否掉（R² = 0.872，截距为负）；更细的按类拆开也
拟合出**负的** keyword 单价（−477 cycles/字符）。这不是测量噪声，两条探针给出机制：

- **顺序探针**（同一批规则、同一段文本，L=100k）：声明顺序 541,342,069 vs 逆序
  570,736,989 ⇒ **+5.43%**，而两次的 `passed` 完全一致 ——
  **判定语义与顺序无关，成本不是**。
- **边际探针**（补上矩阵缺的「只有正则、没有关键词」那格，L=100k）：keyword
  单独加 **+31.6 cycles/字符**；在已有正则的策略里、加在正则**之前** **+585.6**、
  加在正则**之后** **−153.7**（反而更快）。同一个「加一条 keyword 规则」，
  单价随位置在 **−154 ~ +586** 之间**变号**。

⇒ 单价是「**规则 + 上下文**」的属性，不是规则的属性。原因是 zkVM 内 `ascii_lower`
与 Pike VM 都要分配内存，而**分配器状态依赖先前的分配**。所以本仓库引用的一律是
**按规则集的斜率**（上表），不引用任何加式单价。`bench_cycles.py` 的拟合也据此改成
**两段式**（先按规则集量斜率、再解释斜率），并把残差与两条探针一起写进结果 ——
**残差是结论，不是瑕疵。**

`naive` 在非对抗输入下约 1.9× pike（2k×6：22.0M vs 11.8M）；对抗输入下见 §3.2。

### 3.2 消融：病理输入下的二次退化（`bench/results/ablation.md`）

构造：模式 `a+b`，输入 `a`×n（整段没有 `b` ⇒ 必然不匹配 ⇒ 扫到底）。
`naive` 对**每个起点**重新锚定跑一遍。用 `bench/bench_ablation.py` 复跑：

| n | pike (cycles) | naive (cycles) | 比值 | naive 每字符涨幅 |
|---:|---:|---:|---:|---:|
| 100 | 643,894 | 12,382,720 | 19.2× | — |
| 200 | 1,145,209 | 48,638,946 | 42.5× | +96.4% |
| 400 | 2,143,617 | 193,207,130 | 90.1× | +98.6% |

看**每字符成本**：n 翻倍时 pike 基本不变（−11.1%、−6.4%），naive 近乎翻倍
⇒ naive 的绝对代价是 **O(n²)**，pike 保持线性。到 n=400 时 naive 已是 pike 的 **90 倍**。
这是「策略合规匹配」这一场景下的首个消融证据（论文 §7.2）。

**这是个攻击面**：输入长度由外部决定（agent 回复、拼接会话），对手只要把回复写长，
朴素实现的成本就二次增长。
两个匹配器的**语义等价**由 `tests/test_ablation.py` 保证 —— 否则这个对比没有意义。

> 口径变更（2026-09-12）：本表上一版（24.5× / 49.4× / 99.1×）是在**旧的电路构建**上量的；
> 周期数矩阵重跑时（§3.1）发现旧构建与当前 ELF 不可比，故用固定的
> `bench/bench_ablation.py` 重新量了一次。趋势一致，绝对值不同。

### 3.3 真实证明成本与**证明侧天花板**（`bench/results/proofs.md`）

P2-12 把这一节从「三个点」扩成「一条边界」：不只量**能证的多大**，也量**从哪儿开始证不出来**。
采样点与 §3.1 的周期表共用同一份语料（`demo`，372 字符），每点**独立子进程**，OOM 如实记进表里。

| length | rules | time (s) | proof (KiB) | peak RSS (MiB) | verified | 结论 |
|---:|---:|---:|---:|---:|:--|:--|
| 200 | 1 | 123.46 | 2716.4 | 10389.4 | yes | ✓ |
| 200 | 2 | 118.89 | 2716.9 | 10438.4 | yes | ✓ |
| 2,000 | 1 | 138.11 | 2718.6 | 10448.7 | yes | ✓ |
| 10,000 | 1 | 172.50 | 2726.6 | 10506.4 | yes | ✓ |
| 200 | 3 | 87.2 | — | — | — | ✗ OOM |
| 20,000 | 1 | 87.69 | — | — | — | ✗ OOM |

**这一节最该读出来的一句：证明侧与周期侧的天花板不在同一个地方。**

- **固定地板 ~10.15 GiB**：200 字符 × 1 条规则这种最小配置就已经 10,389 MB。
  这层开销与 trace 几乎无关，是 prover 本身（`core` 证明的 trace/permutation 结构）。
  成功的四个点全落在 10,389–10,506 MB 这条带里 —— **加长度、加规则数在内存上的
  边际都很小，但缝太窄**。
- **两级台阶**（不是斜线）：1 条规则 ≤10k 字符可证；2 条规则约 200 字符可证；
  **3 条及以上出不来**。第 3 条规则恰好是 `pattern_block` —— 正则匹配激活另一族
  AIR chip，trace area 一次性抬高一截，所以规则数在 **2→3 之间断崖**；长度则在
  **10k→20k 之间断崖**。
- **卡的是内存不是 CPU**：周期表能扫到 100k 字符 × 6 条规则，因为那只跑执行不出证；
  100k 字符时周期数也才千万级，CPU 完全跑得动。

时间仍由**证明器固定开销主导**（~120–170 s 量级），证明工件稳定在 ~2.7 MiB，
与长度/规则数几乎无关（2716.4 → 2726.6 KiB）。这就是「复现需要 ≥12 GB 内存」的来源，
也是 `cross_validate.py` 必须 `--chunk` 分进程的原因（§5）。

> **可复现性口径**：墙的位置可复现（`(200,3)` 与 `(20000,1)` 各失败两次），
> **墙上的耗时不可复现**（同一组点单跑复核，时间有 ±10% 抖动，内存只有 ±1%）。
> 引用时间时给量级，不要给到小数位。

> **口径绑定（2026-09-12 起）**：上表是 **12 GB / 24 核本机 + SP1 `core`** 的表，
> 两条轴都随机器走 —— 耗时随 CPU 核数与型号，可行域随内存。所以 `bench_proofs.py`
> 现在把**核数 / CPU 型号 / 内存 / hostname** 与 `proof_mode` 一并写进 `proofs.json`、
> 并在 `proofs.md` 顶部打印；换机器（如待办 T1 的云机）重跑时**另存
> `proofs-cloud*.json` 并列呈现，不要覆盖本机这张表**。本机够不着的那半张矩阵
> （20k/50k/100k × 1/2/3/6）就是挂在 T1 租机窗口里做的 —— 它不是 T1 的阻塞项，
> 命令与跨机口径见 [`../reproduce.md`](../reproduce.md) §4½、排期见
> [`../plan-p0p1p2.md`](../plan-p0p1p2.md) §9 待办 T1。

**那条地板本身压得动吗（R11）**：上面这张表问的是「**往里加多少**还能证」。而「那条
~10.15 GiB 的**固定地板本身**能不能压低」是另一个问题 —— 答案在
[`bench/results/prover_knobs.md`](../../bench/results/prover_knobs.md)：6 轮真证明
（同一点 `(200,1)`、每轮一个独立子进程、每轮再用 `pop-script --verify` 复验一次，
首尾各跑一遍默认配置当基线）。结论是**能**，而且能说清是哪一半在起作用：

| 配置 | 动了什么 | peak RSS | 相对当轮基线 |
|---|---|---:|---:|
| `default`（基线） | — | 10,440 MiB | — |
| `few-core-workers` | **`NUM_CORE_WORKERS` 4→1** + `CORE_BUFFER_SIZE` 1 | **9,302 MiB** | **−10.90%** |
| `tiny-buffers` | 只把 7 个 `*_BUFFER_SIZE` 压到 1（**worker 数不动**）| 10,509 MiB | +0.66%（无变化）|
| `no-verify-intermediates` | `VERIFY_INTERMEDIATES=false` | 10,477 MiB | +0.36%（无变化）|

⇒ **占内存的是「同时在飞的 worker 份数」，不是通道容量**。`*_BUFFER_SIZE` 是**通道
容量（元素个数），不是字节数** —— 把它压到 1 一点没省，因为它本来就只装很少的东西。
推荐从**旋钮最少**的那一组开始：`SP1_WORKER_NUM_CORE_WORKERS=1`
`SP1_WORKER_CORE_BUFFER_SIZE=1`（只动这一项就已过 5% 门槛，动得越少越不易顺带影响
别的路径）。⚠️ **这是这台机器、这个点上的结论**，换机器要重跑；它也**只肯定/否定
这一族旋钮**，对 `SHARD_SIZE`、证明模式、换机器这些手段一个字都没说。
机制与判据的完整记录见 [`../dev-plan.md`](../dev-plan.md) §5.7.17。

**边界会跟着地板一起挪**（`bench/results/prover_knobs_cliff.md`）：把上面那张表里标
✗ OOM 的**两个悬崖点**，在**同一次调用、同一份语料**上把**两个臂都量一遍**
（`--arms`）——

| 采样点 | 默认选项（同一轮）| 推荐配置 | peak RSS |
|:--|:--|:--|---:|
| `(200, 3)`（规则数悬崖）| ✗ OOM（57 s 被杀）| **✓ 出证 + `--verify` 通过**，160.1 s | 10,763.8 MB |
| `(20 000, 1)`（长度悬崖）| ✗ OOM（62 s 被杀）| ✗ **仍然 OOM**（131 s 被杀）| — |

⇒ 省下的 ~1.1 GiB **够把一个「刚好越线」的点拉回来，不够把一个「远在界外」的点拉回来**。
所以上面那句「3 条及以上出不来」要读成**默认选项下**的结论。三张表口径各不同
（默认矩阵 / 默认旋钮实验 / 旋钮 A/B），**不要混读**，也不要拿推荐配置的行去改默认表
—— `bench_proofs.py` 的渲染里，**点不全或臂不默认**的结果**根本不出边界结论**，
就是为这条。

> **为什么非得是「同一次调用」**：`demo` 语料是 `scripts/examples/out/**` 的 glob，
> 那些产物会随举例脚本重跑而生灭 —— **同一台机器隔几天再采就是另一个 sha**
> （实测两批只差两个文件、都是 372 字符，sha 却不同：`8381462c…` vs `6a1a3431…`）。
> 所以「两臂在同一份语料上」这件事**不能靠事后比对文件来证**，只能靠**构造**保证：
> `--arms` 让两臂在同一次运行里共用**装载好的那一份**语料。这也意味着拿一份旧结果
> 去与另一份旧结果的语料 sha 对标，测的是一个**假命题**。

### 3.4 验证成本（`bench/results/verify.md`）

| proof | cold CLI (s) | vkey setup (s) | pure verify (ms) |
|---|---:|---:|---:|
| `bench/work/proof.bin` | 22.799 | 1.616 | 89.84 |

- **cold CLI** 包含构造 SP1 证明器客户端（重）—— 这是实现细节造成的，不是密码学成本；
- **pure verify** 是「vkey setup 一次 + N 次验证」，即 ~90 ms。

`pop-verify`（`05` §5）正是为了消掉 cold CLI 里的证明器构造而存在的：它只依赖 `sp1-verifier`。
`bench/results/verify.md` 里那句 “A verifier-only path … is future work” 是**写入时的状态**，
现已实现（`circuits/verifier`、`policydsl/evidence/verifier.py`）；重跑该 benchmark 可更新这一行。

### 3.5 语义规则（ezkl）的出证代价（`bench/results/semantic.md`）

P2-9 的语义规则走**另一套证明系统**（ezkl / halo2），代价必须单独测
（`bench/bench_semantic.py`，每个阶段**分进程**跑 —— 见下）：

| 阶段 | 耗时 | 峰值常驻 | 频次 |
|---|---:|---|---|
| setup | 48.2 s | 4.76 GiB | 每策略一次 |
| prove | 76.6 s（3 次中位） | 8.72 GiB，proof 40 KiB | **每条响应** |
| verify | 1.0 s | — | 每条响应 |

三个结论（也写进了 [`../design-semantic-rules.md`](../design-semantic-rules.md) §8）：

1. **`prove` 的成本落在在线路径上**：每条响应 77 s。这把语义规则定位成**离线审计/
   批量核查**的能力，不是实时护栏 —— 实时护栏仍需轻量的确定性规则。
2. **峰值 ~9 GiB**：`setup` 与 `prove` 必须**分进程**跑，否则两段峰值叠加会在
   12 GB 机器上 OOM。`bench_semantic.py` 的 `_run_phase` 就是为此存在的。
3. **入不入库**：`vk.ezkl`（802 KiB）**必须入库** —— 它是验证方唯一的凭据；
   `pk.ezkl`（2.92 GiB）与 `kzg.srs`（32 MiB）不入库（可重算）；`proof.json`（40 KiB）
   **也不入库** —— 它是**每条响应一份**的产物，随证书归档，入库的只是它的 sha256
   （写在证书的 `semantic.companions[].proof_sha256` 里）。

### 3.6 组合证明（P1-6）的成本（`bench/results/compose.md`）

组合义务 `Compose = (推理完整性 ∧ 策略合规)` 要**两份**证明，来自**两个 guest**
（不同 vkey ⇒ 键分离）。`bench/bench_compose.py` 把两半分开测（各起独立进程），
再测一次合成 + 联合验证：

| 子证明 | 程序 | zkVM 周期数 | prove | 峰值常驻 | 证明体积 | verify |
|---|---|---:|---:|---:|---:|---:|
| 策略合规 | `pop-program` | 643,610 | 127.3 s | 10.2 GiB | 2.72 MiB | 29.6 s |
| 推理完整性（代理 MLP） | `pop-infer` | 83,492 | 110.8 s | 10.0 GiB | 2.72 MiB | 34.2 s |

组合层本身是**毫秒级**（合成 5.0 ms，纯哈希/绑定比对），联合验证 53.8 s ——
主导项是两次 vkey setup，不是比对。出证顺序跑合计 238.1 s。

**两半都必须分进程**：峰值内存**不相加**（取 max ≈ 10.2 GiB）；同一进程里连出两份
会叠加到 ≈ 20 GiB 被 OOM-kill。这是组合在资源上唯一不需要加法的部分。

**计划里那句假设要如实分开看**（`compose.md` 里逐条报）：

1. **「组合成本 ≈ 两者之和」——成立**。合成与联合验证不引入额外证明。
2. **「由推理证明主导」——本机不成立**。代理模型是 16→32→4 的定点 MLP，
   周期数（8.3 万）**低于**策略那一半（64.4 万），两半都被 zkVM 的固定开销
   （setup 与证明器启动）主导。比值 0.87×，看不出成本结构。

> **所以这份实验验证的是组合机制，不是成本结构。** 代理推理证明与真实 zkAgent
> 推理证明的规模差若干个数量级（§3.6 的下一节）；换上真 prover 后「推理主导」才
> 可能成立，而那时的组合层代价仍由**同一个** `policydsl/proofs/compose.py` 承担 ——
> 毫秒级，不随子证明规模变化。

⚠️ 表里两半的 `verify` 都含**从 ELF 重推 vkey** 的 setup；验证方缓存了 vkey 就只付
一次验证器启动。改措辞想重出这份 `.md` 时用 `--render-only`（从已有 JSON 重渲染，
不再花几分钟出证）。

### 3.7 对标 zkAgent

详见 [`bench/comparison_zkagent.md`](../../bench/comparison_zkagent.md) 与论文 §7.4。
一句结论：二者**证明义务不同**（推理完整性 vs 策略合规），**不可宣称「PoP 更快」**；
正确表述是「在不涉模型的前提下，以同量级证明时间、低一个数量级的硬件、与 LogUp 相当的证明规模
完成，并补上没有的内容隐私」。

### 3.8 全量回归留痕：`bench/results/regression-prove.jsonl`（T3）

上面 3.3/3.4 是**采样点**上的量测（几个 `(长度, 规则数)`，为的是画边界）；这一节是
**全量向量**上的回归（19 条，为的是「没坏」），**两条腿**：出证 + 验证。

| | 谁在跑 | 覆盖 |
|---|---|---|
| **出证腿** | `scripts/prove/cross_validate.py`（全量 + golden 逐条比对） | 19/19 |
| **验证腿** | `pop-script --verify`，**另起进程** | **只 1 条**（见下） |

`scripts/prove/regression_prove.py` 只做**编排 + 留痕**，不重写任何一条腿的逻辑 ——
向量表与 golden 比对留在 `cross_validate`，量测口径留在 `bench_proofs`，
它再算一遍就是第二处事实来源。每次运行**追加**一行到
`bench/results/regression-prove.jsonl`：

```
ts · label · git{sha,branch,dirty} · host{hostname,cpu_model,cpu_count,mem_total_mb,platform}
   · driver{path,sha256,bytes,mtime} · chunk · vectors
   · prove_leg{ok, seconds, returncode, peak_rss_mb, host_matched/host_total, prove, log_tail}
   · verify_leg{ok, seconds, vector, proof_bytes, vkey_hash, setup_seconds, verify_times_seconds, note}
   · seconds · result
```

四条设计约束，每条都有理由：

1. **只追加，永不覆盖。** `cross_validate` 每次覆盖 `results_prove.json`，跑完就没了
   上一次；那样「这次比上次慢了多少」无从谈起，论文里的数字也指不回具体的某一次运行。
2. **验证腿是新进程。** 出证进程此时已退出，验证方手里只剩产物 + ELF —— 同进程里
   出证后顺手 `client.verify(...)`（`main.rs:417` 就有一次）是证明器在自证，不算独立验证。
3. **验证腿只覆盖 1 条，且这件事写在记录的 `note` 里。** 它要证的是「这份产物**换个人
   也能验**」这条**路径**没坏，不是把 19 份再验一遍（19 份 ≈ 1 GiB，还要再跑 19 次 vkey setup）。
4. **失败也要留证据。** OOM 被杀（本机 12 GB 上的头号死法）不会有 `RESULT` 末行 ——
   那被判 **FAIL 而不是「没跑」**，并带上 `log_tail`。⚠️ 取尾巴前必须**剥掉 `time -v` 的报告**：
   它打在子进程输出**之后**，「取末尾 30 行」会整段取到它的样板，把解释原因的 traceback
   挤出去 —— 最需要证据的那种失败，证据反而最看不见。

**首条真实记录**（`label=first-real-run`，2026-09-16，`git.sha=6927b63` 且 `dirty=false`）：

| | 数字 |
|---|---|
| 出证腿 | `host 19/19 · prove 19/19`，**2432.0 s（40.5 min）**，峰值 **10,975 MB（10.72 GiB）** |
| 验证腿 | `clean_pass` 单条：**180.4 s**（其中 vkey setup 1.87 s，实际 `--verify` 0.123 s），产物 2,782,131 B |
| 合计 | **43.6 min**，`result: PASS`；驱动 `pop-script` sha256 `a5b70e1a…`（2026-09-12 构建） |

> 峰值 10.72 GiB 与 §3.3「固定地板 10,389 MB」不矛盾：地板是**最小配置**的下限，
> 19 条混合向量按 `--chunk 2` 跑会略高，仍明显低于当初**单进程整批**的 10.65 / 10.82 GB
> （那正是被 OOM 杀掉的口径）。三个数一起读才对：分块是在地板与整批之间取的折中。
> 验证腿 180 s 里 98% 是 vkey setup 而非验证本身 —— 「验证是秒级」说的是 0.123 s 那一项。

**CI 之外定期跑**（45 min 进不了 CI，这是 T3 的前提而非妥协）：

```bash
# crontab -e —— 每周一 04:17
17 4 * * 1  cd /path/to/zk-policy && SP1_PROVER=cpu /usr/bin/python3 \
            scripts/prove/regression_prove.py --label weekly \
            >> bench/results/regression-prove.cron.log 2>&1

python3 scripts/prove/regression_prove.py --print     # 看历史摘要：几次通过、最近一次什么样
```

退出码：任一条腿 FAIL → 非 0。**`--pop-script` 可注入替身驱动**，所以整套编排逻辑
在**没有 Rust 工具链**的机器上也能被单测覆盖（`tests/test_regression_prove.py`，16 例）。

---

## 4. 不变量与边界

1. **结果文件入库**：`bench/results/*.{json,md}` 是**提交进仓库**的（供论文/文档引用），
   中间产物 `bench/work/` 被 gitignore。
2. **重跑要声明环境**：内存、CPU 核数、`SP1_PROVER` 取值都会显著影响数字；
   对比时务必确认是同一档配置（本机：24 核 / 12 GB）。
3. **naive 只在小长度上测**：这不是遗漏，是刻意的（zkVM 内 O(n²) 会失控）。
4. **测试不得依赖网络**：所有网络相关行为都要有离线回退，否则 CI 会红。
5. **测试不得依赖 SP1 证明**（除非显式声明）：默认路径是 `--check`；真实证明用例要
   `skipUnless` 二进制存在。
6. **`tests/mcp_echo_server.py` 的 `@tool` docstring 不翻译**：它会被发给模型，属于功能字符串。

---

## 5. 扩展指引

- **加测试**：优先补「负例」——正向检查容易写成恒真，反例才有价值（参考 `TestMaskCoverage`、
  `TestAnvilEndToEnd` 的反例对照）。
- **加评测点**：改 `bench_cycles.py` 的 `lengths` / `rule_counts`；`bench_proofs.py` 的采样点
  要克制（每点 ~2 分钟 + 10 GB 内存）。
- **更新论文数字**：跑完 `bench_*.py` 后，`README.md`、`paper/proof-of-policy.md` §7、
  `docs/reproduce.md` 的验收判据里都有硬编码的数字，需要一并核对。
  当前验收判据是 **783 passed / 15 skip**（2026-09-13 复跑、2026-09-16 c4 后重测、2026-09-17 `scripts/` 分组后与验收基线加入后重测、2026-09-17 R3（NFA 编译缓存）后重测、2026-09-17 P1-①（加载器对拍）后重测、2026-09-17 R4（驱动路径收敛）后重测、2026-09-17 R5（工件摘要收敛）后重测、2026-09-17 R6（kind 翻译表收敛）后重测、2026-09-17 R7（策略加载器收敛 + 包形状闸门）后重测、2026-09-18 R8–R14（拆 main / 流式等效替代 / 转移表 / 旋钮实验 / 门面 / 死代码 / 分层倒置）后重测、2026-09-18 §5.8 步 5（demo 支路表闸门，+1 例）后重测；CI 上更多 skip，见 §1）、
  `cross_validate` **`RESULT: host 19/19  prove 19/19  PASS`**（2026-09-12 整批重跑，见下）。
  这条判据现在**有自动留痕**：`scripts/prove/regression_prove.py` 每次运行把它追加进
  `bench/results/regression-prove.jsonl`（只追加），并附 git sha / 硬件 / 证明器二进制摘要
  —— 数字因此指得回具体的某一次运行，见 §13（T3）。
- **`cross_validate` 的 prove 侧怎么跑**：19 条向量各出一份真 core 证明，**必须**按
  `--chunk`（默认 4，实测 `--chunk 2` 更稳）切到**独立子进程**里跑 —— SP1 证明器的内存在同一进程内
  **逐份累积**，一口气跑完 19 条会被 OOM 杀掉（本机 12 GB，单份峰值 ~10.3 GB；
  第一次整批重跑就是这么死的：`died with <Signals.SIGKILL: 9>`）。按 2 条/进程切分后
  峰值回到单份水平，全程约 **45 分钟**（≈2.1 分钟/证明）。**别把 `--no-prove` 的末行当出证结论** ——
  它现在会显式打印 `prove SKIPPED (--no-prove)`。另：**证明期间不要并行跑任何重活**
  （整轮测试、另一个出证任务），内存余量只够一件事。

---

## 怎么用它

这里其实是**两件事**：跑测试（证明性质被守住了）、跑评测（产出论文里的数字）。

### 1. 跑测试

```bash
python3 -m unittest discover tests                # 全量：783 passed / 15 skipped，~41 s
python3 -m unittest tests.test_dsl -v             # 单个模块（哪一板块 → 见 §1 的表）
python3 -m unittest tests.test_session.TestSessionEndToEnd -v    # 单个类
```

三条纪律：

1. **⚠️ `unittest` 的 skip 是静默的绿。** 末行是 `OK (skipped=15)` —— `OK` 只说
   「没失败」，不说「都跑了」。要判断某个性质**到底被守住了没**，得看那个 skip 数，
   再看 §1.1 那张表里跳过的是不是设计内的。**这一条是本项目付出过代价的**：
   `test_generic_adapter` 的一次变异改动**等价**，其余 17 例全绿，直到补了断言才杀掉。
2. **默认这一档不需要网络、不需要 key、也不出证明**，所以可以随时跑、随便跑
   （CI 跑的就是它）。要真证明 / 真 ezkl / 真 provider 的全部是**环境变量门控** ——
   `POP_TEST_PROOF` / `POP_TEST_COMPOSE` / `POP_TEST_SESSION` / `POP_TEST_MULTIPARTY`
   / `POP_TEST_EZKL` / `POP_TEST_LLM`，逐条的「怎么启用 + 实测耗时 + 峰值内存」在 §1.1。
3. **开这些门之前先让机器腾空。** 它们每一条都要 ~10 GiB 峰值，和别的重活并跑
   必被 OOM 杀（`test_proof_service` 那一条本机实测：**腾空即过、并跑即 OOM**）。

### 2. 跑评测

| 命令 | 出什么 | 大概多久 |
|---|---|---|
| `python3 bench/bench_cycles.py` | `bench/results/cycles.{json,md}` | 每点数秒 |
| `python3 bench/bench_ablation.py` | `bench/results/ablation.{json,md}` | 每点数秒 |
| `SP1_PROVER=cpu python3 bench/bench_proofs.py [--points "200,1 2000,1"]` | `bench/results/proofs.{json,md}` | 本机每点 **119–173 s** |
| `SP1_PROVER=cpu python3 bench/bench_verify.py --proof <proof.bin>` | `bench/results/verify.{json,md}` | 每次 ~20 s |
| `python3 bench/bench_semantic.py` | `bench/results/semantic.{json,md}` | 真出 ezkl 证明 |
| `SP1_PROVER=cpu python3 bench/bench_compose.py` | `bench/results/compose.{json,md}` | 真出两份 SP1 证明 |
| `python3 bench/bench_compose.py --render-only` | 同上（只重渲染 `.md`） | 秒（改措辞时用，省掉几分钟出证） |

**`bench/work/` 是中间产物**（已 gitignore），入库的只有 `bench/results/`。

**⚠️ 改数字这件事没有自动化检查。** 跑完 bench，硬编码了同一批数字的地方**至少四处**：
`README.md`、`paper/proof-of-policy.md` §7、`docs/reproduce.md` 的验收判据、以及本文件
§3.x。它们不会自己发现不一致 —— 只能人肉核对。

**唯一有留痕的是 `cross_validate` 的判据**：`scripts/prove/regression_prove.py`
每次运行把它追加进 `bench/results/regression-prove.jsonl`（**只追加**），并附
git sha / 硬件 / 证明器二进制摘要，所以「783 passed」这类数字指得回具体的某一次运行（T3）。

## 怎么改它

| 我想改…… | 去哪 | 别忘了 |
|---|---|---|
| **加一个测试** | 放进**对应板块**的 `tests/test_<板块>.py`（§1 的表就是板块清单） | 见下「四处同步」 |
| **新增一个测试模块** | 同上，新开 `tests/test_<新板块>.py` | **四处同步 + 改本文件顶部那句「42 个模块」** |
| **加一条默认关闭的端到端** | `@unittest.skipUnless(os.environ.get("POP_TEST_XXX"), "…")` | 在 §1.1 登记：原因 / 怎么启用 / **实测耗时与峰值内存**（这三项是这张表的价值所在） |
| **加一个 bench 脚本** | 结果写 `bench/results/<name>.{json,md}`，模板抄 `bench_cycles.py`（纯标准库 + `policydsl`，不引 numpy） | §3 的表加一行 + 在 `bench/README.md` 加一条命令 |
| **改「证明模式 / 规则 kind / 契约字段」这类会动数字的东西** | 重跑对应 bench | 上面那四处硬编码数字 |

**「四处同步」清单**（改测试计数时，这四处都写着同一批数字）：

1. 本文件 §1 表的**那一行**与**合计行**；
2. 本文件**顶部**那句「42 个模块，783 个用例」；
3. 本文件 §5 扩展指引里的**验收判据**（`783 passed / 15 skip`）；
4. `docs/README.md` 的计数口径 + `README.md` / `docs/reproduce.md` 的验收判据。

（`docs/README.md` §3 已把「测试计数 → 08」写成约定：**本文件是唯一权威源**，
别处只引用不复算。所以改的时候以本文件为准，其余三处跟着改。）

### ⚠️ 写新测试时一定会再踩的三个坑

这三个都是**本项目真踩过的**，不是通用建议：

1. **「恰好对」的测量比明显错的更危险。** `test_generic_adapter` 的一处变异一度
   **存活**：把网关链改成 `[receipt]`（等价于两条链），其余 17 例全绿 —— 因为
   `trace_root` 只取**最后一条**回执的摘要，`passed` 与规则名**恰好都一样**，
   差别只在 `kind` 和「计到几条」。补了一条断言咬在 `kind`/`evidence` 上的用例才杀掉。
   **写断言时问自己：把它改坏，哪个字段会变？如果答案是「没有」，这条断言不咬人。**
2. **别写「打得太宽」的断言。** `test_proof_service` 的一条用例打的是**全进程**
   `Path.write_text`，连工作线程写的产物一起打中，约 **1/4 概率假失败**。
   （那一轮 6 处变异测试查出三件事：两件是**测试自身**的毛病，一件是真产品 bug。）
3. **断言要咬在结论上，咬「没崩」是咬不住的。** `test_policy_binding` 的
   `test_same_type` 用 `assertIs(type(a), type(b))` 而不是「都继承 `RuntimeError`」，
   并**专门配了一条反例对照**证明前两条不是恒真的（原写法确实接不住）。

```bash
# 改完测试层的两条验证
python3 -m unittest discover tests                # 783 passed / 15 skipped（数对不上先查 §1 表）
python3 -m unittest tests.test_scripts_layout     # 若动过 scripts/ 分组
```

---

**相关**：各板块覆盖了什么 → [`01`](01-policy-dsl.md)～[`07`](07-cli-scripts.md) 各文档的「测试对应」小节；
跑起来 → [`../reproduce.md`](../reproduce.md)；
8 条 demo 支路与「看到什么算对」→ [`../demo/README.md`](../demo/README.md)。
