# 全链路 demo（`scripts/demo/demo_all.sh`）

> **一条命令把项目的 8 条端到端支路跑一遍，并汇总成一份可单独读的报告。**
> 这份文档回答：每条支路在跑什么、看到什么算对、哪一条为什么没跑、
> 以及**跑完之后最容易得到的三个错误结论**。
>
> 完整的从零复现见 [`../reproduce.md`](../reproduce.md)；每条支路背后的机制见
> [`../modules/README.md`](../modules/README.md) 的板块索引。

---

## 1. 为什么需要它

这个项目有若干条端到端支路，每条都有自己的驱动脚本。问题是**没有任何一个入口能把它们串起来看一遍** ——
`demo_e2e.py` 只走「公开模式主干」这一条，其余支路各自为政。第一次读仓库的人跑完 `demo_e2e`
会以为链路已经全覆盖了。

`demo_all.sh` 本身**不重新实现任何东西**，只是按依赖顺序调用既有驱动，并如实汇总：
哪条跑了、哪条跳过了（为什么）、耗时与峰值内存、以及**哪几条是 stand-in**。

---

## 2. 怎么跑

```bash
bash scripts/demo/demo_all.sh                # fast：宿主校验，不出真证明（本机实测 13 s）
bash scripts/demo/demo_all.sh --prove        # 出真证明（每条数分钟、峰值 ~10 GB，本机实测 22.6 分钟）
bash scripts/demo/demo_all.sh --shots        # 额外跑第 9 步：把会话渲染成 HTML/SVG/PNG（见 §6）
bash scripts/demo/demo_all.sh --list         # 只列 8 条支路，不跑
bash scripts/demo/demo_all.sh --out-dir DIR  # 产物与报告落到 DIR
```

产物默认落在 `scripts/examples/out/all/`（gitignore 内），报告是 `REPORT.md`。

> ⏱ **`--prove` 的墙钟是个量级，不是常数。** 2026-09-18 这次 8 条支路合计 **22.6 分钟**
> （09:22:59 → 09:45:36，与各支路墙钟之和 1357.7 s 吻合 —— 八条**严格串行**，
> 所以墙钟 ≈ 逐条相加）；更早一轮读到 **26–27 分钟**。单条最贵的是
> **组合证明 383.6 s**，其次是会话聚合 290.5 s。出证耗时随缓存与机器负载浮动，
> 别拿它当 SLA。

**退出码**：`0` = 所有**应有**的步骤都 PASS；`1` = 有步骤 FAIL。
**跳过（缺依赖）不算失败** —— 但会在报告里单列。跳过与通过必须能分开看，
否则「全绿」会变成一句没法核对的话。

**依赖**：

- **fast 与 `--prove` 都要** `langchain-core` 和 `mcp`：支路①**真的在跑** LangChain
  的流式管线和一台上真实的 MCP stdio 服务器，不是在模拟。装法
  `pip install -r requirements-frameworks.txt`（或只装这两个）。
  ⚠️ 缺了**不会 SKIP，会直接 FAIL** —— 实测 `ImportError: blocked: mcp`
  （别信「fast 只要标准库」那类说法，它是错的）。
- **`--prove` 另要** `circuits/` 构建过（`circuits/target/release/pop-script`，
  见 [`../reproduce.md`](../reproduce.md) §2）。
- **两条支路各有独立依赖**，缺了会 **SKIP 而不是 FAIL**：语义规则要 ezkl，
  链上锚定要 foundry（`anvil`/`cast`）。

---

## 3. 8 条支路

| key | 支路 | 驱动 | 独立依赖 | 缺依赖时 |
|---|---|---|---|---|
| `policy` | 公开模式主干 | `scripts/demo/demo_e2e.py` | — | — |
| `private` | 私有模式 | `scripts/demo/private_demo.py` | — | — |
| `semantic` | 语义规则(P2-9) | `scripts/prove/ezkl_prove.py` | ezkl + `semantic/artifacts/{kzg.srs,model.compiled}` | SKIP |
| `compose` | 组合证明(P1-6) | `scripts/prove/compose_proof.py` | — | — |
| `session` | 会话聚合(P2-10) | `scripts/prove/prove_session.py` | 上游 `policy` 的 `session.json` | SKIP |
| `multiparty` | 多证明者(P2-11) | `scripts/prove/prove_multiparty.py` | — | — |
| `anchor` | 链上锚定(P7-c) | `scripts/anchor/anchor_e2e.sh` | foundry（`anvil`/`cast`） | SKIP |
| `verify` | 第三方独立验证 | `scripts/verify/verify_session.py` | 上游 `policy` 的 `session.json` | SKIP |

顺序就是执行顺序：`session` 与 `verify` 排在被依赖的 `policy` 之后。

> **还有第 9 步，但它不是支路**：`--shots` 会多跑一步「会话报告渲染」
> （`make_shots.py`，见 §6）。它不产生任何**结论**，所以 `--list` 仍列 8 条、
> 验收判据也不含它 —— 上面这张是**支路**表，不是步骤表。

### 3.1 `policy` · 公开模式主干

`demo_e2e.py` 走一条**完整的会话**：LangChain 流式回调（含真早停）+ MCP 工具调用
（参数侧与结果侧都判）+ 真 SP1 证明 + 挑战-响应绑定 + 公私模式对比 + 账本锚定。
它是 8 条里最接近「真实部署长什么样」的一条。

产物：`<out>/policy/session.json`（后面两条支路的输入）、`ledger.jsonl`、
`zk/` 与 `zk_public/`（证明与公开值）、`zk_private/`。

> ⚠️ **缺省走的是离线桩，不是真模型。** 终端会如实打出 `llm model : fake (offline)`。
> 要真模型得显式给 `--model`：`python3 scripts/demo/demo_e2e.py --model openai:<model>`。
> 始终真实的是 **callback 管线**（`PoPCallbackHandler` 跑在 LangChain 流式管线上）。

### 3.2 `private` · 私有模式

响应承诺 + 逐违规证据承诺 + 可证明脱敏（`mask_covered`）+ 证据开示。
关键判据打在 `[PASS] opening … verified=True bound_to_proof=True tamper_rejected=True`
那一行：证书能开、开出来的东西**绑到证明上**、改一个字节就被拒。

### 3.3 `semantic` · 语义规则(P2-9)

跑的是 `ezkl_prove.py selftest` —— 四条文本的端到端自检（含**同形异义**反例），
比单条出证更能说明问题。看到 `✓ 4 条全部判对（阈值 0.5；同形异义那条也被拦下）` 即为通过。

这一条的意义在于「**不在 SP1 内判定**」：语义规则被**委托**给 ezkl/halo2 陪伴证明，
验证方必须把两边的结论**合取**。它成功不等于策略被满足 —— 见
[`../design-semantic-rules.md`](../design-semantic-rules.md)。

### 3.4 `compose` · 组合证明(P1-6)

策略半 ∧ 推理半各出一份证明，两个 guest、两个 vkey，合成一张组合证书。
验的是**键分离**：两份证明必须来自**不同**的 vkey，用错键就得拒。

### 3.5 `session` · 会话聚合(P2-10)

把「公开模式主干」跑出来的一串流式证书用 **Merkle 根**聚合成一次证明，证三条义务：

1. 所有证书 `policy_hash` 完全相同；
2. 流式链无缝拼接、无缺口；
3. 覆盖完整轨迹（链尾带网关的会话末端承诺）。

日志里 `[ ok ] parity  Python == Rust（9 个公开字段逐一相等）` 是**两层对拍**那一层。
⚠️ **尾截断只有 Merkle 根拦得住** —— 前缀链的 `index`/`prev` 依然连续，电路本身会接受
一个被砍了尾巴的证书集；拦下它的是「承诺的根 vs 由交付证书重算的根」这一步。

### 3.6 `multiparty` · 多证明者(P2-11)

按规则类把策略切成三段（模型方 / 工具网关 / 部署方），每个角色用**自己的键**
对**自己那段**出证。切好的三段必须两两不交、并集为全策略，且三个角色恒存在
（空切片也要签名）。这一条还会现场演示两条验收判据的**造假**（单角色切片被换、
三方合谋改 plan），看它们确实被拒。

### 3.7 `anchor` · 链上锚定(P7-c)

起一个真的 anvil → 部署 `Anchor.sol` → 把 13 张证书的摘要上链 → 再用**独立的只读客户端**
`--rpc` 读回来核对。**fast 模式下这条也真跑链** —— 它快（约 6 秒），没有理由假装。

⚠️ **链上只锚定「证书摘要」，不验证证明。** 合约实测只有 `anchor, anchoredAt, anchoredBy,
count, isAnchored`，没有 `anchorWithProof` / `verifyProof`。链上得到的是「该摘要某时刻已存在」，
**不是**「已证明的结论」——对外说「链上可验证」是过度声明。

### 3.8 `verify` · 第三方独立验证（闭环）

`verify_session.py` **只用公开产物**（`session.json` + 账本 + 证明）复算全部结论，
不碰出证方的任何私密材料。这是整条链路唯一一处「以对手视角跑一遍」的地方，
所以它必须排在最后。

日志末行的 `RESULT: PASS` 是**证书层面**的结论（每张证书都真、绑定一致、账本对得上）。
它**不**回答「策略满足了吗」—— 这是两件事：一个 `passed=true` 但 `delegated` 非空的证明
只说明「证书为真」，不说明策略被满足。

单张证书那条路（`scripts/verify/verify_cert.py`）因此打印**两行**：`RESULT:` 说证书真不真，
`合规:` 说策略满足没满足。`verify_session.py` 只打一行 `RESULT:`，因为会话层判的是
「这一串证书自洽且都被签过」，策略满足与否要看各张证书的 outcome —— 见
[`../design-semantic-rules.md`](../design-semantic-rules.md) 的三条硬边界。

---

## 4. 三种读数陷阱

跑完这份报告，最容易得到的三个错误结论**是**什么，`demo_all.sh` 已经写在报告里了。
它们是**从产物与源码现推**的（数 ABI 里的函数名、grep demo 源码、摘安全模型的原话），
不是手写的免责声明 —— 所以不会随文档更新而漂移。

### 4.1 fast 模式下的 `PASS` 不是「已出证」

这是最容易误读的一条。各驱动在 `--no-prove` 下只做 **Python ↔ Rust 宿主对拍**：
两边算出的判定逐字段相同，但**一个字节的密码学都没算**。日志里会明确写着
`(--no-prove: skipped SP1 proof)`。

具体到每条：

| 支路 | fast 模式下 PASS 意味着 | 不意味着 |
|---|---|---|
| `policy` / `private` | 判定与承诺链路自洽 | 已出证明 |
| `semantic` | ezkl 自检的 4 条判对 | 已出陪伴证明 |
| `compose` | **不产出组合证书** —— 组合证书的输入是两份**证明**，宿主校验替代不了 | 任何组合结论 |
| `session` | 两层对拍一致 | 已出会话证明（日志原话：「不要把上面的重算当成已出证」） |
| `multiparty` | Python 参考评估与 Rust 宿主对拍一致 | 已出切片证明 |
| `anchor` | **真跑了链**（起 anvil → 部署 → 锚定 → 读回） | 链上验过证明（它只锚摘要） |
| `verify` | 公开产物自洽；`zk_proof` 卡会如实写 `unproven (host-check only)×N` | 验证过一份真证明 |

要真证明就加 `--prove`。

### 4.2 `SKIP` ≠ `FAIL`

`SKIP` 是**缺依赖**（未装 ezkl / foundry，或上游产物缺失），不代表功能不存在；
`FAIL` 是该步骤真的失败了。二者在汇总表里用不同颜色与不同文字分开，
报告里也各占一行。**别把 SKIP 读成「这条没用」，也别把它的绿读成通过。**

### 4.3 三条「演示印象 ≠ 事实」

这三条**故意**放在报告末尾，因为跑完上面 8 步之后，最自然的三个误解恰好就是它们：

1. **链上只锚定摘要，不验证证明**（见 §3.7）。
2. **流式路径缺省用离线桩，不是真模型**（见 §3.1）。接真 LLM 后仍有一个未解的口径问题：
   流式分片的切分口径跨 provider 不可比 —— 同一句话在两家 provider 下会切出不同的部分证书序列。
3. **组合证明里的「推理」是 stand-in**：那是确定性 MLP 前向，**不是**「某真实 LLM 跑过」的证据。
   组合那一步验收的是**组合机制**（两个 vkey 的键分离），不是推理的成本结构。
   这个项目的非目标里就写着「T 确由某个真实 LLM 产出」不在任何层。

报告里另附两条与「跑通了」无关、但决定能不能落地的硬约束：

- **出证的内存地板 ~10.15 GiB、一份 core 证明数分钟** → 出证只能**异步**，
  不能放进请求链路。见 [`../../bench/results/proofs.md`](../../bench/results/proofs.md)。
- **core 证明不是零知识**，响应内容隐藏对低熵 `T` 有上界（可被猜测—验证还原）。
  能主张的是「**策略**零知识」。见 [`../sp1-zk-audit.md`](../sp1-zk-audit.md) §4。

---

## 5. 产物长什么样

```
scripts/examples/out/all/
├── REPORT.md              # 汇总报告（可单独读；终端那份的落盘版，去色）
├── logs/<key>.log         # 每条支路的完整输出
├── logs/<key>.time        # /usr/bin/time 的峰值 RSS（KiB）
├── policy/                # session.json / ledger.jsonl / zk / zk_public / zk_private
├── private/               # vectors_check.json / host.json（--prove 时另有 proof.json）
├── compose/               # 两份半证明的 vectors 与宿主结果
├── session/               # run*.outcome.json
├── anchor/                # deploy.json / ledger.jsonl / session.json
├── multiparty/            # 各角色的切片与签名
└── shots/                 # 只有 --shots 才有：四份图文物（见 §6）
```

（`semantic` 那条跑的是 `ezkl_prove.py selftest`，不给 `--out-dir`，
所以没有自己的目录 —— 它的产物在 `semantic/artifacts/`。）

**八条支路的产物**都落在这个目录下，一条不漏。私有模式那条此前是个例外：
`private_demo.py` 把路径**硬编码**成 `scripts/examples/out/private`，于是它的产物
散在源码目录里。现在它有了 `--out-dir`（缺省值**不变**，单独跑还是老位置），
`demo_all.sh` 显式传 `$OUT_DIR/private`。

`REPORT.md` 顶上记着模式、生成时间、机器（核数 / CPU 型号 / 内存 GiB）——
数字因此指得回具体的某一次运行。**终端的颜色不会进报告**（落盘前先去色）。

---

## 6. 四份渲染产物（`scripts/demo/make_shots.py`）

[`demo/`](.) 目录下有四份**入库**的图文物，由 `make_shots.py` 从一次会话渲染而来
（不需要浏览器，也不需要 CJK 字体 —— PNG 的文本按设计是纯 ASCII）：

| 产物 | 是什么 |
|---|---|
| [`session_report.html`](session_report.html) | 自包含的报告页（可打开、可打印） |
| [`session_report.svg`](session_report.svg) | 矢量卡片（供查看器/转换器） |
| [`session_summary.png`](session_summary.png) | 摘要卡片（Pillow） |
| [`verify_result.png`](verify_result.png) | 第三方验证清单（Pillow） |

重新生成 —— `--session` 缺省就是 `scripts/examples/out/e2e/session.json`，
`--out-dir` 缺省就是本目录，所以两条命令就是全部：

```bash
python3 scripts/demo/demo_e2e.py --no-prove   # 先产出一份会话（缺省落 out/e2e/）
python3 scripts/demo/make_shots.py            # 再渲染四份产物到 docs/demo/
```

`demo_all.sh --shots`（§2）跑的是同一件事，只是产物落 `$OUT_DIR/shots/`，
**不动入库的这四份**。

> ⚠️ **这四份是从 `--no-prove`（宿主校验）的会话渲染的。** 摘要卡片因此写的是
> `zk proof : unproven (host-check only) passed=True` —— **档位与结论并排出现是
> 刻意的**：宿主校验同样给出 `passed`，但它**一个字节的密码学都没算**；只印一个
> `passed=True`，读的人会把「Python ↔ Rust 对拍一致」读成「出过证明了」。
> 这与 P0-4 是同一条口径（`binding.proof_mode` 如实标注证据档位）。
>
> 想要一份**带真证明**的图文物：先 `bash scripts/demo/demo_all.sh --prove`，
> 再 `python3 scripts/demo/make_shots.py --session scripts/examples/out/all/policy/session.json`。
> `--run-demo` 则让 `make_shots.py` 自己先把 demo 跑一遍。

---

## 7. 常见问题

**`policy` 报 FAIL：`ImportError: blocked: mcp`（或 `langchain_core`）。**
支路①真的在跑 LangChain 与 MCP，所以这两包是硬前置：`pip install -r
requirements-frameworks.txt`。这里**刻意不做成 SKIP** —— 少了它「公开模式主干」
这条支路根本不存在，把它降级成 SKIP 会让八条支路里最重要的那条静默缺席。

**`anchor` 报 SKIP：未装 foundry。**
跑 `bash scripts/ops/retry_install_foundry.sh`，或把 `~/.foundry/bin` 加进 `PATH`
（`demo_all.sh` 自己会追加一次 `$HOME/.foundry/bin`）。

**`semantic` 报 SKIP：缺 `kzg.srs` / `model.compiled`。**
先跑 `python3 scripts/prove/ezkl_prove.py setup`（每策略一次，约 48 秒）；
ezkl 本身没装就先跑 `bash scripts/ops/install_ezkl.sh`。

**`session` / `verify` 报 SKIP：缺上游 `session.json`。**
说明 `policy` 那一条没有成功产出。先看 `logs/policy.log` 的末几行。

**想只跑一条支路。**
直接调它的驱动脚本即可（表里的路径都是现成的）；`demo_all.sh` 的价值在**汇总**，
不在执行 —— 它不做任何额外的事。

**想换成真模型。**
`python3 scripts/demo/demo_e2e.py --model openai:<model>`，需要对应的 API key。
注意这条路径下**真的会调用外部服务**。

**报告里的耗时/内存和我看到的不一样。**
那是正常的：出证成本随响应长度、规则数、匹配模式变化，且本机内存余量只够一件事 ——
**证明期间不要并行跑任何重活**。
