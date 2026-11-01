# 论文输入 · A3 决策备忘（计数 / Ω(n²) / E-1）

> **基线**：`4fe5c41`（`merge: A4 Artifact/Docker 与一键复现`，2026-11-01）
> **分支**：`bhv/a3-decisions`；本文只记录决策与实测，不改代码、不改 `paper/tdsc-paper.tex`
> **用途**：论文 owner 按本文 §1–§3 套用到正文 / 附录；实现 owner 按 §3 的选项拆除 E-1。
> 所有「实测」都在本 worktree 完成，命令与输出摘要见各节；工作树里除本文与计数文档外无改动。

---

## 1. 测试计数：以 916 / 900 / 16 为唯一口径

### 1.1 实测（2026-11-01，基线 `4fe5c41`）

```bash
# ① 静态清点
grep -rho 'def test_' tests | wc -l
# → 916

# ② unittest 收集（不执行）
python3 - <<'PY'   # TestLoader().discover('tests', top_level_dir='.')
# → collected: 916, unique: 916
PY

# ③ 全量实跑（先按 docs/reproduce.md §2 构建 circuits）
unset OPENAI_API_KEY OPENAI_BASE_URL OPENAI_API_BASE   # 真 provider 用例保持门控
python3 -m unittest discover -s tests -t .
# → Ran 916 tests in 44.593s
# → OK (skipped=16)
```

> **本次实测的构建来源**：这个 worktree 本身没有 `circuits/target/`（构建产物
> 不入库）。为得到完整环境的数字，实测时把 `circuits/target` 指向主 checkout 的
> 已构建产物（同一基线的 `pop-script`/`pop-verify`），跑完即删除该符号链接；
> 不是重新 `cargo build`。验证其与源码匹配的旁证：acceptance baseline、
> `test_cross_layer_constants`、`test_rules_incircuit`、`test_driver_paths` 等
> 依赖真实驱动的用例全部通过。复现者按 §2 自己构建即可得到同一计数。

**结论（唯一权威口径）**：

| 指标 | 数值 | 说明 |
|---|---:|---|
| 静态 `def test_` | **916** | 48 个 `tests/test_*.py` |
| unittest 收集 | **916** | 无重名、无 `load_tests` 动态增删 |
| 实跑（`Ran`） | **916** | 完整环境（Rust 驱动 + 本地 fixture 就绪） |
| 通过 | **900** | `Ran - skipped = 916 - 16` |
| skip | **16** | 全部设计内，逐条见 `docs/modules/08-tests-bench.md` §1 |
| failure / error | **0 / 0** | |

> **口径纪律**：`Ran N … OK (skipped=k)` 中，`N` 是「跑了多少个」，不是「通过了多少个」；
> 通过数必须是 `N − k`。**skip 一律不算通过，也不算失败。**

**前置条件必须写进复现文档**：`circuits/target/release/pop-script` 与 `pop-verify`
要先构建。缺构建产物时，本 worktree 实测为
`Ran 911 … FAILED (failures=19, errors=5, skipped=83)`：
- 91 个新增 skip 来自 `skipUnless(POP_SCRIPT.exists())` / `pop-verify` / anvil / 真模型等门控；
- 19 fail + 5 error 全部指向 `pop-script` 不存在或 anvil / 真模型缺失（如
  `FileNotFoundError: …/circuits/target/release/pop-script`），**不是产品回归**；
- `Ran` 从 916 掉到 911 的原因是 `test_policy_binding` 的 5 个类级 skip：
  类整体被跳过时 unittest 只记 1 条 skip，不逐个 `startTest`，所以不进 `Ran`。
  收集数仍是 916。

### 1.2 801 / 783 / 469 的来历

三个数都是**历史快照**，不是今天的全量：

| 数字 | 时点 / 出处 | 当时 skip | 当时实际通过 | 状态 |
|---|---:|---:|---:|---|
| **469** | P2 收尾（2026-09-12，`docs/plan-p0p1p2.md`） | 13 | 456 | **历史**：P2-10/P2-11 完成时的全量 |
| **783** | 2026-09-18 §5.8 步 5 后（`modules/08` / `reproduce` 旧文） | 15 | 768 | **历史**：R3–R14 收敛后的全量 |
| **801** | 2026-09-18 `dev-plan.md` §5.1.2 落地记录（`d5461e0`） | 15 | 786 | **历史**：旧文档最后一次实测 |
| **916** | **2026-11-01，基线 `4fe5c41`（本文实测）** | **16** | **900** | **当前唯一口径** |

> 旧文档写的「783 passed / 15 skip」「801 tests / 15 skipped」都把 skip 混进了
> passed。正确读法分别是 **783 实跑 / 15 skip / 768 通过**、**801 实跑 / 15 skip /
> 786 通过**。论文 §2.2 的「801 tests with 15 skipped」因此既过期、又用了不严谨的
> 「passed」措辞，应改为：**runs 916 tests; 900 pass, 16 are skipped (all by design),
> none fail**。

自 801 之后新增的用例来自 6 个新模块与 3 个模块的扩充：

| 模块 | 新增 | 内容 |
|---|---:|---|
| `test_policy_registry` | 30 | P-PP 策略签发清单 |
| `test_transparency` | 21 | 透明日志原型 |
| `test_disclosure_levels` | 17 | L0/L1/L2 披露层级 |
| `test_fuzz_rules` | 16 | Pike vs Python `re` 差分模糊 |
| `test_receiver_nonce` | 15 | 接收方 nonce（P1-07） |
| `test_policy_commit` | 13 | 带盐策略承诺（定理 D / E4a） |
| `test_frameworks` | 53 → 67（+14） | 框架适配扩充 |
| `test_real_llm` | 13 → 17（+4） | 真模型客户端用例 |
| `test_nfa` | 7 → 10（+3） | NFA 用例补充 |
| **合计** | **783 → 916（+133）** | |

### 1.3 已同步的文档

本次已改（只改计数口径，不动其它事实）：

- `docs/modules/08-tests-bench.md`：顶部模块数/用例数、§1 命令与口径说明、逐模块表
  （补 6 个新模块、修正 3 个模块计数）、合计行、16 个 skip 表、§5 验收判据与
  「四处同步」清单；
- `docs/reproduce.md`：§1 命令注释 + §验收判据；
- `docs/development.md`：§3.1 表格/正文 + §4.2 提交前清单；
- `docs/modules/README.md`：目录树、模块表、命令速查三处。

**未改（超出 A3 硬边界，留给 owner）**：`docs/security-model.md:829`（783）、
`docs/dev-plan.md`（3 处 783/801 历史记录，其中 §5.1.2 是**当时**的落地记录，
按仓库纪律不应篡改）、`docs/report/advisor-report.md`（5 处）、
`docs/tdsc-plan.md` / `docs/tdsc-writing-plan.md`（计划文档，记录漂移本身）。
`paper/tdsc-paper.tex:323` 的 801/15 与附录 `\need{BLOCKER ... document number drift}`
由论文 owner 按 §1.2 的新口径一次改完并删除该 blocker。

---

## 2. Ω(n²)：拆成「朴素匹配器的命题」+「证明侧 DoS 的观察」

### 2.1 当前状态

- 论文 §7.2（`paper/tdsc-paper.tex:1142–1180`）**已经断言**朴素实现
  「reinvents and restarts at every start position, giving Θ(n²)」；
- 但同文 §8（`:1787`）有一条 `\need{BLOCKER}`：**证明没写**，所以草稿只把成本
  写成 observation + `tab:dos` 的实测增长，不敢称下界；
- V1 的 `bench/results/dos_proof.md` 给的是**成本增长阶的证据**：
  - 执行路径（`--execute`，不出证）：`n=100/200/400` 时 naive/pike =
    **19.2× / 42.5× / 90.1×**，naive 每字符周期近似翻倍、pike 基本不变；
  - 证明路径（core）：pike `n=100` 成功（122.2 s / 11,695 MiB），naive `n=25`
    成功（153.2 s / 12,137 MiB），naive `n=50` **OOM/SIGKILL**（226.5 s /
    13,772 MiB）；
  - 作者自己写清了边界：「本实验证明的是**成本增长阶**，不是『pike 部署下存在
    DoS』」。

### 2.2 推荐：**命题（Proposition）给朴素匹配器，Observation 给证明侧 DoS；不写系统级 Ω(n²) 定理**

理由：

1. **Θ(n²) 是「这个朴素算法」的性质，不是「策略合规匹配」的下界。** Pike VM
   在同一输入族上实测线性（每字符周期 −11.1% / −6.4%），所以任何「系统级
   Ω(n²) 下界」都是**假的**；审稿人只要指出 pike 就推翻它。
2. **但「朴素匹配器是 Θ(n²)」是能严格证明的。** 输入族 `a^n`、模式 `a+b`，
   每个起点都必须扫到串尾，计数给出闭式 `n(n+1)/2`。这是一条**关于具体算法**
   的命题，不是关于问题复杂度的下界；写成 Proposition 最准确。
3. **证明侧只能写 Observation。** 证明墙钟由 ~10 GiB 固定地板与 SP1 setup
   主导（pike n=100 也要 122 s），无法从 n=25/50 两个点反推证明复杂度的阶；
   `n=50` 的 OOM 是**资源边界**的实测，不是渐近下界。把它写成 Observation，
   用「若把 naive 当生产配置，对抗输入会把成本二次放大，并在本机 14.6 GiB
   上把证明拖进 OOM」来表述，既有力又不过度声称。

**因此建议把论文那句笼统的 Θ(n²) 拆成两层：**

- **Proposition（可证明，替代 `\need` blocker）**：naive matcher 在对抗族上是
  Θ(n²)；pike 是 Θ(n)。附 3–5 行计数证明。
- **Observation（保留实测）**：在 zkVM 证明路径上，同一对抗族把 naive 从
  `n=25` 的可证推到 `n=50` 的 OOM，而 pike 在 `n=100` 仍可证；这是**成本放大**
  的实测，不是证明复杂度的下界。

### 2.3 需要补的证明（Proposition）

设模式 `a+b`、输入 `a^n`（`n ≥ 1`，不含 `b`）。

- **上界**：对每个起点 `i ∈ {1,…,n}`，naive 从 `i` 重新锚定并逐字符推进；
  由于输入中没有 `b`，它不可能在串尾之前接受或拒绝，故第 `i` 个起点恰好做
  `n − i + 1` 步。总步数
  `W(n) = Σ_{i=1}^{n} (n−i+1) = n(n+1)/2 = Θ(n²)`。
- **下界（同一算法内）**：每个起点至少要做 `n − i + 1` 步（无 `b` ⇒ 没有任何
  提前失败/成功的条件），所以上述计数同时是 Ω；合起来是 Θ。
- **前提**：① 输入族对攻击者**可选**（响应字节由外部决定，agent 回复/拼接会话）；
  ② naive 与 pike 的**判定语义相同**——这一条已由 `tests/test_ablation.py`
  钉住（Python 与 Rust 两侧 `match_search ≡ match_search_naive`），否则周期数
  对比没有意义；③ `n` 指输入字符数，cycles 对步数是常数倍（执行路径实测每字符
  周期近似常数）。
- **不证明什么**：不证明「pike 部署存在 DoS」；不证明「任何算法都需要 Ω(n²)」；
  不证明证明侧时间的渐近阶。这三句要明确写进 Proposition 的 scope。

### 2.4 论文写法（供 owner 套用）

建议把 §7.2 的 `\need{BLOCKER ...}` 替换为（英文示意，非最终 LaTeX）：

> **Proposition (quadratic cost of the naive matcher).** For the pattern `a+b`
> and input `a^n`, the naive backtracking matcher performs
> `Σ_{i=1}^n (n−i+1) = n(n+1)/2 = Θ(n²)` NFA steps, whereas the Pike VM
> performs `Θ(n)`. The adversarial input family is admissible because the
> response bytes are chosen by the party being checked. This bounds the cost of
> *that* baseline, not of policy-compliance matching: the Pike VM is linear on
> the same family, and no lower bound for the problem is claimed.

> **Observation (prover-side amplification).** On the proving path the same
> family moves the naive baseline from a successful proof at `n=25`
> (153.2 s, 12,137 MiB) to OOM/SIGKILL at `n=50` (226.5 s, 13,772 MiB peak) on a
> 14.6 GiB machine, while Pike still proves at `n=100` (122.2 s, 11,695 MiB).
> Because the prover's ~10 GiB fixed floor dominates, these wall-clock figures
> demonstrate amplification and a resource boundary, not an asymptotic lower
> bound.

若作者**不愿补证明**：退路是「只保留测量」——删掉正文的 `Θ(n²)` 断言，只写
「naive 的每字符成本随 n 翻倍（实测 +96.4% / +98.6%），到 n=400 已是 pike 的
90.1×」。这仍然诚实，但放弃了本可以严格得到的一条结果；不推荐。

### 2.5 数据与引用口径

- 执行路径与证明路径的数字**不要混读**：前者是 `pop-script --execute`（不出证，
  周期数可比），后者是 core 证明（受 ~10 GiB 地板与机器内存支配）；
- `dos_proof.md` 的 naive 证明点只有 `n=25`（成功）与 `n=50`（OOM），
  **不要**用它拟合二次曲线；二次增长由 `ablation.md` 的 `n=100/200/400`
  执行周期与每字符涨幅支撑；
- 两个驱动不是同一构建（`dos_proof` 用 `/tmp/pop-script-v1`，sha 已记），
  周期数差约 1e-5，比值一致；引用时说明，不与 post-fix 结果混表。

---

## 3. E-1：推荐**本稿保留弱形式（选项 b）**，把强绑定列为后续工作

### 3.1 当前绑定（事实）

- 推理半的公开值里 `input_binding = IB(n, derive(T_U))`：
  `circuits/types/src/lib.rs:1509` 的 `run_infer` 调 `infer_input(&req.response)`；
- 组合验证第 7 步（`policydsl/proofs/compose.py:412`）：
  ```python
  want_input = infer.input_binding(composite.nonce,
                                   infer.input_from_response(response))
  ```
  它比对的是**由送达响应导出的输入**，`verify_composite` 的签名里**没有 `x_U`**；
- 因此当前实现证明的是
  `∃x : x = derive(T_U) ∧ T_U = M(x)`（弱形式），
  不是定理 E 的 `x = x_U`（强形式）。四格负对照的 (c) 格在
  `bench/results/composition_controls.md` 里**被接受**（`ok=True, satisfied=True`），
  正是这个缺口的实测。

> **一个必须让作者知道的事实（比 E-1 本身更容易被忽略）**：代理推理 guest 的
> 输出是 `INFER_OUT` 维定点向量（`InferOutput.output`），**不是响应字符串
> `T_U`**。所以即使把 `x_U` 绑进去，原型离论文的 `T_U = M(x_U)` 仍差一条
> 「模型输出 ↔ 送达响应」的关系（decode / 直接让模型输出即 `T_U`）。
> E-1 只覆盖「输入绑定」这一半；选项 (a) 若不补这条关系，只能宣称「C4 已落地」，
> 不能宣称「强形式已闭合」。

### 3.2 选项 (a)：落地 `x_U` / `commit(x_U)` + 验证方重算 `IB(n, x_U)`

**改动面（实现）**

| 层 | 改什么 |
|---|---|
| `circuits/types/src/lib.rs` | `InferRequest` 增 `input: Vec<i64>`（或 `input_commitment: String` + 开示）；`run_infer` 改为对 `x_U` 求 `IB` 与 `forward`，不再从 `response` 导出输入 |
| `circuits/infer-program` | 基本不动（`run_job` 仍读 `Job::Infer`）；若改 `Job`/`Outcome` 形状则 ELF 变 |
| `policydsl/proofs/infer.py` | 新增 `input_commitment` / `input_from_user`；保留 `input_from_response` 作 legacy 对照 |
| `policydsl/proofs/compose.py` | `CompositeCertificate` 增 `input` 或 `input_commitment`；`verify_composite` 增 `x_U`（或开示）参数；第 7 步改为 `IB(n, x_U)`，缺失即 **fail closed**；`build_composite` 携带该字段 |
| `scripts/prove/compose_proof.py` | 新增 `--input` / `--input-file`（或 `--input-commitment`）；**必须在出证前固定** `x_U`（C4 的时序） |
| `bench/bench_compose*.py`、`tests/test_compose.py` | 四格实验 (c) 翻转为 REJECT；新增正/负例；驱动接线 |
| 文档 | `theorem-c-e-f.md` §2.7 / E-1 改状态；`composition_controls.md` 四格表重跑 |

**vkey / 成本 / 迁移**

- **vkey 必变**：`InferRequest`（以及可能的 `Outcome`）改变 → `pop-infer` ELF
  变 → 其 vkey 变；`pop-types` 被三个 guest 共用，若 `Job`/`Outcome` 布局变化，
  `pop-program` / `pop-session` 的 vkey 也可能一起变。组合证书把 vkey 钉进
  公开值/证书，**旧组合证书全部按设计验不过**。
- **必须重做**：`POP_TEST_COMPOSE=1` 的 5 条端到端（历史实测 563.5 s）、
  `bench/bench_compose.py`（两份 ~238 s）、`bench/results/compose.{json,md}`、
  `composition_controls.{json,md}`、`scripts/examples/out` 下组合工件；
  若 `pop-program` vkey 也变，则所有策略证明工件与 `cross_validate` golden
  都要重出/重采，成本从「分钟级」升到「小时级」。
- **单次证明成本增量小**：guest 多一次 SHA-256（nonce + 16×8 B）与一次
  forward 输入替换，相对 ~10 GiB 固定地板可忽略；组合层多一次哈希，毫秒级；
  证书多 32 B（承诺）或 128 B（公开 `x_U`，16×i64）。
- **隐私**：`x_U` 可能是用户提示/私有输入，直接放公开值会泄露；若要保持私有，
  必须用「承诺 + 只对验证方开示」或 ZK 证明，设计复杂度与证明成本都要另算。
  这是 (a) 最容易被低估的一项。

**测试面（新增，估算 +6～8 例）**：`x_U = derive(T_U)` 的正例；`x_U ≠ derive(T_U)`
的 (c) 格必须 REJECT；缺 `x_U`/承诺 fail closed；承诺开示不一致；`x_U` 在 nonce
之后才固定的时序反例；旧证书（无该字段）的处理策略（fail closed 或显式 weak
模式）；两半绑不同 `x_U`；换 `x_U` 重放。`test_compose` 从 48 增至约 54–56。

### 3.3 选项 (b)：保留弱形式，论文 §7.5 明确「只证 ∃x=derive(T_U)」

**改动面**：**不改代码、不改 vkey、不重出证明**。只改论文与理论文档：

- 定理 E / Proposition 的陈述加条件：C4 **未**由当前验证器放电，结论只能是
  `∃x: x = derive(T_U) ∧ T_U = M(x)`；
- §7.5（`tdsc-paper.tex:1839` 起）逐句说明：`V_comp` 不接收 `x_U`，第 7 步用的是
  `input_from_response(T_U)`；四格 (c) 是「弱形式被接受」，**不能**称为有效组合；
- 去掉 / 降级任何「composition closes the gap」「bound to the submitted input」
  的措辞；把强形式列入 limitations / future work（E-1）；
- `composition_controls.md`、`theorem-c-e-f.md` §2.7 标为「已声明缺口」而非待修 bug。

**成本 / 迁移 / 测试**

- 实现与证明成本 **0**；无 vkey 轮换、无工件重出、无新增测试；
- 迁移仅限文档：论文、理论稿、`composition_controls.md` 的措辞；
- 风险：审稿人会问「Theorem E 的 C4 呢？」——必须把定理写成**条件命题**或
  弱形式命题，不能保留无条件强陈述；贡献从「强组合」降为「组合机制 + 诚实的
  负对照」。

### 3.4 推荐

**本稿选 (b)**：保留弱形式，论文 §7.5 明确写出
`∃x: x = derive(T_U) ∧ T_U = M(x)`，并把 C4 未落地列为 E-1（高）与 limitation。

理由（按权重）：

1. **(a) 不是一次局部改动**：`pop-types` 共用导致 vkey 可能三域齐变，组合与
   策略工件的重出/重采成本高；在本稿周期内做，容易把「已验证的论文数字」
   全部推到未验证状态。
2. **(a) 即使做完也只闭合 C4 的一半**：代理 guest 的输出向量与 `T_U` 之间
   仍没有论文要求的 `T_U = M(x_U)` 关系（见 §3.1 的提示）。只做 (a) 就宣称
   强形式，属于**过度声称**；补 output↔T_U 是另一个工作项。
3. **隐私未解**：`x_U` 明文进公开值会泄露用户输入；(a) 若同时要求保密，
   需要承诺/开示或 ZK，超出当前原型能力。
4. **(b) 与论文已有的负对照一致**：§7.5 已经把「组合不自动闭合缺口」写成
   贡献的一部分；(b) 只是把这句写得更精确，不损失已有实验价值。

**若作者决定选 (a)**：把它限定为「C4 plumbing」并同时排期
①output↔T_U 关系、②`x_U` 隐私方案、③三域 vkey 冻结与全量重出；三项齐了再在
论文里改「strong form」。不要只做公开值加字段就改结论。

### 3.5 需要作者拍板的点

1. **本稿是否声称强组合？** 是 ⇒ 必须做 (a) + output↔T_U + 隐私方案；否 ⇒ (b)。
2. **`x_U` 是否允许公开？** 公开 ⇒ 可直接放公开值；私有 ⇒ 承诺 + 开示 / ZK，
   成本与安全论证另算。
3. **能否接受 vkey 轮换？** 若 `pop-program`/`pop-session` vkey 一起变，
   策略证明工件、golden、论文所有相关数字都要重跑；预算是否允许。
4. **定理 E 的命名与陈述**：保留「定理 E」但改成条件命题（C4 为假设），还是
   降级为「Proposition（弱形式）」并把强形式写成 open problem。
5. **§7.5 的措辞**：把 (c) 格从「当前实现的缺口」改成「本稿明确不声称的
   强形式」，避免审稿人读成实现 bug。

---

## 4. 一页结论

| 议题 | 决策 | 一句话依据 |
|---|---|---|
| 测试计数 | **916 实跑 / 900 通过 / 16 skip / 0 fail**（2026-11-01，`4fe5c41`） | 801/783/469 都是历史快照；旧「passed」把 skip 算进去了 |
| Ω(n²) | **Proposition（naive matcher Θ(n²)）+ Observation（证明侧放大/OOM）**；不写系统级 Ω 定理 | Θ 是具体算法的性质，pike 实测线性；证明侧受 ~10 GiB 地板支配 |
| E-1 | **选项 (b)：保留弱形式，论文 §7.5 明确只证 ∃x=derive(T_U)** | (a) 会轮换 vkey、未解隐私，且仍缺 output↔T_U，不能单独闭合强形式 |
