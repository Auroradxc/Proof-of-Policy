# 论文主张一致性审计（A6）

> **对象**：[`../../paper/tdsc-paper.tex`](../../paper/tdsc-paper.tex)（2216 行）。
> **审计基线**：`4fe5c41`（2026-11-01，`merge: A4 Artifact/Docker 与一键复现`）；
> 分支 `bhv/a6-audit`；worktree
> `/home/dong/Proof-of-Policy/03_代码仓库/zk-policy/.claude/worktrees/agent-acabc0fd7f52ec592`。
> **本文件不改论文、代码、证明或结果**，只做主张—证据映射与修改建议。
>
> **判定记号**（全文只用文字标签，不用颜色/表情）：
> `supported`（结果文件或证明文档直接支撑）、`supported-doc`（测试/文档/提交记录支撑，不是
> `bench/results/*`）、`overclaim`（措辞强于证据）、`stale`（数字或状态过期）、
> `unsupported`（无支撑）、`pending-X1b/X2`（等云机/真实模型）、`citation-debt`（条目未核实）。

---

## 0. 执行摘要

- **总体**：§3 的定理骨架、§5 的测量数字、§7 的大部分限制陈述都能落到证明底稿或
  `bench/results/*`；问题集中在**标题/摘要的 Zero-Knowledge 口径**、**跨系统表的两个格子**、
  **end-user nonce 的实现措辞**、**策略推断语料的合成性质**，以及**测试计数/页数/引文债**。
- **计数**：P0 = 7，P1 = 19，P2 = 12。
- **最严重的五个 overclaim**（按对审稿结论的影响排序）：
  1. 标题与摘要的 `Zero-Knowledge` 主张，交付档却是 `core`（非 ZK），`groth16/plonk` 未交付（X1）。
  2. 表 `tab:baselines` 的 PoP「信任根」写 `vkey + crypto`，与 §2/§7 明写的「网关公钥仍在信任根」冲突。
  3. 同一张表把 PoP「策略隐私」写成 `witness + salt`，与 `tab:wp4` 第 3 行「证明工件通道 Open」冲突。
  4. §3.5「end-user nonce 只换签发者」：实现上 end-user 绑定是证书 challenge 块的**附加字段**，
     电路仍用 verifier 域；端到端需要改电路与 vkey。
  5. §4.2/§5 的策略推断曲线用 **11 个模板生成的合成响应**，论文正文只写「40 training and 15
     test responses per variant」，未披露语料是合成的。
- **等 X1b/X2 的项**：标题/摘要的 ZK 主张与证明工件通道、`groth16/plonk` 行、策略隐私的
  证明工件上界、§5.10 的 `k`、真实模型端到端与 XSTest 策略质量。X2 分支
  `bhv/x2-llm` 与 X1b 分支 `bhv/x1b-cloud` 均**没有**合入可引用结果；
  `bench/results/wave2_smoke/` 里的 `k_entropy`/`real_llm_e2e` 是 **stub 冒烟**，该目录
  README 明写「不是论文数字」，不能补 X2。

**基线独立复核**（2026-11-01，本 worktree）：

| 检查 | 结果 | 与论文的关系 |
|---|---|---|
| `python3 -m unittest tests.test_doc_links -v` | `Ran 4 tests ... OK` | 验收通过 |
| `python3 -m unittest discover -s tests -t .` | **911 tests collected**；本 worktree 20 F / 5 E / 83 S（缺 `pop-script`、anvil、可选依赖及环境变量所致） | 论文 §2.2 写 `801`，见 P1-06 |
| `pdflatex`（`\SKELQUIET`，非 quiet 标记被吞） | **16 pages** | 写作计划定的是 12 页上限；见 P1-17 |
| 参考文献 | 11 条；论文口径 7 条待核实，但 bibitem 实际有 **8 条**带 "to be verified"（含 PCO 作者） | 见 P1-18 |

> 本 worktree 的失败/跳过数不能当作项目质量结论：它们主要来自构建产物与本地服务缺失。
> 但**测试收集总数 911** 与论文的 `801` 不是同一口径，这一点与运行环境无关。

---

## 1. 审计方法与边界

1. 逐节抽取论文的定量/定性主张（标题、摘要、§1、§3、§4、§5、§7，并补 §2、§6、§8、
   附录与参考文献中会被审稿人当作主张的部分）。
2. 每条主张映射到：`bench/results/*`、`docs/proofs/theorem-*.md`、
   [`../certificate-binding-framework.md`](../certificate-binding-framework.md)、
   [`../blockers/*.md`](../blockers/C1.md)，或测试/提交记录。
3. 只有「结果文件/证明文档/测试记录」能支撑的才标 `supported`；只有文档叙述的标
   `supported-doc`；措辞强于证据的标 `overclaim` 并给改法。
4. 不修改任何被审计文件；本文件只新增。

---

## 2. 主张—证据映射

### 2.1 标题与摘要

| ID | 位置 | 主张 | 证据 | 判定 | 建议 / 备注 |
|---|---|---|---|---|---|
| T1 | `:88` | 标题 `Zero-Knowledge Compliance Certificates` | [`../../bench/results/proofs.md`](../../bench/results/proofs.md) 只有 `core`；[`../sp1-zk-audit.md`](../sp1-zk-audit.md) §2 明写 `core`/`compressed` 非 ZK；X1 blocker 未解除 | **overclaim（条件性）** | 除非 X1b 交付 `groth16/plonk`，改用已注释的 `Succinct` 标题，并同步摘要/§8 的 zero-knowledge 措辞（P0-1） |
| T2 | `:136-138` | `PoP provides policy-zero-knowledge: the certificate reveals neither the policy evaluation trace nor, in policy-private mode, the policy text.` | 同页 `:142-144` 自己承认 `core` 不隐藏见证；[`../blockers/C1.md`](../blockers/C1.md) 说 `core` trace 带 `spec_canonical` | **overclaim + 内部矛盾** | 改为「**public values** reveal neither ...」；证明工件单列一条通道（P0-2） |
| T3 | `:117-118` | 条件三难「below the adversary's evaluation budget, at most two of binding, hiding and public recomputability coexist」 | [`../proofs/theorem-a-b.md`](../proofs/theorem-a-b.md) §2.7 的前提还有 guess-tight、exact-recovery、PV-2、近均匀候选集 | **overclaim（漏前提）** | 摘要补「under the scheme class of §3.2 (guess-tight binding, exact-recovery hiding, PV-2)」（P1-01） |
| T4 | `:125-127` | `top-1 0.810 at rule-name → 0.073 at commitment-only, the latter at zero audit utility` | [`../../bench/results/policy_infer.md`](../../bench/results/policy_infer.md) 数字逐项一致 | `supported`（数字） / 语料范围见 P0-7 | 数字可保留；必须披露合成语料 |
| T5 | `:130-133` | `measured end to end rather than asserted` | `baseline.md`、`gateway_sig.md`、`reproduce.md` 的 14/14、19/19 | `supported-doc` | — |
| T6 | `:108-110` | `without trusted hardware` | 门限/网关仍是信任根，但无硬件信任 | `supported`（有 caveat） | 保留；§2/§7 已写网关 caveat |
| T7 | `:132-133` | 证书泄漏剖面「as a result in its own right」 | §3.3 + `tab:regimes`；但 `core` 行是源码审计，不是测量 | `supported`（论文自己已限定） | 保留 |
| T8 | `:140-142` | 上界 (i)：公开可重算绑定 ⇒ 重执行可恢复 `T` | `theorem-a-b.md` §2.11；`cor:reexec` | `supported` | — |
| T9 | `:142-145` | 上界 (ii)：`core` 不隐藏见证 | `sp1-zk-audit.md` §2；`proofs.md` | `supported` | — |
| T10 | `:145` | 上界 (iii)：无接收方新鲜性 ⇒ 可无限重放 | `theorem-c-e-f.md` 定理 C；[`../../bench/results/delivery_binding.md`](../../bench/results/delivery_binding.md) `f=0` 行 | `supported` | — |
| T11 | `:146-148` | 「§disc-zkmap states the condition」 | §7.2 | `supported` | 但标题仍先行主张，见 P0-1 |

### 2.2 §1 Introduction

| ID | 位置 | 主张 | 证据 | 判定 | 建议 / 备注 |
|---|---|---|---|---|---|
| I1 | `:169-172` | Proof-of-Guardrail `roughly 34% latency overhead` | [`../quadrant.md`](../quadrant.md) 只写「~34%（论文报告）」，无 bib；论文同页 `:193-196` 自认这些名字没有 `\cite` | **citation-debt / unsupported** | 补 PoG 原文与页码；否则删数字，只保留「有硬件依赖」（P1-02） |
| I2 | `:173-178` | Agentrust/cMCP/cA2A、Lean-Agent、zk-regex V2、VDR、ZK Email 等定位 | 无 `\cite`；[`../tdsc-fixlist.md`](../tdsc-fixlist.md) WP8 | **citation-debt** | 逐条开条目并给 bib；未核实前保留名字但不作强弱判断（P1-03） |
| I3 | `:180-191` | WITNESS「two policy primitives、no peer-reviewed paper、Apache-2.0」；`@brivora/verify` 非 ZK；「combination ... explicit vacancy」 | 无 bib；WITNESS 实现许可未在仓库内复核 | **unsupported / citation-debt** | 开 WITNESS 项目页与 `@brivora/verify` 文档；vacancy 改为「据我们扫查」并给扫查范围（P1-03） |
| I4 | `:212-216` | 贡献 1：divergent delivery 是残余缺口；接收方参与才闭合 | `thm:gap`；[`../../bench/results/delivery_binding.md`](../../bench/results/delivery_binding.md) | `supported` | — |
| I5 | `:217-224` | 贡献 2：BHV 框架、条件三难、D-privacy、组合必要条件、测量 | `theorem-a-b.md`、`theorem-c-e-f.md`、`theorem-d-g.md`、§5 | `supported` | — |
| I6 | `:225-228` | 贡献 3：`with an empty nonce the adversary's advantage is 1 regardless of every other parameter` | `delivery_binding.md` `f=0`：重放接受率 1；但 `thm:t3` 的 **divergence** 在 D2 下是 `negl` | **overclaim（主语缺失）** | 改为「**replay/acceptance** advantage is 1；under D2 the divergent-delivery advantage is only `negl`」（P1-04） |
| I7 | `:229-232` | 贡献 4：报告证书泄漏，含三披露级推断曲线 | `policy_infer.md` | `supported`（语料 caveat 见 P0-7） | — |
| I8 | `:199-208` | 「What we do not claim」（不主张绑定为零、不抢 Hollow-LLM/zk-attach、不主张 separation） | `theorem-a-b.md` §2、`rem:designated` | `supported` | 这一段是全文最稳的部分之一 |
| I9 | `:236-243` | 一条脊梁：`k_T`、`f`、`k_π`/128-bit salt | 定理 A/C/D；但 `k_T` 未实测（X2） | `supported`（`k_T` 为结构陈述） | 保留；`k_T` 的实测归 X2 |
| I10 | `:246-249` | 不主张 PoP 强于 TEE；二者正交 | §6、`baselines.md` | `supported` | — |

### 2.3 §2 System and Threat Model（与主张可信度直接相关）

| ID | 位置 | 主张 | 证据 | 判定 | 建议 / 备注 |
|---|---|---|---|---|---|
| S1 | `:264-269` | `ConstraintSpec` 是唯一跨层对象，`cross-layer drift is structurally impossible rather than merely tested against` | `policydsl/core/evaluate.py` 与 `circuits/types/src/lib.rs` 各有一套判定语义；共享的是编译后的 NFA/spec，不是判定实现；跨层靠 `tests/test_cross_validate.py` 与差分模糊 | **overclaim** | 改为「spec bytes are shared, so **spec drift** is structural; evaluator-semantics drift is guarded by 19-vector cross-validation + differential fuzz, not by construction」（P1-05） |
| S2 | `:269-282` | 八类规则、七类在电路内；`semantic_bound` 只登记 `delegated`，需合取 ezkl/halo2 陪伴证明 | `policydsl/core/model.py` 的 8 个 kind；`compile.py`；[`../../bench/results/semantic.md`](../../bench/results/semantic.md) | `supported` | — |
| S3 | `:284-298` | 工具回执链结构在电路内、Ed25519 在电路外；电路对链尾伪造盲；尾截断靠 `ToolSeal`，仍以网关公钥为条件 | [`../blockers/B1.md`](../blockers/B1.md)；`tests/test_trace.py`；[`../../bench/results/gateway_sig.md`](../../bench/results/gateway_sig.md) | `supported` | — |
| S4 | `:300-310` | 双隐私模式：private 只保证公开值无明文，不保证 `T` 不可恢复 | §7.1；`theorem-a-b.md` §3 | `supported` | — |
| S5 | `:312-318` | DSSE/Ed25519、文件账本 + 链上 32-byte digest、交叉校验 | 代码与 `tests/test_anchor*.py`、`docs/modules/04-anchoring-audit.md` | `supported-doc` | — |
| S6 | `:323-324` | `passes 801 tests with 15 skipped; the skipped set is enumerated in Appendix A` | 本基线收集 **911** tests；本 worktree 83 skipped；附录 `:2105-2152` **没有**逐条列 skip | **stale + unsupported** | 按当前 commit 重跑并改数；若保留数字，附录必须真的列 skip，或删「enumerated」（P1-06） |
| S7 | `:326-337` | Definition 1：`b=H(dom‖u32be(|n|)‖n‖T)`、`C=H(T)` | 代码与 `theorem-a-b.md` §1.2 | `supported` | — |

### 2.4 §3 Binding of Policy Proofs

| ID | 位置 | 主张 | 证据 | 判定 | 建议 / 备注 |
|---|---|---|---|---|---|
| B1 | `:409-419` | Proposition（divergent delivery） | 一页证明 + `delivery_binding.md` 的 verifier-only / end-user 对照 | `supported` | — |
| B2 | `:445-456` | 猜测熵定义取平均、可测 | `theorem-a-b.md` §0.2 | `supported` | — |
| B3 | `:467-476` | PV-1 / PV-2 区分；响应绑定满足 PV-2，salted policy commitment 不满足 | framework D9/D10；`theorem-a-b.md` §1.4 | `supported` | — |
| B4 | `:478-495` | 定理 A(1)：`q·Guess(X|Z)+negl` | `theorem-a-b.md` 命题 A.1 | `supported`（ROM） | 论文已在附录声明 ROM；保留 |
| B5 | `:493-495` | `Hiding with advantage ε therefore **needs** k_X ≥ log q + log(1/ε)` | 命题 A.1 只给**上界**；[`theory-updates.md`](theory-updates.md) A-1 明确要求改成「is certified by」 | **overclaim（把充分条件写成必要条件）** | 改为「is **certified** by the bound when ...; for a skewed distribution this is sufficient, not a matching attack」（P0-3） |
| B6 | `:503-507` | 条件三难 `cannot satisfy binding, hiding and PV-2 simultaneously` | `theorem-a-b.md` 命题 A.3 + Remark A.3′：这是**方案类内**的分类 | **overclaim（范围未限定）** | 第 (3) 条首句加「Within the scheme class defined above」（P1-07） |
| B7 | `:541-557` | guess-tight 假设必要；`β=id/encode` 反例 | `theorem-a-b.md` §2.8 | `supported` | — |
| B8 | `:559-566` | 重执行而非枚举；`k≈0` 时一次推理 | `theorem-a-b.md` §2.11；`streaming` 无关 | `supported`（`k` 实测归 X2） | — |
| B9 | `:568-582` | designated-verifier 不构成 separation | `rem:designated` + `theorem-a-b.md` §2.11 | `supported` | — |
| B10 | `:592-614` | 定理 B（泄漏剖面）`q·Guess(X|L_pub,L_proof,L_side)+negl` | `theorem-a-b.md` §3 | `supported` | 但 `tab:regimes` 缺 `n` 公开/保密两行、正文未重复「q 是求值次数」；见 P1-08 |
| B11 | `:616-646` | `tab:regimes`：`core` 行是源码审计、不是测量；`groth16/plonk` 行未测 | `theorem-a-b.md` §3.4；`sp1-zk-audit.md` | `supported`（论文自己限定） | 保留；补 `n` 行 |
| B12 | `:658-668` | `prop:semantic`：`β=encode(T)` 有损，界落在原像类 | `theorem-a-b.md` §2.9、§3；`semantic.md` | `supported` | — |
| B13 | `:687-694` | Definition（D-privacy） | framework D5；`theorem-d-g.md` §2.1、§3 | `supported` | — |
| B14 | `:696-708` | 定理 D：C1/C2/C3 充分，优势 `O(ε_pub+ε_wh+ε_com)` | `theorem-d-g.md` §5（具体为 `4ε_pub+2ε_wh+2ε_com`） | `supported` | 论文未写挑战者/优势游戏；补 2 行（P1-09） |
| B15 | `:710-725` | salted commitment，`2^128` 只作定性 | 代码 `policy_nonce`；`theorem-d-g.md` §6 | `supported` | 精确指数脚注见 P2-01 |
| B16 | `:727-736` | C2 在 `core` 失败：trace 带 `spec_canonical`，可恢复 `s` 再恢复 `π` | [`../blockers/C1.md`](../blockers/C1.md)；`sp1-zk-audit.md` | `supported` | — |
| B17 | `:741-774` | 定理 C：`\|S\|·c·2^{-f}` + `negl`；`f=0` 时可无限重放 | `theorem-c-e-f.md` 定理 C/引理 C.1/C.2 | `supported` | 论文未命名 `G_rep`/`G_del`，`\|S\|·c·2^{-f}` 的主语易被读成 divergence；见 P1-10 |
| B18 | `:787-799` | 三分类（硬件 / 接收方 nonce / prove-before-deliver），非穷尽 | `theorem-c-e-f.md` §1.6；`rem:taxonomy` | `supported` | — |
| B19 | `:801-808` | end-user nonce「mechanism is already implemented, and only the issuer of the nonce changes」 | [`../blockers/C1.md`](../blockers/C1.md)：end-user 绑定是 challenge 块**附加字段** `end_user_binding`（新域 `pop-bind-enduser-v1`），电路仍用 verifier 域 `pop-bind-v1`；端到端需改电路与 vkey | **overclaim** | 改为「certificate-layer issuer switch is implemented; putting U's nonce into the circuit public values needs a circuit change and a new vkey (open)」（P0-5） |

### 2.5 §4 Policy-Private Compliance

| ID | 位置 | 主张 | 证据 | 判定 | 建议 / 备注 |
|---|---|---|---|---|---|
| P1 | `:823-845` | 两个通道：文本是 witness，但 `policy_hash` 是公开可重算绑定 | `theorem-d-g.md` §7；`C1.md` | `supported` | — |
| P2 | `:847-880` | `tab:wp4` 七行通道与闭合状态 | `C1.md`；`sp1-zk-audit.md` | `supported` | 第 1 行「Closed」需与第 3 行「Open」互相指向（P2-03） |
| P3 | `:882-893` | L0/L1/L2 是证书层投影，不是电路级 coarsening | `C1.md` 一句话；`disclosure.py` | `supported` | — |
| P4 | `:895-899` | 推断攻击：20 变体、每变体 40 train / 15 test responses | [`../../bench/bench_policy_infer.py`](../../bench/bench_policy_infer.py) `_responses()` 用 11 个模板循环生成，**不是真实 LLM 响应**；每变体 55 条 | **overclaim（语料未披露）** | 正文与表注写明「template-generated synthetic responses; 11 templates per variant; not real LLM outputs」，或换 XSTest 真实响应重跑（P0-7） |
| P5 | `:922-930` | L1 仍泄露类别；L2 接近随机但零审计效用 | `policy_infer.md` | `supported` | — |
| P6 | `:940-944` | 「policy privacy solved」需三条通道全闭，第三条仍 blocked | `C1.md`；`sp1-zk-audit.md` | `supported` | — |
| P7 | `:946-969` | P-PP：签发权威、登记 `h_π`、持盐；「what is new ... had not been done」 | framework §7；`theorem-d-g.md` §6.6 | `supported` / 新颖性措辞 `unsupported` | 「had not been done」改为「we are not aware of this scoping in prior work」或删除（P2-04） |
| P8 | `:971-997` | 三方模型（authority/operator/third party；auditor 是实例） | framework；`docs/security-model.md` | `supported` | — |
| P9 | `:999-1006` | 策略保密来自数据流（π 不进公开值），不是 ZK；任何把 π 片段写进公开值的规则破坏保密 | `C1.md`；`tab:wp4` 4/6 | `supported` | — |
| P10 | `:1008-1047` | `tab:wp4-capability`：各方能/不能得出什么；end user 行依赖 `f>0` | `theorem-c-e-f.md`；`delivery_binding.md`；但 end-user 绑定只在证书 challenge 块 | `supported`（需加 scope） | end-user 行加「at the certificate layer; circuit still uses verifier-domain `pop-bind-v1`」（P1-11） |
| P11 | `:1049-1056` | 策略隐藏不是新原语；新意是 LLM 输出合规 + 选择性披露 + 问责张力 | 五个 bib 条目均未核实 | **citation-debt** | WP8 开条目；保留「no primacy」的措辞（P1-18） |

### 2.6 §5 Evaluation

| ID | 位置 | 主张 | 证据 | 判定 | 建议 / 备注 |
|---|---|---|---|---|---|
| E1 | `:1068-1098` | 周期矩阵、5 规则集 × 6 长度、`R²≈1.0000`、斜率/截距 | [`../../bench/results/cycles.md`](../../bench/results/cycles.md) 逐项一致 | `supported` | — |
| E2 | `:1100-1111` | 固定规则集时线性；NFA 主导；+31.6 vs +3,634（115×）；4,289.8 vs 73.9（58×） | `cycles.md` | `supported` | — |
| E3 | `:1113-1140` | 单价不可加；顺序探针 +5.43%；边际 +585.6 / −153.7；简式 `R²=0.872` 被数据反驳 | `cycles.md` | `supported` | — |
| E4 | `:1142-1180` | 消融：Pike vs naive，19.2/42.5/90.1×；每字符 −11.1%/−6.4% vs +96.4%/+98.6% | [`../../bench/results/ablation.md`](../../bench/results/ablation.md) | `supported` | — |
| E5 | `:1178-1180` | `To our knowledge this is the first ablation evidence specific to policy-compliance matching` | 无文献扫描记录 | **unsupported（新颖性）** | 改为「we are not aware of ...」或删（P2-05） |
| E6 | `:1182-1215` | 证明路径 DoS：643,906 / 12,382,732；122.2 s/11,695 MiB；153.2 s/12,137 MiB；OOM 226.5 s/13,772 MiB | [`../../bench/results/dos_proof.md`](../../bench/results/dos_proof.md) | `supported` | — |
| E7 | `:1217-1248` | 真实证明表：4 成功 + 2 OOM；2716.4–2726.6 KiB；10,389–10,506 MB | [`../../bench/results/proofs.md`](../../bench/results/proofs.md) | `supported` | `200×3` 的 87.2 s 被写成 `---`，见 P2-07 |
| E8 | `:1250-1256` | `fixed floor of ≈10.15 GiB`（几乎不随 trace 变） | `proofs.md` 是**默认 prover 选项**；[`../../bench/results/prover_knobs.md`](../../bench/results/prover_knobs.md) 的推荐旋钮把它压到 **9,302 MiB（−10.9%）** | **stale / 限定缺失** | 写「under default prover options; `NUM_CORE_WORKERS=1, CORE_BUFFER_SIZE=1` lowers it to ≈9.3 GiB (prover_knobs.md)」（P1-12） |
| E9 | `:1263-1266` | `at 100k characters the cycle count is still on the order of 10^7` | `cycles.md`：100k × 6 rules = **541,342,069**（5.4×10^8）；3 rules = 4.29×10^8 | **stale（量级错）** | 改为「10^7 for one rule, 10^8 for six rules」或直接引用 541M（P1-13） |
| E10 | `:1270-1272` | 证明 2716.4→2726.6 KiB；纯验证 ≈90 ms；vkey setup 1.5 s | [`../../bench/results/verify.md`](../../bench/results/verify.md)：89.84 ms、1.616 s | `supported`（1.5 s 为四舍五入） | 建议写 1.6 s（P2-06） |
| E11 | `:1277-1283` | session 152.5 s；multiparty 每非空切片一份证明（示例包两段） | [`../modules/08-tests-bench.md`](../modules/08-tests-bench.md)（`POP_TEST_SESSION=1`，152.5 s）；[`../modules/07-cli-scripts.md`](../modules/07-cli-scripts.md)（示例包 2 段） | `supported-doc` | 无 `bench/results` 单文件；建议在附录注明来源测试 |
| E12 | `:1298-1347` | 非 ZK 基线：0.132/2.131/0.322/0.772 ms、648 B、761 B；同钥签假内容公开路径全绿 | [`../../bench/results/baseline.md`](../../bench/results/baseline.md) | `supported` | — |
| E13 | `:1349-1387` | 组合四格；cell (c) 只证弱形式 `∃x: x=derive(T_U)`；E-1 | [`../../bench/results/composition_controls.md`](../../bench/results/composition_controls.md) | `supported` | 与证明债 E-1 一致 |
| E14 | `:1389-1425` | 网关签名表：0.058/0.094/…；2-of-3 0.173/0.508/981 B；电路内 blocked | [`../../bench/results/gateway_sig.md`](../../bench/results/gateway_sig.md) | `supported` | — |
| E15 | `:1438-1484` | 跨系统表：7 系统 × 7 维；`49 measured or cited cells` | [`../../bench/results/baselines.md`](../../bench/results/baselines.md)；49 格中 **3 格是 em dash**（Zaguk/PCO 性能） | **overclaim（计数）** | 改为「49 cells, 46 populated (measured or cited), 3 unavailable and marked —」（P2-08） |
| E16 | `:1464-1466` | PoP 信任根 `vkey + crypto [m]`（表下方并称 no hardware） | §2 明写工具回执的网关公钥仍在信任根；`gateway_sig.md` 表 a | **overclaim（与 §2/§7 冲突）** | 格内加「response/policy proofs only; tool-receipt gateway key excluded (§2)」（P0-4） |
| E17 | `:1476-1477` | PoP 策略隐私 `witness + salt [m]` | `tab:wp4` 第 3 行：证明工件通道 **Open**；`C1.md`；§7.1(iii) | **overclaim（与 §4/§7 冲突）** | 改为「public-value channel only; proof-artefact open at `core`」（P0-6） |
| E18 | `:1493-1532` | 签发：0.9948（交付框）/0.0000（日志框）；检测非阻止；split-view 外部假设 | [`../../bench/results/issuance.md`](../../bench/results/issuance.md) | `supported` | — |
| E19 | `:1534-1548` | e2e 14 证书、链上 14/14、19/19 双路径 | [`../reproduce.md`](../reproduce.md) §验收判据；`README.md` | `supported-doc` | 无 `bench/results` 单文件；建议引用 `scripts/prove/regression-prove.jsonl` |
| E20 | `:1550-1562` | §5.10 `k` 与真实模型：**未测**，协议已定 | `bench/results/` 顶层无 `k_entropy.*`/`real_llm_e2e.*`；X2 分支只有 `wave2_smoke` 的 stub 输出；无真实模型结果 | **pending-X2** | 保留 blocker；但「treat the measurement as a contribution」在交付前是贡献债（P1-19） |

### 2.7 §6 Related Work

| ID | 位置 | 主张 | 证据 | 判定 | 建议 / 备注 |
|---|---|---|---|---|---|
| R1 | `:1568-1594` | 五条 prior-art 线；代表性工作 | 多数无 bib 或条目未核实 | **citation-debt** | WP8 统一开条目（P1-18） |
| R2 | `:1605-1646` | zkAgent 对照：194.4 s/0.42 s、96 MiB、32 核/512 GB；「Cost grows with response length × rule count」 | [`../../bench/results/baselines.md`](../../bench/results/baselines.md) 数字有据；但 PoP 侧的「length × rule count」被 §5.1(3) 的实测反驳（单价不可加、R²=0.872） | **overclaim（内部矛盾）** | 改为「response length, with rule-class composition as the multiplier (not rule count)」；或写「per-rule-set slope」（P1-14） |
| R3 | `:1596-1603` | `we are not aware of prior work that quantifies the binding/hiding tradeoff in the terms of §3` | 无文献扫描记录；`theory-updates` 也未给扫查范围 | **unsupported（新颖性）** | 加「in the systems we surveyed」并给扫查表；或降为 observation（P2-05） |
| R4 | `:1658-1665` | zk-regex 的 match-offline 模式、VDR 的 bit selector 影响 | VDR bib 条目未核实；`zk-regex` 无 bib | **citation-debt** | 补两条 bib；VDR 必须用 Springer DOI（P1-18） |

### 2.8 §7 Discussion and Limitations

| ID | 位置 | 主张 | 证据 | 判定 | 建议 / 备注 |
|---|---|---|---|---|---|
| D1 | `:1684-1734` | content privacy = 公开值无明文，不是不可恢复；重执行攻击 | `theorem-a-b.md` §3；`sp1-zk-audit.md` §4 | `supported` | — |
| D2 | `:1693-1702` | SP1 官方安全模型明写单个 STARK 非 ZK；源码无盲化；shard proof 带 trace root/opening | [`../sp1-zk-audit.md`](../sp1-zk-audit.md) §2.1–2.2 | `supported-doc` | 论文自己的 `\need` 说 primary source URL 未钉；补 URL 与节号（P1-18） |
| D3 | `:1703-1708` | `groth16/plonk` 是 wrapper-level、非后量子、≥16 GB、未测 | [`../blockers/B1.md`](../blockers/B1.md)；X1；`sp1-zk-audit.md` §2.3 | `supported` | — |
| D4 | `:1710-1734` | 公开可重算绑定 = 猜测-验证 oracle；re-execution | `cor:reexec`；§3.2 | `supported` | — |
| D5 | `:1736-1745` | 策略隐私同 caliber：core artefact、L0/L1/L2 证书层、L1 仍泄露类别 | `C1.md`；`policy_infer.md` | `supported` | — |
| D6 | `:1747-1765` | ZK 只在响应或策略至少一个保密时有正价值；透明角签名足够；ZK 是 wrapper 性质 | `baseline.md`；§2/§7.1 | `supported` | — |
| D7 | `:1767-1791` | 未锚定正则的 DoS，作为观察而非 Ω(n²) 定理 | `ablation.md`、`dos_proof.md`；论文保留 `\need` 由作者决定是否升格 | `supported` | — |
| D8 | `:1793-1811` | G-1/V1-2 已修（`9ac2d59`），vkey/binary 更新 | [`../blockers/Core.md`](../blockers/Core.md) §1–5；commit `9ac2d59` | `supported` | [`../blockers/V1.md`](../blockers/V1.md) 与 [`../proofs/theorem-d-g.md`](../proofs/theorem-d-g.md) §12.3/§19 仍写「未修」，是**文档 stale**，见 P2-09 |
| D9 | `:1813-1837` | 签发不可能/条件充分/检测；日志只到 checkpoint，无 consistency/gossip | `issuance.md`；`B1.md` split-view | `supported` | F-1/F-3/F-4 未点名，见 P2-10 |
| D10 | `:1860-1872` | 组合五条件；末句只点名 C2/C4/C5 三个反例 | `theorem-c-e-f.md` §2.3 有五个反例；[`theory-updates.md`](theory-updates.md) E-1 要求五条都点名 | **overclaim（必要性举证不全）** | 末句补齐 C1/C3 反例（P1-15） |
| D11 | `:1852-1854` | `it is exactly f>0 ... with the user-submitted x playing the role of the f fresh bits` | `theorem-c-e-f.md` §2.5 明写：`x_U` 是**承诺**，不是熵源；`theory-updates` E-2 | **overclaim（熵类比错）** | 改为「the same structural role: a value the adversary cannot choose after seeing the challenge; this is commitment, not entropy」（P1-16） |
| D12 | `:1895-1912` | 网关信任仍在；电路内验签 blocked，null 不是 0 | `B1.md`；`gateway_sig.md` | `supported` | — |
| D13 | `:1914-1963` | 九条剩余限制 | 各自有代码/结果/blocker 支撑 | `supported` | — |

### 2.9 §8、附录与参考文献

| ID | 位置 | 主张 | 证据 | 判定 | 建议 / 备注 |
|---|---|---|---|---|---|
| C1 | `:1966-1980` | 一条脊梁在响应/策略/请求三侧的总结 | 定理 A/C/D | `supported` | — |
| C2 | `:1982-1987` | PoP 是分析的可构造实例，不用硬件 | §2/§7 的网关 caveat | `supported`（有 caveat） | — |
| C3 | `:1985-1987` | `explicit about the three things such a certificate does not do` | §7 有九条限制；正文没有点名「三件」 | **stale / 含糊** | 点名具体三条（建议：内容不可恢复、策略证明工件、签发完整性），或改「the limits of §7」（P2-11） |
| A1 | `:2006-2103` | 附录 A 的定理 A/D/leak/C 证明 | `theorem-a-b.md`、`theorem-c-e-f.md`、`theorem-d-g.md` | `supported` | ROM 限定已在 `\need` 中声明；保留 |
| A2 | `:2105-2137` | 复现环境、10.15 GiB 地板、哪些要 prover | `docs/reproduce.md`；`proofs.md` | `supported-doc` | 地板限定同 E8 |
| A3 | `:2145-2152` | 801 vs 783 的文档漂移；作者须定夺 | 本基线 911；`docs/development.md`/`08-tests-bench.md` 仍写 783 | **stale** | 同一 P1-06：按当前 commit 重测并统一，不要三分叉（801/783/911） |
| A4 | `:2154-2162` | WP8：除 Hollow-LLM/zkGen/zkAgent/PCO 外全部要开条目 | 实际 `pco` 的 bibitem 也写 "Author list to be verified"；另有 7 条明确占位 | **citation-debt** | 逐条开；`pco` 与 `baselines.md` 已有作者列表，可直接回填（P1-18、P2-12） |
| A5 | `:2164-2213` | 11 条参考文献 | 3 条无待核实（hollowllm/zkgen/zkagent），**8 条**带 to-be-verified（含 PCO 作者） | **citation-debt** | 同上；VDR 必须保持 Springer，不能换 ePrint 2024/813 |

---

## 3. 重点检查（任务指定的七项）

### 3.1 「Zero-Knowledge」与 policy-zero-knowledge 的上界

- **事实**：交付档是 SP1 `core`（[`../../bench/results/proofs.md`](../../bench/results/proofs.md)），
  `core`/`compressed` 不满足 ZK（[`../sp1-zk-audit.md`](../sp1-zk-audit.md) §2）；
  `groth16/plonk` 只有 wrapper-level 声明、≥16 GB、未测（X1）。
- **论文做得好的地方**：摘要 `:140-148` 与 §7.1 明确给出三条上界，并说
  「不主张 zero-knowledge 无条件成立」。这比多数同类稿诚实。
- **问题**：标题 `:88` 仍用 `Zero-Knowledge`；摘要第一句 `:136-138` 说
  「certificate reveals neither the policy evaluation trace」，与紧接着的
  `(ii) core does not hide its witness` **直接矛盾**。这是审稿人最容易抓的一句话。
- **建议**：在 X1b 交付前采用 `Succinct` 备选标题；把 `:136-138` 限定到
  **public values**；全文 `zero-knowledge` 出现处（`:88`、`:136`、`:146`、`:1343`、
  `:1744`、`:1746-1765`）做一次口径扫描。

### 3.2 `core` 非 ZK 与 `groth16` 未交付

- **证据链完整**：`sp1-zk-audit.md` §2（官方明文 + 源码审计）→ `proofs.md`（全部 `core`）
  → X1 blocker → §5.3 `\need`（无 `scale-cloud.json`）→ §7.1。
- **论文没有伪造 ZK 数字**：§5.3 明写「no zero-knowledge proving number appears anywhere」。
- **缺口**：这使标题与摘要成为**条件性主张**；`tab:regimes` 的 `groth16/plonk` 行也明确
  「unmeasured here」。这些应在投稿时与标题一起决策，而不是留两个 `\need` 给排版。

### 3.3 组合 E-1 弱形式

- **支持**：[`../../bench/results/composition_controls.md`](../../bench/results/composition_controls.md)
  的 cell (c) 明确：当前验证器只绑 `derive(T_U)`，强形式 `x=x_U` 未落地；
  `theorem-c-e-f.md` §2.7 把它登记为 E-1。
- **论文陈述**：§5.5 `:1356-1363` 与 §7.5 `:1875-1883` 都**正确**写了弱形式，且说
  「strong form is not claimed」。这是 well-supported 的诚实边界。
- **仍需补的**：`thm:composition` 末句只点名 C2/C4/C5 三个反例（P1-15）；条件 C1/C3 的
  必要性在证明底稿里有，正文没写。

### 3.4 策略私密：证书层投影还是电路级隐藏

- **结论：证书层投影，不是电路级隐藏。** [`../blockers/C1.md`](../blockers/C1.md) 一句话：
  guest 仍把 raw `rule`/`kind` 写进证明公开值；L0/L1/L2 只改证书载荷。
- **论文陈述**：§4.2 `:882-893` 与 §7.1 `:1736-1745` 明确写了这一点，`tab:wp4` 第 4/6 行
  也标 Open。这部分是 `supported`。
- **冲突**：跨系统表 `tab:baselines` 的 PoP 策略隐私格写 `witness + salt [m]`（P0-6），
  读起来像「策略隐私已交付」。必须改。
- **另**：`tab:wp4` 第 1 行「策略文本 Closed（witness）」与第 3 行「`core` artefact Open」
  需要互相指向，否则读者会以为文本在所有通道都关闭（P2-03）。

### 3.5 网关信任 / 电路内验签 blocked

- **支持**：[`../blockers/B1.md`](../blockers/B1.md) 三条原因；`gateway_sig.md` 表 b
  明写电路内三格是 `null` 不是 0；论文 §2.2 `:284-298`、§5.6、§7.6 都正确。
- **结论**：这是全文处理得最一致的一条边界；无需改 claim，只需在 `tab:baselines`
  的信任根格补 scope（P0-4）。

### 3.6 XSTest 策略质量与真实 LLM `k` 的 pending

- **真实 LLM `k`**：仍 **pending-X2**。顶层 `bench/results/` 没有 `k_entropy.*` 或
  `real_llm_e2e.*`；`bhv/x2-llm` 分支也没有可引用结果。
  `bench/results/wave2_smoke/` 的 `k_entropy.md`/`real_llm_e2e.md` **是 stub 冒烟**，
  该目录 [`../../bench/results/wave2_smoke/README.md`](../../bench/results/wave2_smoke/README.md)
  明写「不是论文数字」「不要写进论文/报告」。不能拿它补 X2。
- **XSTest 策略质量**：**已有**一个可复跑的测量
  [`../../bench/results/datasets_summary.json`](../../bench/results/datasets_summary.json)
  （由 [`../../bench/eval_datasets.py`](../../bench/eval_datasets.py) 生成）：XSTest 450 条，
  blacklist 规则 precision 0.4787 / recall 0.9 / F1 0.625；semantic demo 模型在 399 条上
  accuracy 0.5464。论文 §7.7 只说「demonstration proxy, not a usable learned guardrail」，
  **没有引用这组数字**。这不是 overclaim，而是**漏报了一个对论文有利（诚实）的结果**：
  建议在 §5 或 §7.7 报告 P/R/F1，并明确「这是策略本身的质量，不是证明系统的正确性」。
  `safety_xstest_v1.json` 的 6-prompt 端到端 P/R/F1（0.5/1.0/0.6667）是 stub 冒烟，
  **不可引用**。
- **策略推断语料**：与 XSTest 无关，是 `bench_policy_infer.py` 的模板合成响应（P0-7）。

### 3.7 测试计数 / 页数 / 引文债

- **测试计数**：论文 `801`/`15 skipped`；本基线 `discover` 收集 **911**；本 worktree
  20 F/5 E/83 S（缺构建产物与服务）。论文附录说「skipped set is enumerated」，附录没有列。
  三个数字（783/801/911）并存，必须按当前 commit 重测并统一（P1-06）。
- **页数**：写作计划 [`../tdsc-writing-plan.md`](../tdsc-writing-plan.md) §0.1/§1 记录
  TDSC 常规论文 12 页、最多 18 页（超出 $200/页），并决定「不超页」，2026-10-12 实测 11 页。
  本基线用 `\def\SKELQUIET{}` 编译两遍得 **16 页**（标记被吞，已是最短形态）。即使按
  18 页上限也在 MOPC 区；按 12 页目标已超 4 页。需要在投稿前重新排版或移在线附录（P1-17）。
- **引文债**：11 条 bib 中 **8 条**仍带 "to be verified"（论文口径说 7 条，漏了 `pco` 作者）；§1 点名的 PoG/Agentrust/cMCP/cA2A/
  Lean-Agent/zk-regex V2/ZK Email/WITNESS/`@brivora/verify`/DeepProve 多数无 `\cite`；
  `pco` 的 bibitem 与 `baselines.md` 已有作者列表不一致（P1-18、P2-12）。
- **正面**：`tests.test_doc_links` 4 例通过，文档链接层没有新增悬挂。

---

## 4. P0 必须改（7 条）

### P0-1 标题与摘要的 Zero-Knowledge 主张
- **位置**：`:88`（标题）、`:129-133`（摘要条件句）、`:146-148`、`:1744`、`:1761-1765`。
- **问题**：交付档 `core` 非 ZK，`groth16/plonk` 未测（X1）。标题先主张，摘要再补条件，
  审稿人会按标题判 overclaim。
- **建议改法**：除非 X1b 交付 `groth16/plonk`，改用注释中的
  `Proof-of-Policy: Succinct Compliance Certificates for LLM Agent Outputs`；
  摘要把 `circuit whose witness-hiding tier remains conditional` 保留，但删去
  `Zero-Knowledge` 的裸用；关键词改 `zero-knowledge proofs` 为 `succinct proofs`
  或保留并加 `(conditional)`。

### P0-2 摘要「reveals neither the policy evaluation trace」
- **位置**：`:136-138`。
- **问题**：与同段 `:142-144` 的 `core does not hide its witness` 直接矛盾；
  `core` trace 带 `spec_canonical`（[`../blockers/C1.md`](../blockers/C1.md)）。
- **建议改法**：
  > PoP provides **public-value policy privacy**: the **public values** of the certificate
  > reveal neither the policy evaluation trace nor, in policy-private mode, the policy text.
  > The proof artefact is a separate channel and is closed only by a witness-hiding tier
  > (§3.3, §7.1).
  这样既保留上界，又不再与 `(ii)` 打架。

### P0-3 定理 A(1) 的 `needs`
- **位置**：`:493-495`。
- **问题**：命题 A.1 是上界；「needs」把它读成必要条件。偏斜分布下不成立，
  与 `rem:trilemma-scope` 的口径冲突（[`theory-updates.md`](theory-updates.md) A-1）。
- **建议改法**：
  > Hiding with advantage ε is **certified** by the bound when
  > `k_X ≥ log q + log(1/ε)`; for a skewed distribution this is a sufficient condition,
  > not a matching attack.

### P0-4 跨系统表 PoP「信任根」格
- **位置**：`:1464-1466`（`tab:baselines`）。
- **问题**：格内 `vkey + crypto [m]` 与表下叙述暗示 PoP 没有网关信任；但 §2.2 `:284-298`
  和 §7.6 明写工具回执的网关公钥仍在信任根。两处结论相反。
- **建议改法**：格内改为
  `vkey + crypto for response/policy proofs; tool-receipt gateway key remains (§2.2) [m]`，
  并在表注加一句「the trust root is per obligation, not one column」。

### P0-5 end-user nonce「only the issuer changes」
- **位置**：`:801-808`。
- **问题**：[`../blockers/C1.md`](../blockers/C1.md) 明写：end-user 绑定是证书 challenge 块的
  **附加字段** `end_user_binding`（新域 `pop-bind-enduser-v1`），电路仍用 verifier 域
  `pop-bind-v1`；端到端需要把 U 的 nonce 交给电路，需改电路并重建 vkey。因此
  「only the issuer of the nonce changes」不成立。
- **建议改法**：
  > The certificate layer already supports an end-user issuer; the circuit still computes
  > `response_binding` in the verifier domain. Making `f>0` the receiver's contribution
  > end to end therefore needs a circuit change and a new vkey; until then the mechanism
  > is a certificate-layer amendment, not a drop-in issuer swap.

### P0-6 跨系统表 PoP「策略隐私」格
- **位置**：`:1476-1477`（`tab:baselines`）。
- **问题**：写 `witness + salt [m]`，与 `tab:wp4` 第 3 行「证明工件通道 Open」、
  §4.2 `:940-944`、§7.1(iii) 冲突。
- **建议改法**：格内改为
  `public-value channel closed by salt; proof-artefact channel open at core [m]`；
  或写 `partial [m]` 并在表注指向 `tab:wp4`。

### P0-7 策略推断语料未披露为合成
- **位置**：`:895-899`、`:901-920`、`:922-938`；摘要 `:125-127`。
- **问题**：[`../../bench/bench_policy_infer.py`](../../bench/bench_policy_infer.py)
  的 `_responses()` 用 11 个模板循环生成 55 条/变体（含 `#case{j}` 后缀），不是真实 LLM
  响应。论文只写「40 training and 15 test responses per variant」，读者会理解为真实语料。
  这影响摘要 headline 数字的外部效度。
- **建议改法**：在 §5.2 第一段与 `tab:policy-infer` 表注写明：
  > Responses are **template-generated synthetic strings** (11 templates per policy variant,
  > `bench_policy_infer.py::_responses`), not real LLM outputs; the curve estimates how much
  > the certificate projection leaks about the generating variant, not deployment risk.
  若 X2 能提供真实响应，优先用真实语料重跑并替换；否则保留合成并明确限定。

---

## 5. P1 建议改（19 条）

| ID | 位置 | 问题 | 建议改法 |
|---|---|---|---|
| P1-01 | `:117-118` | 摘要三难漏 guess-tight/exact-recovery/PV-2 前提 | 补「under the scheme class of §3.2 ...」 |
| P1-02 | `:169-172` | PoG 34% 无 cite | 补 PoG 原文页码；否则删数字只留「硬件依赖」 |
| P1-03 | `:173-196` | WITNESS/@brivora/lean-agent 等无 cite；vacancy 无扫查范围 | 逐条开 bib；vacancy 改为「in the systems we surveyed」 |
| P1-04 | `:225-228` | 「empty nonce advantage is 1」主语是 replay 不是 divergence | 写 `G_rep`/`G_del` 两个游戏，分别给 1 与 `negl` |
| P1-05 | `:264-269` | `cross-layer drift structurally impossible` 过强 | 区分为 spec drift（结构）与 evaluator drift（19 向量 + 差分模糊） |
| P1-06 | `:323-324`；`../tdsc-writing-plan.md` | 801/15 与基线 911 不符；附录未列 skip | 按当前 commit 重测；统一 783/801/911；附录真列 skip 或删「enumerated」 |
| P1-07 | `:503-507` | 三难(3)读成不可能性 | 首句加「Within the scheme class defined above」 |
| P1-08 | `:616-646`；`:592-614` | `tab:regimes` 缺 `n` 公开/保密两行；未重复 q 语义 | 按 [`theory-updates.md`](theory-updates.md) B-1/B-3 补两行与半句 |
| P1-09 | `:687-708` | D-privacy 定义无挑战者/优势公式 | 加 2 行：`b←{0,1}`，`Adv=|2Pr[b'=b]-1|` |
| P1-10 | `:741-774` | 定理 C 未命名 `G_rep`/`G_del`，`\|S\|c2^{-f}` 主语易混 | 按 [`theory-updates.md`](theory-updates.md) C-1 命名两个游戏 |
| P1-11 | `:1008-1047` | `tab:wp4-capability` end-user 行未限定证书层 | 加脚注「certificate-layer binding; circuit still verifier-domain」 |
| P1-12 | `:1250-1256`；`:2118` | 10.15 GiB 未限定默认 prover 选项 | 写「default options; knob config lowers to ≈9.3 GiB (prover_knobs.md)」 |
| P1-13 | `:1263-1266` | 100k 字符周期数「10^7」错（6 rules 为 5.4×10^8） | 改为「10^7 for one rule, 5.4×10^8 for six」 |
| P1-14 | `:1627-1628` | zkAgent 对照的「length × rule count」与 §5.1(3) 矛盾 | 改为「response length; rule-class composition (per-rule-set slope), not rule count」 |
| P1-15 | `:1870-1871` | 组合五条件只点名 C2/C4/C5 反例 | 按 [`theory-updates.md`](theory-updates.md) E-1 补齐 C1/C3 |
| P1-16 | `:1852-1854` | `x` 被类比为 `f` 位熵 | 改为「commitment role, not entropy」；`x_U` 可以低熵/公开 |
| P1-17 | 全文 | `\SKELQUIET` 编译 16 页；写作计划目标 12 页（最多 18，MOPC $200/页） | 重新排版/移在线附录；把页数写进投稿检查表 |
| P1-18 | `:2154-2162`；bib `:2164-2213` | **8/11** bib 的条目仍带验证标记（含 PCO 作者）；§1 多名无 cite；SP1 安全模型无 URL | WP8 逐条开条目；补 SP1 安全模型 URL/节号；VDR 保持 Springer |
| P1-19 | `:1550-1562` | 把 `k` 的测量称为 contribution，但 X2 未交付 | 改为「planned measurement; protocol fixed; no number claimed until X2」 |

---

## 6. P2 可保留（12 条）

| ID | 位置 | 问题 | 建议 |
|---|---|---|---|
| P2-01 | `:710-725` | salted 枚举只给定性，未放精确指数脚注 | 加 [`theory-updates.md`](theory-updates.md) D-2 的脚注；不要写 `2^{-(λ+128)}` |
| P2-02 | `:727-736`；`tab:wp4` 4/6 | C1 失败与表 4/6 行是同一条债，未交叉引用 | 两处互指，避免读者当两条 |
| P2-03 | `tab:wp4` 第 1/3 行 | 第 1 行「Text Closed」与第 3 行「Artefact Open」需互指 | 表注加「row 1 is the text channel only; see row 3」 |
| P2-04 | `:965-969` | 「what is new ... had not been done」新颖性措辞 | 改「we are not aware of this scoping」 |
| P2-05 | `:1178-1180`；`:1596-1603` | 「first ablation evidence」「not aware of prior work that quantifies ...」两处新颖性主张都无扫查表 | 统一降为「in the systems we surveyed」并给扫查范围，或删 |
| P2-06 | `:1272` | vkey setup 1.5 s vs `verify.md` 1.616 s | 写 1.6 s |
| P2-07 | `:1244` | `200×3` OOM 时间写 `---`，`proofs.md` 有 87.2 s | 补 87.2 s（或注明「SIGKILL at 87 s」） |
| P2-08 | `:1438-1440` | 「49 measured or cited cells」含 3 个 em dash | 改「49 cells: 46 populated, 3 unavailable」 |
| P2-09 | `:1793-1811` | 论文说 G-1/V1-2 已修，但 [`../blockers/V1.md`](../blockers/V1.md) 与 [`../proofs/theorem-d-g.md`](../proofs/theorem-d-g.md) §12.3/§19 仍写未修 | 修文档，不要改论文（论文是对的） |
| P2-10 | `:1813-1837` | F-1/F-3/F-4 三前提未点名 | 段末加三行短句，或保留叙述并加括号标签 |
| P2-11 | `:1985-1987` | 结论「three things」未点名 | 点名三条或改「the limits of §7」 |
| P2-12 | bib `pco` | `pco` 的 bibitem 写 author to be verified，但 `baselines.md` 已有 Avni/Dolev/Yagudaev/Yung | 回填作者；与 A4 的「PCO 已核实」一致 |

---

## 7. 等待 X1b / X2 的项

### 7.1 X1b（云机 ≥16 GB，`groth16/plonk` 与规模矩阵）

| 论文位置 | 现在怎么写 | 等什么 |
|---|---|---|
| 标题 `:88`、摘要 `:129-133` | `Zero-Knowledge` 条件性 | `scale-cloud.json` 证明 `groth16/plonk` 可交付；否则改 `Succinct` |
| `tab:regimes` `:629-631` | `groth16/plonk` 行标「wrapper-level; unmeasured here」 | 实测的 proof 泄漏行 / 证明大小/时间 |
| §5.3 `:1286-1296` | 明写无 ZK 数字 | 规模矩阵 rule count × length × mode × tier |
| §4.2 `tab:wp4` 第 3 行 | 证明工件通道 Open | witness-hiding 档的实测 + 策略恢复实验 |
| §7.1 `:1703-1708` | wrapper-level、非后量子、未测 | 同上 |
| `bench/results/wave2_smoke/privacy_surface.md` | 只有 `unproven`，`hiding=n/a` | `core`/`groth16` 真证明的 canary 探针 |

**状态**：`bhv/x1b-cloud` 分支在本基线**没有** `scale-cloud.*` 或 X1 blocker 结果；
不能引用。`bench/results/` 顶层也没有 `scale-cloud.*`。

### 7.2 X2（真实模型采样：`k`、真实端到端、XSTest 策略质量）

| 论文位置 | 现在怎么写 | 等什么 |
|---|---|---|
| §5.10 `:1550-1562` | 无 `k`、无阈值实例；协议已定 | 真实模型多温度采样 → `k_entropy.{json,md}` |
| `Corollary reexec` `:559-566` | `k≈0` 是结构陈述 | 实测的 `k` 分布 |
| §7.7 `:1944-1948` | semantic model 是 demo proxy | 真实 guardrail 模型质量（XSTest 已有 `datasets_summary.json` 可先引用） |
| §5.10 末句 `:1560-1562` | 把测量称为 contribution | 交付 `k` 与真实端到端后再这样写 |
| §1 贡献 4 / 摘要 | 「measured disclosure-level study」是证书层 | 若换真实语料，更新 §5.2 的数字与边界 |

**状态**：`bench/results/wave2_smoke/` 是 **stub 冒烟**，其 README 明写不可进论文；
顶层 `k_entropy.*` / `real_llm_e2e.*` 不存在；`bhv/x2-llm` 分支无可引用结果。
**XSTest 策略质量**是唯一「已有真结果但论文未用」的项：`datasets_summary.json`
（450 prompts，blacklist F1 0.625；semantic demo accuracy 0.5464）可直接引用，
但必须说明「策略质量 ≠ 证明正确性」。

---

## 8. 验收与复现

```bash
# 必跑：文档链接
python3 -m unittest tests.test_doc_links -v
# → Ran 4 tests ... OK

# 测试计数复核（本基线）
python3 -m unittest discover -s tests -t .
# → Ran 911 tests；本 worktree 20 F / 5 E / 83 S（环境缺失所致，不作为正确性判据）

# 页数复核（不写回仓库；在 /tmp 里编译）
cp paper/tdsc-paper.tex /tmp/a6build/
cd /tmp/a6build
pdflatex -interaction=nonstopmode -halt-on-error '\def\SKELQUIET{}\input{tdsc-paper.tex}'
pdflatex -interaction=nonstopmode -halt-on-error '\def\SKELQUIET{}\input{tdsc-paper.tex}'
# → Output written on tdsc-paper.pdf (16 pages)
```

**未改动清单**：`paper/tdsc-paper.tex`、`docs/proofs/*`、`docs/blockers/*`、
`bench/results/*`、`policydsl/*`、`circuits/*` 均未修改；本文件是唯一新增。
