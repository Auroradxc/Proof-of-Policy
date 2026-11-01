# TDSC 模拟审稿意见（A8 + M6 更新）

> **日期**：2026-11-01　**基线**：`1c1fc60`（M6 更新；首轮基线 `4fe5c41`）
> **审稿对象**：[`paper/tdsc-paper.tex`](../../paper/tdsc-paper.tex)（16 页稿）+ 仓库内证据文件
> **M6 更新（重要）**：首轮评审时 X1b/X2 尚未落地；现在 X1c/X1d/E1/E2/E3/A11 已有结果。
> 本文件保留首轮意见作为“审稿人看到的原稿问题”，并在 §0.1 与各条 `UPDATE` 中给出
> **新证据如何改变结论**。**论文正文未修改**；若修订稿未把新证据写进正文，审稿人仍会
> 按原稿给分。不要用“仓库里有结果”替代“论文里已报告”。
> **口径**：三名审稿人按 IEEE TDSC 常规论文标准独立评审。分数 1–10
> （1 = reject；4 = borderline reject；5 = major revision；7 = minor revision；
> 8–10 = accept）。本文件不是真实审稿意见，也不修改论文、代码、证明或结果。
> 未完成项在首轮标 `pending X1b/X2`、`blocker` 或 `open`，不编造数字；M6 后已落地的
> 项目用 `UPDATE` 覆盖，**不再**当作 pending。
> 首轮时的 **X1b** 指 X1 在 post-NFA-fix 新 vkey 上的云机重跑（现已由 X1c 完成）；
> **X2** 指真实 LLM 采样与 `k` 测量（现已由 E1/E3 部分完成）。

## 0. 汇总

| 审稿人 | 视角 | 首轮分数 | M6 更新后（前提：修订稿纳入新证据） | 一句话 |
|---|---|---:|---:|---|
| R1 | 系统 / 安全 | 5/10 | **6/10（Major Revision）** | groth16 与 EU AI Act 已交付、规模边界已量；网关信任、L2 链接性与页数使其仍非 minor |
| R2 | 理论 | 4/10 | **4/10（Major Revision）** | 新测量不改变“定理多为标准界、三难是分类”的判断；仍需定位为 framework + measurement |
| R3 | 隐私 / 实践 | 5/10 | **6/10（Major Revision）** | 真实模型/端到端已有，但 L2 承诺可链接、`core` 非 ZK、语义模型 demote 使“隐私闭环”仍不成立 |

**Meta-review（模拟，M6 更新）**：首轮的四条硬点里，**(i) ZK 交付档**与
**(ii) 规模/旗舰策略**已被 X1c/X1d 实质解决——`groth16` 18 点中 16 点 `verified=True`，
真实 `eu_ai_act_v1` 两档都过；**(iv) 真实 LLM 与 `k`** 已有 E1/E3，但受 N 截断且
不是策略质量评估。**仍未解决的是**：`core` 非 ZK、`groth16` 仅 wrapper-level、
网关仍是信任根、组合只证弱形式、策略隐私只关证书层且 **E2 暴露出 L2 承诺可链接**、
6 规则边界止于 4500 字符、语义分类器 A11 明确 demote。若修订稿把这些写入正文，
R1 可从 borderline reject 收到 Major Revision；R2 仍是 Major；R3 需要补 L2 修复与
XSTest 策略质量。当前稿（未改正文）最可能仍是 **Major Revision**。

---

## 0.1 M6 更新：最新证据与首轮问题的映射

| 新证据 | 关键数字 | 首轮哪条被改变 | 仍需保留的边界 |
|---|---|---|---|
| **X1c groth16** | 18 点 **16 ✓ / 2 OOM**；成功点 **279–344 s / 29.7–35.1 GB / verified**；`core` 地板 ~10.5 GB | R1 W1/W2、R2 Q1、R3 W1 | `groth16` 是 **wrapper-only、非后量子**；`10000×3` 两档仍 OOM |
| **X1c/X1d EU AI Act** | 真实 3 规则 `eu_ai_act_v1`：core **48.82 s / 12.38 GB / 2.79 MB**；groth16 **301.19 s / 30.07 GB / 1,874 B**；两档 `verify_cert` PASS | R1 W2、R3 W4/Q5 | 示例响应 167 字符；不是 10k 字符的旗舰点；`passed=True` 只说明该响应满足该包 |
| **X1d/X1e/X1f 6 规则边界** | 2000/3000/4000/4500 字符可行（**181.66 s / 64.2 GB** @4500）；**5000 OOM**；6 规则 groth16 未跑 | R1 W2、R3 W4 | 边界是 90 GiB cgroup 的实测，不是“6 规则不可能”；不要把 4500 写成 10000 |
| **X1d 真实响应隐私面** | core/groth16 交付物：响应整条/逐行 **0 命中**；私有输入逐行 **7/7**；策略名 1 处（公开输入） | R1 W5、R3 W1/Q2 | `canary=0` 不是 ZK 证明；`response_commitment=sha256(T)` 仍是公开 oracle |
| **E1 `k` 的 N 截断** | Qwen N=50 全 unique → **k=5.644 bit（=log2 50）**；N=20 Qwen/Mistral **4.322**；DeepSeek mean **4.242**（4 组重复）；均远低于 40 bit | R3 W1/Q3、R2 W6 | **N 截断**：全 unique 只说明未观测到重复，不能证明真实熵；不能把 5.644 当上界或下界 |
| **E2 L2 链接性** | 300 候选：L0/L1/L2 top-1 **0.500 / 0.068 / 0.382**；**L2-count-only 0.014**；承诺字典攻击 **0.207**；真实响应 L2 **0.112** | R1 W5、R3 W2/Q4 | 证书层，不是电路层；确定性 `SHA256(evidence)` 可跨样本链接，需加盐/桶级承诺 |
| **E3 DeepSeek e2e** | 6 轮、**19 证书**、第三方 11 项 PASS；回调 **10.8 ms/轮**；**无 SP1**（`unproven`） | R3 W3/W6、R1 W6 | 机制演示，不是模型合规真值；流式早停受规则粒度限制 |
| **A11 demote** | toxic 分类器：recall **0.50%**、F1 **0.010**、ROC-AUC **0.583**；ONNX 255.5 MiB | R3 W3、R2/R3 的语义主张 | 任务错配（toxic ≠ harmful request）；不能当可用 guardrail |

**一句话**：X1c/X1d 把“没有 ZK 数字、旗舰包不可证”从 decision-critical 降为
“已交付但有 wrapper/规模边界”；E1/E3 把“没有真实模型”降为“有测量但受 N 与任务限制”；
E2 反而**新增**一条隐私反对点（L2 可链接），不能只报好消息。

---

## Reviewer 1 — Systems and Security

### Summary

The paper asks a good question — what does a compliance certificate actually bind? — and
answers it with a binding–hiding–verifiability (BHV) framework, a conditional trilemma,
a policy-side D-privacy instance, and an implemented system (PoP) that compiles a small
policy DSL into an SP1 zkVM circuit. The strongest parts are the negative controls:
divergent delivery, the four-cell composition experiment, the signed-Merkle baseline,
the DoS/OOM points, and the issuance detection experiment. The paper is unusually
careful about what it does *not* claim, which this reviewer appreciates.

But TDSC asks for a dependable and secure *system* contribution, and the current draft
delivers a well-scoped analysis plus a prototype whose security-critical tier is not
the one measured. The gap between the title and the delivered artefact is the main
reason for the score.

> **UPDATE（M6）**：`groth16` 档已测量（16/18 点；EU AI Act 301.19 s / 30.07 GB /
> 1,874 B），所以“security-critical tier 未测”已过时；但 `core` 仍非 ZK、
> `groth16` 仍 wrapper-only。W1/W2 的分数前提改变，W3–W5 不变。见 §0.1。

### Strengths

1. **The problem is real and well isolated.** Divergent delivery (Proposition 1) is a
   clean statement of a gap that survives ZK and TEE, and the paper states it against
   its own design rather than as a straw man.
2. **Negative controls are first class.** Table 8 (composition) reports the failing
   cell (c) instead of hiding it; the OOM rows in Table 6 are retained as results; the
   signed-Merkle baseline is measured rather than asserted.
3. **Measurements are traceable.** Every evaluation number points to a checked-in
   `bench/results/*.md/.json` companion; the reproduction appendix names hardware and
   binary digests. This is better than most systems submissions.
4. **Scope discipline.** The abstract and §7 explicitly bound content privacy to “no
   plaintext in public values”, not unrecoverability. That is the right caliber.

### Weaknesses

**W1 (Critical) — The zero-knowledge claim is not delivered.** The title, abstract and
keywords say “Zero-Knowledge”, but every proving number in the paper is the `core`
(non-ZK) tier; the paper itself says “no zero-knowledge proving number appears anywhere
in this paper” (§5.3) and that the word must leave the title if `groth16` does not become
a delivery tier (§7.2). A TDSC reader will treat this as a title-level overclaim, even
though the text is honest. Either deliver and measure the witness-hiding tier, or
retitle to “Succinct” and remove the ZK wording from the abstract/keywords.

> **UPDATE（M6）**：witness-hiding 档已交付并有测量：
> [`scale-cloud.md`](../../bench/results/scale-cloud.md) 的 `groth16` 18 点中 16 点
> `verified=True`（279–344 s / 29.7–35.1 GB）；真实 `eu_ai_act_v1` 的 `groth16`
> 为 **301.19 s / 30.07 GB / 1,874 B**（[`eu_ai_act_proof.md`](../../bench/results/eu_ai_act_proof.md)）。
> 但这是 **wrapper-level、非后量子** 的隐藏，且 `10000×3` 仍 OOM。若修订稿保留
> “Zero-Knowledge”标题，必须在摘要/§5 写清这三个限定；否则仍应改 “Succinct”。
> 本审稿人不再把 W1 当作 title-level overclaim，前提是限定进入正文。

**W2 (Major) — Evaluation scale is too small for the claims.** On a 24-core / 12 GB
machine the default matrix proves 1 rule up to 10k characters, 2 rules at ~200
characters, and OOMs at 3 rules or 20k characters (Table 6). The flagship
`eu_ai_act_v1` policy has 3 rules including a `pattern_block`, i.e. exactly the OOM
cliff. The repo’s own knob experiment shows `(200, 3)` can succeed with
`NUM_CORE_WORKERS=1 CORE_BUFFER_SIZE=1` at 160 s / 10,764 MiB
([`prover_knobs_cliff.md`](../../bench/results/prover_knobs_cliff.md)), so the paper’s
“three or more do not come out at all” is a default-knob/12 GB statement, not a
machine-independent boundary. The paper should either prove the flagship packs with
tuned knobs or move the scale matrix to a 64–128 GB cloud machine and report it.

> **UPDATE（M6）**：规模与旗舰包问题已实质缓解，但没有消失：
> - 云机 16 核 / 90 GiB 上 `core` 与 `groth16` 矩阵 **16/18 verified**；成功点
>   `groth16` **279–344 s / 29.7–35.1 GB**（[`scale-cloud.md`](../../bench/results/scale-cloud.md)）；
> - 真实 `eu_ai_act_v1`（3 规则含 `pattern_block`）`core` **48.82 s / 12.38 GB**、
>   `groth16` **301.19 s / 30.07 GB**，两档 `verify_cert --proof --response` PASS
>   （[`eu_ai_act_proof.md`](../../bench/results/eu_ai_act_proof.md)）；
> - 6 规则 `core` 到 **4500 字符 / 181.66 s / 64.2 GB** 可行，**5000 OOM**；
>   6 规则 `groth16` 未跑（[`scale-6x4500.md`](../../bench/results/scale-6x4500.md)、
>   [`scale-6x5000.md`](../../bench/results/scale-6x5000.md)）。
>
> 因此“3+ 规则不可能”应改为“默认旋钮/90 GiB 下，3×10k 与 6×5k 不可行”；旗舰包
> 现在可证，但仍是 167 字符示例，不是 10k 字符压力点。修订稿必须把这条口径写进
> 表 caption，不能只报成功点。

**W3 (Major) — TEE comparison is not apples-to-apples.** The “TEE (sim)” column is a
trusted-server signature simulation; no hardware attestation was measured
([`baselines.md`](../../bench/results/baselines.md)). The zkAgent comparison is on
unmatched hardware (24 cores / 12 GB vs 32 cores / 512 GB) and the paper says so, but
the table still invites a “same order of magnitude” reading. A TDSC reviewer will ask
for at least one TEE baseline on the *same policy and response* with attestation cost
included, or for the comparison to be demoted to a qualitative trust table.

**W4 (Major) — Gateway trust remains in the root.** Receipt signatures are verified
off-circuit; the circuit checks only the chain structure and is blind to a forgery in
the final element (§2, §5.6). The in-circuit Ed25519 row is `blocked` with null
cycles/time/memory ([`gateway_sig.md`](../../bench/results/gateway_sig.md),
[`B1.md`](../blockers/B1.md)). The 2-of-3 prototype is host-side only and does not close
tail truncation, because two gateways can collude. This is honestly disclosed, but it
means the “without trusted hardware” claim still contains a trusted gateway key.

**W5 (Major) — Policy privacy is not landed end to end.** The salted commitment closes
only the public-value channel; the `core` artefact carries `spec_canonical` (policy and
salt), the circuit still writes raw `rule`/`kind`, `delegated` leaks structure, evidence
opening reveals the rule, L1 still has top-3 = 0.313, and L2 has zero audit utility
(§3.4, §4.1 Table 2, §4.2 Table 3). The inference study is 20 variants with a stdlib
naive Bayes classifier; it is a good shape result, not a deployment risk estimate.

> **UPDATE（M6）**：隐私面有正面证据，也有**更坏的负结果**：
> - 真实 chat 响应的交付物探针在 `core`/`groth16` 两档均为 **0 命中**
>   （响应整条与逐行），私有输入逐行 7/7（[`privacy_surface_real.md`](../../bench/results/privacy_surface_real.md)）；
> - 但 E2 用 300 候选、220 条真实响应发现 **L2 的确定性 `evidence_commitment`
>   可跨样本链接**：构造性 holdout top-1 **0.382**、真实响应 **0.112**、承诺字典
>   攻击 **0.207**；而 `L2-count-only` 只有 **0.014**
>   （[`policy_corpus_infer.md`](../../bench/results/policy_corpus_infer.md)）。
>
> 这意味着“L2 只给承诺所以不泄露”不成立；修订稿必须把 L2 的可链接性写成限制，
> 并给出加盐/桶级承诺的修复方向，不能只报 count-only 的旧数字。

**W6 (Moderate) — System novelty is thin relative to the title.** In the transparent
corner the paper concedes a signed log is enough at three to four orders of magnitude
less cost (§7.2). In the private corner the policy-private mode depends on an issuing
authority (P-PP) that holds the salt; the operator also gets the salt and can leak it.
The system is a composition of an existing zkVM, an existing compiler, and a signature
layer. That is a legitimate engineering contribution, but it should be positioned as
such rather than as a new proof system.

### Questions

- Q1. Can the authors provide any `groth16`/`plonk` number, even one point (1 rule ×
  200 chars), or retitle the paper? Without either, the title is not defensible.
  **（M6 后已可回答：16/18 点，EU AI Act 两档 PASS；见 §0.1。）**
- Q2. Why not prove `eu_ai_act_v1` under tuned knobs? If it still OOMs, what is the
  minimum machine that proves the flagship policy, and what does that imply for
  deployment?
  **（M6 后已可回答：`eu_ai_act_v1` 在 16 核/90 GiB 上 core 12.38 GB、
  groth16 30.07 GB；3×10k 仍 OOM，6 规则止于 4500 字符。）**
- Q3. What exactly does the TEE baseline attest, and on what hardware? If only a
  trusted-server signature was measured, please label it as such in the table caption.
- Q4. Has the `core` trace leakage been measured, even at source level (e.g. can a
  verifier recover `T` from `opened_values`)? The paper says “structural”, but a
  small experiment would be more convincing.
- Q5. Is the 2-of-3 gateway integrated into the certificate path, or only a host-side
  cost probe? If only a probe, please say so in the evaluation section, not only in
  the artifact notes.
- Q6. The paper reports “801 tests with 15 skipped”; the repository docs are reported
  to still say 783. Which number should a reproducer trust?
- Q7. What is the operational trust model for the policy authority (P-PP)? Who runs it,
  what happens if it colludes with the operator, and why is that better than a TEE?

### Score and decision

**Score: 5/10.** **Decision: Major Revision.** If X1 (witness-hiding tier) is not
delivered in the rebuttal period, this reviewer would move to **Reject / resubmit as a
“Succinct” system paper**. The negative controls and reproducibility are strong enough
to keep the paper alive, but the title-level ZK claim and the scale ceiling are
decision-critical.

> **UPDATE（M6）**：X1 已交付（16/18 点；EU AI Act 两档 PASS），规模边界已量。
> 若修订稿把这些数字写进 §5、保留 wrapper-only/非后量子限定，并把“3+ 规则不可能”
> 改为机器/旋钮口径，本审稿人从 5 分升到 **6/10、Major Revision**。剩余必须修的是：
> 网关信任（W4）、E2 的 L2 链接性（W5 更新）、页数与引文债；这些修完才到 Minor。
> 若正文仍只报 `core` 且不改标题，分数不升。

---

## Reviewer 2 — Theory

### Summary

The paper proposes a BHV framework in which response, request and policy are three
instances of one accounting: binding force equals the committed, adversary-non-selectable
bits. It proves a public-binding bound (Proposition 2/A), a leakage-profile decomposition
(Theorem 3/B), a delivery-binding bound (Theorem 5/C), a D-privacy theorem with a salted
commitment (Theorem 4/D), necessary conditions for composition (Proposition 6/E), and
an issuance impossibility/sufficiency pair (F); a compiler-correctness theorem (G)
exists in the repository proofs but is not in the paper. The writing is careful, the
hypotheses are explicit, and the paper repeatedly demotes claims that would be false
(e.g. the designated-verifier “separation” is withdrawn).

> **UPDATE（M6）**：新实验（groth16、6 规则边界、真实 `k`、E2/E3）增强了“framework +
> measurement”的定位，但**没有**产生新的定理或 tightness 结果；因此 W1（标准界）、
> W2（三难是分类）、W4（E-1 弱形式）和 W5（G 不在正文）的评分理由不变。新增的
> `k` 测量还带来一个理论口径问题：N 截断下 `k=log2(N)` 只是可观测上限，不能当信息论
> 界；修订稿若引用 `k`，必须在定理旁写明估计口径。本审稿人维持 **4/10**，除非作者
> 明确把论文定位从“新定理”改为“统一框架 + 策略侧实例 + 测量”，并加一张
>“standard vs new”表。

### Strengths

1. **Hypotheses are explicit and counterexamples are included.** The guess-tight
   hypothesis is necessary, and the paper shows why with `β = id` and `β = encode`
   (Remark 4). The trilemma is correctly labeled a conditional classification rather
   than an impossibility theorem (Remark 3).
2. **The policy-side instance is a genuine addition.** Observing that `policy_hash` is
   the same mathematical object as `response_binding` — a public, offline-recomputable
   function of a low-entropy secret — is the paper’s best conceptual move. The salted
   commitment is the right minimal fix, and the paper correctly says it closes only one
   channel.
3. **D-privacy fixes a real defect.** Requiring the artifact `T` to be fixed (or the
   public `T`-view to be equal) is necessary; otherwise the verifier distinguishes by
   recomputing `B(n,T)` and the game measures response leakage, not policy leakage.
4. **The composition conditions are useful engineering theory.** The four-cell
   experiment ties each condition to an observed accept/reject behavior, which is more
   than a list of assumptions.

### Weaknesses

**W1 (Critical) — Most theorems are standard bounds in new clothing.** Proposition A.1
is the standard `q · Guess(X|Z)` bound under a random oracle; Theorem B is close to the
definition of guessing entropy when `q ≥ 1` (the paper admits this); Theorem C is a
union bound over a precomputed transcript set; Theorem D is a standard five-hybrid
argument of the hidden-credentials / predicate-encryption family; Theorem E’s five
conditions are largely definitional; Theorem F’s impossibility direction is trivial
(“do nothing” wins) and its sufficiency direction is a standard transparency-log
argument plus a sampling formula. The paper’s own framework document says not to
package standard bounds as new theorems
([`certificate-binding-framework.md`](../certificate-binding-framework.md) §14). What
is new is the *unified framing*, the policy-side instance, and the measurements — not
the depth of any individual bound. A theory reviewer at TDSC will ask: what is the
strongest new theorem, and what would falsify the framework?

**W2 (Major) — The trilemma is a classification, not a theorem with bite.** Remark 3
lists six escapes (PV-1 + keyed binding + ZK, TEE, interactive/designated verifier,
high-entropy secret, relaxed hiding, `k_X = 0`). That honesty is good, but it means the
“at most two of three” statement holds only inside a carefully defined class `𝒞`. The
paper needs a tightness/necessity result or a concrete scheme outside `𝒞` that shows
the boundary is meaningful, not just a definitional partition. Otherwise the trilemma
reads as a taxonomy.

**W3 (Major) — D-privacy is incomplete as a deployed claim.** The theorem is
conditional on C1 (public-value simulation), C2 (witness-hiding), and C3 (D-hiding
commitment). In the current system C1 fails (`PrivateViolation{rule,kind}` and
`delegated` depend on `π`) and C2 fails at `core`; the paper says so, but then the
theorem’s practical content is limited to the salted public-value channel. The game
also fixes one `T` and one `n`; multi-certificate / multi-challenge composition is
mentioned only as a remark. The disclosure function `D` is not formally tied to the
L0/L1/L2 implementation, so “D-private” and “L1 certificate” are not the same object.

**W4 (Major) — E-1 means the composition theorem is not the implemented contract.**
Proposition 6/E states five necessary conditions and the paper claims the four-cell
experiment confirms them. But cell (c) shows the implementation binds
`derive(T_U)`, not the user-submitted `x_U`; the strong form `x = x_U` is not proved or
implemented (§5.5, §7.5; [`composition_controls.md`](../../bench/results/composition_controls.md);
[`theorem-c-e-f.md`](../proofs/theorem-c-e-f.md) §2.7). The paper is honest about the
weak form, but a theory reviewer will object that the theorem and the system are two
different statements. Either implement the `x_U` commitment and verifier recomputation,
or separate the theorem (ideal) from the implementation (weak form) explicitly in the
statement, not only in the discussion.

> **UPDATE（M6）**：E-1 **仍未闭合**；本轮没有实现 `x_U` 承诺或验证方重算，也没有
> 改电路/vkey。修订稿继续只能写弱形式，并把“strong form = open”放在定理陈述层，
> 不能只放在 §7.5。

**W5 (Moderate) — Theorem G is absent from the paper.** The repository proofs contain a
three-part compiler-correctness theorem (language preservation, Pike search semantics,
Python/Rust bisimulation), but the paper only mentions the NFA contract in §2 and the
two implementation defects in §7.3. If the paper wants credit for a verified compiler,
it must state G and its assumptions; if not, it should avoid implying compiler
correctness beyond the differential tests. The actual Rust code layer is supported by
differential fuzzing, not by the paper’s proof.

**W6 (Moderate) — Random-oracle heuristic and the `q` accounting need a cleaner
statement.** The paper correctly says the bounds are ROM heuristics and that `q` counts
`β` evaluations, not time. But the `negl(λ)` absorption and the SHA-256 instantiation
loss are not quantified, and the `q`-unbounded case is relegated to a sentence. A
theory reviewer will want a table of “standard model vs ROM”, “bounded vs unbounded
`q`”, and “exact recovery vs consistency” for each theorem.

### Questions

- Q1. What is the single strongest *new* theorem in the paper, stated without the
  framework vocabulary? If the answer is “the policy-side instance”, what is the
  minimal counterexample that shows the old two-sided account missed it?
- Q2. Can the trilemma be strengthened to a tightness statement, or is it by design
  only a classification? If only a classification, why is it a proposition rather than
  a definition plus an observation?
- Q3. How does the formal `D` in Definition 4 relate to the implemented L0/L1/L2?
  Please give the mapping table, including which fields each level suppresses.
- Q4. Does D-privacy compose across multiple certificates and challenges? If not, what
  is the failure mode?
- Q5. Why is E a theorem rather than a set of necessary conditions? Which condition is
  non-obvious enough to require proof?
- Q6. Will G be integrated into the paper, or is it future work? If integrated, what
  are A-G1–A-G5 and what does the Rust differential campaign cover?
- Q7. What would falsify the BHV framework? A concrete adversarial example would
  strengthen the paper more than another standard bound.

### Score and decision

**Score: 4/10.** **Decision: Major Revision (borderline reject on theory novelty).**
The paper is mathematically careful and the policy-side observation is good, but the
individual theorems are standard and the trilemma is a classification. To survive, the
paper should reposition itself explicitly as a **framework + measurement** paper,
cite the standard bounds it uses, and add one tightness/necessity result or a concrete
counterexample outside the trilemma class. It should not claim a new impossibility
theorem.

> **UPDATE（M6）**：分数维持 **4/10（Major Revision）**。系统与测量部分的进步由
> R1/R3 反映；理论部分的新证据不足以改变“单条定理标准、三难是分类”的判断。
> 若作者加 “standard vs new” 表、tightness 例，并把 `k`/D-privacy 的估计口径写清，
> 可到 5/10；但没有新定理就不应期待更高。

---

## Reviewer 3 — Privacy and Practice

### Summary

The paper studies whether an LLM agent's response satisfies a policy without revealing
the response (and, in policy-private mode, without revealing the policy). It is candid
about the limits: `core` is not zero-knowledge, re-execution recovers `T`, the salt
closes only the public-value channel, and L2 buys privacy at zero audit utility. The
measured disclosure curve and the delivery-binding experiment are useful. But the
practical privacy claim is still far from what a deployment would need, and the paper
does not report policy quality on a real benchmark (XSTest) or a real LLM end-to-end
run.

> **UPDATE（M6）**：真实 LLM 端到端（E3）与 `k`（E1）已有结果；但 E3 是机制演示，
> E1 受 N 截断，策略质量（XSTest P/R/F1）仍缺；A11 的语义分类器明确 demote。
> E2 还新增了 L2 承诺可链接的负结果。见 §0.1。

### Strengths

1. **The privacy scope is stated before the claims.** The abstract’s “Scope of privacy”
   paragraph and §7.1 are exactly what a privacy reviewer wants: no plaintext in public
   values, not unrecoverability; re-execution named as the real attack; the title’s ZK
   word made conditional.
2. **The policy-inference curve is a real measurement.** L0 0.810 → L1 0.113 → L2 0.073
   top-1, with mutual information 3.445 → 0.940 → 0.216 bits, is a clean demonstration
   that the certificate layer leaks monotonically with disclosure
   ([`policy_infer.md`](../../bench/results/policy_infer.md)).
3. **The salted commitment is tested negatively.** The enumeration benchmark recovers
   the unsalted policy at candidate 1000 in 56.8 ms but fails with a wrong salt, and
   succeeds again when the salt is leaked ([`policy_leak.md`](../../bench/results/policy_leak.md)).
   That is the right control.
4. **Delivery binding is measured, not asserted.** `f = 0` replay 1.00, verifier-only
   divergent delivery 1.00, end-user divergent delivery 0.00
   ([`delivery_binding.md`](../../bench/results/delivery_binding.md)). The distinction
   between verifier-issued and end-user-issued nonces is practically important.

### Weaknesses

**W1 (Critical) — The delivered private mode is not content-hiding.** The default
`core` tier does not hide its witness; the public `response_binding` and
`response_commitment` are offline-recomputable functions of `T`; under greedy or
low-temperature decoding the re-execution attack costs one inference. The paper says
this, but the title and abstract still lead with “Zero-Knowledge”. A practitioner will
read “private mode” as “the content is protected”, which the paper explicitly denies.
Retitle to “Succinct” unless the witness-hiding tier is delivered, and consider renaming
“private mode” to “committed mode” to avoid the same misreading.

> **UPDATE（M6）**：`groth16` 档现在有测量（EU AI Act **301.19 s / 30.07 GB /
> 1,874 B**；矩阵 16/18 verified），因此“没有 witness-hiding 数字”不再成立。
> 但 `groth16` 仍是 **wrapper-only、非后量子**，且 `core` 仍不隐藏 witness。
> 建议：标题可保留 “Zero-Knowledge” 只在摘要明确写“wrapper-level, non-PQ,
> `core` not ZK”；否则改 “Succinct”。把 “private mode” 改名仍值得做。

**W2 (Major) — Policy-private leakage is only partially closed.** The salt closes the
`policy_hash` channel, but the `core` trace carries `spec_canonical` (policy and salt),
the circuit writes raw `rule`/`kind`, `delegated` exposes structure, and evidence
opening reveals the rule (§4.1 Table 2; [`C1.md`](../blockers/C1.md)). L1 still leaks
rule categories (top-3 0.313), and L2 has zero audit utility. The 20-variant corpus and
stdlib naive Bayes classifier are a shape result, not a deployment estimate. The paper
needs a larger policy corpus (the repo has 13 packs), a stronger classifier, and a
circuit-level coarsening experiment before “policy-private mode” is a usable claim.

> **UPDATE（M6）**：E2 已把语料扩到 **300 候选 / 13 模板 / 220 条真实响应**，并给出
> 一个比原稿更不利的结果：**L2 的确定性 `evidence_commitment` 可跨样本链接**
> （构造性 top-1 **0.382**、真实 **0.112**、字典攻击 **0.207**；count-only 仅
> **0.014**）。因此“L2 只给承诺”不足以保护策略隐私；修订稿必须报告该通道，
> 并给出按证书加盐或桶级承诺的修复。L1 的审计效用、L2 的零效用、`delegated`
> 暴露结构仍成立。语料仍不是生产分布，不能外推部署风险。

**W3 (Major) — XSTest policy quality is not reported.** The paper evaluates the
*mechanism* but not whether the bundled policies are any good on a standard safety
benchmark. `safety_xstest_v1` is described in the repository as a naive keyword
blocklist designed to expose false positives; at the time of this review the real-LLM
end-to-end script was ready but its results were `pending X2` ([`plan-bhv.md`](../plan-bhv.md) P0-09/P0-10;
[`plan-m2-m6.md`](../plan-m2-m6.md) M2-03). Without P/R/F1 on XSTest (and ideally
τ-bench), a reader cannot tell whether “compliance” means anything. The demo semantic
model is a proxy, not a usable guardrail (§7.7).

> **UPDATE（M6）**：真实模型结果已落地，但没有解决“策略质量”问题：
> - E1 在 XSTest 50 条上测了 `k`（Qwen/Mistral/DeepSeek），**不是**策略 P/R/F1；
> - E3 跑通了真实 DeepSeek 6 轮、19 证书、第三方验证 PASS，但这是**机制**演示，
>   不是“模型合规”样本；
> - A11 用真实 toxic 分类器在 XSTest 上得到 recall **0.50%**、F1 **0.010**、
>   ROC-AUC **0.583**，判定 **demote**——这是任务错配（toxic ≠ harmful request），
>   也说明不能把 XSTest accuracy 当作 guardrail 质量。
>
> 因此“没有真实 LLM”已不成立，“没有策略质量评估”仍成立；修订稿必须保留
> A11 的负结果，不能把它写成可用语义模型。

**W4 (Major) — Usability is not deployment-grade.** Proving takes 118–172 s and
~2.7 MiB per certificate with a ~10.15 GiB fixed floor; 3 rules OOM at default knobs;
verification is `O(N)` with no recursive aggregation; multiparty proving is serial
because each proof adds ~10 GiB. Signing and key custody are not production-grade
(plaintext private-key parameters, public Anvil test key, local Anvil deployment). The
paper acknowledges these, but a TDSC practitioner will ask for a deployment cost model,
not only a list of limitations.

> **UPDATE（M6）**：成本模型更完整了，但仍不是部署级：
> `groth16` **279–344 s / 29.7–35.1 GB** 每点；`eu_ai_act_v1` **301.19 s / 30.07 GB**；
> 6 规则 `core` 到 **4500 字符 / 64.2 GB**，**5000 OOM**；E3 的宿主回调只有
> **10.8 ms/轮**，但 zk 证明不在请求链路里（`unproven`）。结论应是“异步出证 +
> 第三方验证”，不是“在线低延迟合规”。

**W5 (Major) — Accountability depends on a trusted authority and voluntary disclosure.**
P-PP requires an issuing authority that signs `π`, registers `h_π`, and holds the salt.
The operator also gets the salt and can leak it; the auditor can check only when the
operator chooses to disclose; three-party collusion is undetectable at the signature
layer. This is a real trust shift, not a cryptographic guarantee, and the paper should
make it a first-class part of the threat model rather than a paragraph in §4.3.

**W6 (Moderate) — The evaluation lacks real agent workloads.** The cycle corpus is a
372-character demo tiled to longer lengths; the semantic model is a demonstration proxy;
the inference half is a 640-weight fixed-point MLP; the composition cost is not
inference-dominated at proxy scale (§5.5; [`compose.md`](../../bench/results/compose.md)).
There is no real agent trace, no τ-bench, no user study. The paper’s claims are about
mechanism, which is fine, but the title and abstract should not imply deployment
readiness.

> **UPDATE（M6）**：E3 提供了一条真实 DeepSeek + 真实 MCP stdio 工具 + LangChain
> 流式回调的会话（6 轮、19 证书、11 项第三方验证 PASS），部分缓解了“没有真实 agent
> workload”。但仍没有 τ-bench、没有用户研究、没有真实工具轨迹的统计分布；
> 早停受规则粒度限制（`sk-…{16,}` 会先送达匹配前缀，证书标 `scope=partial-prefix`）。
> 因此“机制可行”有证据，“部署就绪”仍不成立。

### Questions

- Q1. Can the authors measure the `core` trace leakage directly (e.g. recover `T` from
  `opened_values` for a small policy and response)? A negative result would strengthen
  the “structural” claim.
- Q2. What does the `groth16` privacy-surface probe show about `spec_canonical`? Is the
  salt actually hidden, or only the public hash? (`pending X1b`)
  **（M6 后已可回答：真实响应探针在交付物中响应整条/逐行 0 命中；但策略名 1 处
  命中是公开输入；`response_commitment=sha256(T)` 仍是公开 oracle。）**
- Q3. What are the P/R/F1 numbers of `safety_xstest_v1` on XSTest? If the pack is a
  keyword blocklist, what is the false-positive rate on safe prompts? (`pending X2`)
  **（M6 后仍未回答：E1 只测 `k`，E3 不是策略质量，A11 是 demote 的 toxic 分类器。）**
- Q4. Is the L2 “zero audit utility” a property of the proxy or of the level? Please
  define the utility metric and validate it with a human or LLM auditor.
  **（M6 后部分回答：E2 显示 L2 在构造性/真实响应的 top-1 为 0.382/0.112，
  且承诺可链接；utility 仍不是人工/LLM 审计验证。）**
- Q5. What is the minimum viable deployment (machine size, HSM, log)? If a 3-rule
  policy cannot be proved on 12 GB, what does the operator need?
- Q6. What happens if the P-PP authority is compromised or colludes with the operator?
  Is there any detection mechanism, or is it purely trust?
- Q7. Why should a practitioner choose PoP over a TEE or a signed log in each of the
  four privacy corners? The paper’s own §7.2 says a signature suffices in the
  transparent corner; please make the recommendation explicit.

### Score and decision

**Score: 5/10.** **Decision: Major Revision.** The privacy analysis is honest and the
measurements are useful, but the delivered artefact does not support the title-level
ZK claim, and policy privacy / XSTest quality / real-LLM evaluation are not closed.
If the paper is retitled “Succinct”, the privacy claims are narrowed to “committed
public values”, and X2 lands, this reviewer could support acceptance after revision.
Without X1b/X2, the practical contribution is a well-documented prototype, not a
deployable privacy system.

> **UPDATE（M6）**：分数 **5/10 → 6/10（Major Revision）**。`groth16`、EU AI Act
> 两档、真实响应隐私面与 DeepSeek e2e 把“没有隐私交付档/没有真实模型”部分消解；
> 但 E2 暴露的 **L2 承诺可链接**是新的隐私反对点，A11 又证明真实语义模型不可用，
> 策略质量（XSTest P/R/F1）仍缺。若修订稿加入 L2 加盐/桶级承诺、保留 A11 负结果、
> 并把 `core` 非 ZK 与 wrapper-only 写在摘要，可到 7/10。
