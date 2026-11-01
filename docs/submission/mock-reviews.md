# TDSC 模拟审稿意见（A8）

> **日期**：2026-11-01　**基线**：`4fe5c41`（分支 `bhv/a8-review`）
> **审稿对象**：[`paper/tdsc-paper.tex`](../../paper/tdsc-paper.tex)（16 页稿）+ 仓库内证据文件
> **口径**：三名审稿人按 IEEE TDSC 常规论文标准独立评审。分数 1–10
> （1 = reject；4 = borderline reject；5 = major revision；7 = minor revision；
> 8–10 = accept）。本文件不是真实审稿意见，也不修改论文、代码、证明或结果。
> 未完成项一律标 `pending X1b/X2`、`blocker` 或 `open`，不编造数字。
> 其中 **X1b** 指 X1 在 post-NFA-fix 新 vkey 上的云机重跑（团队若已有编号，以团队为准）；
> **X2** 指真实 LLM 采样与 `k` 测量。

## 0. 汇总

| 审稿人 | 视角 | 分数 | 倾向 | 一句话 |
|---|---|---:|---|---|
| R1 | 系统 / 安全 | **5/10** | **Major Revision**（X1 不交付则 borderline reject） | 诚实、可复现，但 ZK 标题、规模、网关信任和策略隐私都还没到 TDSC 的“已交付”线 |
| R2 | 理论 | **4/10** | **Major Revision**（理论新颖性接近 borderline reject） | 定理大多标准；三难是分类；D-privacy 条件未落地；E-1 只证弱形式；G 不在正文 |
| R3 | 隐私 / 实践 | **5/10** | **Major Revision** | 隐私主张写得克制，但 `core` 非 ZK、重执行、策略泄露和 XSTest 质量使“合规”仍未闭环 |

**Meta-review（模拟）**：三份意见的共同硬点是 **(i) 标题/摘要的 zero-knowledge 尚无交付档**、
**(ii) 证明规模与旗舰策略包不可证**、**(iii) 策略隐私只关闭公开值通道**、
**(iv) 没有真实 LLM 与实测 `k`**。如果 rebuttal 期 X1b/X2 仍无结果，R1/R3 会转向
Reject 或建议改投 “Succinct / verifiable-audit” 方向的系统论文；如果 X1b/X2 落地，
三份都可以收到 Major Revision 以内。当前稿最可能的程序委员会结果是
**Major Revision**，而不是直接 Accept。

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
- Q2. Why not prove `eu_ai_act_v1` under tuned knobs? If it still OOMs, what is the
  minimum machine that proves the flagship policy, and what does that imply for
  deployment?
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

**W2 (Major) — Policy-private leakage is only partially closed.** The salt closes the
`policy_hash` channel, but the `core` trace carries `spec_canonical` (policy and salt),
the circuit writes raw `rule`/`kind`, `delegated` exposes structure, and evidence
opening reveals the rule (§4.1 Table 2; [`C1.md`](../blockers/C1.md)). L1 still leaks
rule categories (top-3 0.313), and L2 has zero audit utility. The 20-variant corpus and
stdlib naive Bayes classifier are a shape result, not a deployment estimate. The paper
needs a larger policy corpus (the repo has 13 packs), a stronger classifier, and a
circuit-level coarsening experiment before “policy-private mode” is a usable claim.

**W3 (Major) — XSTest policy quality is not reported.** The paper evaluates the
*mechanism* but not whether the bundled policies are any good on a standard safety
benchmark. `safety_xstest_v1` is described in the repository as a naive keyword
blocklist designed to expose false positives; the real-LLM end-to-end script is ready
but its results are `pending X2` ([`plan-bhv.md`](../plan-bhv.md) P0-09/P0-10;
[`plan-m2-m6.md`](../plan-m2-m6.md) M2-03). Without P/R/F1 on XSTest (and ideally
τ-bench), a reader cannot tell whether “compliance” means anything. The demo semantic
model is a proxy, not a usable guardrail (§7.7).

**W4 (Major) — Usability is not deployment-grade.** Proving takes 118–172 s and
~2.7 MiB per certificate with a ~10.15 GiB fixed floor; 3 rules OOM at default knobs;
verification is `O(N)` with no recursive aggregation; multiparty proving is serial
because each proof adds ~10 GiB. Signing and key custody are not production-grade
(plaintext private-key parameters, public Anvil test key, local Anvil deployment). The
paper acknowledges these, but a TDSC practitioner will ask for a deployment cost model,
not only a list of limitations.

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

### Questions

- Q1. Can the authors measure the `core` trace leakage directly (e.g. recover `T` from
  `opened_values` for a small policy and response)? A negative result would strengthen
  the “structural” claim.
- Q2. What does the `groth16` privacy-surface probe show about `spec_canonical`? Is the
  salt actually hidden, or only the public hash? (`pending X1b`)
- Q3. What are the P/R/F1 numbers of `safety_xstest_v1` on XSTest? If the pack is a
  keyword blocklist, what is the false-positive rate on safe prompts? (`pending X2`)
- Q4. Is the L2 “zero audit utility” a property of the proxy or of the level? Please
  define the utility metric and validate it with a human or LLM auditor.
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
