# Cover letter（TDSC 投稿）

> **状态**：草稿，待 M5 定稿后核对数字与标题。  
> **基线**：仓库 `1c1fc60`；文中数字均可在 `bench/results/*` 找到对应文件。  
> **待填**：`<DATE>`、`<AUTHOR NAMES>`、`<AFFILIATION>`、`<CORRESPONDING EMAIL>`、
> `<FUNDING>`、`<PAPER DOI / MANUSCRIPT ID>`。不要填写虚构 DOI。  
> **注意**：若最终 PDF 仍用 “Succinct” 标题，本信中的 “Zero-Knowledge” 措辞必须同步
> 改为 “Succinct”，并保留 §Boundaries 的 wrapper-only 说明。

---

<DATE>

Prof. \<Editor-in-Chief\>  
Editor-in-Chief, *IEEE Transactions on Dependable and Secure Computing*  
Re: Submission of “Proof-of-Policy: Zero-Knowledge Compliance Certificates for LLM Agent Outputs”

Dear Editor-in-Chief,

We submit the enclosed manuscript, **“Proof-of-Policy: Zero-Knowledge Compliance Certificates for LLM Agent Outputs,”** for consideration as a regular paper in *IEEE Transactions on Dependable and Secure Computing* (TDSC). The manuscript studies a question that is becoming operationally urgent: when an LLM agent claims that its response satisfies a policy, **what exactly does a compliance certificate bind, and what can an auditor independently check?** We answer with an analytical framework, a policy-side privacy definition and construction, an implemented system, and measurements that include negative controls. The paper does not claim a new proof system; its contribution is the framework, the policy-side instance, and the measured leak profile of the certificate.

## The problem

Enterprises and regulators increasingly require that agent behaviour be auditable—the EU AI Act’s record-keeping and transparency obligations (Articles 12–13) are a concrete example—while content-privacy rules discourage retaining the plaintext that would settle a compliance question. Existing approaches each occupy one corner: TEE execution proofs show that guardrail code ran, formal verification requires the policy to be formalised by hand, and ZK regex/PII primitives are building blocks rather than policy-level systems. The gap that survives in every design we surveyed is **divergent delivery**: a proof can bind a computation without binding the bytes the end user actually received. We isolate that gap (Proposition 1) and show that neither hardware nor a proof closes it unless the receiver contributes freshness to the proven statement.

## Contributions

1. **A binding–hiding–verifiability (BHV) framework.** We organise response, request, and policy as three instances of one accounting: binding force equals the committed, adversary-non-selectable bits. The framework yields a conditional trilemma—below the adversary’s evaluation budget, at most two of binding, hiding, and public recomputability coexist—and a leakage-profile theorem separating public values, proof artefacts, and side information. The single guess bound is standard; what is new is the unified accounting, the policy-side leg, and the measurements that instantiate it.
2. **The policy side.** We observe that `policy_hash` is the same kind of object as `response_binding`—a public, offline-recomputable function of a low-entropy secret—and give a D-privacy definition that fixes the response artefact so that response leakage is not misattributed to the policy. A salted commitment closes the public-value enumeration channel; a measured disclosure-level study then shows what remains open.
3. **A constructive instance (PoP).** A small policy DSL compiles to an SP1 circuit; certificates are Ed25519-signed and chained in an append-only ledger; a third-party verifier recomputes the verdict from public artefacts only. The system deliberately does not use a TEE.
4. **Measurement, including negative controls.** We report proof cost and memory, the scale boundary (including OOM points), composition controls (including the failing cell), gateway-signing cost, issuance detection, policy-inference curves, and real-model behaviour. Failures are retained as results rather than omitted.

## Why TDSC

TDSC is the right venue because the paper’s central question is a **dependability and security** question, not a proof-system performance question: what trust assumptions remain, which adversary can recover the response, what a verifier may conclude from a certificate, and where the design fails closed. The paper combines a formal model with an implemented, independently verifiable pipeline and a reproducible measurement record. It also states its negative results—OOM rows, a failing composition cell, zero audit utility at one disclosure level, and a demoted semantic classifier—which we believe matches TDSC’s expectation that security claims be bounded and auditable.

## Relation to zkAgent and Proof-of-Guardrail

- **zkAgent** proves the *model computation*; PoP proves *policy compliance* of the delivered response. The obligations are different, so the numbers are not a race: we compare orders of magnitude under explicitly unmatched hardware and do not claim PoP is faster. PoP adds committed content privacy and a policy-side leak analysis that a model-computation proof does not provide.
- **Proof-of-Guardrail** is a TEE execution proof: it shows that guardrail code ran and that inputs/outputs were signed. As that line of work itself observes, *execution is not compliance*. PoP targets the compliance predicate directly and avoids hardware trust, at the cost of proving cost and a memory-bound scale ceiling. The two approaches are complementary rather than substitutes.

## Evidence in the revision

The revision and the accompanying repository report, among other results:

- a **groth16** matrix on a 16-core / 90 GiB cloud container (post-NFA-fix binary, policy vkey `0x003eb14d…`): **16 of 18 points verified**, with successful points at **279–344 s and 29.7–35.1 GB**; the two failures are retained as OOM;
- a real **EU AI Act** policy (three rules including a `pattern_block`) proved in both tiers: `core` **48.82 s / 12.38 GB / 2.79 MB**, `groth16` **301.19 s / 30.07 GB / 1,874 B**, both independently verified with `verify_cert.py --proof --response`;
- a **6-rule** scale boundary: `core` succeeds at 2000/3000/4000/4500 characters (**181.66 s / 64.2 GB** at 4500) and OOMs at 5000 on the 90 GiB cgroup; 6-rule `groth16` was not run because `core` hits the wall first;
- a **real-response privacy probe**: neither the response plaintext nor the canary appears in delivered artefacts at either tier, while the response commitment remains a publicly recomputable guess-and-check oracle by design;
- **measured guessing entropy** `k` on real models (Qwen2.5-7B, Mistral-7B, DeepSeek): all measured values are far below the 40-bit threshold used in the paper, with an explicit **N-truncation caveat**—the experiment cannot certify high entropy;
- a **policy-corpus inference study** (300 candidates, 220 real responses) showing that deterministic L2 evidence commitments are **linkable** (top-1 0.382 on the constructive holdout, 0.112 on real responses, dictionary attack 0.207), which is a new limitation we report rather than hide;
- a **real DeepSeek agent end-to-end session** (19 certificates, third-party verification PASS, no SP1 proof), and a **real semantic-classifier feasibility study that we explicitly demote** (recall 0.50%, F1 0.010, ROC-AUC 0.583; it measures toxic text, not harmful requests).

## Boundaries we state in the paper

We would rather bound the claims than let a reviewer discover the gap:

1. **Composition is the weak form.** The implementation binds `derive(T_U)`, not the user-submitted `x_U`; the strong form is stated as an ideal/open item, and the failing four-cell control is reported.
2. **`core` is not zero-knowledge.** The default proving tier does not hide its witness; content privacy means “no response plaintext in public values,” not “unrecoverable.”
3. **`groth16` is wrapper-level and non-post-quantum.** Its hiding claim is conditional on the SP1 wrapper; we do not claim post-quantum security.
4. **The 6-rule boundary is a measured machine boundary.** 4500 characters is feasible on the 90 GiB cgroup, 5000 is not; we do not claim “six rules are impossible.”
5. **The semantic classifier is demoted.** It is a feasibility negative result, not a deployable guardrail, and we do not use XSTest accuracy to endorse policy quality.

## Reproducibility and artifact

The submission is accompanied by an artifact containing a pure-Python Dockerfile, a one-command host reproduction script, and the result files behind every number. In our environment the Docker engine was unavailable at the final check, so we do not claim a built image; we report the equivalent host execution (42 unit tests), the host fast demo (`RESULT: PASS`, 13 certificates), and the doc-link gate. The cloud proving results are repository results with binary digest, policy vkey, host, and `proof_mode` recorded. A Zenodo DOI will be added after acceptance; no DOI is fabricated in the submission.

## Declarations

This manuscript is original, has not been published, and is not under consideration elsewhere. All authors have approved the submission. The work involves no human subjects; the LLM outputs used in the measurements are not treated as compliance ground truth. API keys, private keys, and model caches are not included in the artifact. \<FUNDING\> and \<CONFLICT OF INTEREST\> statements are provided in the manuscript. We would be glad to suggest qualified reviewers and to provide any additional artefact material the editors require.

Thank you for considering our submission.

Sincerely,

\<AUTHOR NAMES\>  
\<AFFILIATION\>  
\<CORRESPONDING EMAIL\>
