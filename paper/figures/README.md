# Proof-of-Policy — paper figures

This directory holds every vector figure, its 300 dpi PNG preview, the script
or TikZ source that produces it, and the audit that justifies (or rejects) each
candidate. All numbers in the data figures are read from `bench/results/*.json`;
no value is hand-entered. The two concept figures are hand-drawn TikZ and show
the design as written in the paper, not a measured claim.

**Headline result.** The main paper is still 12 pages and unchanged. One
page-neutral integration was tested and passes: replacing Table I
(`tab:proofs`) with the compact single-column proof-feasibility figure
`fig06b_proof_main.pdf` yields **12 pages / 0 errors** (baseline **12 / 0**).
Everything else is proposed for the supplementary material.

---

## 1. Figure inventory

| ID | File (PDF + PNG) | Type | Width (design) | One-sentence scientific message | Primary data |
|---|---|---|---|---|---|
| F1 | `fig01_architecture` | concept, double | 7.17 in | The certificate pipeline from policy to zkVM to signed public values, with the witness, the public values, the operator trust boundary, and the residual delivery gap drawn explicitly. | design; §II, §III |
| F2 | `fig02_bhv_leakage` | concept, double | 7.17 in | BHV has at most two legs below the entropy threshold, and the three leakage channels (`L_pub`, `L_proof`, `L_side`) are closed differently by `core` and `groth16`. | design; §III, §IV |
| F4 | `fig04_cycles_vs_length` | data, double | 6.44 in | With a fixed rule set, zkVM cycles are linear in response length; one NFA regex costs 58× a string-only rule set. | `cycles.json` |
| F5 | `fig05_matcher_ablation` | data, double | 6.44 in | Naive re-anchoring grows as Θ(n²) while Pike is linear, and the quadratic term meets the 14.6 GiB memory floor at n=50 on the proving path. | `ablation.json`, `dos_proof.json` |
| F6 | `fig06_proof_feasibility` | data, double | 7.08 in | Proving time is not the binding resource: peak RSS is, the core feasible set is not a rectangle, and OOM points are observed kills rather than interpolated failures. | `scale-cloud.json`, `scale-6x*.json`, `eu_ai_act_proof.json` |
| F6b | `fig06b_proof_main` | data, single | 3.62 in (1.75 in tall; scales to `\columnwidth`) | Compact main-text version of F6: core floor, groth16 cluster, six-rule edge, EU AI Act points, and OOM events at the cgroup limit. | same as F6 |
| F7 | `fig07_k_est` | data, single | 3.44 in | The teacher-forced estimator gives an **upper** bound on guessing entropy; 16/50 Qwen and 11/50 Mistral groups are provably below 40 bit, and greedy decoding gives k=0 in all groups. | `k_logprobs.json`, `e6_mistral/k_logprobs.json` |
| F8 | `fig08_policy_disclosure` | data, double | 7.05 in | Policy inference falls from L0 to L1 but the v1 L2 evidence commitments link across samples; the 20-variant synthetic corpus and the 300-candidate real corpus are kept in separate panels. | `policy_infer.json`, `policy_corpus_infer.json` |
| F9 | `fig09_issuance_detection` | data, single | 3.44 in | Auditing delivered artifacts detects 0.9948 of 100 withheld violations at p=0.05, while auditing the log detects 0.0000 because the frame is wrong. | `issuance.json` |

All PDFs embed only TrueType fonts (Type 42); all PNGs are 300 dpi. See
`scripts/check_fonts.py`.

---

## 2. Candidate audit

The table records every candidate requested by the brief, including those that
were deliberately **not** drawn. “Placement” is the recommendation given the
hard 12-page constraint.

| Candidate | Scientific information | Source | Placement / page cost | Decision and risk |
|---|---|---|---|---|
| PoP architecture (request → compile → zkVM → certificate → verifier/ledger) | Where the witness, public values, challenge nonce, policy commitment, response binding, and trust boundary sit. | design, §II | Supplementary; ≈0.40 page if added to main. | **Drawn (F1).** Design diagram, not an implementation trace. `core` = no hiding; `groth16` = wrapper-only, non-post-quantum. The tool-gateway key is named as a trust root but the gateway is not drawn. |
| BHV triangle + three-channel leakage profile | Which of binding/hiding/PV-2 can coexist, and which channel each tier closes. | design, §III–IV | Supplementary; ≈0.39 page if added. | **Drawn (F2).** Conceptual. `L_side` is closed by no tier; a zero canary probe is not a zero-knowledge proof. Salted policy closes `L_pub`/hash but loses PV-2. |
| Certificate lifecycle (issue → deliver → verify → audit/anchor; challenge, streaming early stop, session aggregation) | The order of operations and where the freshness budget enters. | design, §II, §VI | Supplementary candidate only. | **Not drawn separately.** It is already the left-to-right path of F1; a second timeline would duplicate it and add page cost without new information. If a venue wants an explicit lifecycle, add one to the supplement. |
| D-privacy salt/commitment mechanism (`policy_hash` vs `policy_commit`) | The public, recomputable hash and the salted commitment are different objects; the salt is withheld and PV-2 is lost. | design, §III-D | Folded into F1 (author box, certificate box) and F2 (policy row). | **Not drawn separately.** The construction is one line; a standalone mechanism figure would overstate how much is implemented. |
| Cycle count vs response length (40 points) | Fixed rule set ⇒ exactly linear; NFA-bearing slopes are 58× string-only slopes. | `bench/results/cycles.json` | Supplementary (replaces/complements Table S1); ≈0.32 page. | **Drawn (F4).** Corpus is 372 characters tiled to 100k; it measures the scan curve, not a real 100k document. 30 pike points are fitted; the refuted unit-price model is text, not plotted. |
| Matcher ablation (naive vs Pike) + OOM boundary | Θ(n²) vs linear, and where the quadratic term hits the memory wall. | `ablation.json`, `dos_proof.json` | Supplementary (complements Tables S2–S3); ≈0.23 page. | **Drawn (F5).** Execution and proving counts come from separate driver builds (≈1e-5 difference); proving runs are pre-NFA-fix (`b81e6d07…`). No n≥100 naive or n=400 proving point exists, so no proving curve is drawn. The n=50 point is an observed kill at 13.77 GiB measured peak. |
| Proof time vs peak RSS / feasible region / OOM / EU AI Act / 6×4500 | Memory, not time, binds; the feasible set is non-rectangular; OOM is a result. | `scale-cloud.json`, `scale-6x{2000,3000,4000,4500,5000}.json`, `eu_ai_act_proof.json` | F6 supplementary; **F6b main candidate replacing Table I** (verified page-neutral). | **Drawn (F6, F6b).** Post-NFA-fix cloud only (vkey `0x003eb14d…`), 16-core / 92,160 MiB cgroup. `GiB = peak_rss_mb/1024`; the source counter is MiB. Table I prints the same counter divided by 1000 under the label GB, so its values are 2.4% larger; the figures use GiB. OOM crosses sit at the cgroup limit, not at a measured peak. EU AI Act is one policy and one 167-character response. 6×4500 passed with 20,480 B headroom after page-cache reclaim; 4750 was not measured. 6-rule OOM at 10000/50000 is omitted for space, not because it succeeded. |
| E6 `k_est` distribution | The log-probability estimator breaks the N cap but returns an upper bound; some groups are provably below 40 bit, and greedy decoding is k=0. | `k_logprobs.json`, `e6_mistral/k_logprobs.json` | Supplementary; ≈0.17 page. | **Drawn (F7).** `k_est` is an upper bound on true k: left of 40 refutes, right of 40 does not certify. N=20, 50 XSTest prompts, T=0.7, chat template. Temperature 0 is a separate panel because k=0 cannot share a log axis. |
| Policy disclosure inference L0/L1/L2 | L0→L1 lowers inference; v1 L2 commitments re-link across samples; audit utility falls to zero at L2. | `policy_infer.json`, `policy_corpus_infer.json` | Supplementary; ≈0.25 page. | **Drawn (F8).** A1 (20 synthetic variants, 11 templates) and E2 (300 candidates, 220 real responses) are separate panels; never averaged. F8 shows L2 = v1 payload and L2* = count-only projection. The v2 circuit-level L2 has not been re-measured. `policy_hash` is excluded from features (a hash lookup would be top-1 = 1.0). |
| Issuance audit (delivered 0.9948 vs log 0.0000) | The sample frame, not luck, determines detection of withheld violations. | `issuance.json` | Supplementary; ≈0.18 page. | **Drawn (F9).** Exact hypergeometric curve, 500 MC trials per cell. Detection, not prevention; independent violations; append-before-delivery is an external premise. |
| Privacy surface / canary | Whether the response or canary appears in delivered artifacts. | `privacy_surface*.json/.md` | Not drawn. | **Rejected.** The data are probe negatives (0 hits) at two tiers; a bar of zeros would be read as a zero-knowledge claim, which the paper explicitly rejects. The honest statements live in the text and in F2. |
| Non-ZK signature baseline | Signing/verification is milliseconds; a signature binds who, not whether. | `baseline.json` | Not drawn. | **Rejected as a figure.** Four medians with ±20% host drift and a static Θ(n) append; a log-scale bar would invite an unfair comparison. Table/paragraph is the right form. |
| Order probe / marginal unit price | Cost depends on rule order and context; unit prices are not additive. | `cycles.json` (`order_probe`, `marginal_probe`) | Not drawn. | **Rejected.** The quantities have different units (total cycles at L=1e5 vs cycles/char vs %); one shared axis would mislead. Reported as text. |

---

## 3. Main-text integration proposal (tested)

**Recommendation: one figure, F6b.**

1. Replace the `table` environment labelled `tab:proofs` in
   `paper/tdsc-paper.tex` (the 10-row real-proof table) with a single-column
   `figure` using `fig06b_proof_main.pdf`.
2. Move the old Table I verbatim to the supplementary material as the numeric
   per-point table; the figure caption points there.
3. Update the one textual reference from `Table~\ref{tab:proofs}` to
   `Fig.~\ref{fig:proofs}`.

`scripts/page_budget_test.py` performs exactly this replacement on copies under
`integration-test/` and compiles both versions with `\def\SKELQUIET{}`:

```
baseline: 12 pages, 0 errors
table->figure: 12 pages, 0 errors
page-neutral: YES
verdict: PASS
```

Evidence: `integration-test/page-budget.txt`. The main paper itself was **not
modified**.

**Do not** add F1, F2, F7 or F8 to the main text without cutting text. Their
estimated areas are 0.17–0.40 page each; the paper is exactly 12 pages, so any
addition would push it to 13. If the venue requires Table I to stay in the main
text, the correct decision is **supplementary only** for every figure. F8 could
in principle replace Table `tab:policy-infer` (a 3-row table) plus a sentence,
but that replacement was not tested and is not recommended for this submission.

---

## 4. Data provenance, hashes, and regeneration

Every data figure is generated from the JSON files below. SHA-256 is of the
checked-in file at the figure commit.

| File | SHA-256 | Used by |
|---|---|---|
| `bench/results/cycles.json` | `92ea2b0f…2984d` | F4 |
| `bench/results/ablation.json` | `673b7192…a256` | F5 |
| `bench/results/dos_proof.json` | `b9ea9bab…b146` | F5 |
| `bench/results/scale-cloud.json` | `5fbe5b77…92ac` | F6, F6b |
| `bench/results/scale-6x2000.json` | `3dd50b79…74fe` | F6, F6b |
| `bench/results/scale-6x3000.json` | `b6aaa8be…36e6` | F6, F6b |
| `bench/results/scale-6x4000.json` | `adbc9ae4…58e5` | F6, F6b |
| `bench/results/scale-6x4500.json` | `58d2bd37…b2ca` | F6, F6b |
| `bench/results/scale-6x5000.json` | `8c95ef50…a484` | F6, F6b |
| `bench/results/eu_ai_act_proof.json` | `f355e411…5008` | F6, F6b |
| `bench/results/k_logprobs.json` | `af4382ea…8d93` | F7 |
| `bench/results/e6_mistral/k_logprobs.json` | `98d561fe…3161` | F7 |
| `bench/results/policy_infer.json` | `42378d9a…f31e` | F8 |
| `bench/results/policy_corpus_infer.json` | `ff32c460…fed8` | F8 |
| `bench/results/issuance.json` | `6e98ae68…b1e9` | F9 |

Human-readable companions (not parsed by the scripts): `cycles.md`,
`ablation.md`, `dos_proof.md`, `scale-cloud.md`, `eu_ai_act_proof.md`,
`k_logprobs.md`, `e6_mistral/k_logprobs.md`, `policy_infer.md`,
`policy_corpus_infer.md`, `issuance.md`.

Rebuild everything:

```bash
cd paper/figures
make all          # data PDF/PNG, concept PDF/PNG, font/width/Png check
make page-budget  # 12-page integration test
./build.sh        # both of the above
```

Requirements: Python 3 with `matplotlib`, `numpy`, and `pymupdf` (`pip install
--user matplotlib pymupdf`); `pdflatex` with IEEEtran for the page-budget test;
`xelatex` with fontspec for the TikZ concept figures. Concept figures use the
bundled **DejaVu Sans** TTFs in `paper/figures/fonts/` (italic and bold faces
included) and the system DejaVu Sans Mono; data figures use **STIXGeneral**,
which ships with matplotlib. No absolute font paths are used.

The concept sources are `src/fig01_architecture.tex` and
`src/fig02_bhv_leakage.tex`. They are compiled with XeLaTeX to a fixed
7.16-inch-wide page; the data figures are written by the seven scripts in
`scripts/`.

---

## 5. Known risks, boundaries, and non-claims

**Statistics and measurement**

- No figure carries error bars. The underlying runs are single measurements;
  the paper reports ±10% wall-clock and ±1% peak-RSS jitter. Adding error bars
  would fabricate a confidence interval that was not measured.
- F4: the corpus is 372 characters tiled to 100k; it is a scan-cost curve, not
  a real 100k-character document. Every point was checked to match no rule.
- F5: execution and proving counts come from different driver builds
  (≈1 part in 10⁵). The proving points predate the NFA fix and are not pooled
  with post-fix data. The n=50 naive point is an observed OOM/SIGKILL at
  13.77 GiB measured peak; no proving curve is drawn.
- F6/F6b: cloud post-fix only (binary `7f99fdb1…`, vkey `0x003eb14d…`), 16-core
  / 92,160 MiB cgroup, one proof per process. `GiB = peak_rss_mb / 1024`; the counter itself is
  MiB. Table I prints the same counter divided by 1000 under the label GB, so
  its values are 2.4% larger. OOM crosses are at the cgroup limit, not
  measured peaks. 6×4500 is a cache-dependent boundary (20,480 B headroom after
  reclaiming 5.27 GB of page cache); 4750 was not measured, and groth16 at six
  rules was not attempted because core hit the wall first.
- F7: `k_est` is an **upper bound** on true k. Points below 40 bit refute the
  40-bit condition; points above it do not certify it. N=20, 50 XSTest prompts,
  T=0.7, chat template. Greedy decoding is k=0 in all 50/50 groups and is a
  separate panel; it cannot share a log axis with positive k.
- F8: A1 and E2 are different corpora and different projections. L2 is the v1
  certificate payload; L2* is the count-only A1 convention. The v2
  circuit-level L2 is not re-measured. `policy_hash` is excluded from features.
  Evidence coverage in E2 is 0.677, so most files exercise coarse rules only.
- F9: detection, not prevention; independent violations; the log-frame zero is
  a wrong-frame result by construction, not an unlucky sample. Append-before-
  delivery and a binding leaf are external premises.

**Conceptual**

- F1 is a design diagram. `core` reports `hiding = none`; `groth16` hiding is
  wrapper-level and not post-quantum. The architecture does not claim a TEE,
  and the gateway key/signing key remain trust roots.
- F2 marks `L_side` open at both tiers. A zero canary count is a probe negative,
  not a zero-knowledge proof. The salted commitment closes the hash channel and
  loses PV-2; it does not close the proof-artefact channel of `core`.
- The certificate lifecycle and the salt/commitment mechanism are folded into
  F1/F2 rather than drawn separately, to avoid duplicating the same design.

**Accessibility**

- Okabe–Ito palette; every multi-series plot also encodes by marker, linestyle,
  or hatch so it survives grayscale. No red–green-only encoding. The status
  cells in F2 carry the words `open` / `closed` / `bounded`, not only colour.
- Data figures use 6.5–7.5 pt axis/tick text; dense annotations are 5.3–6.0 pt
  and are intended for print at column width. F6b is the main-text candidate;
  F6 is the full supplementary version.

---

## 6. File map

```
paper/figures/
  fig01_architecture.{tex,pdf,png}      concept, double column
  fig02_bhv_leakage.{tex,pdf,png}       concept, double column
  fig04_cycles_vs_length.{py,pdf,png}   data, double column
  fig05_matcher_ablation.{py,pdf,png}   data, double column
  fig06_proof_feasibility.{py,pdf,png}  data, double column
  fig06b_proof_main.{py,pdf,png}        data, single column (main candidate)
  fig07_k_est.{py,pdf,png}              data, single column
  fig08_policy_disclosure.{py,pdf,png}  data, double column
  fig09_issuance_detection.{py,pdf,png} data, single column
  figstyle.py                           shared IEEE geometry, palette, export
  src/                                  TikZ sources
  fonts/                                bundled DejaVu Sans TTFs (TrueType)
  scripts/                              data scripts, pdf2png, checks,
                                        page-budget test
  integration-test/page-budget.txt      measured 12-page evidence
  CAPTIONS.md                           English caption drafts
  Makefile, build.sh, .gitignore
../../docs/figures/style-guide.md       project-wide figure rules
```
