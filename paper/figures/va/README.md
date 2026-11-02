# VA figure set — Proof-of-Policy (visual architect)

Branch `bhv/visual-architect`, base `91ca397` (`tdsc-conversion`).
This directory is additive: no file under `paper/` outside `paper/figures/va/`
is modified. The main paper remains 12 pages.

**What this set is.** Four new figures that fill gaps left by the existing nine
figures: a three-party deployment/trust-boundary view (not a copy of Fig. 1), a
certificate-lifecycle flow with fail-closed exits, a categorical Table S6
comparison matrix, and a claim–evidence synthesis. All four are **supplement
only** as drawn; a page-neutral VA1 swap was tested and is reported in
`PLACEMENT.md`.

---

## 1. Inventory

| ID | File (PDF + PNG) | Type | Design size | One-sentence message | Primary data |
|---|---|---|---|---|---|
| VA1 | `va01_deployment_trust` | TikZ concept, double column | 7.165 × 3.543 in | Who holds what, which channels are closed by cryptography, and which trust roots/assumptions remain when the authority, an untrusted operator, a verifier, an optional ledger and a tool gateway are drawn as separate parties. | design; §II, §III, Table S8 |
| VA2 | `va02_certificate_lifecycle` | TikZ flow, double column | 7.165 × 4.646 in | The issuance-to-verification contract in ten obligations, with eight fail-closed exits and no silent proof-tier downgrade. | design; §II, §VI, Table S4 |
| VA3 | `va03_comparison_matrix` | matplotlib categorical matrix, double column | 7.160 × 6.400 in | Table S6's 49 cells rendered as categorical evidence (46 populated, 3 unavailable), plus the three requested dimensions that Table S6 does not contain. | `baselines.json`, `scale-cloud.json`, `eu_ai_act_proof.json`, `issuance.json`, Table S6 |
| VA4 | `va04_claim_evidence` | matplotlib synthesis matrix, double column | 7.160 × 5.350 in | Which of E1/E6/E2/E3/X1/C2/CC supports, refutes, or leaves unknown each of seven claims — with the boundary of every verdict printed in the cell. | `k_entropy_*.json`, `k_logprobs.json`, `policy_corpus_infer.json`, `agent_e2e_deepseek.json`, `scale-cloud.json`, `c2/verify_L*.json`, `composition_controls.json` |

The four figures cover architecture, flowchart/sequence, comparative analysis,
and experimental synthesis. No existing figure is duplicated: F1 is a
left-to-right pipeline; VA1 is a three-party deployment/trust diagram. F2 is a
theoretical leakage profile; VA4 is an evidence-coverage matrix. Table S6 is
prose/tabular; VA3 is a categorical figure.

---

## 2. Why the comparison has two panels (important audit note)

The brief asks for seven dimensions: proof obligation, trust root, policy
privacy, response privacy, cost, issuance/audit, implementation status. **Table
S6's seven dimensions are different**: trust root, latency, size, response
privacy, policy privacy, needs `T` plaintext, needs `π` plaintext. We did not
silently relabel one as the other.

- **Panel (a)** is exactly Table S6's 49 cells. It keeps the 46 populated /
  3 unavailable count: Zaguk size, PCO latency, PCO size are em dashes. Every
  cell carries `[m]`, `[c]`, or `—`.
- **Panel (b)** adds the three requested dimensions that Table S6 does not
  contain: proof obligation, issuance/audit, implementation status. Only cells
  explicitly documented in `bench/results/baselines.md`,
  `bench/results/comparison_zkagent.md`, `bench/results/issuance.md` or the
  cited papers are filled; everything else is `—`, not inferred.
- Cell tint encodes **evidence status**, not quality or rank. A thin bar
  encodes only a named privacy category; no continuous score, heat scale, ranking, or
  interpolation is used.

**Known discrepancy.** Panel (a) prints the PoP core range as **39.8–100.3 s**
from `scale-cloud.json` (the 2000×1 core point is 39.83 s). Table S6 rounds the
lower bound to **40.5 s**. The 0.7 s difference is a table-text rounding, not a
different measurement; the caption states it. The `groth16` range is
279.3–343.8 s (Table S6 prints 279–344 s). `groth16` proof size is 1,874–1,875 B
across the nine successful points; Table S6 prints 1,874 B.

---

## 3. Data provenance (SHA-256)

All numbers in VA3/VA4 are read at build time. The scripts assert structural
counts and numeric tokens, so a changed result file fails the build instead of
silently changing the figure.

| File | SHA-256 | Used by |
|---|---|---|
| `bench/results/baselines.json` | `1863a626…0d588c` | VA3 |
| `bench/results/scale-cloud.json` | `5fbe5b77…d892ac` | VA3, VA4 |
| `bench/results/eu_ai_act_proof.json` | `f355e411…b5008` | VA3 |
| `bench/results/issuance.json` | `6e98ae68…aeb1e9` | VA3 |
| `bench/results/k_entropy_largeN.json` | `03a40976…e90dc3` | VA4 |
| `bench/results/k_entropy_crossmodel.json` | `de8dae53…2fee5b` | VA4 |
| `bench/results/k_logprobs.json` | `af4382ea…1848d93` | VA4 |
| `bench/results/e6_mistral/k_logprobs.json` | `98d561fe…1883161` | VA4 |
| `bench/results/policy_corpus_infer.json` | `ff32c460…767fed8` | VA4 |
| `bench/results/agent_e2e_deepseek.json` | `47c44867…e79c26f` | VA4 |
| `bench/results/composition_controls.json` | `0b40afbf…2ae760e` | VA4 |
| `bench/results/c2/verify_L{0,1,2}.json` | `ed714956…`, `84e2dd32…`, `8a96fda4…` | VA4 |

Human-readable companions: `baselines.md`, `scale-cloud.md`,
`eu_ai_act_proof.md`, `issuance.md`, `k_entropy_largeN.md`,
`k_entropy_crossmodel.md`, `k_logprobs.md`, `policy_corpus_infer.md`,
`agent_e2e_deepseek.md`, `composition_controls.md`, `c2/README.md`.

---

## 4. Build and checks

```bash
cd paper/figures/va
make all        # TikZ PDFs + data PDFs/PNGs + TrueType/width/PNG check
make placement  # page-neutral VA1 swap test (writes integration-test/page-budget-va1.txt)
./build.sh      # both
```

Requirements: Python 3 with `matplotlib`, `numpy`, `pymupdf`; XeLaTeX with
`fontspec`; `pdflatex` with IEEEtran. Concept figures use the bundled DejaVu
Sans TTFs in `paper/figures/fonts/`; data figures use STIXGeneral from
matplotlib. Both embed TrueType only.

`make all` output at this commit:

```text
ok   va01_deployment_trust.pdf           7.17 in  fonts=['ttf']  ...
ok   va02_certificate_lifecycle.pdf      7.17 in  fonts=['ttf']  ...
ok   va03_comparison_matrix.pdf          7.16 in  fonts=['ttf']  ...
ok   va04_claim_evidence.pdf             7.16 in  fonts=['ttf']  ...
all VA figures: TrueType-only fonts, within column width, PNG preview present
```

---

## 5. Placement (summary; details in `PLACEMENT.md`)

The main paper is exactly 12 pages, 0 errors, 0 undefined references. Final
placement: VA2 lifecycle is **main Fig. 1**, VA3 comparison is **main Fig. 5**;
VA1 deployment and VA4 claim–evidence are **supplement Figs. S4–S5**. The
page-neutral VA1 test below is retained as evidence for the earlier layout
decision; the main paper was subsequently shortened to make room for VA2/VA3.

- VA1 at `0.86\textwidth`: **13 pages** (fails the hard 12-page constraint).
- VA1 at `0.82\textwidth`: **12 pages**, 0 errors, 0 undefined, but the
  7.165-inch design is reduced to 5.87 inches; 5.75 pt body text prints at
  about 4.7 pt, below the 6 pt minimum. Not recommended.
- VA1 at `0.80\textwidth`: **12 pages**, same readability problem (4.6 pt).
- Control (unmodified main paper): 12 pages, 0 errors, 0 undefined.

Final placement: VA2 lifecycle is main-text Fig. 1, VA3 comparison is main-text
Fig. 5; VA1 deployment is supplement Fig. S4, VA4 claim–evidence is supplement
Fig. S5. Approximate page cost at 1:1: VA1 0.38, VA2 0.50, VA3 0.69, VA4 0.58
of a text page, plus captions.

---

## 6. Known risks and non-claims

**Conceptual**

- VA1/VA2 are **design diagrams, not measured traces**. They draw the design
  contract, not an implementation trace or latency timeline. Step numbers in
  VA2 are obligations, not timestamps.
- VA1 draws no TEE. The operator is untrusted. The trust roots are the signing
  key, the gateway key, and the policy registry/P-PP — not the operator
  machine. `core` leaves the witness open; `groth16` hiding is wrapper-only and
  not post-quantum; `L_side` (re-execution) is open at every tier.
- VA1 marks `T″ ≠ T′` as an open delivery gap (Prop. 1), and marks
  append-before-delivery, authority salt custody, gateway key custody, and the
  absence of split-view resistance as external assumptions.
- VA2's F1 (policy violation) is not a system failure: a certificate with
  `passed=false` is a valid certificate. The verifier must not read it as a
  compliance claim. F3 (`unproven`) is host-check only; it is not a proof.

**Data**

- VA3 is categorical, not a ranking. `[c]` cells are cited, not reproduced in
  this repository. `—` means not available, not zero and not estimated.
  `TEE (sim)` measures signature/verification only; hardware attestation was
  not measured. Zaguk and PCO did not yield comparable performance numbers.
- VA3's PoP latency mixes cloud proof time (16-core / 92,160 MiB cgroup,
  post-NFA-fix) with local verify (24-core / 11.7 GiB), exactly as Table S6
  does; do not compare across hosts. PoP proof times are single runs with
  ±10% wall-clock and ±1% peak-RSS jitter; the Merkle medians use n=500 and
  the TEE simulation n=300.
- VA4 verdicts are an **author mapping** of each experiment's result to the
  claim as stated. They are not a statistical test. `unknown` means the
  experiment does not address the claim, not a negative result.
- VA4 boundaries: E1 is N-capped and cannot certify `k ≥ 40`; E6 is an upper
  bound (left of 40 bit refutes, right does not certify); E3 is host-check only
  (`proof_mode=unproven`); X1 OOM points are observed kills, not measured
  peaks; C2 did not implement `delegated`; CC cell c is the weak form only
  (proof debt E-1).

**Visual**

- No 3D, shadows, gradients, decorative icons, dual y-axes, or truncated axes.
- Okabe–Ito palette; every categorical cell also carries the words
  `supports`/`refutes`/`unknown`, `closed`/`bounded`/`open`, `[m]`/`[c]`/`—`,
  so the figures survive greyscale.
- Data figures are generated by scripts; concept figures are TikZ. No
  screenshots.

---

## 7. File map

```text
paper/figures/va/
  src/va01_deployment_trust.tex
  src/va02_certificate_lifecycle.tex
  scripts/va03_comparison_matrix.py
  scripts/va04_claim_evidence.py
  scripts/check_fonts.py
  scripts/placement_test.py
  va01_deployment_trust.{pdf,png}
  va02_certificate_lifecycle.{pdf,png}
  va03_comparison_matrix.{pdf,png}
  va04_claim_evidence.{pdf,png}
  Makefile  build.sh
  README.md  CAPTIONS.md  PLACEMENT.md
  integration-test/page-budget-va1.txt
```
