# Placement recommendation — VA figure set

**Decision: all four figures are supplement-only as drawn.** The main paper is
already exactly 12 pages with zero errors and zero undefined references, and it
has no unallocated float slot and no table that can be replaced without
removing a result. We did not modify the main paper.

The page-neutral test was actually run; its raw output is
`integration-test/page-budget-va1.txt`.

---

## 1. Measured 12-page test

Command: `make placement` (compiles a copy of `paper/tdsc-paper.tex` under
`paper/figures/va/integration-test/`; no file outside that directory changes).

```text
control (unmodified 91ca397): 12 pages, 0 errors, 0 undefined refs, 1 overfull
VA1 at 0.86 textwidth:       13 pages, 0 errors, 0 undefined refs, 1 overfull
VA1 at 0.82 textwidth:       12 pages, 0 errors, 0 undefined refs, 1 overfull
VA1 at 0.80 textwidth:       12 pages, 0 errors, 0 undefined refs, 1 overfull
target:                      12 pages, 0 errors, 0 undefined refs
```

Read the scale factor, not only the page count:

| VA1 include width | Rendered width | Rendered height | Body text at 5.75 pt design | 12 pages? | Verdict |
|---|---:|---:|---:|---|---|
| 0.86 `\textwidth` | 6.16 in | 3.05 in | 4.95 pt | **no (13)** | not page-neutral |
| 0.82 `\textwidth` | 5.87 in | 2.91 in | 4.72 pt | yes | page-neutral but below 6 pt |
| 0.80 `\textwidth` | 5.73 in | 2.83 in | 4.60 pt | yes | page-neutral but below 6 pt |

The 0.82/0.80 swaps pass the page count because they shrink the figure to the
height of the existing Fig. 1, not because the content became cheaper. At
0.80 the 7.165-inch design is reduced to 5.73 inches; body text is about
4.6 pt, and some 4.2 pt labels fall to 3.4 pt. That violates the style guide's
6 pt minimum and would be unreadable in print. We therefore do **not**
recommend a main-text swap.

If the authors later free about 0.35 page and accept the caption/text rewrite
(VA1 is a deployment/trust view, not the pipeline drawing of Fig. 1), the 0.86
include is the first candidate; today it is 13 pages and does not qualify.

---

## 2. Per-figure recommendation and page cost

Page cost is the figure height divided by the IEEEtran text height (≈9.25 in),
plus 0.04–0.08 page for the caption. Supplement placement has no hard page
limit in this task; the main paper does.

| Figure | Design size | 1:1 page cost | Main paper | Supplement slot |
|---|---:|---:|---|---|
| VA1 deployment/trust | 7.165 × 3.543 in | ≈0.38 page | no: 0.86 swap is 13 pages; 0.82 swap is 12 pages but text < 5 pt | §S1, next to the three-party model (Table S8) |
| VA2 lifecycle | 7.165 × 4.646 in | ≈0.50 page | no: single/double-column replacement would delete a measured figure | §S1/S2, next to the certificate/ledger description |
| VA3 comparison | 7.160 × 6.400 in | ≈0.69 page | no: Table S6 is already in the supplement; adding it to main is not page-neutral | §S5, immediately after Table S6 |
| VA4 claim–evidence | 7.160 × 5.350 in | ≈0.58 page | no: no page-neutral slot; replacing F2 would remove the theory figure | §S5, evaluation synthesis |

Recommended supplement order: **VA1 → VA2 → VA3 → VA4**. VA1 and VA2 belong
with the design/model material; VA3 belongs with the cross-system table; VA4
belongs with the evaluation synthesis. No figure is duplicated between main and
supplement.

---

## 3. What would have to be true for a main-text figure

A main-text placement is possible only under one of these author decisions:

1. **Replace Fig. 1 with VA1 at 0.86 width and free ≈0.22 in of vertical
   space elsewhere.** The swap is currently 13 pages. Any freed space must come
   from a real edit (shorter paragraph, table move), not negative `\vspace`.
   The Fig. 1 caption and the sentence "Fig. 1 shows the pipeline" would need
   rewriting because VA1 is a deployment/trust view, not the pipeline.
2. **Replace Fig. 2 with VA4 at 0.86 width.** VA4 is a synthesis of the
   evaluation, not a theory figure; this removes the BHV/leakage visual and is
   not recommended.
3. **Accept a 0.82 VA1 include.** It is 12 pages, 0 errors, 0 undefined, but
   the body text is ≈4.7 pt. This is below the 6 pt minimum and not
   recommended.

No other figure has a page-neutral swap that preserves the main paper's
measured-result coverage. VA2/VA3/VA4 add new material and would push the main
paper to 13 pages.

---

## 4. Supplement integration checklist

- [ ] Add VA1 as Fig. S4 (or the next free number) near Table S8.
- [ ] Add VA2 as Fig. S5 near the certificate/ledger description.
- [ ] Add VA3 as Fig. S6 immediately after Table S6; keep the caption's
      39.8 vs 40.5 s note.
- [ ] Add VA4 as Fig. S7 in the evaluation synthesis; keep the "unknown is not
      negative" note.
- [ ] Use `\includegraphics[width=\textwidth]{figures/va0X_...pdf}`.
- [ ] Do not duplicate any VA figure in the main text.
- [ ] Re-run the supplement compile; this task did not modify the supplement.
- [ ] If the supplement page count becomes a constraint, VA3 (0.69 page) is
      the first candidate to move to the artifact/reproducibility appendix;
      VA1/VA2 are the design pair and should stay together.

---

## 5. Risks of the recommendation

- **VA1 at 0.82 is page-neutral but not print-legible.** The page count alone
  is not sufficient evidence for a main-text claim; the scale factor matters.
- **VA3 is a supplement companion to Table S6, not a replacement.** It repeats
  the same 49 cells by design; the value is categorical legibility, not new
  data.
- **VA4 verdicts are authored.** The numeric evidence is read from JSON and
  asserted, but the supports/refutes/unknown mapping is an author judgment.
  A reviewer may disagree with a verdict; the evidence and source file are in
  the cell so the disagreement is local and checkable.
- **The main paper remains unchanged.** If the authors want a main-text figure,
  they must make the caption/text/space decision above and re-run the page
  budget; this branch does not do it silently.
