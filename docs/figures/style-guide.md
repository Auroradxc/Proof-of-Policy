# Proof-of-Policy — figure style guide

Scope: every figure that enters `paper/tdsc-paper.tex`, the supplementary
material, or a venue submission derived from this repository. The goal is IEEE
TDSC / IEEE conference quality: legible at column width, honest about what was
measured, and reproducible from checked-in data.

The reference implementation is `paper/figures/figstyle.py` (data figures) and
`paper/figures/src/*.tex` (concept figures). This document explains the rules
those files encode.

---

## 1. Geometry

| Item | Value |
|---|---|
| Single-column design width | **3.5 in** (88.9 mm) |
| Double-column design width | **7.16 in** (181.9 mm) |
| Text width in IEEEtran compsoc | `\columnwidth` / `\textwidth` |
| Preferred include | `\includegraphics[width=\columnwidth]{...}` or `[width=\textwidth]{...}` |
| Main-text preference | single column for data figures; double column for concept diagrams only |
| Margin/padding | `savefig.pad_inches = 0.015`; no decorative border |

Author the figure at its design width. A tight-bbox PDF may come out a few
percent narrower or wider; the final width is set by `\includegraphics`, so
never hand-scale a figure to a non-standard width. Do not use `\vspace` hacks to
force a page count.

---

## 2. Fonts and type sizes

| Element | Rule |
|---|---|
| Data figures | **STIXGeneral** (Times-compatible, ships with matplotlib), `mathtext.fontset = stix` |
| Concept diagrams | **DejaVu Sans** from the bundled TTFs in `paper/figures/fonts/`; DejaVu Sans Mono by name (XeLaTeX + fontspec) |
| Axis labels | 7.5 pt |
| Tick labels | 6.5 pt |
| Legend | 6.5 pt (data), 5.5–6.0 pt for dense insets |
| Panel tags `(a)` | 8 pt bold |
| Provenance footer | 5.4 pt grey, wrapped to the figure width |
| Minimum practical size | 6 pt preferred for main-text labels; 5.4 pt permitted for dense single-column annotations; 5.2 pt only inside matrix cells / supplementary |

Use real text, not paths, and embed **TrueType / Type 42** fonts. Every figure
PDF is checked by `paper/figures/scripts/check_fonts.py`; the check fails on any
non-`ttf` embedded font. Do not use Computer Modern math in a figure whose text
is Times/Helvetica: it reads as a different document. In TikZ, write variables
as `\textit{T}`, Greek as Unicode `π`, and avoid `$...$` unless a math font is
explicitly configured.

---

## 3. Colour

Use the **Okabe–Ito** palette. It is colour-blind safe and survives greyscale
when combined with the marker/linestyle redundancy below.

| Name | Hex | Typical role |
|---|---|---|
| Blue | `#0072B2` | core / primary series |
| Orange | `#E69F00` | secondary series / bounded |
| Green | `#009E73` | verified, anchored, six-rule series |
| Vermillion | `#D55E00` | warning, naive path, open |
| Purple | `#CC79A7` | fifth series |
| Sky | `#56B4E9` | auxiliary |
| Yellow | `#F0E442` | bounded background tint |
| Grey | `#7F7F7F` / `#D9D9D9` | reference lines / bands |

Rules:

- Never encode a category by red vs green alone.
- Every multi-series plot also varies **marker** (`o s ^ D v P`) and
  **linestyle** (`- -- -. :`); every bar series also varies **hatch**
  (`/ // .. \\ x`).
- Do not use colour to encode a quantity that is already printed as a number
  (e.g., the feasibility grid prints both `✓`/`×` and the GiB value).
- Keep the background white. No gradients, shadows, 3D, or decorative fills.

---

## 4. Data-figure rules

1. **One message per panel.** If a panel needs two y-axes, split it.
2. **Units on every axis.** `cycles`, `cycles per character`, `s`, `GB`, `GiB`,
   `bit`, `probability`; state log scales in the label.
3. **State the sample and configuration** in the caption (and, where useful, in
   the footer): `n`, number of points, corpus, host, `proof_mode`, policy vkey,
   binary digest.
4. **Never interpolate a failure.** OOM/SIGKILL is drawn as an observed kill at
   its measured peak, or at the resource limit with an explicit note that the
   peak was not measured; it is never connected to a success curve.
5. **No fabricated uncertainty.** If there are no repeated measurements or CIs,
   do not draw error bars. State single-run jitter in the caption instead.
6. **No truncated axes without a note.** If an axis is clipped, say so; prefer
   a log scale or a broken axis to a misleading zoom.
7. **Do not mix口径.** Different vkeys, pre/post-fix binaries, proof tiers, or
   corpora live in separate series/panels and are named in the caption.
8. **Do not average incompatible corpora.** E.g., the 20-variant synthetic and
   300-candidate real policy corpora stay in separate panels.
9. **Generated, not typed.** Data figures read `bench/results/*.json` in the
   script. If a number is not in a result file, it does not go in the figure.
10. **Provenance footer.** Each data figure carries a 5.4 pt footer naming the
    JSON files, the host/口径, and any exclusions.

---

## 5. Concept-figure rules

- Draw the design **as implemented or explicitly labelled as a design**. Do not
  draw a planned component as if it were measured.
- Mark the trust boundary (dashed orange), public values (blue), witness/secret
  (orange), and verified/anchored artefacts (green) consistently with Fig. 1.
- Name the proof tier and its hiding property on the figure: `core` = no
  hiding; `groth16` = wrapper-level hiding, not post-quantum.
- Show `L_side` (re-execution) as open at every tier. A zero probe is not a
  zero-knowledge proof.
- Omit decoration; every arrow should carry data, control, or a binding.

---

## 6. Export

| Output | Requirement |
|---|---|
| Vector | PDF, one page, TrueType/Type 42 fonts, no raster fallback |
| Preview | PNG, 300 dpi, same basename |
| Source | Python script (data) or `.tex` (concept) in the same directory |
| Build | `make all`; `make page-budget`; `./build.sh` |
| Check | `python3 scripts/check_fonts.py` must print `ok` for every PDF |

Rules:

- `pdf.fonttype = 42`, `ps.fonttype = 42`.
- XeLaTeX concept figures use `fontspec`, not Type 1 math packages.
- Do not deliver a screenshot, an Office export, or a PNG-only figure.
- File naming: `figNN_short_name.pdf` / `.png`; the source keeps the same stem.
- Keep the PDF and PNG in `paper/figures/`; the source in `src/` or `scripts/`.

---

## 7. Accessibility and print

- Check every figure in greyscale: markers/linestyles/hatches must still
  distinguish series; status cells spell out `open` / `closed` / `bounded`.
- Contrast: black text on white or on the lightest tints; no white text on
  yellow/orange.
- Minimum 6 pt preferred for any text a reader must read at 100% print; 5.4 pt
  is permitted for dense single-column annotations, and 5.2 pt only for
  secondary cell annotations in the supplementary.
- Avoid thin hairlines below 0.4 pt; use 0.5–0.6 pt for axes and 1.0–1.2 pt for
  primary data lines.
- Legends must not cover data or failure markers. Prefer direct labels when a
  legend would sit over an OOM band.

---

## 8. Pre-submission checklist

- [ ] The figure states one scientific message, and the caption says what
      cannot be inferred from it.
- [ ] Axis labels carry units and scale.
- [ ] `n`, configuration, source file, `proof_mode`/vkey (if applicable) are in
      the caption or footer.
- [ ] No error bars/CIs unless the underlying repeated measurements exist.
- [ ] Every OOM/SIGKILL is an observed marker with a note; no interpolation.
- [ ] Different vkeys/corpora/tiers are not mixed in one series.
- [ ] `k_est` is labelled an upper bound; temperature 0 is separate.
- [ ] Policy A1 vs E2 and L2 vs L2* are separate and named.
- [ ] Issuance is labelled detection, not prevention.
- [ ] `core` vs `groth16` hiding is stated correctly.
- [ ] PDF fonts are TrueType and `check_fonts.py` passes.
- [ ] PNG preview is 300 dpi and visually inspected.
- [ ] The main paper is still 12 pages (`make page-budget`); if not, the figure
      goes to the supplement.
