#!/usr/bin/env python3
"""Fig. 8 -- policy disclosure levels and the inference they permit.

Two corpora are kept in separate rows and never merged into one bar:
  * A1, ``bench/results/policy_infer.json``: 20 synthetic policy variants,
    template-generated responses, count-only L2.
  * E2, ``bench/results/policy_corpus_infer.json``: 300 candidates, 220 real
    chat responses, v1 certificate payload (deterministic evidence commitments).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import figstyle as fs  # noqa: E402


def grouped(
    ax,
    levels,
    series,
    ylabel,
    ylim=(0, 1.06),
    chance=None,
    legend_loc="upper right",
):
    """Draw two grouped bars per level."""
    x = np.arange(len(levels))
    width = 0.34
    for i, (label, vals, color, hatch) in enumerate(series):
        offset = (i - 0.5) * width
        bars = ax.bar(
            x + offset,
            vals,
            width,
            label=label,
            color=color,
            edgecolor="black",
            linewidth=0.3,
            hatch=hatch,
            zorder=2,
        )
        for b, v in zip(bars, vals):
            ax.text(
                b.get_x() + b.get_width() / 2,
                v + 0.012,
                f"{v:.2f}",
                ha="center",
                va="bottom",
                fontsize=5.4,
                zorder=3,
            )
    ax.set_xticks(x)
    ax.set_xticklabels(levels, fontsize=6.3)
    ax.set_ylim(*ylim)
    ax.set_ylabel(ylabel)
    if chance is not None:
        ax.axhline(chance, color=fs.GREY, linestyle=":", linewidth=0.7, label="chance")
    ax.legend(loc=legend_loc, ncol=1, fontsize=5.8, handlelength=1.3, borderaxespad=0.15)


def main() -> None:
    a1 = json.loads((fs.RESULTS / "policy_infer.json").read_text())
    e2 = json.loads((fs.RESULTS / "policy_corpus_infer.json").read_text())

    a_lv = ["L0", "L1", "L2"]
    a = a1["levels"]
    e = e2["datasets"]["300"]["real"]["levels"]
    e_lv = ["L0", "L1", "L2", "L2*"]
    e_keys = ["L0", "L1", "L2", "L2_count_only"]

    fig, axes = plt.subplots(2, 2, figsize=(fs.DOUBLE_COL_IN, 3.25), gridspec_kw={"wspace": 0.30, "hspace": 0.52})
    ax_a, ax_b, ax_c, ax_d = axes.ravel()

    # (a) A1: recovery
    grouped(
        ax_a,
        a_lv,
        [
            ("top-1", [a[l]["top1"] for l in a_lv], fs.BLUE, ""),
            ("top-3", [a[l]["top3"] for l in a_lv], fs.ORANGE, "///"),
        ],
        "Recovery rate",
        chance=a["L0"]["chance_top1"],
    )
    ax_a.set_title(f"(a) A1: {a1['variants']} synthetic variants, recovery")
    ax_a.set_ylim(0, 1.12)

    # (b) A1: leakage and audit utility
    grouped(
        ax_b,
        a_lv,
        [
            ("norm. MI", [a[l]["normalized_mi"] for l in a_lv], fs.GREEN, ".."),
            ("audit utility", [a[l]["action_utility"] for l in a_lv], fs.VERMILLION, "\\\\\\"),
        ],
        "Normalized score",
        legend_loc="upper right",
    )
    ax_b.set_title("(b) A1: leakage vs. repair utility")

    # (c) E2 real: recovery
    grouped(
        ax_c,
        e_lv,
        [
            ("top-1", [e[k]["top1"] for k in e_keys], fs.BLUE, ""),
            ("top-3", [e[k]["top3"] for k in e_keys], fs.ORANGE, "///"),
        ],
        "Recovery rate",
        chance=e["L0"]["chance_top1"],
    )
    ax_c.set_title(
        f"(c) E2: {e2['candidate_corpus']['generated']} candidates, "
        f"{e2['response_sources']['real_unique_responses']} real responses"
    )
    ax_c.set_ylim(0, 0.72)

    # (d) E2 real: leakage and audit utility
    grouped(
        ax_d,
        e_lv,
        [
            ("norm. MI", [e[k]["normalized_mi"] for k in e_keys], fs.GREEN, ".."),
            ("audit utility", [e[k]["action_utility"] for k in e_keys], fs.VERMILLION, "\\\\\\"),
        ],
        "Normalized score",
        legend_loc="upper right",
    )
    ax_d.set_title("(d) E2: the v1 L2 payload links across samples")
    ax_d.set_xlabel("Disclosure level  (L2* = count-only projection)")
    fs.provenance(
        fig,
        "A1: policy_infer.json, 20 variants, 40 train / 15 test synthetic responses, multinomial NB; L2 is count-only. "
        "E2: policy_corpus_infer.json, 300 candidates x 220 real chat responses (19,800 test pairs), v1 certificate payload; "
        "evidence coverage 0.677. policy_hash is excluded as a feature. The v2 circuit-level L2 has NOT been re-measured; "
        "L2 and L2* are different projections of different corpora and are not averaged.",
        y=-0.045,
    )
    fig.subplots_adjust(bottom=0.19, left=0.075, right=0.985, top=0.92)
    fs.save(fig, "fig08_policy_disclosure")


if __name__ == "__main__":
    main()
