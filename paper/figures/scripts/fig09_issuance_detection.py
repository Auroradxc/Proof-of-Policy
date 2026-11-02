#!/usr/bin/env python3
"""Fig. 9 -- issuance audit detection and the sample frame.

All values come from ``bench/results/issuance.json``: the exact hypergeometric
detection probability 1 - C(N-m,s)/C(N,s) over the N=2000, p, m grid, and the
F1 simulation that contrasts the delivered-artifact frame with the log frame.
Detection is not prevention; the figure says so in the caption and footer.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import figstyle as fs  # noqa: E402


def main() -> None:
    d = json.loads((fs.RESULTS / "issuance.json").read_text())
    table = d["table"]
    f1 = d["f1"]
    N = d["model"]["deliveries"]

    fig = plt.figure(figsize=(fs.SINGLE_COL_IN, 3.15))
    gs = fig.add_gridspec(2, 1, height_ratios=[2.2, 1.0], hspace=0.62)
    ax = fig.add_subplot(gs[0])
    axb = fig.add_subplot(gs[1])

    ps = sorted({round(t["p"], 4) for t in table})
    for i, p in enumerate(ps):
        pts = sorted([t for t in table if abs(t["p"] - p) < 1e-9], key=lambda t: t["m"])
        ax.plot(
            [t["m"] for t in pts],
            [t["exact_hypergeom"] for t in pts],
            marker=fs.MARKERS[i],
            linestyle=fs.LINESTYLES[i],
            color=fs.PALETTE[i],
            markersize=3.0,
            linewidth=1.0,
            label=f"p = {p:.2f}",
        )
    ax.set_xscale("log")
    ax.set_xlim(0.8, 620)
    ax.set_ylim(0, 1.04)
    ax.set_xlabel("Withheld violations $m$ (log scale)")
    ax.set_ylabel("Detection probability")
    ax.set_title(f"Exact detection over delivered artifacts ($N{{=}}{N:,}$)")
    ax.legend(loc="lower right", ncol=1, fontsize=5.6, handlelength=1.9)
    fs.panel_tag(ax, "(a)", x=-0.19, y=1.03)

    labels = ["Delivered\nartifact frame", "Log\nentry frame"]
    vals = [f1["delivery_frame_exact"], f1["log_frame_exact"]]
    bars = axb.bar(
        [0, 1],
        vals,
        width=0.52,
        color=[fs.BLUE, fs.VERMILLION],
        edgecolor="black",
        linewidth=0.35,
        hatch=["", "///"],
    )
    for b, v in zip(bars, vals):
        axb.text(
            b.get_x() + b.get_width() / 2,
            v + 0.035,
            f"{v:.4f}",
            ha="center",
            va="bottom",
            fontsize=6.2,
        )
    axb.set_xticks([0, 1])
    axb.set_xticklabels(labels, fontsize=6.0)
    axb.set_ylim(0, 1.18)
    axb.set_ylabel("Detection")
    axb.set_title(
        f"p=0.05, s={f1['s']}, m={f1['violations']}: frame, not luck",
        fontsize=6.8,
    )
    axb.text(
        0.98,
        0.58,
        f"{N:,} delivered; {f1['log_size']:,} log entries\nwithheld deliveries have no entry",
        transform=axb.transAxes,
        ha="right",
        va="center",
        fontsize=5.4,
        color=fs.BLACK,
    )
    fs.panel_tag(axb, "(b)", x=-0.24, y=1.05)

    fs.provenance(
        fig,
        f"Source: issuance.json. N={N:,}; p in {{{min(ps):.2f}..{max(ps):.2f}}}; exact hypergeometric, "
        f"{d['model']['trials']} MC trials/cell. F1: m={f1['violations']} withheld, {f1['log_size']:,} log entries. "
        "Detection, not prevention; the log frame is wrong by construction.",
        y=-0.05,
    )
    fig.subplots_adjust(bottom=0.22, left=0.20, right=0.98, top=0.92)
    fs.save(fig, "fig09_issuance_detection")


if __name__ == "__main__":
    main()
