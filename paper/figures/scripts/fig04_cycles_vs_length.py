#!/usr/bin/env python3
"""Fig. 4 -- zkVM scanning cost: cycles versus response length.

Reads ``bench/results/cycles.json`` only.  Panel (a) plots the 30 pike-mode
measurement points (five fixed rule sets x six lengths) with the per-rule-set
least-squares line; panel (b) reports the fitted per-character slope.  The
refuted unit-price model and the order probe are deliberately *not* plotted:
they are textual findings, and putting them on the same axes would mix units.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import figstyle as fs  # noqa: E402


def main() -> None:
    data = json.loads((fs.RESULTS / "cycles.json").read_text())
    rows = [r for r in data["rows"] if r["mode"] == "pike" and r["passed"]]
    fits = data["fit"]["per_rule_set"]

    rules = sorted({r["rules"] for r in rows})
    fig, (ax_a, ax_b) = plt.subplots(
        1,
        2,
        figsize=(fs.DOUBLE_COL_IN, 2.55),
        gridspec_kw={"width_ratios": [1.55, 1.0], "wspace": 0.30},
    )

    # ---------------- (a) cycles vs length ---------------------------------
    for i, n_rules in enumerate(rules):
        pts = sorted([r for r in rows if r["rules"] == n_rules], key=lambda r: r["length"])
        xs = [p["length"] for p in pts]
        ys = [p["cycles"] for p in pts]
        fit = fits[str(n_rules)]
        kc = fit["kind_counts"]
        label = f"{n_rules} rule{'s' if n_rules > 1 else ''} ({kc['keyword']} kw, {kc['pattern']} pat)"
        color = fs.BLUE if kc["pattern"] == 0 else fs.ORANGE
        marker = fs.MARKERS[i]
        ls = fs.LINESTYLES[i]
        ax_a.plot(
            xs,
            ys,
            linestyle="none",
            marker=marker,
            markersize=3.2,
            markerfacecolor=color,
            markeredgecolor="white",
            markeredgewidth=0.25,
            zorder=3,
        )
        xline = [200, 100000]
        yline = [fit["intercept"] + fit["slope"] * x for x in xline]
        ax_a.plot(
            xline,
            yline,
            color=color,
            linestyle=ls,
            linewidth=0.9,
            alpha=0.9,
            zorder=2,
            label=label,
        )

    ax_a.set_xscale("log")
    ax_a.set_yscale("log")
    ax_a.set_xlim(150, 1.5e5)
    ax_a.set_ylim(4.5e4, 8e8)
    ax_a.set_xlabel("Response length $|T|$ (characters, log scale)")
    ax_a.set_ylabel("zkVM execution cycles (log scale)")
    ax_a.set_title("Fixed rule set: exactly linear in length ($R^2{=}1.0000$)")
    ax_a.legend(loc="upper left", handlelength=1.8, handletextpad=0.5, borderaxespad=0.2)
    string_slopes = [
        fits[str(n)]["slope"] for n in rules if fits[str(n)]["kind_counts"]["pattern"] == 0
    ]
    regex_slopes = [
        fits[str(n)]["slope"] for n in rules if fits[str(n)]["kind_counts"]["pattern"] > 0
    ]
    ax_a.text(
        0.97,
        0.06,
        f"regex-bearing sets\n{min(regex_slopes):,.0f}--{max(regex_slopes):,.0f} cyc/char",
        transform=ax_a.transAxes,
        ha="right",
        va="bottom",
        fontsize=6.2,
        color=fs.ORANGE,
    )
    ax_a.text(
        0.97,
        0.30,
        f"string-only sets\n{min(string_slopes):.1f}--{max(string_slopes):.1f} cyc/char",
        transform=ax_a.transAxes,
        ha="right",
        va="bottom",
        fontsize=6.2,
        color=fs.BLUE,
    )
    fs.panel_tag(ax_a, "(a)")

    # ---------------- (b) fitted slope per rule set ------------------------
    slopes = [fits[str(n)]["slope"] for n in rules]
    colors = [fs.BLUE if fits[str(n)]["kind_counts"]["pattern"] == 0 else fs.ORANGE for n in rules]
    ypos = list(range(len(rules)))
    bars = ax_b.barh(ypos, slopes, color=colors, height=0.62, edgecolor="black", linewidth=0.35)
    for y, s in zip(ypos, slopes):
        ax_b.text(s + 90, y, f"{s:,.1f}", va="center", ha="left", fontsize=6.2)
    ax_b.set_yticks(ypos)
    ax_b.set_yticklabels(
        [
            f"{n} r\n({fits[str(n)]['kind_counts']['keyword']}kw,"
            f"{fits[str(n)]['kind_counts']['pattern']}pat)"
            for n in rules
        ],
        fontsize=6.0,
    )
    ax_b.invert_yaxis()
    ax_b.set_xlim(0, 6600)
    ax_b.set_xlabel("Fitted slope (cycles per character)")
    ax_b.set_title("One NFA regex costs $58\\times$ a string-only set")
    fs.panel_tag(ax_b, "(b)")

    fs.provenance(
        fig,
        "Source: bench/results/cycles.json (30 pike fit points of 40 total). Corpus 'demo', 372 chars, tiled for longer "
        "lengths; zkVM execution only (no proof). Every point matched no rule. Slopes are per-rule-set OLS, not a unit-price model.",
    )
    fig.subplots_adjust(bottom=0.19)
    fs.save(fig, "fig04_cycles_vs_length")


if __name__ == "__main__":
    main()
