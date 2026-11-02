#!/usr/bin/env python3
"""Fig. 5 -- matcher ablation: quadratic naive vs linear Pike.

Panel (a) reads the three execution-path points from
``bench/results/ablation.json``; panel (b) reads the three proving-path points
from ``bench/results/dos_proof.json``.  The out-of-memory point is plotted as an
observed kill at its measured peak, never smoothed into a curve.
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
    abl = json.loads((fs.RESULTS / "ablation.json").read_text())
    dos = json.loads((fs.RESULTS / "dos_proof.json").read_text())

    fig, (ax_a, ax_b) = plt.subplots(
        1, 2, figsize=(fs.DOUBLE_COL_IN, 2.45), gridspec_kw={"wspace": 0.32}
    )

    # ---------------- (a) execution cycles ---------------------------------
    series = {}
    for mode in ("pike", "naive"):
        pts = sorted([r for r in abl["rows"] if r["mode"] == mode], key=lambda r: r["n"])
        series[mode] = (np.array([p["n"] for p in pts]), np.array([p["cycles"] for p in pts]))

    for i, mode in enumerate(("pike", "naive")):
        n, c = series[mode]
        color = fs.BLUE if mode == "pike" else fs.VERMILLION
        ax_a.plot(
            n,
            c,
            marker=fs.MARKERS[i],
            linestyle=fs.LINESTYLES[i],
            color=color,
            linewidth=1.1,
            markersize=4.0,
            label="Pike VM (linear)" if mode == "pike" else "naive re-anchoring",
        )

    n_ref = np.array([90, 450])
    pike0 = series["pike"][1][0] / series["pike"][0][0]  # cycles per char at n=100
    naive0 = series["naive"][1][0] / series["naive"][0][0]
    ax_a.plot(
        n_ref,
        naive0 * n_ref**2,
        color=fs.GREY,
        linestyle=":",
        linewidth=0.9,
        zorder=1,
    )
    ax_a.plot(
        n_ref,
        pike0 * n_ref,
        color=fs.GREY,
        linestyle=":",
        linewidth=0.9,
        zorder=1,
    )
    ax_a.text(118, 3.1e7, r"$\Theta(n^2)$ reference", fontsize=6, color=fs.GREY, rotation=13)
    ax_a.text(240, 1.8e6, r"$\Theta(n)$ reference", fontsize=6, color=fs.GREY, rotation=10)

    ratios = {r["n_from"]: r for r in abl["ratios"]}
    ax_a.annotate(
        f"{ratios[200]['ratio']:.1f}$\\times$ at $n{{=}}400$",
        xy=(400, series["naive"][1][-1]),
        xytext=(205, 2.5e8),
        fontsize=6.2,
        color=fs.VERMILLION,
        arrowprops=dict(arrowstyle="-", color=fs.VERMILLION, lw=0.5),
    )
    ax_a.set_xscale("log")
    ax_a.set_yscale("log")
    ax_a.set_xlim(80, 520)
    ax_a.set_ylim(4e5, 4e8)
    ax_a.set_xlabel("Input length $n$ ($a^n$, no match)")
    ax_a.set_ylabel("zkVM execution cycles (log scale)")
    ax_a.set_title("Execution: naive grows as $n^2$")
    ax_a.legend(loc="upper left", handlelength=2.0, borderaxespad=0.15)
    fs.panel_tag(ax_a, "(a)")

    # ---------------- (b) proving path -------------------------------------
    host_gib = dos["machine"]["mem_total_gib"]
    proof = dos["proof"]
    for p in proof:
        n = p["n"]
        rss = p["peak_rss_mib"] / 1024.0
        ok = p["status"] == "ok"
        color = fs.BLUE if p["mode"] == "pike" else fs.VERMILLION
        marker = "o" if p["mode"] == "pike" else "s"
        if ok:
            ax_b.plot(
                n,
                rss,
                marker=marker,
                color=color,
                markerfacecolor=color,
                markeredgecolor="white",
                markeredgewidth=0.4,
                markersize=5.2,
                linestyle="none",
                zorder=3,
            )
        else:
            ax_b.plot(
                n,
                rss,
                marker="X",
                color=fs.BLACK,
                markerfacecolor="white",
                markeredgewidth=0.9,
                markersize=5.8,
                linestyle="none",
                zorder=4,
            )

    ax_b.axhline(host_gib, color=fs.GREY, linestyle="--", linewidth=0.8)
    ax_b.text(2, host_gib - 0.10, f"host memory: {host_gib:.1f} GiB", fontsize=6.0, color=fs.GREY, va="top")
    for p in proof:
        n = p["n"]
        rss = p["peak_rss_mib"] / 1024.0
        if p["mode"] == "pike":
            txt = f"Pike $n{{=}}{n}$\n{p['prove_wall_s']:.1f} s, proved"
            xytext = (64, 11.62)
            ha, va = "left", "top"
        elif p["status"] == "ok":
            txt = f"naive $n{{=}}{n}$\n{p['prove_wall_s']:.1f} s, proved"
            xytext = (6, 11.62)
            ha, va = "left", "top"
        else:
            txt = f"naive $n{{=}}{n}$\nOOM / SIGKILL after {p['prove_wall_s']:.1f} s"
            xytext = (57, 14.28)
            ha, va = "left", "top"
        ax_b.annotate(
            txt,
            xy=(n, rss),
            xytext=xytext,
            fontsize=5.9,
            ha=ha,
            va=va,
            arrowprops=dict(arrowstyle="-", color=fs.GREY, lw=0.4),
        )

    ax_b.annotate(
        "",
        xy=(48, 13.40),
        xytext=(27, 12.05),
        arrowprops=dict(arrowstyle="->", color=fs.GREY, lw=0.6, linestyle=(0, (2, 2))),
    )
    ax_b.text(31.5, 12.62, "$2\\times$ length", fontsize=6.0, color=fs.GREY, rotation=15, bbox=dict(facecolor="white", edgecolor="none", pad=0.5))
    ax_b.set_xlim(-2, 115)
    ax_b.set_ylim(10.4, 15.4)
    ax_b.set_xlabel("Input length $n$")
    ax_b.set_ylabel("Peak RSS (GiB)")
    ax_b.set_title("Proving: the quadratic term meets the memory floor")
    fs.panel_tag(ax_b, "(b)")

    fs.provenance(
        fig,
        "Sources: bench/results/ablation.json (execution) and dos_proof.json (proving; 24-core / 14.6 GiB host, "
        "pre-NFA-fix binary b81e6d07..., core tier). Points at n=25/50/100 are separate runs; no n>=100 naive or n=400 "
        "proving point was measured, so no proving curve is drawn. The n=50 point is an observed kill at measured peak.",
    )
    fig.subplots_adjust(bottom=0.22)
    fs.save(fig, "fig05_matcher_ablation")


if __name__ == "__main__":
    main()
