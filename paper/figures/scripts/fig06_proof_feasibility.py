#!/usr/bin/env python3
"""Fig. 6 -- real SP1 proofs: wall time vs peak RSS, feasibility not a rectangle.

Sources (post-NFA-fix cloud runs only, policy vkey 0x003eb14d...):
  bench/results/scale-cloud.json      18-point 3x3x2 matrix (core, groth16)
  bench/results/scale-6x20xx.json     6-rule length sweep (core)
  bench/results/eu_ai_act_proof.json  EU AI Act pack, both tiers

OOM points have no measured peak RSS.  They are drawn at the cgroup memory
limit with an open cross and an explicit note; they are never connected.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import figstyle as fs  # noqa: E402


def load_json(name: str):
    return json.loads((fs.RESULTS / name).read_text())


def main() -> None:
    scale = load_json("scale-cloud.json")
    eu = load_json("eu_ai_act_proof.json")
    six = []
    for name in ("scale-6x2000.json", "scale-6x3000.json", "scale-6x4000.json", "scale-6x4500.json", "scale-6x5000.json"):
        six.extend(load_json(name)["rows"])

    cgroup_gib = scale["host"]["mem_total_cgroup_mb"] / 1024.0
    rows = scale["rows"]
    core_ok = [r for r in rows if r["proof_mode"] == "core" and r["ok"]]
    g16_ok = [r for r in rows if r["proof_mode"] == "groth16" and r["ok"]]
    six_ok = [r for r in six if r["ok"]]
    oom = [r for r in rows if not r["ok"]] + [r for r in six if not r["ok"]]
    core_floor = min(r["peak_rss_mb"] for r in core_ok) / 1024.0
    six_last = six_ok[-1]
    six_kill = next(r for r in six if not r["ok"])
    headroom = load_json("scale-6x4500.json")["provenance"]["sampling"]["headroom_vs_memory_max_bytes"]

    fig, (ax_a, ax_b, ax_c) = plt.subplots(
        1,
        3,
        figsize=(fs.DOUBLE_COL_IN, 2.72),
        gridspec_kw={"width_ratios": [1.50, 1.0, 0.92], "wspace": 0.38},
    )

    # ---------------- (a) time vs peak RSS ---------------------------------
    ax_a.axvspan(88, 106, color=fs.LIGHT_GREY, alpha=0.45, lw=0)
    ax_a.axvline(cgroup_gib, color=fs.GREY, linestyle=":", linewidth=0.8)

    def xy(r):
        return r["peak_rss_mb"] / 1024.0, r["seconds"]

    ax_a.plot(
        [xy(r)[0] for r in core_ok],
        [xy(r)[1] for r in core_ok],
        "o",
        color=fs.BLUE,
        markerfacecolor=fs.BLUE,
        markeredgecolor="white",
        markeredgewidth=0.3,
        markersize=4.2,
        linestyle="none",
        label="core (STARK)",
        zorder=3,
    )
    ax_a.plot(
        [xy(r)[0] for r in g16_ok],
        [xy(r)[1] for r in g16_ok],
        "s",
        color=fs.ORANGE,
        markerfacecolor=fs.ORANGE,
        markeredgecolor="white",
        markeredgewidth=0.3,
        markersize=4.2,
        linestyle="none",
        label="groth16 wrapper",
        zorder=3,
    )
    ax_a.plot(
        [xy(r)[0] for r in six_ok],
        [xy(r)[1] for r in six_ok],
        "^",
        color=fs.GREEN,
        markerfacecolor=fs.GREEN,
        markeredgecolor="white",
        markeredgewidth=0.3,
        markersize=4.6,
        linestyle="none",
        label="core, 6 rules",
        zorder=3,
    )
    for p, marker in ((eu["points"][0], "*"), (eu["points"][1], "*")):
        ax_a.plot(
            p["peak_rss_mb"] / 1024.0,
            p["seconds"],
            marker=marker,
            color=fs.BLACK,
            markerfacecolor="none",
            markeredgewidth=0.7,
            markersize=8.5,
            linestyle="none",
            zorder=5,
        )

    # OOM events: x is the cgroup limit, not a measured peak.
    for r in oom:
        ax_a.plot(
            cgroup_gib,
            r["seconds"],
            marker="X",
            color=fs.BLACK,
            markerfacecolor="white",
            markeredgewidth=0.9,
            markersize=5.2,
            linestyle="none",
            zorder=6,
        )
    ax_a.text(
        cgroup_gib + 1.2,
        205,
        "OOM / SIGKILL\n(peak unmeasured;\nx = cgroup limit)",
        fontsize=5.7,
        color=fs.BLACK,
        va="center",
        ha="left",
    )
    ax_a.annotate(
        "EU groth16",
        xy=(eu["points"][1]["peak_rss_mb"] / 1024.0, eu["points"][1]["seconds"]),
        xytext=(36.5, 318),
        fontsize=5.8,
        color=fs.BLACK,
        arrowprops=dict(arrowstyle="-", color=fs.GREY, lw=0.4),
    )
    ax_a.annotate(
        f"6 rules x {six_last['length']}\n{six_last['peak_rss_mb'] / 1024.0:.1f} GiB",
        xy=(six_last["peak_rss_mb"] / 1024.0, six_last["seconds"]),
        xytext=(44, 205),
        fontsize=5.8,
        color=fs.GREEN,
        arrowprops=dict(arrowstyle="-", color=fs.GREEN, lw=0.45),
    )
    ax_a.annotate(
        f"core floor\n$\\approx${core_floor:.1f} GiB",
        xy=(10.6, 41.5),
        xytext=(15.5, 42),
        fontsize=5.8,
        color=fs.BLUE,
        arrowprops=dict(arrowstyle="-", color=fs.BLUE, lw=0.4),
    )
    ax_a.text(38.0, 268, "groth16", fontsize=5.8, color=fs.ORANGE)
    ax_a.set_xlim(8, 106)
    ax_a.set_ylim(30, 380)
    ax_a.set_xlabel("Peak RSS (GiB)")
    ax_a.set_ylabel("Proving wall time (s)")
    ax_a.set_title("Time is not the binding resource")
    fs.panel_tag(ax_a, "(a)", x=-0.15)

    # ---------------- (b) 3x3 feasibility grid -----------------------------
    lengths = [200, 2000, 10000]
    rules = [1, 2, 3]
    lookup = {(r["length"], r["rules"]): r for r in rows if r["proof_mode"] == "core"}
    for xi, length in enumerate(lengths):
        for yi, rule in enumerate(rules):
            r = lookup[(length, rule)]
            ok = r["ok"]
            face = "#E8F1F8" if ok else "#EDEDED"
            rect = Rectangle(
                (xi - 0.5, yi - 0.5),
                1,
                1,
                facecolor=face,
                edgecolor="black",
                linewidth=0.4,
                hatch=None if ok else "///",
                zorder=1,
            )
            ax_b.add_patch(rect)
            if ok:
                txt = f"$\\checkmark$\n{r['peak_rss_mb']/1024:.1f} GiB"
                color = fs.BLACK
            else:
                txt = "$\\times$\nOOM"
                color = fs.BLACK
            ax_b.text(xi, yi, txt, ha="center", va="center", fontsize=5.7, color=color, zorder=2)
    ax_b.set_xlim(-0.5, 2.5)
    ax_b.set_ylim(-0.5, 2.5)
    ax_b.set_xticks(range(3))
    ax_b.set_xticklabels([f"{v:,}" for v in lengths], fontsize=6.2)
    ax_b.set_yticks(range(3))
    ax_b.set_yticklabels(rules, fontsize=6.2)
    ax_b.set_xlabel("Response length (characters)")
    ax_b.set_ylabel("Rules")
    ax_b.set_title("core feasible set is not a rectangle")
    ax_b.tick_params(length=0)
    for s in ax_b.spines.values():
        s.set_visible(True)
        s.set_linewidth(0.4)
    fs.panel_tag(ax_b, "(b)", x=-0.20)

    # ---------------- (c) six-rule memory cliff ----------------------------
    lens = [r["length"] for r in six_ok]
    rss = [r["peak_rss_mb"] / 1024.0 for r in six_ok]
    ax_c.plot(lens, rss, "-o", color=fs.GREEN, markerfacecolor=fs.GREEN, markeredgecolor="white", markersize=3.8)
    ax_c.axhline(cgroup_gib, color=fs.GREY, linestyle=":", linewidth=0.8)
    ax_c.plot(six_kill["length"], cgroup_gib, marker="X", color=fs.BLACK, markerfacecolor="white", markeredgewidth=0.9, markersize=5.4)
    ax_c.annotate(
        f"{six_kill['length']}: SIGKILL\nafter {six_kill['seconds']:.1f} s",
        xy=(six_kill["length"], cgroup_gib),
        xytext=(5220, 84),
        ha="right",
        fontsize=5.8,
        color=fs.BLACK,
        arrowprops=dict(arrowstyle="-", color=fs.GREY, lw=0.4),
    )
    ax_c.text(2050, 94, f"cgroup limit {cgroup_gib:.0f} GiB", fontsize=5.4, color=fs.GREY, va="top")
    ax_c.annotate(
        f"{six_last['length']}: {headroom:,} B\nheadroom",
        xy=(six_last["length"], rss[-1]),
        xytext=(2100, 72),
        fontsize=5.7,
        color=fs.GREEN,
        arrowprops=dict(arrowstyle="-", color=fs.GREEN, lw=0.45),
    )
    ax_c.set_xlim(1800, 5300)
    ax_c.set_ylim(30, 100)
    ax_c.set_xlabel("Length (characters)")
    ax_c.set_ylabel("Peak RSS (GiB)")
    ax_c.set_title(f"6 rules: measured edge at {six_last['length']}")
    fs.panel_tag(ax_c, "(c)", x=-0.26)

    fs.provenance(
        fig,
        "Sources: scale-cloud.json (18 matrix points), scale-6x{2000,3000,4000,4500,5000}.json, eu_ai_act_proof.json. "
        "Host: 16-core / 92,160 MiB cgroup, post-NFA-fix binary 7f99fdb1..., policy vkey 0x003eb14d..., core/groth16, "
        "one proof per process serially. Each OOM cross marks a kill; its x is the cgroup limit, not a measured peak. "
        "6-rule OOM at 10000/50000 chars is omitted for space, not for a better result.",
    )
    fig.subplots_adjust(bottom=0.23, left=0.06, right=0.99, top=0.90)
    fs.save(fig, "fig06_proof_feasibility")


if __name__ == "__main__":
    main()
