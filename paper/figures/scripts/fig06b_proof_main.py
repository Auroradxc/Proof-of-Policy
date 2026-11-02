#!/usr/bin/env python3
"""Fig. 6b -- compact single-column proof-feasibility panel (main-text candidate).

Same sources and exclusions as Fig. 6; only the encoding changes.  This variant
is 3.5 in wide and is the one tested for a page-neutral replacement of Table I.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import figstyle as fs  # noqa: E402


def main() -> None:
    scale = json.loads((fs.RESULTS / "scale-cloud.json").read_text())
    eu = json.loads((fs.RESULTS / "eu_ai_act_proof.json").read_text())
    six = []
    for name in ("scale-6x2000.json", "scale-6x3000.json", "scale-6x4000.json", "scale-6x4500.json", "scale-6x5000.json"):
        six.extend(json.loads((fs.RESULTS / name).read_text())["rows"])

    cgroup = scale["host"]["mem_total_cgroup_mb"] / 1024.0
    rows = scale["rows"]
    core = [r for r in rows if r["proof_mode"] == "core" and r["ok"]]
    g16 = [r for r in rows if r["proof_mode"] == "groth16" and r["ok"]]
    six_ok = [r for r in six if r["ok"]]
    oom = [r for r in rows if not r["ok"]] + [r for r in six if not r["ok"]]
    core_floor = min(r["peak_rss_mb"] for r in core) / 1024.0
    p_2000_3 = next(r for r in rows if r["length"] == 2000 and r["rules"] == 3)
    six_last = six_ok[-1]
    g16_min = min(r["peak_rss_mb"] for r in g16) / 1024.0
    g16_times = [r["seconds"] for r in g16]

    fig, ax = plt.subplots(figsize=(fs.SINGLE_COL_IN, 1.75))
    ax.axvspan(88, 106, color=fs.LIGHT_GREY, alpha=0.45, lw=0)
    ax.axvline(cgroup, color=fs.GREY, linestyle=":", linewidth=0.8)

    for pts, marker, color, label in (
        (core, "o", fs.BLUE, "core"),
        (g16, "s", fs.ORANGE, "groth16"),
        (six_ok, "^", fs.GREEN, "core, 6 rules"),
    ):
        ax.plot(
            [r["peak_rss_mb"] / 1024.0 for r in pts],
            [r["seconds"] for r in pts],
            marker=marker,
            linestyle="none",
            color=color,
            markerfacecolor=color,
            markeredgecolor="white",
            markeredgewidth=0.3,
            markersize=3.8,
            label=label,
            zorder=3,
        )
    for idx, p in enumerate(eu["points"]):
        ax.plot(
            p["peak_rss_mb"] / 1024.0,
            p["seconds"],
            marker="*",
            color=fs.BLACK,
            markerfacecolor="none",
            markeredgewidth=0.6,
            markersize=7.5,
            linestyle="none",
            zorder=5,
            label="EU AI Act" if idx == 0 else None,
        )
    for r in oom:
        ax.plot(
            cgroup,
            r["seconds"],
            marker="X",
            color=fs.BLACK,
            markerfacecolor="white",
            markeredgewidth=0.9,
            markersize=4.6,
            linestyle="none",
            zorder=6,
        )

    ax.text(86.0, 210, "OOM / SIGKILL\n(peak unmeasured;\nx = cgroup limit)", fontsize=5.3, va="center", ha="right")
    ax.annotate(
        f"2000x3\n{p_2000_3['peak_rss_mb'] / 1024.0:.1f} GiB",
        xy=(p_2000_3["peak_rss_mb"] / 1024.0, p_2000_3["seconds"]),
        xytext=(21, 150),
        fontsize=5.4,
        color=fs.BLUE,
        arrowprops=dict(arrowstyle="-", color=fs.BLUE, lw=0.4),
    )
    ax.annotate(
        f"6 rules x {six_last['length']}\n{six_last['peak_rss_mb'] / 1024.0:.1f} GiB",
        xy=(six_last["peak_rss_mb"] / 1024.0, six_last["seconds"]),
        xytext=(47, 262),
        fontsize=5.4,
        color=fs.GREEN,
        arrowprops=dict(arrowstyle="-", color=fs.GREEN, lw=0.4),
    )
    ax.annotate(
        f"core floor\n$\\approx${core_floor:.1f} GiB",
        xy=(core_floor, 41.5),
        xytext=(15.5, 50),
        fontsize=5.4,
        color=fs.BLUE,
        arrowprops=dict(arrowstyle="-", color=fs.BLUE, lw=0.4),
    )
    ax.text(
        38.5,
        52,
        f"groth16: +{g16_min - core_floor:.0f} GiB,\n{min(g16_times):.0f}--{max(g16_times):.0f} s",
        fontsize=5.4,
        color=fs.ORANGE,
    )
    ax.text(36.5, 282, "groth16", fontsize=5.4, color=fs.ORANGE)
    ax.text(30.8, 314, "EU AI Act", fontsize=5.4, color=fs.BLACK)

    ax.set_xlim(8, 106)
    ax.set_ylim(30, 330)
    ax.set_xlabel("Peak RSS (GiB)", fontsize=7.0)
    ax.set_ylabel("Proving time (s)", fontsize=7.0)
    ax.tick_params(labelsize=6.0)

    fig.text(
        0.01,
        0.006,
        "Source: scale-cloud.json, scale-6x*.json, eu_ai_act_proof.json; post-NFA-fix vkey 0x003eb14d...",
        fontsize=4.4,
        color=fs.GREY,
        ha="left",
        va="bottom",
    )
    fig.subplots_adjust(bottom=0.28, left=0.20, right=0.985, top=0.98)
    fs.save(fig, "fig06b_proof_main")


if __name__ == "__main__":
    main()
