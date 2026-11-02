#!/usr/bin/env python3
"""Fig. 7 -- measured guessing entropy upper bound k_est (E6).

Qwen and Mistral values come from the teacher-forced log-probability runs
``bench/results/k_logprobs.json`` and ``bench/results/e6_mistral/k_logprobs.json``.
The estimator returns an *upper* bound on the true k, so points below 40 bit
refute the 40-bit condition while points above it do not certify it.  The
temperature-0 greedy control is kept in a separate panel rather than being
mixed into the same axis.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import figstyle as fs  # noqa: E402


def groups(path: Path, temp: float):
    d = json.loads(path.read_text())
    return [g for g in d["groups"] if abs(g["temperature"] - temp) < 1e-9], d


def main() -> None:
    q_path = fs.RESULTS / "k_logprobs.json"
    m_path = fs.RESULTS / "e6_mistral" / "k_logprobs.json"
    q_g, q_doc = groups(q_path, 0.7)
    m_g, m_doc = groups(m_path, 0.7)
    q0, _ = groups(q_path, 0.0)
    m0, _ = groups(m_path, 0.0)
    threshold = float(q_doc["threshold_bits"])

    fig = plt.figure(figsize=(fs.SINGLE_COL_IN, 2.95))
    gs = fig.add_gridspec(2, 1, height_ratios=[2.5, 1.0], hspace=0.78)
    ax = fig.add_subplot(gs[0])
    ax0 = fig.add_subplot(gs[1])

    # ---------------- (a) k_est distribution -------------------------------
    ax.axvspan(8, threshold, color=fs.ORANGE, alpha=0.10, lw=0)
    ax.axvline(threshold, color=fs.BLACK, linestyle="--", linewidth=0.8)
    ax.text(
        threshold * 1.05,
        0.38,
        "40-bit",
        rotation=90,
        ha="left",
        va="center",
        fontsize=5.8,
        bbox=dict(facecolor="white", edgecolor="none", pad=0.5),
    )

    rng = np.random.default_rng(20261102)
    series = [
        ("Qwen2.5-7B", q_g, 1.0, fs.BLUE, "o"),
        ("Mistral-7B", m_g, 0.0, fs.VERMILLION, "s"),
    ]
    for label, gs_list, y0, color, marker in series:
        ks = np.array([g["k_est_bits"] for g in gs_list])
        jitter = rng.uniform(-0.13, 0.13, size=len(ks))
        ax.plot(
            ks,
            y0 + jitter,
            linestyle="none",
            marker=marker,
            color=color,
            markerfacecolor=color,
            markeredgecolor="white",
            markeredgewidth=0.25,
            markersize=3.0,
            alpha=0.85,
            zorder=3,
        )
        med = float(np.median(ks))
        ax.plot([med, med], [y0 - 0.26, y0 + 0.26], color="black", linewidth=0.9, zorder=4)
        below = int((ks < threshold).sum())
        ax.text(
            8.6,
            1.72 if y0 > 0.5 else 1.48,
            f"{label}: median {med:.1f} bit; {below}/{len(ks)} below 40",
            fontsize=5.9,
            va="center",
            ha="left",
            color=color,
            bbox=dict(facecolor="white", edgecolor="none", pad=0.6),
        )

    ax.set_xscale("log")
    ax.set_xlim(8, 320)
    ax.set_ylim(-0.55, 1.95)
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["Mistral", "Qwen"], fontsize=6.5)
    ax.set_xlabel("$k^{\\mathrm{est}}$ = $-\\log_2 p_{\\max}^{\\mathrm{est}}$ (bit, log scale)")
    ax.set_title("Upper bound on guessing entropy at temperature 0.7 ($N{=}20$)")
    ax.text(
        threshold * 1.06,
        -0.42,
        "not certified by this bound",
        fontsize=5.6,
        color=fs.GREY,
        va="center",
        ha="left",
    )
    ax.text(
        8.6,
        -0.42,
        "refuted: true $k<40$",
        fontsize=5.6,
        color=fs.VERMILLION,
        va="center",
        ha="left",
    )
    fs.panel_tag(ax, "(a)", x=-0.13, y=1.02)

    # ---------------- (b) temperature-0 control ----------------------------
    names = ["Qwen", "Mistral"]
    fracs = [
        sum(1 for g in q0 if g["k_est_bits"] == 0.0) / len(q0),
        sum(1 for g in m0 if g["k_est_bits"] == 0.0) / len(m0),
    ]
    bars = ax0.bar([0, 1], fracs, width=0.55, color=[fs.BLUE, fs.VERMILLION], edgecolor="black", linewidth=0.35)
    for x, f in zip([0, 1], fracs):
        ax0.text(x, f + 0.05, f"{f:.2f}", ha="center", va="bottom", fontsize=6.2)
    ax0.set_xticks([0, 1])
    ax0.set_xticklabels(names, fontsize=6.5)
    ax0.set_ylim(0, 1.18)
    ax0.set_ylabel("Fraction $k{=}0$")
    ax0.set_title("Greedy decoding (T=0): $k{=}0$ in all 50/50 groups", fontsize=6.6)
    fs.panel_tag(ax0, "(b)", x=-0.22, y=1.02)

    fs.provenance(
        fig,
        "Source: k_logprobs.json + e6_mistral/k_logprobs.json. XSTest, 50 prompts x 20 samples, T=0.7, "
        "chat template; threshold 40 bit (q=2^20, eps=2^-20). k_est is an UPPER bound: left of 40 refutes, "
        "right of 40 does not certify.",
        y=-0.055,
    )
    fig.subplots_adjust(bottom=0.20, left=0.19, right=0.98, top=0.92)
    fs.save(fig, "fig07_k_est")


if __name__ == "__main__":
    main()
