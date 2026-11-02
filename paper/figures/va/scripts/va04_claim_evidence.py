#!/usr/bin/env python3
"""VA4 -- Claim-evidence matrix.

Rows are the claims the paper makes (k, L2, OOM, agent e2e, prover cost,
delegated fail-closed, strong composition).  Columns are the experiments
E1/E6/E2/E3/X1/C2 plus the composition negative-control suite (CC).

Each cell is one of three verdicts -- supports / refutes / unknown -- plus the
numeric evidence read from the experiment's JSON and the source file.  The
script asserts every numeric token it prints against the result file, so a
changed result fails the build instead of silently changing the figure.

Run from anywhere: ``python3 scripts/va04_claim_evidence.py``.
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
import figstyle  # noqa: E402

RESULTS = figstyle.ROOT / "bench" / "results"
OUT = HERE.parent
W, H = figstyle.DOUBLE_COL_IN, 5.35

SUP, REF, UNK = "#E4F2EA", "#FBE7E1", "#F0F0F0"
SUP_E, REF_E, UNK_E = "#009E73", "#D55E00", "#9A9A9A"

CLAIMS = [
    ("C-k", "k ≥ 40 bit for all 50 XSTest prompts", "universal threshold"),
    ("C-L2", "L2 evidence commitments leak policy identity", "v1 certificate payload"),
    ("C-OOM", "Prover memory binds; core feasible set is non-rectangular", "not a time-only cost"),
    ("C-e2e", "A real agent issues and third-party verifies certificates", "mechanism, not model safety"),
    ("C-cost", "core/groth16 proving cost is measured", "not a ranking"),
    ("C-deleg", "A delegated rule without a companion proof fails closed", "conjunctive obligation"),
    ("C-strong", "Composition binds the user input x_U", "strong form, not derive(T_U)"),
]

EXPS = [
    ("E1", "E1\nk entropy"),
    ("E6", "E6\nlogprob k"),
    ("E2", "E2\nL2 inference"),
    ("E3", "E3\nagent e2e"),
    ("X1", "X1\ncloud matrix"),
    ("C2", "C2\ncircuit L0-L2"),
    ("CC", "CC\ncomposition"),
]

SOURCE = {
    "E1": "k_entropy_largeN",
    "E6": "k_logprobs",
    "E2": "policy_corpus_infer",
    "E3": "agent_e2e_deepseek",
    "X1": "scale-cloud",
    "C2": "c2/verify_L*",
    "CC": "composition_controls",
}


def load(name: str):
    with open(RESULTS / name, encoding="utf-8") as fh:
        return json.load(fh)


def build() -> dict[tuple[str, str], tuple[str, str]]:
    e1 = load("k_entropy_largeN.json")
    e1x = load("k_entropy_crossmodel.json")
    e6 = load("k_logprobs.json")
    e6m = load("e6_mistral/k_logprobs.json")
    e2 = load("policy_corpus_infer.json")
    e3 = load("agent_e2e_deepseek.json")
    x1 = load("scale-cloud.json")
    x1_6x = load("scale-6x5000.json")
    c2 = [load(f"c2/verify_L{i}.json") for i in (0, 1, 2)]
    cc = load("composition_controls.json")

    # ---------------- E1: N-capped, cannot certify the threshold -------------
    a1 = e1["aggregate"]["0.7"]
    assert a1["n_groups"] == 50 and a1["below_threshold_fraction"] == 1.0
    assert abs(a1["k_median"] - 5.643856189774724) < 1e-9
    qwen = next(m for m in e1x["models"] if "Qwen" in m["label"] and "N=50" in m["label"])
    assert qwen["aggregate"]["groups_at_ceiling"] == 50
    e1_ev = (f"{a1['n_groups']}/{a1['n_groups']} at N ceiling; "
             f"k={a1['k_median']:.2f}; cannot certify ≥40")

    # ---------------- E6: upper-bound estimator, some groups below 40 --------
    q = e6["aggregate"]["temperature_gt0"]
    m = e6m["aggregate"]["temperature_gt0"]
    assert q["threshold_bits"] == 40.0 and m["threshold_bits"] == 40.0
    assert q["n_k_below_threshold"] == 16, q["n_k_below_threshold"]
    assert m["n_k_below_threshold"] == 11, m["n_k_below_threshold"]
    assert e6["aggregate"]["greedy_temperature_0"]["n_k_below_threshold"] == 50
    e6_ev = (f"{q['n_k_below_threshold']}/{q['n_groups']} Qwen, "
             f"{m['n_k_below_threshold']}/{m['n_groups']} Mistral <40 bit; "
             f"greedy k=0 {e6['aggregate']['greedy_temperature_0']['n_k_below_threshold']}/"
             f"{e6['aggregate']['greedy_temperature_0']['n_groups']}")

    # ---------------- E2: L2 commits re-link across samples ------------------
    con = e2["datasets"]["300"]["constructive"]["levels"]
    real = e2["datasets"]["300"]["real"]["levels"]
    assert con["L2"]["top1"] == 0.3822 and con["L2_count_only"]["top1"] == 0.0142
    assert real["L2"]["top1"] == 0.1124 and real["L2_count_only"]["top1"] == 0.0167
    e2_ev = (f"L2 {con['L2']['top1']:.3f} vs L2* {con['L2_count_only']['top1']:.3f} "
             f"(constructive); {real['L2']['top1']:.3f} vs "
             f"{real['L2_count_only']['top1']:.3f} (real)")

    # ---------------- E3: real session, but no SP1 proof --------------------
    sess = next(s for s in e3["sessions"] if s["id"] == "multi_turn_agent")
    assert sess["certificates"] == 19
    assert sess["verify"]["result"] == "PASS"
    assert len(sess["verify"]["cards"]) == 11
    assert all(c["ok"] for c in sess["verify"]["cards"])
    assert any(c["name"] == "zk_proof" and "unproven" in c["detail"] for c in sess["verify"]["cards"])
    e3_ev = (f"{sess['certificates']} certs; "
             f"{sum(c['ok'] for c in sess['verify']['cards'])}/"
             f"{len(sess['verify']['cards'])} checks PASS; proof_mode=unproven")

    # ---------------- X1: 16/18 pass, 2 OOM; 6-rule 5000 OOM ----------------
    core = [r for r in x1["rows"] if r["proof_mode"] == "core"]
    g16 = [r for r in x1["rows"] if r["proof_mode"] == "groth16"]
    assert len(core) == 9 and len(g16) == 9
    assert sum(1 for r in x1["rows"] if r["ok"]) == 16
    assert sum(1 for r in x1["rows"] if not r["ok"]) == 2
    assert x1_6x["rows"][0]["ok"] is False
    core_ok = [r["seconds"] for r in core if r["ok"]]
    g16_ok = [r["seconds"] for r in g16 if r["ok"]]
    x1_oom = (f"{sum(1 for r in x1['rows'] if r['ok'])}/{len(x1['rows'])} pass; "
              f"{sum(1 for r in x1['rows'] if not r['ok'])} OOM at 10000×3; "
              "6-rule 5000 OOM")
    x1_cost = f"core {min(core_ok):.1f}-{max(core_ok):.1f} s; g16 {min(g16_ok):.1f}-{max(g16_ok):.1f} s"

    # ---------------- C2: all three disclosure levels verify -----------------
    for i, rec in enumerate(c2):
        assert rec["verified"] is True
        assert rec["outcome"]["disclosure_level"] == f"L{i}"
        assert rec["outcome"]["delegated"] == []
    c2_ev = (f"L0/L1/L2 verified ({sum(1 for r in c2 if r['verified'])} tiers); "
             "delegated empty; no inference run")

    # ---------------- CC: cell (d) fails closed; cell (c) is weak form --------
    by_id = {c["id"]: c for c in cc["cells"]}
    assert by_id["d"]["verify"]["ok"] is True
    assert by_id["d"]["verify"]["satisfied"] is False
    assert "fail closed" in by_id["d"]["verdict"]
    assert cc["summary"]["strong_form_x_U_landed"] is False
    assert by_id["c"]["verify"]["ok"] is True
    cc_deleg = "cell d: true but unsatisfied; fail closed"
    cc_strong = "cell c: weak form only; strong not landed"

    # ---------------- matrix --------------------------------------------------
    M: dict[tuple[str, str], tuple[str, str]] = {}
    for claim, _, _ in CLAIMS:
        for exp, _ in EXPS:
            M[(claim, exp)] = ("unknown", "not addressed")

    M[("C-k", "E1")] = ("unknown", e1_ev)
    M[("C-k", "E6")] = ("refutes", e6_ev)
    M[("C-L2", "E2")] = ("supports", e2_ev)
    M[("C-L2", "C2")] = ("unknown", c2_ev)
    M[("C-OOM", "X1")] = ("supports", x1_oom)
    M[("C-e2e", "E3")] = ("supports", e3_ev)
    M[("C-cost", "X1")] = ("supports", x1_cost)
    M[("C-cost", "C2")] = ("unknown", "verification only; no cost measured")
    M[("C-deleg", "C2")] = ("unknown", "delegated not implemented")
    M[("C-deleg", "CC")] = ("supports", cc_deleg)
    M[("C-strong", "CC")] = ("refutes", cc_strong)
    return M


def draw() -> None:
    M = build()
    fig = plt.figure(figsize=(W, H))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, W)
    ax.set_ylim(0, H)
    ax.axis("off")

    left = 1.92
    colw = (W - left) / 7.0
    header_h = 0.36
    row_h = 0.55
    top = H - 0.10

    ax.text(0.02, top, "Claim-evidence matrix: supports / refutes / unknown",
            fontsize=7.2, fontweight="bold", va="top")
    ax.text(0.02, top - 0.19,
            "Every cell names the experiment and its source file; numeric evidence is read from the result JSON.",
            fontsize=5.0, color="#666666", va="top")

    # legend
    for i, (lab, fill, edge) in enumerate([("supports", SUP, SUP_E),
                                           ("refutes", REF, REF_E),
                                           ("unknown", UNK, UNK_E)]):
        x = 4.78 + i * 0.80
        ax.add_patch(Rectangle((x, top - 0.15), 0.12, 0.09, facecolor=fill,
                               edgecolor=edge, linewidth=0.5))
        ax.text(x + 0.15, top - 0.105, lab, fontsize=4.7, va="center")

    # header row
    hy = top - 0.38 - header_h
    ax.add_patch(Rectangle((0, hy), left, header_h, facecolor="#F4F4F4",
                           edgecolor="#BBBBBB", linewidth=0.4))
    ax.text(0.03, hy + header_h / 2, "Claim", fontsize=5.8, fontweight="bold",
            va="center")
    for c, (_, label) in enumerate(EXPS):
        x = left + c * colw
        ax.add_patch(Rectangle((x, hy), colw, header_h, facecolor="#F4F4F4",
                               edgecolor="#BBBBBB", linewidth=0.4))
        ax.text(x + colw / 2, hy + header_h / 2, label, ha="center", va="center",
                fontsize=5.2, fontweight="bold", linespacing=0.95)

    # rows
    for r, (claim, text, sub) in enumerate(CLAIMS):
        ry = hy - (r + 1) * row_h
        ax.add_patch(Rectangle((0, ry), left, row_h, facecolor="white",
                               edgecolor="#CCCCCC", linewidth=0.4))
        ax.text(0.03, ry + row_h - 0.08, claim, fontsize=5.8, fontweight="bold",
                va="top")
        ax.text(0.03, ry + row_h - 0.20, textwrap.fill(text, 36), fontsize=4.9,
                va="top", linespacing=1.0)
        ax.text(0.03, ry + 0.05, sub, fontsize=4.2, color="#777777", va="bottom")
        for c, (exp, _) in enumerate(EXPS):
            x = left + c * colw
            verdict, ev = M[(claim, exp)]
            fill = {"supports": SUP, "refutes": REF, "unknown": UNK}[verdict]
            edge = {"supports": SUP_E, "refutes": REF_E, "unknown": UNK_E}[verdict]
            ax.add_patch(Rectangle((x, ry), colw, row_h, facecolor=fill,
                                   edgecolor="#BBBBBB", linewidth=0.35))
            ax.text(x + colw / 2, ry + row_h - 0.05, verdict, ha="center",
                    va="top", fontsize=5.2, fontweight="bold", color=edge)
            ax.text(x + 0.035, ry + row_h - 0.20,
                    textwrap.fill(ev, 23), ha="left", va="top",
                    fontsize=4.35, linespacing=0.98)
            ax.text(x + 0.035, ry + 0.035, SOURCE[exp], ha="left", va="bottom",
                    fontsize=4.3, color="#777777")

    # provenance / reading rules
    footer = (
        "Verdicts are an author mapping of each experiment's measured result to the claim as stated; "
        "numeric evidence is read from the JSON and asserted at build time. "
        "unknown = the experiment does not address the claim, not a negative result. "
        "E1 is N-capped (cannot certify k); E6 is an upper bound (left of 40 bit refutes, right does not certify); "
        "E3 is host-check only (proof_mode=unproven); X1 OOM points are observed kills, not peaks; "
        "C2 did not implement delegated; CC cell c is the weak form only (proof debt E-1). "
        "Sources: bench/results/{k_entropy_largeN,k_logprobs,policy_corpus_infer,agent_e2e_deepseek,"
        "scale-cloud,scale-6x5000}.json, c2/verify_L{0,1,2}.json, composition_controls.json."
    )
    ax.text(0.02, 0.10, "\n".join(textwrap.wrap(footer, width=160)),
            fontsize=4.60, color="#666666", va="bottom", linespacing=1.12)

    plt.rcParams["savefig.bbox"] = None
    pdf = OUT / "va04_claim_evidence.pdf"
    png = OUT / "va04_claim_evidence.png"
    fig.savefig(pdf, bbox_inches=None, pad_inches=0)
    fig.savefig(png, dpi=300, bbox_inches=None, pad_inches=0)
    plt.close(fig)
    print(f"wrote {pdf} and {png}")


if __name__ == "__main__":
    draw()
