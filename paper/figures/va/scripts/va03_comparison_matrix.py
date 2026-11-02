#!/usr/bin/env python3
"""VA3 -- Categorical cross-system comparison matrix.

Panel (a) renders the seven Table S6 dimensions (49 cells: 46 populated, 3
unavailable).  Panel (b) adds the three dimensions the brief asks for that are
*not* in Table S6 (proof obligation, issuance/audit, implementation status).

Design rules encoded here:
  * every cell carries its evidence tag ``[m]`` / ``[c]`` / ``--``;
  * cell tint encodes evidence status, never a score or a ranking;
  * a thin left bar encodes only the named privacy/need category;
  * numbers in panel (a) are read from result JSON, never typed in;
  * ``--`` means not available, not estimated, and is not interpolated.

Run from anywhere: ``python3 scripts/va03_comparison_matrix.py``.
"""

from __future__ import annotations

import json
import re
import sys
import textwrap
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
import figstyle  # noqa: E402  (sets STIX fonts, Type 42, IEEE geometry)

RESULTS = figstyle.ROOT / "bench" / "results"
OUT = HERE.parent
W, H = figstyle.DOUBLE_COL_IN, 6.40

# Okabe--Ito, with light evidence tints.
BLUE, ORANGE, GREEN = "#0072B2", "#E69F00", "#009E73"
VERM, GREY = "#D55E00", "#7F7F7F"
TINT_M = "#EAF2F8"
TINT_C = "#FDF1DF"
TINT_U = "#EEEEEE"

SYSTEMS = [
    ("PoP", "PoP"),
    ("signed-Merkle", "signed-Merkle"),
    ("TEE (sim)", "TEE (sim)"),
    ("zkAgent", "zkAgent"),
    ("NiyamAI", "NiyamAI"),
    ("Zaguk", "Zaguk"),
    ("PCO", "PCO"),
]

DIMS = [
    ("信任根", "Trust root"),
    ("延迟（出证 + 验证）", "Latency\n(prove / verify)"),
    ("证明/证书大小", "Size"),
    ("响应隐私", "Response\nprivacy"),
    ("策略隐私", "Policy\nprivacy"),
    ("验证者需要 T 明文？", "Needs T\nplaintext"),
    ("验证者需要 π 明文？", "Needs π\nplaintext"),
]

# The three em-dash cells of Table S6.  Every other cell is populated.
UNAVAILABLE = {("Zaguk", "证明/证书大小"), ("PCO", "延迟（出证 + 验证）"), ("PCO", "证明/证书大小")}

# Qualitative category for the thin left bar.  None = no bar.
CATEGORY = {
    ("PoP", "Response privacy"): "bounded",
    ("PoP", "Policy privacy"): "bounded",
    ("signed-Merkle", "Response privacy"): "open",
    ("signed-Merkle", "Policy privacy"): "open",
    ("TEE (sim)", "Response privacy"): "open",
    ("TEE (sim)", "Policy privacy"): "open",
    ("zkAgent", "Response privacy"): "bounded",
    ("zkAgent", "Policy privacy"): "na",
    ("NiyamAI", "Response privacy"): "na",
    ("NiyamAI", "Policy privacy"): "bounded",
    ("Zaguk", "Response privacy"): "closed",
    ("Zaguk", "Policy privacy"): "closed",
    ("PCO", "Response privacy"): "closed",
    ("PCO", "Policy privacy"): "bounded",
    # ("PoP", "Needs T\nplaintext"): "closed",
    # ("PoP", "Needs π\nplaintext"): "closed",
    # ("signed-Merkle", "Needs T\nplaintext"): "open",
    # ("signed-Merkle", "Needs π\nplaintext"): "open",
    # ("TEE (sim)", "Needs T\nplaintext"): "closed",
    # ("TEE (sim)", "Needs π\nplaintext"): "closed",
    # ("zkAgent", "Needs T\nplaintext"): "closed",
    # ("zkAgent", "Needs π\nplaintext"): "na",
    # ("NiyamAI", "Needs T\nplaintext"): "na",
    # ("NiyamAI", "Needs π\nplaintext"): "na",
    # ("Zaguk", "Needs T\nplaintext"): "closed",
    # ("Zaguk", "Needs π\nplaintext"): "closed",
    # ("PCO", "Needs T\nplaintext"): "closed",
    # ("PCO", "Needs π\nplaintext"): "bounded",
}
BAR = {"closed": GREEN, "bounded": ORANGE, "open": VERM, "na": "#B0B0B0"}


def load(name: str):
    with open(RESULTS / name, encoding="utf-8") as fh:
        return json.load(fh)


def num(value: float, digits: int = 1) -> str:
    return f"{value:,.{digits}f}"


def mb(nbytes: int) -> str:
    return f"{nbytes / 1e6:.2f} MB"


def scale_stats(rows: list[dict], mode: str) -> tuple[float, float, int, int]:
    ok = [r for r in rows if r["proof_mode"] == mode and r["ok"]]
    times = [r["seconds"] for r in ok]
    sizes = [r["proof_bytes"] for r in ok]
    return min(times), max(times), min(sizes), max(sizes)


BASE_SYSTEM = {"TEE (sim)": "trusted-server / TEE (sim)"}


def status(system: str, dim: str, base: dict) -> str:
    if (system, dim) in UNAVAILABLE:
        return "—"
    raw = base["cells"][dim][BASE_SYSTEM.get(system, system)]["status"]
    return {"measured": "[m]", "cited": "[c]"}.get(raw, "—")


def build_cells():
    base = load("baselines.json")
    scale = load("scale-cloud.json")
    eu = load("eu_ai_act_proof.json")
    issuance = load("issuance.json")

    # --- structural assertions: 7 systems x 7 dimensions = 49 cells ---------
    assert len(base["systems"]) == 7 and len(base["dimensions"]) == 7
    assert len(SYSTEMS) == 7 and len(DIMS) == 7
    n_unavailable = len(UNAVAILABLE)
    assert n_unavailable == 3, n_unavailable

    # --- PoP numbers: cloud proof cost, local verify (same口径 as Table S6) --
    core_min, core_max, core_size_min, core_size_max = scale_stats(scale["rows"], "core")
    g16_min, g16_max, g16_size_min, g16_size_max = scale_stats(scale["rows"], "groth16")
    assert (core_min, core_max) == (39.83, 100.3), (core_min, core_max)
    assert (g16_min, g16_max) == (279.34, 343.75), (g16_min, g16_max)
    assert (g16_size_min, g16_size_max) == (1874, 1875), (g16_size_min, g16_size_max)
    eu_core = next(p for p in eu["points"] if p["tier"] == "core")
    eu_g16 = next(p for p in eu["points"] if p["tier"] == "groth16")
    assert eu_core["proof_mode"] == "core" and eu_g16["proof_mode"] == "groth16"

    # --- measured baseline arms --------------------------------------------
    merkle = base["merkle"]
    server = base["server"]
    assert merkle["sign_ms"] == 0.132 and merkle["append_ms"] == 2.131
    assert merkle["verify_public_ms"] == 0.322 and merkle["cert_bytes"] == 648
    assert server["server_eval_and_sign_median_ms"] == 0.139
    assert server["verify_median_ms"] == 0.102 and server["tee_sim_bytes"] == 520

    # --- cited cells: assert the token we display is in the source string ---
    def raw(system: str, dim: str) -> str:
        return base["cells"][dim][system]["value"]

    za_lat = raw("zkAgent", "延迟（出证 + 验证）")
    for token in ["194.40", "0.42", "1069", "0.038"]:
        assert token in za_lat, (token, za_lat)
    za_size = raw("zkAgent", "证明/证书大小")
    for token in ["96", "3.1"]:
        assert token in za_size, (token, za_size)
    ni_lat = raw("NiyamAI", "延迟（出证 + 验证）")
    for token in ["1.7", "51"]:
        assert token in ni_lat, (token, ni_lat)
    assert "18.6" in raw("NiyamAI", "证明/证书大小")
    assert "未取到" in raw("Zaguk", "证明/证书大小")
    assert base["cells"]["延迟（出证 + 验证）"]["PCO"]["value"] is None
    assert base["cells"]["证明/证书大小"]["PCO"]["value"] is None

    # Displayed cited numbers are parsed from the checked-in value strings,
    # never typed into the figure.
    za_m1 = re.search(r"Shout:\s*([\d.]+)\s*s\s*/\s*([\d.]+)\s*s", za_lat)
    za_m2 = re.search(r"LogUp:\s*~?([\d.]+)\s*s\s*/\s*([\d.]+)\s*s", za_lat)
    assert za_m1 and za_m2, za_lat
    za_sizes = re.findall(r"~?([\d.]+)\s*MiB", za_size)
    assert len(za_sizes) == 2, za_size
    ni_s = re.search(r"([\d.]+)\s*s", ni_lat)
    ni_ms = re.search(r"([\d.]+)\s*ms", ni_lat)
    ni_kb = re.search(r"([\d.]+)\s*KB", raw("NiyamAI", "证明/证书大小"))
    assert ni_s and ni_ms and ni_kb, (ni_lat, raw("NiyamAI", "证明/证书大小"))
    za_lat_disp = (
        f"Shout {float(za_m1.group(1)):.1f} s / {float(za_m1.group(2)):.2f} s; "
        f"LogUp ~{int(za_m2.group(1))} s / {float(za_m2.group(2)):.3f} s"
    )
    za_size_disp = f"Shout ~{za_sizes[0]} MiB; LogUp {za_sizes[1]} MiB"
    ni_lat_disp = f"{ni_s.group(1)} s per approved action; {ni_ms.group(1)} ms verify"
    ni_size_disp = f"{ni_kb.group(1)} KB"

    # --- panel (a) text -----------------------------------------------------
    cells: dict[tuple[str, str], str] = {}
    cells[("PoP", "Trust root")] = "vkey + crypto; no hardware; gateway key for tool receipts"
    cells[("PoP", "Latency\n(prove / verify)")] = (
        f"core {num(core_min)}–{num(core_max)} s; g16 {num(g16_min)}–{num(g16_max)} s; "
        f"verify {num(base['pop']['verify_ms'], 2)} ms"
    )
    cells[("PoP", "Size")] = f"core {mb(core_size_min)}; g16 {num(g16_size_min, 0)}–{num(g16_size_max, 0)} B"
    cells[("PoP", "Response\nprivacy")] = "bounded: commitment; no full hiding"
    cells[("PoP", "Policy\nprivacy")] = "bounded: π witness; P-PP for accountability"
    cells[("PoP", "Needs T\nplaintext")] = "no (private mode)"
    cells[("PoP", "Needs π\nplaintext")] = "no (P-PP exception)"

    cells[("signed-Merkle", "Trust root")] = "Ed25519 gateway key; trusts key holder"
    cells[("signed-Merkle", "Latency\n(prove / verify)")] = (
        f"sign {num(merkle['sign_ms'], 3)} ms; append {num(merkle['append_ms'], 3)} ms; "
        f"verify {num(merkle['verify_public_ms'], 3)} ms"
    )
    cells[("signed-Merkle", "Size")] = f"{merkle['cert_bytes']} B cert + {merkle['inclusion_bytes']} B proof"
    cells[("signed-Merkle", "Response\nprivacy")] = "open: verifier re-runs on T"
    cells[("signed-Merkle", "Policy\nprivacy")] = "open: verifier needs π"
    cells[("signed-Merkle", "Needs T\nplaintext")] = "yes"
    cells[("signed-Merkle", "Needs π\nplaintext")] = "yes"

    cells[("TEE (sim)", "Trust root")] = "server / TEE; hardware not measured"
    cells[("TEE (sim)", "Latency\n(prove / verify)")] = (
        f"eval+sign {num(server['server_eval_and_sign_median_ms'], 3)} ms; "
        f"verify {num(server['verify_median_ms'], 3)} ms"
    )
    cells[("TEE (sim)", "Size")] = f"{server['cert_bytes']} B cert; {server['tee_sim_bytes']} B sim attest"
    cells[("TEE (sim)", "Response\nprivacy")] = "open to verifier; TEE hides from server (untested)"
    cells[("TEE (sim)", "Policy\nprivacy")] = "open to server; verifier needs no π"
    cells[("TEE (sim)", "Needs T\nplaintext")] = "no (server yes)"
    cells[("TEE (sim)", "Needs π\nplaintext")] = "no (server yes)"

    cells[("zkAgent", "Trust root")] = "zkVM + provider"
    cells[("zkAgent", "Latency\n(prove / verify)")] = za_lat_disp
    cells[("zkAgent", "Size")] = za_size_disp
    cells[("zkAgent", "Response\nprivacy")] = "committed"
    cells[("zkAgent", "Policy\nprivacy")] = "n/a: no policy obligation"
    cells[("zkAgent", "Needs T\nplaintext")] = "no"
    cells[("zkAgent", "Needs π\nplaintext")] = "n/a"

    cells[("NiyamAI", "Trust root")] = "SNARK + judge"
    cells[("NiyamAI", "Latency\n(prove / verify)")] = ni_lat_disp
    cells[("NiyamAI", "Size")] = ni_size_disp
    cells[("NiyamAI", "Response\nprivacy")] = "not reported"
    cells[("NiyamAI", "Policy\nprivacy")] = "partial: contract commitment"
    cells[("NiyamAI", "Needs T\nplaintext")] = "unclear"
    cells[("NiyamAI", "Needs π\nplaintext")] = "unclear"

    cells[("Zaguk", "Trust root")] = "ezkl + commitment"
    cells[("Zaguk", "Latency\n(prove / verify)")] = "not comparable (proof generation dominates)"
    cells[("Zaguk", "Size")] = "—"
    cells[("Zaguk", "Response\nprivacy")] = "reported yes: output prefix hidden"
    cells[("Zaguk", "Policy\nprivacy")] = "closed: filter parameters hidden"
    cells[("Zaguk", "Needs T\nplaintext")] = "no"
    cells[("Zaguk", "Needs π\nplaintext")] = "no"

    cells[("PCO", "Trust root")] = "authority + ledger"
    cells[("PCO", "Latency\n(prove / verify)")] = "—"
    cells[("PCO", "Size")] = "—"
    cells[("PCO", "Response\nprivacy")] = "closed: binding + hiding"
    cells[("PCO", "Policy\nprivacy")] = "partial: authority predicate"
    cells[("PCO", "Needs T\nplaintext")] = "no"
    cells[("PCO", "Needs π\nplaintext")] = "partial"

    # --- panel (b): dimensions requested by the brief, outside Table S6 -----
    extra = {
        "PoP": (
            "response/trace satisfies public policy π (compliance)",
            f"detection {issuance['f1']['delivery_frame_exact']:.4f} on delivered artifacts; "
            f"log frame {issuance['f1']['log_frame_exact']:.4f}; not prevention",
            "prototype; core/g16 measured; delegated companion and Ed25519-in-guest not built",
        ),
        "signed-Merkle": (
            "who signed the bytes; verifier re-runs J(π,T)",
            "append measured; issuance detection not measured",
            "prototype measured; static Θ(n) append, not RFC-6962",
        ),
        "TEE (sim)": (
            "server/TEE attests execution + verdict; hardware not measured",
            "not measured",
            "simulated signature only; no hardware attestation",
        ),
        "zkAgent": (
            "provider ran declared model + tool trace (inference integrity)",
            "not reported",
            "cited; artifact not run here",
        ),
        "NiyamAI": (
            "tool-call intent bound to contract; guardrails",
            "not reported",
            "cited; artifact not run here",
        ),
        "Zaguk": (
            "output-prefix PII filter predicate",
            "not reported",
            "cited; proceedings PDF unreachable; qualitative only",
        ),
        "PCO": (
            "proof-carrying output satisfies authority predicate + ledger",
            "ledger in design; detection not evaluated",
            "cited; no performance table",
        ),
    }
    extra_status = {
        "PoP": ("[m]", "[m]", "[m]"),
        "signed-Merkle": ("[m]", "[m]", "[m]"),
        "TEE (sim)": ("[m]", "—", "[m]"),
        "zkAgent": ("[c]", "[c]", "[c]"),
        "NiyamAI": ("[c]", "[c]", "[c]"),
        "Zaguk": ("[c]", "[c]", "[c]"),
        "PCO": ("[c]", "[c]", "[c]"),
    }
    return base, cells, extra, extra_status


def wrap(text: str, width: int) -> str:
    return "\n".join(textwrap.wrap(text, width=width, break_long_words=False))


def draw() -> None:
    base, cells, extra, extra_status = build_cells()
    fig = plt.figure(figsize=(W, H))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, W)
    ax.set_ylim(0, H)
    ax.axis("off")

    left = 1.02
    colw = (W - left) / 7.0
    row_h = 0.52
    top = 6.28

    # panel (a) title
    ax.text(0.02, 6.30, "(a) Table S6 dimensions: 49 cells, 46 populated, 3 unavailable",
            fontsize=7.0, fontweight="bold", va="bottom")
    ax.text(W - 0.02, 6.30, "tint = evidence status, not quality",
            fontsize=5.2, color=GREY, ha="right", va="bottom")

    # header
    y = top - 0.34
    for i, (_, label) in enumerate(DIMS):
        x = left + i * colw
        ax.add_patch(Rectangle((x, y), colw, 0.34, facecolor="#F4F4F4",
                               edgecolor="#BBBBBB", linewidth=0.4))
        ax.text(x + colw / 2, y + 0.17, label, ha="center", va="center",
                fontsize=5.3, fontweight="bold", linespacing=0.95)
    ax.add_patch(Rectangle((0, y), left, 0.34, facecolor="#F4F4F4",
                           edgecolor="#BBBBBB", linewidth=0.4))
    ax.text(0.03, y + 0.17, "System", ha="left", va="center",
            fontsize=5.6, fontweight="bold")

    # rows
    for r, (key, label) in enumerate(SYSTEMS):
        ry = y - (r + 1) * row_h
        ax.add_patch(Rectangle((0, ry), left, row_h, facecolor="white",
                               edgecolor="#CCCCCC", linewidth=0.4))
        ax.text(0.03, ry + row_h / 2, label, ha="left", va="center",
                fontsize=5.5, fontweight="bold")
        for c, (dim_cn, dim_en) in enumerate(DIMS):
            x = left + c * colw
            tag = status(key, dim_cn, base)
            fill = TINT_U if tag == "—" else (TINT_M if tag == "[m]" else TINT_C)
            hatch = "////" if tag == "—" else None
            ax.add_patch(Rectangle((x, ry), colw, row_h, facecolor=fill,
                                   edgecolor="#BBBBBB", linewidth=0.35,
                                   hatch=hatch))
            cat = CATEGORY.get((key, dim_en.replace("\n", " ")))
            if cat:
                ax.add_patch(Rectangle((x + 0.015, ry + 0.04), 0.045, row_h - 0.08,
                                       facecolor=BAR[cat], edgecolor="none"))
            txt = cells[(key, dim_en)]
            ax.text(x + colw / 2 + (0.02 if cat else 0), ry + row_h / 2 + 0.025,
                    wrap(txt, 26), ha="center", va="center",
                    fontsize=5.20, linespacing=1.02)
            ax.text(x + colw - 0.035, ry + 0.035, tag, ha="right", va="bottom",
                    fontsize=4.35, color=(BLUE if tag == "[m]" else
                                          ORANGE if tag == "[c]" else GREY))

    # panel (b) title
    py = y - 7 * row_h - 0.12
    ax.text(0.02, py, "(b) Requested dimensions not in Table S6: only explicitly documented cells",
            fontsize=7.0, fontweight="bold", va="bottom")
    ax.text(W - 0.02, py, "em dash = not reported; not inferred",
            fontsize=5.2, color=GREY, ha="right", va="bottom")

    headers = ["Proof obligation", "Issuance / audit", "Implementation status"]
    bcolw = (W - left) / 3.0
    btop = py - 0.05
    for i, h in enumerate(headers):
        x = left + i * bcolw
        ax.add_patch(Rectangle((x, btop - 0.22), bcolw, 0.22, facecolor="#F4F4F4",
                               edgecolor="#BBBBBB", linewidth=0.4))
        ax.text(x + bcolw / 2, btop - 0.11, h, ha="center", va="center",
                fontsize=5.4, fontweight="bold")
    ax.add_patch(Rectangle((0, btop - 0.22), left, 0.22, facecolor="#F4F4F4",
                           edgecolor="#BBBBBB", linewidth=0.4))
    ax.text(0.03, btop - 0.11, "System", ha="left", va="center",
            fontsize=5.6, fontweight="bold")

    brow_h = 0.165
    for r, (key, label) in enumerate(SYSTEMS):
        ry = btop - 0.22 - (r + 1) * brow_h
        ax.add_patch(Rectangle((0, ry), left, brow_h, facecolor="white",
                               edgecolor="#CCCCCC", linewidth=0.35))
        ax.text(0.03, ry + brow_h / 2, label, ha="left", va="center",
                fontsize=5.1, fontweight="bold")
        for c in range(3):
            x = left + c * bcolw
            tag = extra_status[key][c]
            fill = TINT_U if tag == "—" else (TINT_M if tag == "[m]" else TINT_C)
            hatch = "////" if tag == "—" else None
            ax.add_patch(Rectangle((x, ry), bcolw, brow_h, facecolor=fill,
                                   edgecolor="#BBBBBB", linewidth=0.35,
                                   hatch=hatch))
            ax.text(x + 0.035, ry + brow_h / 2, wrap(extra[key][c], 42),
                    ha="left", va="center", fontsize=4.90, linespacing=0.98)
            ax.text(x + bcolw - 0.03, ry + 0.02, tag, ha="right", va="bottom",
                    fontsize=4.2, color=(BLUE if tag == "[m]" else
                                         ORANGE if tag == "[c]" else GREY))

    # legend
    ly = 0.55
    ax.add_patch(Rectangle((0.03, ly), 0.18, 0.10, facecolor=TINT_M,
                           edgecolor="#BBBBBB", linewidth=0.3))
    ax.text(0.24, ly + 0.05, "[m] measured here", va="center", fontsize=4.8)
    ax.add_patch(Rectangle((1.55, ly), 0.18, 0.10, facecolor=TINT_C,
                           edgecolor="#BBBBBB", linewidth=0.3))
    ax.text(1.76, ly + 0.05, "[c] cited, not reproduced", va="center", fontsize=4.8)
    ax.add_patch(Rectangle((3.40, ly), 0.18, 0.10, facecolor=TINT_U,
                           edgecolor="#BBBBBB", linewidth=0.3, hatch="////"))
    ax.text(3.61, ly + 0.05, "— unavailable, not estimated", va="center", fontsize=4.8)
    for i, (cat, lab) in enumerate([("closed", "closed"), ("bounded", "bounded"),
                                    ("open", "open"), ("na", "n/a / unclear")]):
        bx = 5.45 + i * 0.42
        ax.add_patch(Rectangle((bx, ly + 0.01), 0.055, 0.08, facecolor=BAR[cat],
                               edgecolor="none"))
        ax.text(bx + 0.07, ly + 0.05, lab, va="center", fontsize=4.4)

    # provenance (wrapped so the PDF stays at the 7.16 in design width)
    footer = ("Sources: bench/results/baselines.json (49 cells; 46 populated, 3 unavailable); "
              "scale-cloud.json + eu_ai_act_proof.json (PoP core/g16); issuance.json (PoP audit); Table S6.  "
              "[m] measured here; [c] cited, not reproduced; — not available, not interpolated.  "
              "Cell tint is evidence status, not a score; no ranking is implied.")
    ax.text(0.02, 0.24, "\n".join(textwrap.wrap(footer, width=165)),
            fontsize=4.90, color=GREY, va="bottom", linespacing=1.12)

    pdf = OUT / "va03_comparison_matrix.pdf"
    png = OUT / "va03_comparison_matrix.png"
    plt.rcParams["savefig.bbox"] = None
    fig.savefig(pdf, bbox_inches=None, pad_inches=0)
    fig.savefig(png, dpi=300, bbox_inches=None, pad_inches=0)
    plt.close(fig)
    print(f"wrote {pdf} and {png}")


if __name__ == "__main__":
    draw()
