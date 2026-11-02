"""Shared plotting style for Proof-of-Policy figures.

All data figures are generated from the checked-in result files under
``bench/results/``.  This module fixes the IEEE two-column geometry, the
colour-blind-safe palette, and the export contract (PDF for LaTeX, PNG 300 dpi
for preview).  It deliberately contains no data.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager

# ---------------------------------------------------------------------------
# Geometry (IEEE Transactions, two-column)
# ---------------------------------------------------------------------------
SINGLE_COL_IN = 3.5      # 88.9 mm
DOUBLE_COL_IN = 7.16     # 181.9 mm
GOLDEN = 0.618

# ---------------------------------------------------------------------------
# Fonts: STIXGeneral is a Times-compatible TrueType family shipped with
# matplotlib, so PDF output embeds TrueType (Type 42) and matches IEEE body text.
# ---------------------------------------------------------------------------
_MPL_TTF = Path(matplotlib.get_data_path()) / "fonts" / "ttf"
for _p in _MPL_TTF.glob("STIXGeneral*.ttf"):
    try:
        font_manager.fontManager.addfont(str(_p))
    except Exception:
        pass

plt.rcParams.update(
    {
        "font.family": "STIXGeneral",
        "mathtext.fontset": "stix",
        "font.size": 7.0,
        "axes.titlesize": 7.5,
        "axes.labelsize": 7.5,
        "xtick.labelsize": 6.5,
        "ytick.labelsize": 6.5,
        "legend.fontsize": 6.5,
        "legend.frameon": False,
        "axes.linewidth": 0.6,
        "xtick.major.width": 0.5,
        "ytick.major.width": 0.5,
        "xtick.major.size": 2.4,
        "ytick.major.size": 2.4,
        "xtick.minor.width": 0.4,
        "ytick.minor.width": 0.4,
        "lines.linewidth": 1.15,
        "lines.markersize": 3.4,
        "patch.linewidth": 0.5,
        "axes.grid": False,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "figure.dpi": 150,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.015,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "svg.fonttype": "none",
    }
)

# ---------------------------------------------------------------------------
# Okabe--Ito palette (colour-blind safe), plus grayscale-safe linestyles and
# markers used in every multi-series plot.
# ---------------------------------------------------------------------------
BLUE = "#0072B2"
ORANGE = "#E69F00"
GREEN = "#009E73"
VERMILLION = "#D55E00"
PURPLE = "#CC79A7"
SKY = "#56B4E9"
YELLOW = "#F0E442"
GREY = "#7F7F7F"
LIGHT_GREY = "#D9D9D9"
BLACK = "#000000"

PALETTE = [BLUE, ORANGE, GREEN, VERMILLION, PURPLE, SKY]
MARKERS = ["o", "s", "^", "D", "v", "P"]
LINESTYLES = ["-", "--", "-.", ":", (0, (5, 1, 1, 1, 1, 1))]
HATCHES = ["", "///", "...", "\\\\\\", "xxx"]

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "bench" / "results"
OUT = Path(__file__).resolve().parent


def save(fig, stem: str) -> None:
    """Write ``stem.pdf`` and ``stem.png`` (300 dpi) next to this module."""
    pdf = OUT / f"{stem}.pdf"
    png = OUT / f"{stem}.png"
    fig.savefig(pdf)
    fig.savefig(png, dpi=300)
    plt.close(fig)
    print(f"wrote {pdf.relative_to(ROOT)} and {png.relative_to(ROOT)}")


def provenance(fig, text: str, y: float = -0.035) -> None:
    """Small provenance footer carried inside the figure itself.

    The text is wrapped to the figure width so that ``bbox_inches='tight'`` cannot
    widen the exported page beyond the IEEE column geometry.
    """
    import textwrap

    width_chars = 108 if fig.get_figwidth() > 5.0 else 54
    wrapped = "\n".join(textwrap.wrap(text, width=width_chars))
    fig.text(
        0.005,
        y,
        wrapped,
        ha="left",
        va="top",
        fontsize=5.4,
        color=GREY,
        transform=fig.transFigure,
    )


def panel_tag(ax, tag: str, x: float = -0.16, y: float = 1.04) -> None:
    """IEEE-style (a)/(b) panel tag in axes coordinates."""
    ax.text(
        x,
        y,
        tag,
        transform=ax.transAxes,
        fontsize=8,
        fontweight="bold",
        va="bottom",
        ha="left",
    )
