#!/usr/bin/env python3
"""Check the export contract: embedded TrueType fonts, IEEE column widths, PNG previews."""

from __future__ import annotations

import sys
from pathlib import Path

import pymupdf

FIG = Path(__file__).resolve().parents[1]
MAX_DOUBLE_IN = 7.25
MAX_SINGLE_IN = 3.55


def main() -> int:
    bad = 0
    for pdf in sorted(FIG.glob("fig*.pdf")):
        doc = pymupdf.open(pdf)
        page = doc[0]
        width_in = page.rect.width / 72.0
        fonts = page.get_fonts(full=True)
        exts = {f[1] for f in fonts}
        names = sorted({f[3].split("+")[-1] for f in fonts})
        ok_fonts = exts <= {"ttf"} and bool(fonts)
        ok_width = width_in <= MAX_DOUBLE_IN
        png = pdf.with_suffix(".png")
        ok_png = png.exists() and png.stat().st_size > 10_000
        status = "ok" if (ok_fonts and ok_width and ok_png) else "FAIL"
        if status != "ok":
            bad += 1
        print(
            f"{status:4} {pdf.name:34} {width_in:5.2f} in  "
            f"fonts={sorted(exts)}  {', '.join(names)}  png={ok_png}"
        )

    if bad:
        print(f"\n{bad} figure(s) violate the export contract", file=sys.stderr)
        return 1
    print("\nall figures: TrueType-only fonts, within column width, PNG preview present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
