#!/usr/bin/env python3
"""Rasterise a generated figure PDF to a 300 dpi PNG preview."""

from __future__ import annotations

import sys
from pathlib import Path

import pymupdf


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: pdf2png.py FIGURE.pdf")
    pdf = Path(sys.argv[1]).resolve()
    png = pdf.with_suffix(".png")
    doc = pymupdf.open(pdf)
    pix = doc[0].get_pixmap(dpi=300, alpha=False)
    pix.save(png)
    print(f"wrote {png} ({pix.width}x{pix.height})")


if __name__ == "__main__":
    main()
