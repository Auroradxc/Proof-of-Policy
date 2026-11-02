#!/usr/bin/env python3
"""Page/compile check for the integrated main paper.

The main paper now contains ``figures/fig06b_proof_main.pdf`` (Fig. 1) in place
of the old Table I.  This script compiles a copy of the current main paper and
asserts the hard constraint: 12 pages, zero errors, zero undefined references.
Table I itself now lives in the supplementary material.

Nothing in ``paper/`` is modified; the build lives under
``paper/figures/integration-test/`` and the result is written to
``page-budget.txt``.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

FIG = Path(__file__).resolve().parents[1]
ROOT = FIG.parents[1]
PAPER = ROOT / "paper" / "tdsc-paper.tex"
OUT = FIG / "integration-test"
TARGET_PAGES = 12


def compile_tex(tex: Path) -> tuple[int, int, int, int]:
    for _ in range(2):
        subprocess.run(
            [
                "pdflatex",
                "-interaction=nonstopmode",
                "-halt-on-error",
                r"\def\SKELQUIET{}\input{" + tex.name + "}",
            ],
            cwd=tex.parent,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    log = tex.with_suffix(".log").read_text(errors="replace")
    pages = re.search(r"Output written on .*?\((\d+) pages", log)
    errors = len(re.findall(r"^! ", log, flags=re.MULTILINE))
    undefined = len(re.findall(r"undefined", log, flags=re.IGNORECASE))
    overfull = len(re.findall(r"Overfull \\hbox", log))
    return (
        int(pages.group(1)) if pages else -1,
        errors,
        undefined,
        overfull,
    )


def main() -> int:
    OUT.mkdir(exist_ok=True)
    (OUT / "figures").mkdir(exist_ok=True)
    shutil.copy2(PAPER, OUT / "tdsc-paper-integrated.tex")
    shutil.copy2(FIG / "fig06b_proof_main.pdf", OUT / "figures" / "fig06b_proof_main.pdf")

    pages, errors, undefined, overfull = compile_tex(OUT / "tdsc-paper-integrated.tex")
    ok = pages == TARGET_PAGES and errors == 0 and undefined == 0

    lines = [
        f"generated_at: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"main (integrated): {pages} pages, {errors} errors, {undefined} undefined refs, {overfull} overfull",
        f"target: {TARGET_PAGES} pages, 0 errors, 0 undefined refs",
        f"verdict: {'PASS' if ok else 'FAIL'}",
        "",
        "Integration: Fig. fig:proofs (fig06b_proof_main.pdf, single column) replaces the old Table I.",
        "Table I moved to the supplementary material as Table S12 with a GB-vs-GiB unit note.",
        "paper/ is not modified by this test; only the copy under integration-test/ is built.",
    ]
    (OUT / "page-budget.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
