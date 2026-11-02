#!/usr/bin/env python3
"""Page-budget test for the one main-text integration we propose.

It compiles the unmodified main paper (baseline) and a copy in which
Table~\\ref{tab:proofs} is replaced by the compact single-column proof figure.
Nothing in ``paper/`` is modified: both builds live under
``paper/figures/integration-test/`` and the result is written to
``page-budget.txt``.

Exit status is 0 only if the baseline is 12 pages / 0 errors and the figure
version is also 12 pages / 0 errors.
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

FIGURE_BLOCK = r"""\begin{figure}[t]
\centering
\includegraphics[width=\columnwidth]{fig06b_proof_main.pdf}
\caption{Real SP1 proofs on the 16-core / 92{,}160\,MiB cgroup
(post-NFA-fix). Blue: \texttt{core}; orange: \texttt{gr\-oth16}; green:
six-rule \texttt{core}; stars: EU AI Act. Crosses are SIGKILL/OOM at the cgroup
limit, not measured peaks. The numeric table is in the supplement.}
\label{fig:proofs}
\end{figure}
"""


def compile_tex(tex: Path) -> tuple[int, int]:
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
    return (int(pages.group(1)) if pages else -1, errors)


def main() -> int:
    OUT.mkdir(exist_ok=True)
    source = PAPER.read_text()

    baseline = OUT / "tdsc-paper-baseline.tex"
    baseline.write_text(source)
    shutil.copy2(FIG / "fig06b_proof_main.pdf", OUT / "fig06b_proof_main.pdf")

    label_at = source.index(r"\label{tab:proofs}")
    start = source.rindex(r"\begin{table}", 0, label_at)
    end = source.index(r"\end{table}", label_at) + len(r"\end{table}")
    patched = source[:start] + FIGURE_BLOCK + source[end:]
    patched = patched.replace(r"Table~\ref{tab:proofs}", r"Fig.~\ref{fig:proofs}")
    test = OUT / "tdsc-paper-fig-test.tex"
    test.write_text(patched)

    base_pages, base_errors = compile_tex(baseline)
    test_pages, test_errors = compile_tex(test)
    ok = base_pages == 12 and base_errors == 0 and test_pages == 12 and test_errors == 0

    lines = [
        f"generated_at: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"baseline: {base_pages} pages, {base_errors} errors",
        f"table->figure: {test_pages} pages, {test_errors} errors",
        f"page-neutral: {'YES' if test_pages == base_pages else 'NO'}",
        f"verdict: {'PASS' if ok else 'FAIL'}",
        "",
        "Replacement: Table tab:proofs -> Fig. fig:proofs (fig06b_proof_main.pdf, single column).",
        "Both builds use \\def\\SKELQUIET{}; paper/ is not modified.",
    ]
    (OUT / "page-budget.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
