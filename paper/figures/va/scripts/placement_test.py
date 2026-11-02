#!/usr/bin/env python3
"""Page-neutral placement test for VA1.

Compiles two copies of the main paper under ``integration-test/``:

  * ``tdsc-control.tex`` -- the unmodified 91ca397 main paper (control);
  * ``tdsc-va1.tex``     -- the same paper with the Fig. 1 ``figure*`` block
                            replaced by ``va01_deployment_trust.pdf`` and the
                            VA1 caption.  The label ``fig:architecture`` is
                            preserved so no reference becomes undefined.

Nothing under ``paper/`` outside ``paper/figures/va/integration-test/`` is
modified.  The test passes only if both compiles are 12 pages / 0 errors /
0 undefined references.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

VA = Path(__file__).resolve().parents[1]
FIG = VA.parent
ROOT = FIG.parent.parent
PAPER = ROOT / "paper" / "tdsc-paper.tex"
OUT = VA / "integration-test"
TARGET_PAGES = 12

VA1_CAPTION = (
    r"\caption{Three-party deployment and trust boundaries (design, not "
    r"measured). The policy authority holds $\pi$ and salt $s$ and publishes "
    r"$h_\pi=H(s\Vert\pi)$; the operator is untrusted and runs the agent, "
    r"compiler, zkVM guest, optional tool gateway and signer without a TEE; "
    r"the verifier supplies $n$, receives $T'$ and the certificate, recomputes "
    r"$b$, and checks the delegated companion and ledger inclusion. Blue: "
    r"public; orange: witness; green: signed/anchored; dashed: external "
    r"assumption or open gap. Trust anchors are the signing key, gateway key "
    r"and policy registry/P-PP, not the operator machine. The certificate "
    r"binds $T'$, not the end-user delivery $T''$. \texttt{core} does not hide "
    r"the witness; \texttt{gr\-oth16} hiding is wrapper-only and not "
    r"post-quantum; $L_{\mathrm{side}}$ (re-execution) is open at every tier.}"
)

def va1_block(width: str) -> str:
    return (
        "\\begin{figure*}[!t]\n"
        "\\centering\n"
        f"\\includegraphics[width={width}\\textwidth]{{figures/va01_deployment_trust.pdf}}\n"
        f"{VA1_CAPTION}\n"
        "\\label{fig:architecture}\n"
        "\\end{figure*}"
    )


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


def prepare() -> None:
    OUT.mkdir(exist_ok=True)
    figs = OUT / "figures"
    figs.mkdir(exist_ok=True)
    for pdf in FIG.glob("*.pdf"):
        shutil.copy2(pdf, figs / pdf.name)
    shutil.copy2(FIG / "va" / "va01_deployment_trust.pdf", figs / "va01_deployment_trust.pdf")
    shutil.copy2(PAPER, OUT / "tdsc-control.tex")
    text = PAPER.read_text()
    pattern = re.compile(
        r"\\begin\{figure\*\}\[!t\].*?"
        r"\\includegraphics\[width=0\.86\\textwidth\]\{figures/fig01_architecture\.pdf\}.*?"
        r"\\end\{figure\*\}",
        flags=re.DOTALL,
    )
    if len(pattern.findall(text)) != 1:
        raise SystemExit("could not locate the Fig. 1 figure* block")
    for width in ("0.86", "0.82", "0.80"):
        (OUT / f"tdsc-va1-{width.replace('.', '')}.tex").write_text(
            pattern.sub(lambda _, w=width: va1_block(w), text)
        )


def main() -> int:
    prepare()
    control = compile_tex(OUT / "tdsc-control.tex")
    ok_control = control[0] == TARGET_PAGES and control[1] == 0 and control[2] == 0
    variants = {}
    for width in ("0.86", "0.82", "0.80"):
        variants[width] = compile_tex(OUT / f"tdsc-va1-{width.replace('.', '')}.tex")
    ok_page_neutral = any(
        v[0] == TARGET_PAGES and v[1] == 0 and v[2] == 0 for v in variants.values()
    )
    lines = [
        f"generated_at: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"control (unmodified 91ca397): {control[0]} pages, {control[1]} errors, "
        f"{control[2]} undefined refs, {control[3]} overfull",
    ]
    for width, v in variants.items():
        lines.append(
            f"VA1 at {width} textwidth: {v[0]} pages, {v[1]} errors, "
            f"{v[2]} undefined refs, {v[3]} overfull"
        )
    lines += [
        f"target: {TARGET_PAGES} pages, 0 errors, 0 undefined refs",
        f"page-neutral at some width: {'YES' if (ok_control and ok_page_neutral) else 'NO'}",
        f"recommended width 0.86 page-neutral: "
        f"{'YES' if (ok_control and variants['0.86'][0] == TARGET_PAGES and variants['0.86'][1] == 0 and variants['0.86'][2] == 0) else 'NO'}",
        "",
        "Read the width table with the scale factor: at 0.80 textwidth the",
        "7.16-inch design is reduced to 5.73 inches, so 5.75 pt body text prints",
        "at about 4.6 pt. The 0.86 swap is the only readable candidate; if it is",
        "13 pages, VA1 is supplement-only. A page-neutral 0.80 swap would not",
        "meet the 6 pt minimum and is not recommended.",
    ]
    (VA / "integration-test" / "page-budget-va1.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if ok_control else 1


if __name__ == "__main__":
    raise SystemExit(main())
