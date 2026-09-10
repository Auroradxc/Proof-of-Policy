#!/usr/bin/env python3
"""Render the end-to-end demo as shareable artefacts (no browser needed).

Produces, from a demo session bundle:
  docs/demo/session_report.html   — styled, self-contained report (open/print)
  docs/demo/session_report.svg    — vector card (viewers/converters)
  docs/demo/session_summary.png   — summary card (Pillow)
  docs/demo/verify_result.png     — third-party verification checklist (Pillow)

Usage:
  python3 scripts/make_shots.py [--session PATH] [--out-dir docs/demo] [--run-demo]

If the session is missing (or --run-demo), the demo is run in host-check mode
(fast) first. PNG text is ASCII so no CJK font is required.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
DEFAULT_SESSION = REPO / "scripts" / "examples" / "out" / "e2e" / "session.json"

FONT_REG = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

BG = (18, 20, 28)
CARD = (28, 32, 44)
FG = (232, 236, 244)
MUTED = (150, 160, 178)
GREEN = (52, 199, 123)
RED = (232, 90, 90)
ACCENT = (110, 168, 254)


def run(cmd: list[str]) -> str:
    return subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True).stdout


def ensure_session(session: Path, run_demo: bool) -> None:
    if run_demo or not session.exists():
        print("running demo (host-check mode) ...")
        subprocess.run([sys.executable, str(REPO / "scripts" / "demo_e2e.py"), "--no-prove",
                        "--out-dir", str(session.parent)], cwd=str(REPO), check=True)


def collect(session_path: Path) -> dict:
    session = json.loads(session_path.read_text(encoding="utf-8"))
    kinds: dict = {}
    for e in session["certificates"]:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    verify_out = run([sys.executable, str(REPO / "scripts" / "verify_session.py"),
                      "--session", str(session_path)])
    checks = [{"name": m.group(2), "detail": m.group(3).strip(), "ok": m.group(1) == "PASS"}
              for m in re.finditer(r"\[(PASS|FAIL)\]\s+(\S+)\s+(.*)", verify_out)]
    ok = "RESULT: PASS" in verify_out
    return {"session": session, "kinds": kinds, "checks": checks, "ok": ok, "raw": verify_out}


def _font(bold: bool = False, mono: bool = False, size: int = 20):
    from PIL import ImageFont

    path = FONT_MONO if mono else (FONT_BOLD if bold else FONT_REG)
    return ImageFont.truetype(path, size)


def _card(size, lines, title, subtitle):
    from PIL import Image, ImageDraw

    w, h = size
    img = Image.new("RGB", size, BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, 64], fill=CARD)
    d.text((24, 20), title, font=_font(bold=True, size=24), fill=FG)
    d.text((24, 82), subtitle, font=_font(size=16), fill=MUTED)
    y = 124
    for text, color in lines:
        if text == "":
            y += 10
            continue
        f = _font(mono=True, size=18) if color == MUTED else _font(size=19)
        d.text((32, y), text, font=f, fill=color)
        y += 32
    return img


def render_pngs(data: dict, out: Path) -> list:
    written = []
    s = data["session"]
    summ = s.get("summary", {})
    kinds_txt = "  ".join(f"{k}={v}" for k, v in sorted(data["kinds"].items()))
    lines = [
        (f"session      : {s.get('session_id', '')}", FG),
        (f"certificates : {summ.get('certificates', len(s['certificates']))}   stream={summ.get('stream_certs', 0)}", FG),
        (f"kinds        : {kinds_txt}", MUTED),
        (f"blocked calls: {summ.get('blocked_tool_calls')}", FG),
        (f"zk proof     : {'present' if summ.get('zk_passed') is not None else '-'}   passed={summ.get('zk_passed')}", FG),
        (f"ledger       : {s.get('ledger', 'ledger.jsonl')}  chain={'ok' if summ.get('ledger_ok') else 'broken'}", FG),
        ("", FG),
        ("agent session -> certificates -> anchor ledger -> independent verification", MUTED),
    ]
    img = _card((1180, 420), lines, "Proof-of-Policy — end-to-end demo",
                "Scripts/demo_e2e.py  |  certificates: streaming chain, MCP args+result, zk proof")
    p1 = out / "session_summary.png"
    img.save(p1)
    written.append(p1)

    vlines = [(f"{'PASS' if c['ok'] else 'FAIL'}  {c['name']:<24} {c['detail']}", GREEN if c["ok"] else RED)
              for c in data["checks"]]
    vlines += [("", FG), (f"RESULT: {'PASS' if data['ok'] else 'FAIL'}", GREEN if data["ok"] else RED)]
    img2 = _card((1180, 150 + 32 * len(vlines)), vlines, "Third-party verification",
                 "scripts/verify_session.py — public artefacts only (session.json + ledger + proof)")
    p2 = out / "verify_result.png"
    img2.save(p2)
    written.append(p2)
    return written


def render_svg(data: dict, out: Path) -> Path:
    s = data["session"]
    summ = s.get("summary", {})
    lines = [
        ("Proof-of-Policy — end-to-end demo", 26, FG_S, True),
        (f"certificates: {summ.get('certificates', 0)}  stream: {summ.get('stream_certs', 0)}  "
         f"blocked: {summ.get('blocked_tool_calls')}", 16, MUTED_S, False),
        ("", 10, MUTED_S, False),
    ]
    lines += [(f"{'PASS' if c['ok'] else 'FAIL'}  {c['name']}  {c['detail']}",
               16, GREEN_S if c["ok"] else RED_S, False) for c in data["checks"]]
    y = 40
    body = []
    for text, size, fill, bold in lines:
        if text:
            weight = ' font-weight="bold"' if bold else ""
            body.append(f'<text x="32" y="{y}" font-size="{size}" fill="{fill}"{weight}>'
                        f'{_esc(text)}</text>')
        y += size + 12
    height = y + 24
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="980" height="{height}" '
           f'viewBox="0 0 980 {height}"><rect width="980" height="{height}" fill="#12141c"/>'
           f'<rect width="980" height="56" fill="#1c2029"/>' + "".join(body) + "</svg>")
    p = out / "session_report.svg"
    p.write_text(svg, encoding="utf-8")
    return p


FG_S, MUTED_S, GREEN_S, RED_S = "#e8ecf4", "#96a0b2", "#34c77b", "#e85a5a"


def _esc(t: str) -> str:
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_html(data: dict, out: Path) -> Path:
    s = data["session"]
    summ = s.get("summary", {})
    kinds = "".join(f"<span class='pill'>{_esc(k)} <b>{v}</b></span>" for k, v in sorted(data["kinds"].items()))
    checks = "".join(
        f"<li class='{'ok' if c['ok'] else 'bad'}'><span>{'PASS' if c['ok'] else 'FAIL'}</span>"
        f"<code>{_esc(c['name'])}</code><em>{_esc(c['detail'])}</em></li>"
        for c in data["checks"])
    html = f"""<!doctype html><html lang="zh"><meta charset="utf-8">
<title>Proof-of-Policy demo report</title>
<style>
 body{{background:#12141c;color:#e8ecf4;font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,'Noto Sans CJK SC',sans-serif;margin:0;padding:32px}}
 h1{{font-size:26px;margin:0 0 4px}} .sub{{color:#96a0b2;margin-bottom:20px}}
 .card{{background:#1c2029;border:1px solid #262c38;border-radius:12px;padding:18px 20px;margin:14px 0}}
 .pill{{display:inline-block;background:#232a36;border-radius:999px;padding:4px 10px;margin:3px 6px 3px 0;color:#cfe0ff}}
 .big{{font-size:34px;font-weight:700;color:#6ea8fe}}
 ul{{list-style:none;padding:0;margin:0}} li{{display:flex;gap:10px;padding:7px 0;border-bottom:1px dashed #262c38}}
 li span{{width:52px;font-weight:700}} li.ok span{{color:#34c77b}} li.bad span{{color:#e85a5a}}
 li code{{color:#cfe0ff}} li em{{color:#96a0b2;font-style:normal;margin-left:auto}}
 .result{{font-size:20px;font-weight:700;color:{'#34c77b' if data['ok'] else '#e85a5a'}}}
 .muted{{color:#96a0b2}} code.k{{background:#232a36;padding:2px 6px;border-radius:6px}}
</style>
<h1>Proof-of-Policy — 端到端 demo 报告</h1>
<div class="sub">agent 会话 → 证书（流式链 / MCP 参数+结果 / zk 证明）→ 锚定账本 → 第三方独立验证</div>
<div class="card">
  <div class="big">{summ.get('certificates', 0)} 张证书</div>
  <div class="muted">stream={summ.get('stream_certs', 0)} · blocked tool calls={summ.get('blocked_tool_calls')}
   · zk passed={summ.get('zk_passed')} · ledger chain={'ok' if summ.get('ledger_ok') else 'broken'}</div>
  <div style="margin-top:10px">{kinds}</div>
</div>
<div class="card">
  <h2 style="margin:0 0 8px;font-size:18px">第三方验证（scripts/verify_session.py）</h2>
  <ul>{checks}</ul>
  <div class="result">RESULT: {'PASS' if data['ok'] else 'FAIL'}</div>
</div>
<div class="card muted">复现：<code class="k">SP1_PROVER=cpu python3 scripts/demo_e2e.py</code> →
<code class="k">python3 scripts/verify_session.py --session scripts/examples/out/e2e/session.json</code>
· 详见 <code class="k">docs/reproduce.md</code></div>
</html>"""
    p = out / "session_report.html"
    p.write_text(html, encoding="utf-8")
    return p


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", type=Path, default=DEFAULT_SESSION)
    ap.add_argument("--out-dir", type=Path, default=REPO / "docs" / "demo")
    ap.add_argument("--run-demo", action="store_true")
    args = ap.parse_args()

    ensure_session(args.session, args.run_demo)
    data = collect(args.session)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    written = render_pngs(data, args.out_dir)
    written.append(render_svg(data, args.out_dir))
    written.append(render_html(data, args.out_dir))
    for p in written:
        try:
            shown = p.relative_to(REPO)
        except ValueError:
            shown = p
        print(f"wrote {shown} ({p.stat().st_size} bytes)")
    print("verify:", "PASS" if data["ok"] else "FAIL")
    return 0 if data["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
