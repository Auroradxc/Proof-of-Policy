#!/usr/bin/env python3
"""隐私面探针：每个证明档到底泄露什么（P0-07 / Wave 2 X1）。

**要回答什么。** 一张**私有模式**证书在 `core` / `groth16` / `unproven` 下，
验证者（或拿到工件的人）实际能看到什么：

1. 证书/证明工件里有没有 `T` 的**明文**（用 canary 字符串搜）；
2. 公开值里是不是只有承诺（`response_commitment` / `evidence_commitment`）；
3. `response_commitment` 是不是一个**猜测-验证 oracle**（公开可重算，设计如此）；
4. 该证明档的 witness-hiding 程度（`cert.proof_hiding`）；
5. 重执行攻击（需要真实模型；本脚本默认**不跑**，标 `skipped`，由 E2 承担）。

**这不是“证明零知识”。** 搜不到明文只说明**这一组探针**没找到；搜到明文就是
**确定的泄露**。`core`/`compressed` 的 trace 开值在证明里明文可见（`sp1-zk-audit.md`），
本脚本用 canary 把它变成可复现的判据；`groth16/plonk` 是唯一可能隐藏见证的档，
但属包装器层面声明、非后量子。

用法::

    # 冒烟：只跑 host check（unproven），不需要 SP1 证明
    python3 bench/bench_privacy_surface.py --tiers unproven --no-prove \
        --out-dir bench/results

    # 云机：core 与 groth16（groth16 需要 ≥64 GB）
    SP1_PROVER=cpu python3 bench/bench_privacy_surface.py \
        --tiers core,groth16 --timeout 3600 --out-dir bench/results
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl.evidence.cert import proof_hiding  # noqa: E402

DEFAULT_PACK = REPO / "policy_packs" / "agent_content_v1.json"
CANARY = "POP_PRIVACY_CANARY_7f3a9c"


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _run_issue(pack: Path, response_file: Path, out_dir: Path,
               tier: str, no_prove: bool, timeout: int) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, str(REPO / "scripts" / "prove" / "issue_cert.py"),
           "--pack", str(pack), "--response", str(response_file),
           "--out-dir", str(out_dir), "--mode", "private"]
    if no_prove or tier == "unproven":
        cmd.append("--no-prove")
    else:
        cmd += ["--proof-mode", tier]
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(cmd, cwd=str(REPO), capture_output=True,
                              text=True, timeout=timeout)
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        rc = 124
        out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = f"timeout after {timeout}s"
    elapsed = time.perf_counter() - t0
    status = "ok" if rc == 0 else ("oom" if "SIGKILL" in out + err or "MemoryError" in out + err
                                   else f"fail({rc})")
    return {"tier": tier, "status": status, "elapsed_s": round(elapsed, 2),
            "stdout_tail": out[-1200:], "stderr_tail": err[-1200:],
            "out_dir": str(out_dir)}


def _files(out_dir: Path) -> List[Path]:
    return sorted(p for p in out_dir.rglob("*") if p.is_file())


def _search_bytes(files: List[Path], needle: bytes) -> List[Dict[str, Any]]:
    hits = []
    for p in files:
        try:
            data = p.read_bytes()
        except Exception:  # noqa: BLE001
            continue
        if needle in data:
            hits.append({"file": p.name, "size": len(data)})
    return hits


def _load_public_values(out_dir: Path) -> Dict[str, Any]:
    """从 proof.bin.pv / results.json / payload.json 里拼出公开值。"""
    merged: Dict[str, Any] = {}
    pv = out_dir / "proof.bin.pv"
    if pv.exists():
        try:
            data = json.loads(pv.read_text(encoding="utf-8"))
            merged["proof_bin_pv"] = data
        except Exception:  # noqa: BLE001
            merged["proof_bin_pv_raw_sha256"] = _sha256_bytes(pv.read_bytes())
    results = out_dir / "results.json"
    if results.exists():
        try:
            data = json.loads(results.read_text(encoding="utf-8"))
            merged["results"] = data
        except Exception:  # noqa: BLE001
            pass
    payload = out_dir / "payload.json"
    if payload.exists():
        try:
            data = json.loads(payload.read_text(encoding="utf-8"))
            merged["payload_outcome"] = data.get("outcome")
            merged["payload_binding"] = data.get("binding")
            merged["payload_challenge"] = data.get("challenge")
        except Exception:  # noqa: BLE001
            pass
    return merged


def _probe(out_dir: Path, response: str, tier: str,
           no_prove: bool) -> Dict[str, Any]:
    files = _files(out_dir)
    canary_b = CANARY.encode()
    response_b = response.encode()
    # 验证者拿到的是证书 + 证明工件；vectors.json 是**出证方的私有输入**，
    # 里面当然有 response —— 把它算进“泄露”会把出证方自己的输入当成交付物。
    delivered = [p for p in files
                 if p.name in ("cert.json", "payload.json") or p.name.startswith("proof")]
    prover_inputs = [p for p in files if p.name in ("vectors.json", "results.json")]
    text_hits = _search_bytes([p for p in delivered if p.suffix in
                               (".json", ".pv")], canary_b)
    proof_hits = _search_bytes([p for p in delivered if p.name.startswith("proof")],
                               canary_b)
    resp_hits = _search_bytes(delivered, response_b)
    input_hits = _search_bytes(prover_inputs, response_b)

    pv = _load_public_values(out_dir)
    commitment = None
    results = pv.get("results")
    if isinstance(results, list) and results:
        commitment = results[0].get("response_commitment")
    elif isinstance(results, dict):
        commitment = results.get("response_commitment")
    if commitment is None and isinstance(pv.get("payload_outcome"), dict):
        commitment = pv["payload_outcome"].get("response_commitment")

    oracle = None
    if commitment:
        oracle = {
            "response_sha256": _sha256_bytes(response_b),
            "published_commitment": commitment,
            "matches_sha256_T": _sha256_bytes(response_b) == commitment,
            "note": "public, offline-recomputable function of T — guess-and-verify "
                    "oracle by design (see Theorem A/B)",
        }

    proof_files = [p for p in files if p.name.startswith("proof")]
    return {
        "tier": tier,
        "proof_mode": "unproven" if (no_prove or tier == "unproven") else tier,
        "proof_hiding": proof_hiding("unproven" if (no_prove or tier == "unproven") else tier),
        "files": [str(p.relative_to(out_dir)) for p in files],
        "proof_files": [{"name": p.name, "size": p.stat().st_size}
                        for p in proof_files],
        "canary_in_text": text_hits,
        "canary_in_proof": proof_hits,
        "response_in_delivered": resp_hits,
        "response_in_prover_inputs": input_hits,
        "public_values": pv,
        "commitment_oracle": oracle,
        "re_execution": {
            "status": "skipped",
            "reason": "needs a real model + prompt; measured by bench_k_entropy / E2",
        },
    }


def run(args: argparse.Namespace) -> Dict[str, Any]:
    response = (f"Here is a safe-looking answer ({CANARY}). "
                f"Also a secret-looking token sk-{CANARY.lower()}0123456789abcdef, "
                f"and the word exploit appears here to trigger the keyword rule.")
    work_root = Path(args.work_dir) if args.work_dir else (
        REPO / "scripts" / "examples" / "out" / "privacy_surface")
    work_root.mkdir(parents=True, exist_ok=True)
    response_file = work_root / "response.txt"
    response_file.write_text(response, encoding="utf-8")

    runs = []
    for tier in [t.strip() for t in args.tiers.split(",") if t.strip()]:
        out_dir = work_root / tier
        # 清掉旧产物，避免把上一次的 proof.bin 当成本次
        if out_dir.exists():
            for p in sorted(out_dir.rglob("*"), reverse=True):
                if p.is_file():
                    p.unlink()
                elif p.is_dir():
                    p.rmdir()
        issue = _run_issue(Path(args.pack), response_file, out_dir, tier,
                           args.no_prove, args.timeout)
        if issue["status"] == "ok":
            issue.update(_probe(out_dir, response, tier, args.no_prove))
        runs.append(issue)

    result = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pack": str(args.pack),
        "out_dir": str(args.out_dir),
        "response_sha256": _sha256_bytes(response.encode()),
        "response_chars": len(response),
        "canary": CANARY,
        "tiers": runs,
        "notes": [
            "A negative plaintext search is a probe, not a proof of zero-knowledge.",
            "A positive hit is a definite leak in that artefact.",
            "core/compressed STARK proofs are not witness-hiding; groth16/plonk "
            "are the only wrapper-level hiding tier (not post-quantum).",
            "response_commitment is a public guess-and-verify oracle by design.",
            "Re-execution is independent of the proving tier; measure it in E2.",
        ],
    }
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "privacy_surface.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "privacy_surface.md").write_text(render_md(result), encoding="utf-8")
    return result


def render_md(r: Dict[str, Any]) -> str:
    lines = [
        "# 隐私面探针（P0-07 / Wave 2 X1）",
        "",
        f"**生成时间**：{r['generated_at']}  **pack**：`{r['pack']}`  ",
        f"**canary**：`{r['canary']}`  **响应哈希**：`{r['response_sha256'][:16]}…`",
        "",
        "| tier | status | hiding | proof 文件 | canary 在文本 | canary 在证明 | 响应在任一文件 |",
        "|---|---|---|---:|---|---|---|",
    ]
    for x in r["tiers"]:
        lines.append(
            f"| {x['tier']} | {x['status']} | {x.get('proof_hiding','')} | "
            f"{len(x.get('proof_files') or [])} | "
            f"{len(x.get('canary_in_text') or [])} | "
            f"{len(x.get('canary_in_proof') or [])} | "
            f"{len(x.get('response_in_any_file') or [])} |")
    lines += [
        "",
        "## 怎么读",
        "",
        "- **canary 在证明里 > 0** = 该档**确定泄露** `T` 的明文；"
        "`core`/`compressed` 的 trace 开值本来就明文可见。",
        "- **canary 在文本/证明里 = 0** 只说明这一组探针没找到，"
        "**不是**零知识证明；`groth16/plonk` 才在包装器层面隐藏见证。",
        "- `response_commitment` 是公开、可离线重算的 `T` 的函数 —— "
        "它本来就是猜测-验证 oracle；真正的攻击是**重执行**（E2）。",
        "- `re_execution.status=skipped` 是诚实的：本脚本不跑模型；"
        "`bench_k_entropy.py` 负责测 `k`。",
        "",
        "## 复现",
        "",
        "```bash",
        f"python3 bench/bench_privacy_surface.py --tiers {r['tiers'][0]['tier']} "
        f"--no-prove --out-dir {Path(r.get('out_dir', 'bench/results'))}",
        "# 云机：",
        "SP1_PROVER=cpu python3 bench/bench_privacy_surface.py --tiers core,groth16",
        "```",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--tiers", default="unproven",
                    help="逗号分隔：unproven,core,compressed,groth16,plonk")
    ap.add_argument("--pack", default=str(DEFAULT_PACK))
    ap.add_argument("--out-dir", default=str(REPO / "bench" / "results"))
    ap.add_argument("--work-dir", default=None)
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--no-prove", action="store_true",
                    help="所有 tier 都走 host check（冒烟用；不产生证明工件）")
    args = ap.parse_args()
    result = run(args)
    for x in result["tiers"]:
        print(f"{x['tier']}: {x['status']}  hiding={x.get('proof_hiding','')}  "
              f"canary_in_proof={len(x.get('canary_in_proof') or [])}")
    print(f"wrote {Path(args.out_dir) / 'privacy_surface.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
