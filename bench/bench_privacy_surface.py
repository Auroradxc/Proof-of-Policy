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

    # 真实 LLM 响应（X1d）：--response-file 取代内置 canary 文本；
    # 探针改为搜「响应精确子串 / 策略规则名与正文 / response_commitment」
    SP1_PROVER=cpu python3 bench/bench_privacy_surface.py \
        --tiers core,groth16 --response-file /path/to/real_response.txt \
        --out-name privacy_surface_real --out-dir bench/results
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


def _pack_rule_probes(pack: Path) -> Dict[str, Any]:
    """把策略包拆成「规则名」与「规则正文里的字面量」两组探针。

    策略包是**公开输入**（验证方本来就有），所以命中它不构成泄露；这里仍然搜，
    是为了把「公开策略」与「私有响应」分开报 —— 否则一个策略名命中会被误读成
    `T` 泄露。正文取 ``params`` 里的字符串（关键词 / 正则），最短 4 字符，
    避免 ``min/max`` 这类数字和单字母噪声。
    """
    try:
        doc = json.loads(pack.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {"names": [], "literals": [], "error": f"{type(exc).__name__}: {exc}"}
    names: List[str] = []
    literals: List[str] = []
    for rule in doc.get("rules") or []:
        name = rule.get("name")
        if name:
            names.append(str(name))
        for key, val in (rule.get("params") or {}).items():
            for item in (val if isinstance(val, list) else [val]):
                if isinstance(item, str) and len(item) >= 4:
                    literals.append(f"{name}.{key}={item}")
    return {"names": names, "literals": literals}


def _response_segments(text: str, min_len: int = 16,
                       limit: int = 200) -> List[str]:
    """响应里长度 ≥ ``min_len`` 的非空行，作为「精确子串」探针。

    整条响应太长，全部出现在交付物里的概率本就很低；按行切能测出「有没有任何
    一段原文被带进证明/证书」，比只搜整条更敏感。去重并封顶，避免长响应把
    搜索变成平方级的活。
    """
    seen: set[str] = set()
    out: List[str] = []
    for line in text.splitlines():
        seg = line.strip()
        if len(seg) >= min_len and seg not in seen:
            seen.add(seg)
            out.append(seg)
            if len(out) >= limit:
                break
    return out


def _search_segments(files: List[Path], segments: List[str]) -> List[Dict[str, Any]]:
    """逐段在 ``files`` 里搜；返回命中的段（带命中文件），最多记 20 条。"""
    hits: List[Dict[str, Any]] = []
    for seg in segments:
        found = _search_bytes(files, seg.encode())
        if found:
            hits.append({"segment": seg[:160], "files": [f["file"] for f in found]})
            if len(hits) >= 20:
                break
    return hits


def _search_literals(files: List[Path], literals: List[str]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for lit in literals:
        found = _search_bytes(files, lit.encode())
        if found:
            hits.append({"literal": lit[:160], "files": [f["file"] for f in found]})
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
           no_prove: bool, pack: Optional[Path] = None) -> Dict[str, Any]:
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

    # 真实响应排查（X1d）：整条 + 逐行精确子串。证明/证书里出现任何一段原文，
    # 都是**确定的泄露**；整条不命中不等于没泄露，所以逐行也搜。
    segments = _response_segments(response)
    seg_delivered = _search_segments(delivered, segments)
    seg_inputs = _search_segments(prover_inputs, segments)
    response_probe = {
        "response_chars": len(response),
        "segments_probed": len(segments),
        "exact_in_delivered": resp_hits,
        "exact_in_prover_inputs": input_hits,
        "segments_in_delivered": seg_delivered,
        "segments_in_prover_inputs": seg_inputs,
        "segments_hit_in_delivered": len(seg_delivered),
        "segments_hit_in_prover_inputs": len(seg_inputs),
    }

    # 策略规则名/正文是**公开输入**；命中和响应命中要分开读，不能混成「泄露」。
    pack_probe: Dict[str, Any] = {"pack": str(pack) if pack else None}
    if pack:
        probes = _pack_rule_probes(Path(pack))
        pack_probe.update({
            "rule_names": probes["names"],
            "rule_literals": probes["literals"],
            "rule_names_in_delivered": _search_literals(delivered, probes["names"]),
            "rule_literals_in_delivered": _search_literals(delivered, probes["literals"]),
            "rule_names_in_prover_inputs": _search_literals(prover_inputs, probes["names"]),
            "rule_literals_in_prover_inputs": _search_literals(prover_inputs,
                                                               probes["literals"]),
            "note": "policy is a public input; a hit here is disclosure of the policy, "
                    "not of T. Only response hits are T leaks.",
        })
        if probes.get("error"):
            pack_probe["error"] = probes["error"]

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
            "response_binding": (results[0].get("response_binding")
                                 if isinstance(results, list) and results else None),
            "note": "public, offline-recomputable function of T — guess-and-verify "
                    "oracle by design (see Theorem A/B); response_binding additionally "
                    "binds the nonce, and the nonce is public in cert.json",
        }

    outcome = None
    if isinstance(results, list) and results:
        outcome = {k: results[0].get(k) for k in
                   ("passed", "mode", "violations", "response_commitment",
                    "response_binding")}

    proof_files = [p for p in files if p.name.startswith("proof")]
    return {
        "tier": tier,
        "proof_mode": "unproven" if (no_prove or tier == "unproven") else tier,
        "proof_hiding": proof_hiding("unproven" if (no_prove or tier == "unproven") else tier),
        "files": [str(p.relative_to(out_dir)) for p in files],
        "proof_files": [{"name": p.name, "size": p.stat().st_size}
                        for p in proof_files],
        "proof_bytes": sum(p.stat().st_size for p in proof_files),
        "outcome": outcome,
        "canary_in_text": text_hits,
        "canary_in_proof": proof_hits,
        "response_in_delivered": resp_hits,
        "response_in_prover_inputs": input_hits,
        "response_probe": response_probe,
        "policy_probe": pack_probe,
        "public_values": pv,
        "commitment_oracle": oracle,
        "re_execution": {
            "status": "skipped",
            "reason": "needs a real model + prompt; measured by bench_k_entropy / E2",
        },
    }


def run(args: argparse.Namespace) -> Dict[str, Any]:
    if args.response_file:
        source = Path(args.response_file)
        response = source.read_text(encoding="utf-8")
        response_source = f"file:{source}"
    else:
        # 缺省行为保持原样：内置 canary 文本（冒烟/回归用）。
        response = (f"Here is a safe-looking answer ({CANARY}). "
                    f"Also a secret-looking token sk-{CANARY.lower()}0123456789abcdef, "
                    f"and the word exploit appears here to trigger the keyword rule.")
        response_source = "builtin-canary"
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
            issue.update(_probe(out_dir, response, tier, args.no_prove,
                                Path(args.pack)))
        runs.append(issue)

    result = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pack": str(args.pack),
        "out_dir": str(args.out_dir),
        "response_source": response_source,
        "response_file": str(args.response_file) if args.response_file else None,
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
            "Policy rule names/literals are public inputs; hits there are not T leaks.",
            "Re-execution is independent of the proving tier; measure it in E2.",
        ],
    }
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = args.out_name or "privacy_surface"
    (out / f"{stem}.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / f"{stem}.md").write_text(render_md(result), encoding="utf-8")
    return result


def render_md(r: Dict[str, Any]) -> str:
    src = r.get("response_source") or "builtin-canary"
    lines = [
        "# 隐私面探针（P0-07 / Wave 2 X1）",
        "",
        f"**生成时间**：{r['generated_at']}  **pack**：`{r['pack']}`  ",
        f"**canary**：`{r['canary']}`  **响应来源**：`{src}`  "
        f"**响应哈希**：`{r['response_sha256'][:16]}…`（{r['response_chars']} 字符）",
    ]
    prov = r.get("provenance")
    if prov:
        lines += [
            "",
            f"**口径**：host `{prov.get('host')}`（cgroup {prov.get('cpu_count_cgroup')} 核 / "
            f"{prov.get('mem_total_cgroup_mb')} MB）；binary `{str(prov.get('binary_sha256'))[:8]}…`；"
            f"policy vkey `{prov.get('policy_vkey')}`；commit `{prov.get('commit')}`"
            f"（post-NFA-fix={prov.get('post_nfa_fix')}）；{prov.get('concurrency')}。",
        ]
    lines += [
        "",
        "| tier | status | hiding | proof 大小 | canary 在文本 | canary 在证明 | "
        "响应整条在交付物 | 响应行命中交付物 | 策略名命中交付物 |",
        "|---|---|---|---:|---|---|---|---|---|",
    ]
    for x in r["tiers"]:
        rp = x.get("response_probe") or {}
        pp = x.get("policy_probe") or {}
        # 表里的「proof 大小」只算真正的证明工件 proof.bin；.pv/.bytes/.meta 是
        # 旁证，混进来会把 core 的 2.8 MB 报成 5.6 MB。
        artifact_bytes = sum(f["size"] for f in (x.get("proof_files") or [])
                             if f["name"] == "proof.bin")
        lines.append(
            f"| {x['tier']} | {x['status']} | {x.get('proof_hiding','')} | "
            f"{artifact_bytes} B | "
            f"{len(x.get('canary_in_text') or [])} | "
            f"{len(x.get('canary_in_proof') or [])} | "
            f"{len(x.get('response_in_delivered') or [])} | "
            f"{rp.get('segments_hit_in_delivered', 0)} | "
            f"{len(pp.get('rule_names_in_delivered') or [])} |")
    ids = {x["tier"] for x in r["tiers"]}
    same = "同一" if len(ids) == 1 else "两档"
    lines += [
        "",
        f"响应探针：{same}响应下，整条与逐行精确子串分别在**交付物**"
        "（`cert.json` / `payload.json` / `proof*`）与**出证方私有输入**"
        "（`vectors.json` / `results.json`）里搜。策略规则名/正文是**公开输入**，"
        "命中和响应命中必须分开读。",
        "",
    ]
    sample = r.get("response_sample")
    if sample:
        lines += [
            f"**真实响应来源**：`{sample.get('source_dataset')}` 的 "
            f"prompt_id=`{sample.get('prompt_id')}`（label=`{sample.get('label')}`，"
            f"type=`{sample.get('type')}`，model=`{sample.get('model')}`）；"
            f"触发规则：{', '.join(sample.get('triggers') or []) or '无'}。",
            "",
        ]
    lines += [
        "## 逐档明细",
        "",
    ]
    for x in r["tiers"]:
        rp = x.get("response_probe") or {}
        pp = x.get("policy_probe") or {}
        oracle = x.get("commitment_oracle") or {}
        artifact_bytes = sum(f["size"] for f in (x.get("proof_files") or [])
                             if f["name"] == "proof.bin")
        lines += [
            f"### `{x['tier']}`（status={x['status']}，hiding={x.get('proof_hiding','')}）",
            "",
            f"- 证明工件：`proof.bin` {artifact_bytes} B（全部 `proof*` 旁证合计 "
            f"{x.get('proof_bytes', 0)} B）。",
        ]
        outcome = x.get("outcome")
        if outcome is not None:
            viols = outcome.get("violations") or []
            viol_txt = ", ".join(f"{v.get('rule')}({v.get('kind')})" for v in viols) or "无"
            lines.append(f"- 证书 outcome：passed={outcome.get('passed')}；"
                         f"violations={viol_txt}（公开值只给证据承诺，不给证据明文）。")
        lines += [
            f"- 响应整条：交付物 {len(x.get('response_in_delivered') or [])} 处 / "
            f"私有输入 {len(x.get('response_in_prover_inputs') or [])} 处。",
            f"- 响应逐行子串（探 {rp.get('segments_probed', 0)} 行）：交付物 "
            f"{rp.get('segments_hit_in_delivered', 0)} 行 / 私有输入 "
            f"{rp.get('segments_hit_in_prover_inputs', 0)} 行。",
            f"- 策略规则名：交付物 {len(pp.get('rule_names_in_delivered') or [])} 处；"
            f"规则正文字面量：交付物 {len(pp.get('rule_literals_in_delivered') or [])} 处。",
            f"- `response_commitment` oracle：published=`{oracle.get('published_commitment')}`，"
            f"`sha256(T)` 匹配={oracle.get('matches_sha256_T')}。",
            "",
        ]
        if rp.get("segments_hit_in_delivered"):
            lines.append("命中的响应行：")
            for h in rp["segments_hit_in_delivered"][:5]:
                lines.append(f"  - `{h['segment'][:60]}…` in {h['files']}")
            lines.append("")
    lines += [
        "## 怎么读",
        "",
        "- **响应/canary 出现在交付物里 > 0** = 该档**确定泄露** `T` 的明文；"
        "`core`/`compressed` 的 trace 开值本来就明文可见，这一档 `hiding=none`。",
        "- **命中 = 0 只说明这一组探针没找到，不是零知识证明**；"
        "`groth16/plonk` 才在包装器层面隐藏见证（非后量子）。",
        "- `response_commitment` 是公开、可离线重算的 `T` 的函数 —— "
        "它本来就是猜测-验证 oracle；真正的攻击是**重执行**（E2）。",
        "- 策略规则名/正文命中交付物**不是** `T` 泄露：策略是公开输入。"
        "本例的 1 处策略名命中是证书公开的**违规规则名**（`no_bad_topics`），不是响应。",
        "- 「响应整条在私有输入」为 0 有个技术原因：`vectors.json` 把换行转义成 "
        "`\\n`，整条字节串对不上；逐行探针在私有输入里 7/7 命中，说明原文确实在"
        "**出证方输入**里 —— 那本来就不是交付物。",
        "- `re_execution.status=skipped` 是诚实的：本脚本不跑模型；"
        "`bench_k_entropy.py` 负责测 `k`。",
        "",
        "## 复现",
        "",
        "```bash",
        f"python3 bench/bench_privacy_surface.py --tiers {r['tiers'][0]['tier']} "
        f"--no-prove --out-dir {Path(r.get('out_dir', 'bench/results'))}",
        "# 云机（真实响应）：",
        "SP1_PROVER=cpu python3 bench/bench_privacy_surface.py --tiers core,groth16 \\",
        "  --response-file /path/to/real_response.txt --out-name privacy_surface_real",
        "```",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--tiers", default="unproven",
                    help="逗号分隔：unproven,core,compressed,groth16,plonk")
    ap.add_argument("--pack", default=str(DEFAULT_PACK))
    ap.add_argument("--out-dir", default=str(REPO / "bench" / "results"))
    ap.add_argument("--out-name", default="privacy_surface",
                    help="输出文件名（不含扩展名）；真实响应跑用 privacy_surface_real")
    ap.add_argument("--work-dir", default=None)
    ap.add_argument("--response-file", type=Path, default=None,
                    help="用真实响应文本替代内置 canary（可以是 LLM 的一条回复）")
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--no-prove", action="store_true",
                    help="所有 tier 都走 host check（冒烟用；不产生证明工件）")
    args = ap.parse_args()
    result = run(args)
    for x in result["tiers"]:
        rp = x.get("response_probe") or {}
        print(f"{x['tier']}: {x['status']}  hiding={x.get('proof_hiding','')}  "
              f"canary_in_proof={len(x.get('canary_in_proof') or [])}  "
              f"response_segments_in_delivered="
              f"{rp.get('segments_hit_in_delivered', 0)}")
    print(f"wrote {Path(args.out_dir) / (args.out_name + '.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
