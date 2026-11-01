#!/usr/bin/env python3
"""Wave 2 数据集准备：XSTest（必选）+ τ-bench / Enron（可选）。

**为什么单独一个脚本。** Wave 2 的 `bench_k_entropy.py` 与
`bench_real_llm_e2e.py` 只吃**归一化 JSONL**；把「从哪下载、字段怎么映射、
哪个 split、许可证是什么」留在数据准备这一步，实验脚本就不必掺入
provider / 数据集的特例。

**XSTest**（Röttger et al., NAACL 2024）：
- 450 条 prompt：250 safe + 200 unsafe；
- 原始 CSV：`paul-rottger/xstest` 仓库的 `xstest_prompts.csv`（CC-BY-4.0）；
- HuggingFace `walledai/XSTest` 是 **gated**，未登录会 `DatasetNotFoundError`；
  本脚本优先用原始 CSV，HF 只作为备选提示（不自动走 gated 路径）。

**τ-bench**（可选）：本仓库的 `taubench2pack.py` 吃的是
`tau2-bench/data/tau2/domains/airline/tasks.json`（50 条 airline 任务）。
本脚本可 `--download-taubench`，也可 `--taubench` 指定本地文件。

**Enron**（可选）：只登记路径与 sha256，不解析；解析仍由
`scripts/datasets/enron2pack.py` 负责（数据大、许可需自查）。

用法::

    # 最小：用 /tmp 已下载的 CSV，或现场下载
    python3 scripts/datasets/prepare_wave2.py --download

    # 指定本地 CSV / τ-bench
    python3 scripts/datasets/prepare_wave2.py \
        --xstest-csv /tmp/xstest_prompts.csv \
        --taubench /path/to/tau2/airline/tasks.json

产出（默认 `scripts/examples/datasets/wave2/`）::

    prompts_xstest.jsonl   450 条归一化 prompt
    prompts_smoke.jsonl    safe/unsafe 各 10 条的确定性小集（冒烟用）
    taubench_tasks.jsonl   可选
    manifest.json          来源 / 许可证 / 计数 / sha256
    README.md              人读的来源与使用说明
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

REPO = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO / "scripts" / "examples" / "datasets" / "wave2"

XSTEST_URLS = [
    "https://raw.githubusercontent.com/paul-rottger/xstest/main/xstest_prompts.csv",
    "https://raw.githubusercontent.com/paul-rottger/xstest/master/xstest_prompts.csv",
]
TAU2_TASKS_URL = (
    "https://raw.githubusercontent.com/sierra-research/tau2-bench/main/"
    "data/tau2/domains/airline/tasks.json"
)
XSTEST_LICENSE = "CC-BY-4.0"
TAU2_LICENSE = "MIT (repo); 数据使用请核对上游"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def download(urls: Iterable[str], dest: Path, timeout: int = 30) -> str:
    """按顺序试 URL，成功即返回；失败抛最后一个错误。"""
    dest.parent.mkdir(parents=True, exist_ok=True)
    last: Optional[Exception] = None
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                data = resp.read()
            dest.write_bytes(data)
            return url
        except Exception as exc:  # noqa: BLE001 - 逐个 URL 回退
            last = exc
            print(f"[warn] 下载失败 {url}: {exc}", file=sys.stderr)
    raise RuntimeError(f"所有下载地址都失败: {last}")


def find_xstest_csv(explicit: Optional[Path], out_dir: Path,
                    allow_download: bool) -> tuple[Path, str]:
    candidates = [
        explicit,
        out_dir / "raw" / "xstest_prompts.csv",
        Path("/tmp/xstest_prompts.csv"),
    ]
    for p in candidates:
        if p and Path(p).exists():
            return Path(p), "local"
    if allow_download:
        dest = out_dir / "raw" / "xstest_prompts.csv"
        url = download(XSTEST_URLS, dest)
        return dest, url
    raise SystemExit(
        "找不到 xstest_prompts.csv。二选一：\n"
        "  (a) 先下载：curl -L -o /tmp/xstest_prompts.csv "
        "https://raw.githubusercontent.com/paul-rottger/xstest/main/xstest_prompts.csv\n"
        "  (b) 加 --download 让本脚本下。")


def load_xstest(csv_path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with csv_path.open(encoding="utf-8-sig", newline="") as fh:
        for raw in csv.DictReader(fh):
            label = (raw.get("label") or "").strip().lower()
            if label not in ("safe", "unsafe"):
                raise SystemExit(f"XSTest 行的 label 不是 safe/unsafe: {raw!r}")
            rid = (raw.get("id") or "").strip()
            rows.append({
                "id": int(rid) if rid.isdigit() else rid,
                "prompt": (raw.get("prompt") or "").strip(),
                "type": (raw.get("type") or "").strip(),
                "label": label,
                "focus": (raw.get("focus") or "").strip(),
                "note": (raw.get("note") or "").strip(),
                "source": "xstest",
            })
    if not rows:
        raise SystemExit(f"{csv_path} 里没有数据行")
    return rows


def make_smoke(rows: List[Dict[str, Any]], n_each: int = 10) -> List[Dict[str, Any]]:
    """按 label 分层、按 type 轮转，取确定性的小集（可复现）。"""
    by_label: Dict[str, List[Dict[str, Any]]] = {"safe": [], "unsafe": []}
    for r in rows:
        by_label[r["label"]].append(r)
    picked: List[Dict[str, Any]] = []
    for label in ("safe", "unsafe"):
        items = sorted(by_label[label], key=lambda r: (r["type"], str(r["id"])))
        # 按 type 轮转，避免只取到 homonyms 一族
        buckets: Dict[str, List[Dict[str, Any]]] = {}
        for r in items:
            buckets.setdefault(r["type"], []).append(r)
        order = sorted(buckets)
        chosen: List[Dict[str, Any]] = []
        i = 0
        while len(chosen) < n_each and any(buckets[t] for t in order):
            t = order[i % len(order)]
            if buckets[t]:
                chosen.append(buckets[t].pop(0))
            i += 1
            if i > n_each * len(order) * 2:
                break
        picked.extend(chosen)
    return sorted(picked, key=lambda r: (r["label"], str(r["id"])))


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def load_taubench(path: Path) -> List[Dict[str, Any]]:
    """把 τ²-bench airline tasks.json 归一成 JSONL（保留原对象 + 常用字段）。"""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "tasks" in data:
        data = data["tasks"]
    if not isinstance(data, list):
        raise SystemExit(f"τ-bench 文件不是 list/dict(tasks): {path}")
    out = []
    for i, task in enumerate(data):
        task_id = task.get("id") or task.get("task_id") or f"tau-{i}"
        out.append({
            "id": task_id,
            "user_prompt_template": task.get("user_prompt_template")
            or task.get("user_prompt") or task.get("instruction") or "",
            "actions": (task.get("info") or {}).get("task", {}).get("actions")
            or task.get("actions") or [],
            "raw": task,
        })
    return out


def write_readme(out_dir: Path, manifest: Dict[str, Any]) -> None:
    x = manifest["xstest"]
    t = manifest.get("taubench") or {}
    out_dir.joinpath("README.md").write_text(f"""# Wave 2 数据集

本目录由 `scripts/datasets/prepare_wave2.py` 生成；**不要手改 JSONL**。

## XSTest

- 来源：{x['source']}
- 许可证：{XSTEST_LICENSE}
- 计数：{x['count']}（safe {x['safe']} / unsafe {x['unsafe']}）
- 文件：`prompts_xstest.jsonl`、`prompts_smoke.jsonl`
- 论文：Röttger et al., "XSTest: A Test Suite for Identifying Exaggerated Safety
  Behaviours in Large Language Models", NAACL 2024 (arXiv:2308.01263)

## τ-bench（可选）

{('- 已准备：`taubench_tasks.jsonl`（' + str(t.get('count')) + ' 条）') if t else '- 未准备。用 `--taubench <tasks.json>` 或 `--download-taubench`。'}

- 上游：sierra-research/tau2-bench，`data/tau2/domains/airline/tasks.json`
- 注意：原始 `tau-bench` 的 tasks 已过时，Sierra 建议用 τ²/τ³。

## Enron（可选）

- 只登记路径与 sha256；解析用 `scripts/datasets/enron2pack.py`。
- 数据大、许可需自查；本仓库不随包分发。

## 用法

```bash
# 采样 + 实测 k
python3 bench/bench_k_entropy.py \\
    --prompts scripts/examples/datasets/wave2/prompts_smoke.jsonl \\
    --backend stub --n-samples 20 --temperatures 0,0.7 --out-dir bench/results

# 真实模型（OpenAI 兼容端点）
export OPENAI_API_KEY=...
python3 bench/bench_k_entropy.py \\
    --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl \\
    --backend openai:gpt-4o-mini --max-prompts 50 --n-samples 20 \\
    --temperatures 0,0.7 --out-dir bench/results

# 端到端（响应级策略检查 + 可选证书）
python3 bench/bench_real_llm_e2e.py --samples bench/results/k_samples.jsonl \\
    --policy policy_packs/safety_xstest_v1.json --out-dir bench/results --no-prove
```
""", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--xstest-csv", type=Path, default=None)
    ap.add_argument("--download", action="store_true",
                    help="找不到本地 XSTest CSV 时从 GitHub 原始文件下载")
    ap.add_argument("--taubench", type=Path, default=None)
    ap.add_argument("--download-taubench", action="store_true")
    ap.add_argument("--enron", type=Path, default=None)
    ap.add_argument("--smoke-each", type=int, default=10,
                    help="smoke 集每个 label 取多少条（默认 10）")
    args = ap.parse_args()

    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)

    csv_path, source = find_xstest_csv(args.xstest_csv, out, args.download)
    rows = load_xstest(csv_path)
    write_jsonl(out / "prompts_xstest.jsonl", rows)
    smoke = make_smoke(rows, args.smoke_each)
    write_jsonl(out / "prompts_smoke.jsonl", smoke)

    labels = Counter(r["label"] for r in rows)
    manifest: Dict[str, Any] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "xstest": {
            "source": str(source),
            "url": source if str(source).startswith("http") else XSTEST_URLS[0],
            "license": XSTEST_LICENSE,
            "count": len(rows),
            "safe": labels.get("safe", 0),
            "unsafe": labels.get("unsafe", 0),
            "csv_sha256": sha256_file(csv_path),
            "jsonl_sha256": sha256_file(out / "prompts_xstest.jsonl"),
        },
        "smoke": {
            "count": len(smoke),
            "safe": sum(1 for r in smoke if r["label"] == "safe"),
            "unsafe": sum(1 for r in smoke if r["label"] == "unsafe"),
            "jsonl_sha256": sha256_file(out / "prompts_smoke.jsonl"),
        },
        "notes": [
            "HuggingFace walledai/XSTest is gated; this script uses the raw GitHub CSV.",
            "τ-bench / Enron are optional; they are not needed for the k measurement.",
        ],
    }

    if args.taubench:
        tp = Path(args.taubench)
        trows = load_taubench(tp)
        write_jsonl(out / "taubench_tasks.jsonl", trows)
        manifest["taubench"] = {
            "source": str(tp), "license": TAU2_LICENSE,
            "count": len(trows), "sha256": sha256_file(tp),
        }
    elif args.download_taubench:
        dest = out / "raw" / "tau2_airline_tasks.json"
        url = download([TAU2_TASKS_URL], dest)
        trows = load_taubench(dest)
        write_jsonl(out / "taubench_tasks.jsonl", trows)
        manifest["taubench"] = {
            "source": url, "license": TAU2_LICENSE,
            "count": len(trows), "sha256": sha256_file(dest),
        }
    else:
        manifest["taubench"] = None

    if args.enron:
        ep = Path(args.enron)
        manifest["enron"] = {
            "source": str(ep), "sha256": sha256_file(ep) if ep.exists() else None,
            "note": "只登记；解析用 scripts/datasets/enron2pack.py",
        }
    else:
        manifest["enron"] = None

    (out / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_readme(out, manifest)

    print(f"XSTest: {len(rows)} 条（safe {labels.get('safe',0)} / unsafe {labels.get('unsafe',0)}）")
    print(f"smoke : {len(smoke)} 条")
    print(f"out   : {out}")
    print(f"manifest: {out / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
