#!/usr/bin/env python3
"""Wave 2 环境/资源体检（X1 cloud / X2 GPU / X3 语义与推理）。

**为什么要有它。** Wave 2 的失败模式不是“逻辑错”，而是“机器不够”：
groth16 在 12 GB 上被 OOM 杀、8B 模型在 8 GB 显存上装不下、API key 没配。
这些失败如果等到跑了几十分钟才出现，代价很高。本脚本**在开跑前**把每条线
的最低资源写成判据，并给出下一步命令。

用法::

    python3 scripts/ops/check_wave2_env.py
    python3 scripts/ops/check_wave2_env.py --require P0-06,P0-08 --json

退出码：所有 `--require` 的任务都 PASS ⇒ 0；否则 1。
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO = Path(__file__).resolve().parents[2]

#: 各任务的最低资源（与 bench_scale.py 的 MODE_MIN_MEM_MB 同口径）。
MIN_MEM_GB = {
    "P0-06_groth16": 64,
    "P0-07_privacy_surface": 64,
    "P0-08_scale": 64,
}


def _run(cmd: List[str]) -> Optional[str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if p.returncode != 0:
            return None
        return (p.stdout or p.stderr).strip().splitlines()[0] if (p.stdout or p.stderr).strip() else ""
    except Exception:  # noqa: BLE001
        return None


def mem_total_gb() -> float:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                kb = int(line.split()[1])
                return kb / (1024 * 1024)
    except Exception:  # noqa: BLE001
        pass
    return 0.0


def mem_available_gb() -> float:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                kb = int(line.split()[1])
                return kb / (1024 * 1024)
    except Exception:  # noqa: BLE001
        pass
    return 0.0


def gpu_info() -> List[Dict[str, Any]]:
    out = _run(["nvidia-smi", "--query-gpu=name,memory.total",
                "--format=csv,noheader,nounits"])
    if not out:
        return []
    gpus = []
    for line in out.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 2:
            try:
                gpus.append({"name": parts[0], "mem_mb": int(float(parts[1]))})
            except ValueError:
                gpus.append({"name": line, "mem_mb": 0})
    return gpus


def module_ok(name: str) -> bool:
    try:
        __import__(name)
        return True
    except Exception:  # noqa: BLE001
        return False


def collect() -> Dict[str, Any]:
    total = mem_total_gb()
    avail = mem_available_gb()
    disk = shutil.disk_usage(str(REPO))
    gpus = gpu_info()
    env = {
        "OPENAI_API_KEY": bool(os.environ.get("OPENAI_API_KEY")),
        "ANTHROPIC_API_KEY": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "OPENAI_BASE_URL": os.environ.get("OPENAI_BASE_URL"),
        "OPENAI_API_BASE": os.environ.get("OPENAI_API_BASE"),
        "SP1_PROVER": os.environ.get("SP1_PROVER"),
    }
    tools = {
        "cargo": _run(["cargo", "--version"]),
        "cargo_prove": _run(["cargo", "prove", "--version"]),
        "go": _run(["go", "version"]),
        "python": _run([sys.executable, "--version"]),
    }
    modules = {m: module_ok(m) for m in
               ("torch", "transformers", "datasets", "langchain_openai",
                "ezkl", "onnxruntime")}
    checks: Dict[str, Dict[str, Any]] = {}

    for task, need in MIN_MEM_GB.items():
        ok = total >= need and tools["cargo_prove"] is not None
        checks[task] = {
            "ok": ok,
            "detail": f"total RAM {total:.1f} GiB (need {need}) | "
                      f"cargo-prove {'yes' if tools['cargo_prove'] else 'NO'}",
            "next": "SP1_PROVER=cpu bash scripts/ops/run_wave2_cloud.sh" if ok
                    else "换 ≥64 GB 云机；或改标题为 Succinct 并收窄 ZK 措辞",
        }

    gpu_mem = max((g["mem_mb"] for g in gpus), default=0)
    local_ok = bool(gpus) and gpu_mem >= 8 * 1024 and modules["torch"] and modules["transformers"]
    checks["P0-09_local_llm"] = {
        "ok": local_ok,
        "detail": (f"GPU {gpu_mem/1024:.0f} GiB | torch={modules['torch']} | "
                   f"transformers={modules['transformers']}"),
        "next": ("python3 bench/bench_k_entropy.py --backend local:<3B-model> "
                 "--load-in-4bit --device cuda") if local_ok
                else "pip install transformers accelerate（8B fp16 需 ≥16 GB 显存；"
                     "8 GB 用 3B + 4bit）或改走 API",
    }
    api_ok = env["OPENAI_API_KEY"] or env["ANTHROPIC_API_KEY"]
    base = env["OPENAI_BASE_URL"] or env["OPENAI_API_BASE"]
    base_warn = None
    if base and "deepseek" in base.lower():
        base_warn = (f"OPENAI 端点指向 {base}；本仓库的测试/脚本会用这个端点。"
                     "要接官方 OpenAI 就先 unset OPENAI_BASE_URL/OPENAI_API_BASE，"
                     "或显式设成目标端点。")
    key_warn = None
    if env["OPENAI_API_KEY"]:
        key_warn = "只检查了 key 是否存在；无效 key 会在第一次请求时 401。"
    checks["P0-09_api"] = {
        "ok": api_ok,
        "detail": (f"OPENAI_API_KEY={env['OPENAI_API_KEY']} | "
                   f"ANTHROPIC_API_KEY={env['ANTHROPIC_API_KEY']} | "
                   f"base={env['OPENAI_BASE_URL'] or env['OPENAI_API_BASE'] or '(default)'}"),
        "next": ("export OPENAI_API_KEY=... && python3 bench/bench_k_entropy.py "
                 "--backend openai:gpt-4o-mini") if api_ok
                else "配一个 API key，或走 local backend",
        "warning": " | ".join(x for x in (base_warn, key_warn) if x) or None,
    }
    checks["P2-01_semantic"] = {
        "ok": modules["ezkl"] and modules["onnxruntime"],
        "detail": f"ezkl={modules['ezkl']} | onnxruntime={modules['onnxruntime']}",
        "next": "python3 bench/bench_semantic_real.py（待 X3 落地）",
    }
    checks["P2-02_inference"] = {
        "ok": gpu_mem >= 8 * 1024 and modules["torch"],
        "detail": f"GPU {gpu_mem/1024:.0f} GiB | torch={modules['torch']}",
        "next": "先做选型报告；真推理证明很可能降级为机制演示",
    }

    return {
        "host": {
            "hostname": _run(["hostname"]) or "?",
            "cpu_count": os.cpu_count(),
            "mem_total_gb": round(total, 2),
            "mem_available_gb": round(avail, 2),
            "disk_free_gb": round(disk.free / (1024 ** 3), 2),
            "repo": str(REPO),
        },
        "gpus": gpus,
        "tools": tools,
        "modules": modules,
        "env": env,
        "checks": checks,
    }


def print_human(d: Dict[str, Any]) -> None:
    h = d["host"]
    print(f"host      : {h['hostname']}  {h['cpu_count']} 核  "
          f"{h['mem_total_gb']:.1f} GiB total / {h['mem_available_gb']:.1f} GiB avail  "
          f"disk {h['disk_free_gb']:.1f} GiB free")
    print(f"gpus      : {d['gpus'] or '(none)'}")
    print(f"tools     : cargo={d['tools']['cargo']} | cargo-prove={d['tools']['cargo_prove']} "
          f"| go={d['tools']['go']}")
    print(f"modules   : {d['modules']}")
    print("")
    print(f"{'task':<24} {'PASS':<5} detail")
    for task, c in d["checks"].items():
        print(f"{task:<24} {'✅' if c['ok'] else '⛔':<5} {c['detail']}")
        if c.get("warning"):
            print(f"{'':<24} ⚠ {c['warning']}")
        if not c["ok"]:
            print(f"{'':<24} → {c['next']}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--require", default=None,
                    help="逗号分隔的任务名；全部 PASS 才返回 0")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    d = collect()
    if args.json:
        print(json.dumps(d, ensure_ascii=False, indent=2))
    else:
        print_human(d)
    if args.require:
        req = [x.strip() for x in args.require.split(",") if x.strip()]
        bad = [t for t in req if not d["checks"].get(t, {}).get("ok")]
        if bad:
            print(f"\n[BLOCKED] {', '.join(bad)}", file=sys.stderr)
            return 1
        print(f"\n[PASS] {', '.join(req)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
