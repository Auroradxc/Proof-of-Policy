#!/usr/bin/env python3
"""实测猜测熵 `k = -log2 Guess(T | Z)`（P0-09 / Wave 2 X2）。

**要回答什么。** 证书绑定的是 `T` 的一个公开函数；对手知道 `(prompt, model,
decoding)`。如果同一 prompt 上模型的响应分布高度集中，`Guess(T|Z)` 就接近 1，
`k` 接近 0，重执行一次模型即可恢复 `T`。本脚本：

1. 对每条 prompt、每个温度采样 `N` 次；
2. 用**同一响应的最大经验频率**估计 `p_max = Guess(T|Z)`；
3. 报告 `k = -log2(p_max)`、分布、以及 `k < log q + log(1/eps)` 的比例；
4. 原始样本落盘，供 `bench_real_llm_e2e.py` 复用。

**三个 backend**（`--backend`）：

- `stub`：确定性伪模型，**不需要 key、不需要 GPU**，用于冒烟与 CI；
- `openai:<model>` / `anthropic:<model>`：走 `policydsl.adapters.llm`，需要对应 key；
- `local:<model-or-path>`：走 `transformers`，需要 `pip install transformers accelerate`；
  8 GB 显存建议 3B 级模型 + `--load-in-4bit`（需 bitsandbytes），8B fp16 装不下。

**边界（必须写进论文）**：

- 精确字符串计数会**低估**长响应的多样性；`N` 只有 20–50，`p_max` 是估计值；
- API 的采样随机性/版本漂移会让结果不可逐字节复现；记录 model / 时间 / 参数；
- 这里的 `k` 是**采样分布**的估计，不是对任意 `Z` 的信息论上界；
- 真正的攻击是**重执行**（Corollary reexec），不是枚举字符串空间。

用法::

    # 冒烟（无需任何外部资源）
    python3 bench/bench_k_entropy.py --backend stub --max-prompts 6 \
        --n-samples 10 --temperatures 0,0.7 --out-dir bench/results

    # 真实 API
    export OPENAI_API_KEY=...
    python3 bench/bench_k_entropy.py \
        --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl \
        --backend openai:gpt-4o-mini --max-prompts 50 --n-samples 20 \
        --temperatures 0,0.7 --out-dir bench/results

    # 本地显卡（3B 级 + 4bit）
    python3 bench/bench_k_entropy.py --backend local:Qwen/Qwen2.5-3B-Instruct \
        --load-in-4bit --device cuda --max-prompts 30 --n-samples 10
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

DEFAULT_PROMPTS = REPO / "scripts" / "examples" / "datasets" / "wave2" / "prompts_smoke.jsonl"


# --------------------------------------------------------------------------- #
# 数据
# --------------------------------------------------------------------------- #

def load_prompts(path: Path, max_prompts: int, stratify: bool = True) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    if not rows:
        raise SystemExit(f"{path} 是空的")
    if max_prompts and len(rows) > max_prompts:
        if stratify and any("label" in r for r in rows):
            safe = [r for r in rows if r.get("label") == "safe"]
            unsafe = [r for r in rows if r.get("label") == "unsafe"]
            half = max_prompts // 2
            rows = safe[:half] + unsafe[:max_prompts - half]
        else:
            rows = rows[:max_prompts]
    return rows


# --------------------------------------------------------------------------- #
# Backends
# --------------------------------------------------------------------------- #

class StubBackend:
    """确定性伪模型：temperature 0 恒定，>0 时 80% 众数 + 20% 变体。

    这样 `k` 在冒烟里可手算：p_max≈0.8 ⇒ k≈0.32 bit；temperature 0 ⇒ k=0。
    """

    name = "stub"

    def __init__(self, seed: int):
        self.seed = seed

    def generate(self, prompt: str, temperature: float, sample_index: int,
                 max_tokens: int) -> str:
        base = f"[stub] {prompt[:60]}"
        if temperature <= 0:
            return base
        h = hashlib.sha256(f"{self.seed}|{prompt}|{temperature}".encode()).digest()
        rng = random.Random(int.from_bytes(h[:8], "big") ^ sample_index)
        r = rng.random()
        if r < 0.8:
            return base
        if r < 0.9:
            return base + " (variant A)"
        return base + " (variant B)"


class ChatBackend:
    """OpenAI / Anthropic，经 policydsl.adapters.llm 构造。"""

    def __init__(self, spec: str):
        from policydsl.adapters import llm
        self.spec = spec
        self.name = llm.describe(spec)
        try:
            self._llm = llm.build_chat_model(spec, streaming=False, temperature=0.0)
        except Exception as exc:
            raise SystemExit(f"构造模型失败：{exc}") from exc

    def _client(self, temperature: float):
        # temperature 是构造参数；每次换温度就重建一个轻量客户端。
        from policydsl.adapters import llm
        return llm.build_chat_model(self.spec, streaming=False,
                                    temperature=temperature)

    def generate(self, prompt: str, temperature: float, sample_index: int,
                 max_tokens: int) -> str:
        model = self._client(temperature)
        resp = model.invoke(prompt, max_tokens=max_tokens)
        content = getattr(resp, "content", str(resp))
        if isinstance(content, list):  # 某些 provider 返回分段
            content = "".join(str(c.get("text", c)) if isinstance(c, dict) else str(c)
                              for c in content)
        return str(content)


class LocalBackend:
    """transformers 本地模型；缺失依赖时给得出下一步。"""

    def __init__(self, model_id: str, device: str = "auto",
                 load_in_4bit: bool = False, chat_template: bool = False):
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:
            raise SystemExit(
                "local backend 需要 transformers + torch：\n"
                "  pip install transformers accelerate\n"
                "  （4bit 还需 bitsandbytes）\n"
                f"原始错误：{exc}") from exc
        self.torch = torch
        self.model_id = model_id
        if device == "auto":
            device = "cuda" if torch.cuda.is_available() else "cpu"
        self.device = device
        self.chat_template = chat_template
        self.name = f"local:{model_id}@{device}" + ("+4bit" if load_in_4bit else "") \
            + ("+chat_template" if chat_template else "")
        kwargs: Dict[str, Any] = {"device_map": "auto" if device == "cuda" else None}
        if load_in_4bit:
            try:
                from transformers import BitsAndBytesConfig
                kwargs["quantization_config"] = BitsAndBytesConfig(
                    load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16)
            except Exception as exc:  # noqa: BLE001
                print(f"[warn] 4bit 不可用，回退 fp16/CPU：{exc}", file=sys.stderr)
        else:
            # 不指定 dtype 时 from_pretrained 默认 fp32：7B ≈ 28 GB、8B ≈ 32 GB，
            # 32 GB 卡上会把 KV cache 挤爆。GPU 用 fp16，CPU 保持 fp32。
            kwargs["torch_dtype"] = torch.float16 if device == "cuda" else torch.float32
        self.tok = AutoTokenizer.from_pretrained(model_id)
        if self.tok.pad_token is None:
            self.tok.pad_token = self.tok.eos_token
        self.model = AutoModelForCausalLM.from_pretrained(model_id, **kwargs)
        if device == "cpu":
            self.model.to("cpu")
        self.model.eval()

    def generate(self, prompt: str, temperature: float, sample_index: int,
                 max_tokens: int) -> str:
        torch = self.torch
        text = prompt
        if self.chat_template:
            # Instruct 模型的训练/部署口径：把 prompt 包成单轮 user 消息，
            # 让模型在 assistant 轮上续写；否则裸续写会让 instruct 模型
            # 复读/补全 prompt，k 与端到端指标都不可比。
            messages = [{"role": "user", "content": prompt}]
            text = self.tok.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True)
        inputs = self.tok(text, return_tensors="pt")
        if self.device == "cuda":
            inputs = {k: v.to("cuda") for k, v in inputs.items()}
        gen_kwargs: Dict[str, Any] = {
            "max_new_tokens": max_tokens,
            "pad_token_id": self.tok.pad_token_id,
        }
        if temperature <= 0:
            gen_kwargs.update(do_sample=False)
        else:
            gen_kwargs.update(do_sample=True, temperature=temperature, top_p=1.0)
        with torch.no_grad():
            out = self.model.generate(**inputs, **gen_kwargs)
        new = out[0][inputs["input_ids"].shape[1]:]
        return self.tok.decode(new, skip_special_tokens=True)


def build_backend(spec: str, args: argparse.Namespace):
    if spec == "stub":
        return StubBackend(args.seed)
    if spec.startswith("openai:") or spec.startswith("anthropic:"):
        return ChatBackend(spec)
    if spec.startswith("local:"):
        return LocalBackend(spec.split(":", 1)[1], device=args.device,
                            load_in_4bit=args.load_in_4bit,
                            chat_template=getattr(args, "chat_template", False))
    raise SystemExit(
        f"不认识的 backend '{spec}'；可用 stub / openai:<model> / "
        f"anthropic:<model> / local:<model-or-path>")


# --------------------------------------------------------------------------- #
# 估计
# --------------------------------------------------------------------------- #

def wilson_interval(count: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    if n <= 0:
        return (0.0, 0.0)
    phat = count / n
    denom = 1.0 + z * z / n
    center = (phat + z * z / (2 * n)) / denom
    margin = z * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def estimate_group(responses: List[str]) -> Dict[str, Any]:
    n = len(responses)
    counts = Counter(r.strip() for r in responses)
    mode, mode_count = counts.most_common(1)[0] if counts else ("", 0)
    p_max = mode_count / n if n else 0.0
    # p_max=1 时 -log2(1) 在浮点里可能是 -0.0；统一成 0.0，免得报告里出现 "-0.00"
    k = 0.0 if p_max >= 1.0 else (-math.log2(p_max) if p_max > 0 else float("inf"))
    probs = [c / n for c in counts.values()]
    entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    lo, hi = wilson_interval(mode_count, n)
    k_lo = 0.0 if hi >= 1.0 else (-math.log2(hi) if hi > 0 else float("inf"))
    k_hi = 0.0 if lo >= 1.0 else (-math.log2(lo) if lo > 0 else float("inf"))
    return {
        "n": n,
        "mode": mode,
        "mode_count": mode_count,
        "p_max": p_max,
        "k_bits": k,
        "k_bits_ci": (k_lo, k_hi),
        "distinct": len(counts),
        "empirical_entropy_bits": entropy,
    }


def aggregate(groups: List[Dict[str, Any]], threshold_bits: float) -> Dict[str, Any]:
    ks = [g["k_bits"] for g in groups if g["n"] > 0]
    if not ks:
        return {"n_groups": 0}
    return {
        "n_groups": len(ks),
        "k_mean": statistics.fmean(ks),
        "k_median": statistics.median(ks),
        "k_min": min(ks),
        "k_max": max(ks),
        "k_zero_fraction": sum(1 for k in ks if k <= 1e-9) / len(ks),
        "below_threshold_fraction": sum(1 for k in ks if k < threshold_bits) / len(ks),
        "threshold_bits": threshold_bits,
    }


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #

def run(args: argparse.Namespace) -> Dict[str, Any]:
    prompts = load_prompts(args.prompts, args.max_prompts, stratify=not args.no_stratify)
    backend = build_backend(args.backend, args)
    temps = [float(t) for t in args.temperatures.split(",") if t.strip()]
    samples_path = Path(args.samples_out) if args.samples_out else (
        Path(args.out_dir) / "k_samples.jsonl")
    samples_path.parent.mkdir(parents=True, exist_ok=True)

    existing: set[Tuple[str, float, int]] = set()
    if args.resume and samples_path.exists():
        with samples_path.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                    existing.add((str(r["prompt_id"]), float(r["temperature"]),
                                  int(r["sample_index"])))
                except Exception:  # noqa: BLE001 - 坏行跳过
                    continue
        print(f"续跑：{len(existing)} 条样本已存在，跳过", flush=True)

    fh = samples_path.open("a", encoding="utf-8")
    total = 0
    t0 = time.time()
    try:
        for p_i, p in enumerate(prompts):
            pid = str(p.get("id", p_i))
            prompt = p.get("prompt", "")
            for temp in temps:
                for s in range(args.n_samples):
                    if (pid, temp, s) in existing:
                        continue
                    start = time.perf_counter()
                    try:
                        resp = backend.generate(prompt, temp, s, args.max_tokens)
                        err = None
                    except Exception as exc:  # noqa: BLE001 - 单点失败不拖垮整批
                        resp, err = "", f"{type(exc).__name__}: {exc}"
                    rec = {
                        "prompt_id": pid, "prompt": prompt,
                        "label": p.get("label"), "type": p.get("type"),
                        "temperature": temp, "sample_index": s,
                        "response": resp, "error": err,
                        "latency_ms": round((time.perf_counter() - start) * 1000, 2),
                        "model": backend.name,
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    fh.flush()
                    total += 1
                    if total % 20 == 0:
                        print(f"  ... {total} samples, {time.time()-t0:.0f}s", flush=True)
    finally:
        fh.close()

    # 从落盘样本重算（续跑时也覆盖旧样本）
    groups: List[Dict[str, Any]] = []
    by_group: Dict[Tuple[str, float], List[str]] = defaultdict(list)
    by_group_meta: Dict[Tuple[str, float], Dict[str, Any]] = {}
    with samples_path.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            if r.get("error"):
                continue
            key = (str(r["prompt_id"]), float(r["temperature"]))
            by_group[key].append(r["response"])
            by_group_meta[key] = {"prompt": r.get("prompt"),
                                  "label": r.get("label"),
                                  "type": r.get("type")}
    for (pid, temp), responses in sorted(by_group.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        est = estimate_group(responses)
        est.update({"prompt_id": pid, "temperature": temp,
                    **by_group_meta[(pid, temp)]})
        groups.append(est)

    threshold = math.log2(args.q) + math.log2(1.0 / args.eps)
    agg_by_temp = {t: aggregate([g for g in groups if g["temperature"] == t], threshold)
                   for t in temps}
    result = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "backend": args.backend,
        "model": backend.name,
        "prompts_file": str(args.prompts),
        "n_prompts": len(prompts),
        "n_samples_per_prompt": args.n_samples,
        "chat_template": bool(getattr(args, "chat_template", False)),
        "temperatures": temps,
        "q": args.q,
        "eps": args.eps,
        "threshold_bits": threshold,
        "samples_file": str(samples_path),
        "groups": groups,
        "aggregate": agg_by_temp,
        "notes": [
            "p_max is the empirical mode frequency; exact-string counting may "
            "underestimate diversity for long responses.",
            "k is an estimate of the sampled distribution, not an "
            "information-theoretic bound for all Z.",
            "The relevant attack is re-execution under greedy/low-temperature "
            "decoding, not enumeration over the string space.",
        ],
    }
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "k_entropy.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out_dir / "k_entropy.md").write_text(render_md(result), encoding="utf-8")
    return result


def render_md(r: Dict[str, Any]) -> str:
    lines = [
        "# 实测猜测熵 `k`（P0-09 / Wave 2 X2）",
        "",
        f"**生成时间**：{r['generated_at']}  ",
        f"**backend**：`{r['backend']}` → `{r['model']}`  ",
        f"**prompts**：`{r['prompts_file']}`（{r['n_prompts']} 条）  ",
        f"**每 prompt 采样**：{r['n_samples_per_prompt']}  "
        f"**温度**：{r['temperatures']}  ",
        f"**chat template**：{'开启（单轮 user）' if r.get('chat_template') else '关闭（裸续写）'}  ",
        f"**阈值**：`k ≥ log2(q)+log2(1/eps)` = **{r['threshold_bits']:.1f} bit** "
        f"(q={r['q']}, eps={r['eps']})",
        "",
        "## 按温度汇总",
        "",
        "| 温度 | 组数 | mean k | median k | min | max | k=0 比例 | k<阈值 比例 |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for t, a in r["aggregate"].items():
        if not a.get("n_groups"):
            continue
        lines.append(
            f"| {t} | {a['n_groups']} | {a['k_mean']:.2f} | {a['k_median']:.2f} | "
            f"{a['k_min']:.2f} | {a['k_max']:.2f} | {a['k_zero_fraction']:.2f} | "
            f"{a['below_threshold_fraction']:.2f} |")
    lines += [
        "",
        "## 逐 prompt（前 50 行）",
        "",
        "| prompt_id | temp | label | N | mode_count | p_max | k (bit) | distinct |",
        "|---|---:|---|---:|---:|---:|---:|---:|",
    ]
    for g in r["groups"][:50]:
        lines.append(
            f"| {g['prompt_id']} | {g['temperature']} | {g.get('label') or ''} | "
            f"{g['n']} | {g['mode_count']} | {g['p_max']:.3f} | "
            f"{g['k_bits']:.2f} | {g['distinct']} |")
    lines += [
        "",
        "## 怎么读",
        "",
        "- **温度 0**：响应若确定，`p_max=1`、`k=0` ⇒ 重执行一次模型即可恢复 `T`，"
        "与证明系统无关。",
        "- **温度 > 0**：`k` 升高，但自然语言响应的众数仍常占很高比例；"
        "要判断证书是否真的隐藏 `T`，看 `k < 阈值` 的比例，而不是看平均值。",
        "- 精确字符串计数会低估长响应的多样性；`N` 只有 20–50。本表是**采样分布的"
        "估计**，不是信息论上界。",
        f"- `N={r['n_samples_per_prompt']}` 的截断：`p_max` 最小只能分辨 "
        f"`1/{r['n_samples_per_prompt']}`，故 `k` 的**最大可观测值**约为 "
        f"`{math.log2(r['n_samples_per_prompt']):.2f} bit`；所有样本互不相同时只会"
        "得到这个上界，而不是真实熵。`k=0` 也可能只是 `N` 太小没采到变体。",
        "- chat template 开启时，prompt 被包成单轮 user 消息，解码只取新 token；"
        "关闭时是裸续写（X2 口径）。两种口径的 `k` 与端到端指标不可直接混用。",
        "- 真正的攻击是**重执行**（`Corollary reexec`），不是枚举字符串空间。",
        "",
        "## 复现",
        "",
        "```bash",
        f"python3 bench/bench_k_entropy.py --backend {r['backend']} "
        f"--prompts {r['prompts_file']} --max-prompts {r['n_prompts']} "
        f"--n-samples {r['n_samples_per_prompt']} "
        f"--temperatures {','.join(str(t) for t in r['temperatures'])}"
        + (" --chat-template" if r.get("chat_template") else ""),
        "```",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--prompts", type=Path, default=DEFAULT_PROMPTS)
    ap.add_argument("--out-dir", default=str(REPO / "bench" / "results"))
    ap.add_argument("--samples-out", default=None,
                    help="原始样本 JSONL；默认 <out-dir>/k_samples.jsonl")
    ap.add_argument("--backend", default="stub",
                    help="stub | openai:<model> | anthropic:<model> | local:<model-or-path>")
    ap.add_argument("--max-prompts", type=int, default=50)
    ap.add_argument("--n-samples", type=int, default=20)
    ap.add_argument("--temperatures", default="0,0.7")
    ap.add_argument("--max-tokens", type=int, default=256)
    ap.add_argument("--seed", type=int, default=20261101)
    ap.add_argument("--q", type=int, default=1 << 20)
    ap.add_argument("--eps", type=float, default=2.0 ** -20)
    ap.add_argument("--device", default="auto", choices=["auto", "cuda", "cpu"])
    ap.add_argument("--load-in-4bit", action="store_true")
    ap.add_argument("--chat-template", action="store_true",
                    help="local backend 把 prompt 包成单轮 user 消息并 apply_chat_template"
                         "（缺省关闭，保持旧续写口径）")
    ap.add_argument("--no-stratify", action="store_true",
                    help="默认按 safe/unsafe 分层取前 max-prompts 条")
    ap.add_argument("--resume", action="store_true",
                    help="跳过 samples-out 里已有的 (prompt_id, temperature, sample_index)")
    args = ap.parse_args()
    result = run(args)
    for t, a in result["aggregate"].items():
        if a.get("n_groups"):
            print(f"temp={t}: median k={a['k_median']:.2f} bit, "
                  f"below threshold={a['below_threshold_fraction']:.2%}")
    print(f"wrote {Path(args.out_dir) / 'k_entropy.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
