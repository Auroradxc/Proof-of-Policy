#!/usr/bin/env python3
"""E6：用模型概率估计猜测熵 `k = -log2 Guess(T|Z)`，绕开 E1 的 `N` 截断。

**要回答什么。** E1 用**精确字符串计数**估计 `p_max = Guess(T|Z)`：`N=50` 时
`p_max >= 1/N` 是数学必然，所有样本互不相同时只能得到 `p_max = 1/N`、
`k = log2(N) = 5.64 bit`，这只是**采样分辨率**，不是真实熵。E6 不再数重复，
而是对每条已采样响应做 **teacher-forced forward**，直接求该响应的**序列对数
概率**：

    logprob(T) = sum_{t in assistant new tokens} log p_model / p_sampling(t)

再取

    p_max_est = max_{i=1..N} exp(logprob_i)
    k_est     = -log2(p_max_est)

**估计器偏差（必须写进论文）**：

1. `max` over `N` 个已采样候选只是**下界**：真实众数概率 `p_max_true` 至少是
   任一已采样响应的概率，所以 `p_max_est <= p_max_true`，于是
   `k_est = -log2(p_max_est) >= -log2(p_max_true) = k_true`。也就是说
   **`p_max_est` 是众数概率的下界，`k_est` 是真实 `k` 的严格上界**。
   E1 的经验 `k = log2(N)`（全唯一时）只是**采样分辨率上限**，不是
   `k_true` 的下界；正确可写的单向结论是 `k_true <= k_est`。
2. **序列概率随长度衰减**：`logprob` 是逐 token 求和，长响应天然更小。因此跨
   prompt 比较 `p_max_est` 会被长度混淆；本脚本同时报告**每 token 平均对数概率**
   （长度的几何平均口径）。
3. **温度缩放口径**：主口径是**采样分布** `softmax(logits / T)`（与 `generate`
   的 `do_sample=True, temperature=T, top_p=1.0` 一致），因为 `Z` 包含解码参数，
   `Guess(T|Z)` 是"按这套解码重新生成出同一串 token"的概率。次口径是**模型分布**
   `softmax(logits)`（T=1），便于与"重执行但换温度"的对手对比。两者都报告。
4. **精确匹配 vs 语义相似**：这里估的是**精确 token 串**的概率。两个语义相同、
   措辞不同的响应仍是两个不同的 `T`，各自的概率都很小。本脚本不估计语义簇的
   质量。

**温度 0 对照**：贪心解码是确定性的，`p_max = 1`、`k = 0`（重执行一次即恢复
`T`）。本脚本同时报告**贪心响应在模型分布下的概率** `exp(logprob_greedy)`，这是
一个比 1 更有信息量的量。

复用 `bench/bench_k_entropy.py` 的 `load_prompts`、`LocalBackend` 与
`wilson_interval`，不改动原脚本。

用法::

    # 云机 GPU（Qwen2.5-7B-Instruct，50 prompt × 20 采样）
    python3 bench/bench_k_logprobs.py \
        --backend local:Qwen/Qwen2.5-7B-Instruct \
        --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl \
        --max-prompts 50 --n-samples 20 --temperature 0.7 \
        --max-tokens 256 --device cuda \
        --out-dir bench/results \
        --samples-out bench/results/k_logprobs_samples.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

LN2 = math.log(2.0)
LN10 = math.log(10.0)


def _load_k_entropy_module():
    """按路径加载 bench/bench_k_entropy.py（bench/ 不是包）。"""
    path = Path(__file__).resolve().parent / "bench_k_entropy.py"
    spec = importlib.util.spec_from_file_location("bench_k_entropy", path)
    if spec is None or spec.loader is None:  # pragma: no cover - 配置错误
        raise SystemExit(f"无法加载 {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_k_entropy = _load_k_entropy_module()
load_prompts = _k_entropy.load_prompts
LocalBackend = _k_entropy.LocalBackend

DEFAULT_PROMPTS = REPO / "scripts" / "examples" / "datasets" / "wave2" / "prompts_xstest.jsonl"


# --------------------------------------------------------------------------- #
# 采样与打分
# --------------------------------------------------------------------------- #

def _prompt_ids(backend: LocalBackend, prompt: str):
    """chat template 单轮 user；返回 prompt 的 token id 列表。"""
    tok = backend.tok
    if backend.chat_template:
        text = tok.apply_chat_template(
            [{"role": "user", "content": prompt}],
            tokenize=False, add_generation_prompt=True)
    else:
        text = prompt
    enc = tok(text, return_tensors="pt")
    return enc["input_ids"][0].tolist()


def _seed_for(seed: int, prompt_id: str, chunk: int) -> int:
    h = hashlib.sha256(f"{seed}|{prompt_id}|{chunk}".encode("utf-8")).digest()
    return int.from_bytes(h[:8], "big") % (2**31 - 1)


def _stop_ids(backend: LocalBackend) -> set:
    """生成侧真正的终止 token（Qwen: <|im_end|>，与 pad 151643 不同）。"""
    ids: set = set()
    gc = getattr(backend.model, "generation_config", None)
    for cand in (getattr(backend.tok, "eos_token_id", None),
                 getattr(gc, "eos_token_id", None)):
        if cand is None:
            continue
        if isinstance(cand, (list, tuple)):
            ids.update(int(x) for x in cand)
        else:
            ids.add(int(cand))
    return ids


def trim_generation_ids(backend: LocalBackend, gids: List[int]) -> List[int]:
    """去掉 batched generate 在 EOS 之后补的 padding token。

    `num_return_sequences` 批生成会把先结束的序列右侧补 `pad_token_id`；若不
    截断，会把 padding 当成响应 token 参与打分（长度虚高、logprob 虚低）。
    保留真正的终止 token（它是"生成到这里并停下"的一部分），去掉其后的 padding。
    """
    stop = _stop_ids(backend)
    pad = getattr(backend.tok, "pad_token_id", None)
    for i, t in enumerate(gids):
        if t in stop:
            return list(gids[:i + 1])
    if pad is not None:
        for i, t in enumerate(gids):
            if t == pad:
                return list(gids[:i])
    return list(gids)


def sample_ids(backend: LocalBackend, prompt: str, n: int, temperature: float,
               max_tokens: int, seed: int, gen_batch: int) -> List[List[int]]:
    """采样 n 条响应，返回**新 token id**（不含 prompt）。分批以控显存。"""
    torch = backend.torch
    pids = _prompt_ids(backend, prompt)
    input_ids = torch.tensor([pids], dtype=torch.long, device=backend.device)
    out: List[List[int]] = []
    remaining = n
    chunk = 0
    while remaining > 0:
        take = min(gen_batch, remaining)
        torch.manual_seed(_seed_for(seed, str(prompt), chunk))
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(_seed_for(seed, str(prompt), chunk))
        gen_kwargs: Dict[str, Any] = {
            "max_new_tokens": max_tokens,
            "pad_token_id": backend.tok.pad_token_id,
            "return_dict_in_generate": True,
        }
        if temperature <= 0:
            gen_kwargs.update(do_sample=False, num_return_sequences=1)
            take = 1
        else:
            gen_kwargs.update(do_sample=True, temperature=temperature,
                              top_p=1.0, num_return_sequences=take)
        with torch.no_grad():
            seqs = backend.model.generate(input_ids, **gen_kwargs).sequences
        prompt_len = len(pids)
        for row in seqs:
            out.append(trim_generation_ids(backend, row[prompt_len:].tolist()))
        remaining -= take
        chunk += 1
    return out


def score_group(backend: LocalBackend, prompt_ids: List[int],
                gen_ids_list: Sequence[List[int]], temperature: float,
                batch_size: int = 8) -> List[Dict[str, Any]]:
    """对一组响应做 teacher-forced forward，求序列与每 token 对数概率。

    只对 **assistant 新 token** 求和（prompt token 不计入）；logits 在位置
    `prompt_len - 1 + j` 预测第 `j` 个新 token。
    """
    torch = backend.torch
    if batch_size < 1:
        batch_size = 1
    results: List[Optional[Dict[str, Any]]] = [None] * len(gen_ids_list)
    gen_ids_list = [trim_generation_ids(backend, g) for g in gen_ids_list]
    order = sorted(range(len(gen_ids_list)), key=lambda i: len(gen_ids_list[i]))
    prompt_len = len(prompt_ids)
    pad_id = backend.tok.pad_token_id

    for start in range(0, len(order), batch_size):
        idxs = order[start:start + batch_size]
        seqs = [prompt_ids + gen_ids_list[i] for i in idxs]
        maxlen = max(len(s) for s in seqs)
        input_ids = torch.full((len(idxs), maxlen), pad_id, dtype=torch.long)
        attn = torch.zeros((len(idxs), maxlen), dtype=torch.long)
        for bi, s in enumerate(seqs):
            input_ids[bi, :len(s)] = torch.tensor(s, dtype=torch.long)
            attn[bi, :len(s)] = 1
        input_ids = input_ids.to(backend.device)
        attn = attn.to(backend.device)
        with torch.no_grad():
            logits = backend.model(input_ids=input_ids, attention_mask=attn).logits
        for bi, i in enumerate(idxs):
            gids = gen_ids_list[i]
            n_tok = len(gids)
            if n_tok == 0:
                results[i] = {
                    "n_tokens": 0, "sum_logprob": 0.0, "sum_logprob_scaled": 0.0,
                    "per_token_mean_logprob": 0.0,
                    "per_token_mean_logprob_scaled": 0.0,
                }
                continue
            sel = logits[bi, prompt_len - 1:prompt_len - 1 + n_tok, :].float()
            tgt = torch.tensor(gids, dtype=torch.long, device=backend.device)
            # log p = logit[target] - logsumexp(logits)
            raw = (sel.gather(1, tgt.unsqueeze(1)).squeeze(1)
                   - torch.logsumexp(sel, dim=-1))
            raw_sum = float(raw.sum().item())
            rec: Dict[str, Any] = {
                "n_tokens": n_tok,
                "sum_logprob": raw_sum,
                "per_token_mean_logprob": raw_sum / n_tok,
            }
            if temperature > 0:
                scaled = (sel / temperature)
                sc = (scaled.gather(1, tgt.unsqueeze(1)).squeeze(1)
                      - torch.logsumexp(scaled, dim=-1))
                sc_sum = float(sc.sum().item())
                rec.update({
                    "sum_logprob_scaled": sc_sum,
                    "per_token_mean_logprob_scaled": sc_sum / n_tok,
                })
            else:
                rec.update({
                    "sum_logprob_scaled": None,
                    "per_token_mean_logprob_scaled": None,
                })
            results[i] = rec
    return [r if r is not None else {} for r in results]


# --------------------------------------------------------------------------- #
# 估计
# --------------------------------------------------------------------------- #

def fmt_sci(log10v: Optional[float]) -> str:
    """把 log10(p) 格式化成 'm.mmeE'，便于人读。"""
    if log10v is None:
        return "n/a"
    if log10v < -320:
        return "<1e-320"
    if log10v >= 0:
        return f"{10.0 ** log10v:.3g}"
    exp = math.floor(log10v)
    mant = 10.0 ** (log10v - exp)
    return f"{mant:.2f}e{exp}"


def qsummary(xs: Sequence[float]) -> Dict[str, float]:
    if not xs:
        return {"n": 0}
    ys = sorted(xs)
    return {
        "n": len(ys),
        "mean": statistics.fmean(ys),
        "median": statistics.median(ys),
        "min": ys[0],
        "max": ys[-1],
    }


def analyze_group(prompt_meta: Dict[str, Any], samples: List[Dict[str, Any]],
                  temperature: float) -> Dict[str, Any]:
    n = len(samples)
    inv_n = 1.0 / n if n else float("inf")

    has_scaled = temperature > 0
    sums = [s["sum_logprob_scaled"] if has_scaled else s["sum_logprob"]
            for s in samples]
    sums = [x for x in sums if x is not None]
    raw_sums = [s["sum_logprob"] for s in samples if s.get("sum_logprob") is not None]

    # 主口径：采样分布 T（温度 0 时按确定性 p_max=1）
    if has_scaled and sums:
        best_sum = max(sums)
        best_idx = sums.index(best_sum)
        p_max_est = math.exp(best_sum) if best_sum > -745.0 else 0.0
        p_max_est_log10 = best_sum / LN10
        k_est = -best_sum / LN2
        mass_n = sum(math.exp(x) if x > -745.0 else 0.0 for x in sums)
    else:
        # 温度 0：贪心确定 ⇒ p_max=1, k=0；序列概率只作为模型分布参考
        best_sum = max(raw_sums) if raw_sums else None
        best_idx = raw_sums.index(best_sum) if best_sum is not None else None
        p_max_est = 1.0
        p_max_est_log10 = 0.0
        k_est = 0.0
        mass_n = 1.0 if raw_sums else 0.0

    # 次口径：模型分布（T=1）
    if raw_sums:
        best_raw = max(raw_sums)
        p_max_raw = math.exp(best_raw) if best_raw > -745.0 else 0.0
        p_max_raw_log10 = best_raw / LN10
        k_raw = -best_raw / LN2
    else:
        p_max_raw = 0.0
        p_max_raw_log10 = None
        k_raw = float("inf")

    # 经验（精确字符串）口径，按 E1 的同一批样本直接对照
    texts = [s.get("response", "").strip() for s in samples]
    counts = Counter(texts)
    mode_count = counts.most_common(1)[0][1] if counts else 0
    empirical_p = mode_count / n if n else 0.0
    empirical_k = 0.0 if empirical_p >= 1.0 else (
        -math.log2(empirical_p) if empirical_p > 0 else float("inf"))

    lm = [s["per_token_mean_logprob_scaled"] if has_scaled
          else s["per_token_mean_logprob"] for s in samples]
    lm = [x for x in lm if x is not None]

    exceeds = p_max_est > inv_n * (1.0 + 1e-12)
    below = p_max_est < inv_n * (1.0 - 1e-12)
    ratio = (p_max_est / inv_n) if inv_n > 0 else float("inf")

    return {
        "prompt_id": prompt_meta.get("prompt_id"),
        "temperature": temperature,
        "prompt": prompt_meta.get("prompt"),
        "label": prompt_meta.get("label"),
        "type": prompt_meta.get("type"),
        "n": n,
        "inv_n": inv_n,
        # 主口径：采样分布
        "p_max_est": p_max_est,
        "p_max_est_log10": p_max_est_log10,
        "p_max_est_str": fmt_sci(p_max_est_log10),
        "k_est_bits": k_est,
        "p_max_est_over_inv_n": ratio,
        "exceeds_inv_n": exceeds,
        "below_inv_n": below,
        "best_sample_index": best_idx,
        "mass_n": mass_n,
        # 次口径：模型分布 T=1
        "p_max_est_raw": p_max_raw,
        "p_max_est_raw_log10": p_max_raw_log10,
        "p_max_est_raw_str": fmt_sci(p_max_raw_log10),
        "k_est_raw_bits": k_raw,
        # 长度混淆：每 token 平均对数概率
        "logprob_per_token": qsummary(lm),
        # 序列对数概率分布
        "sequence_logprob": qsummary(sums),
        "sequence_logprob_raw": qsummary(raw_sums),
        # 精确字符串口径（E1）
        "empirical": {
            "mode_count": mode_count,
            "p_max": empirical_p,
            "k_bits": empirical_k,
            "distinct": len(counts),
            "at_n_cap": abs(empirical_p - inv_n) <= 1e-12 and len(counts) == n,
        },
        # 逐样本对数概率分布（不含 response / gen_ids，原始串在 samples 文件里）
        "samples": [{
            "sample_index": s.get("sample_index"),
            "n_tokens": s.get("n_tokens"),
            "chars": s.get("chars"),
            "sum_logprob": s.get("sum_logprob"),
            "sum_logprob_scaled": s.get("sum_logprob_scaled"),
            "per_token_mean_logprob": s.get("per_token_mean_logprob"),
            "per_token_mean_logprob_scaled": s.get("per_token_mean_logprob_scaled"),
        } for s in samples],
    }


def aggregate(groups: List[Dict[str, Any]], threshold_bits: float) -> Dict[str, Any]:
    if not groups:
        return {"n_groups": 0}
    log10s = [g["p_max_est_log10"] for g in groups if g["p_max_est_log10"] is not None]
    ks = [g["k_est_bits"] for g in groups]
    per_tok = [g["logprob_per_token"]["median"] for g in groups
               if g["logprob_per_token"].get("n")]
    raw_log10 = [g["p_max_est_raw_log10"] for g in groups
                 if g["p_max_est_raw_log10"] is not None]
    emp = [g["empirical"]["p_max"] for g in groups]
    return {
        "n_groups": len(groups),
        "p_max_est_log10": qsummary(log10s),
        "p_max_est_median_str": fmt_sci(statistics.median(log10s)) if log10s else "n/a",
        "k_est_bits": qsummary(ks),
        "logprob_per_token_median": qsummary(per_tok),
        "p_max_est_raw_log10": qsummary(raw_log10),
        "empirical_p_max": qsummary(emp),
        "n_exceeds_inv_n": sum(1 for g in groups if g["exceeds_inv_n"]),
        "n_below_inv_n": sum(1 for g in groups if g["below_inv_n"]),
        "n_equal_inv_n": sum(1 for g in groups
                             if not g["exceeds_inv_n"] and not g["below_inv_n"]),
        "frac_exceeds_inv_n": sum(1 for g in groups if g["exceeds_inv_n"]) / len(groups),
        "frac_below_inv_n": sum(1 for g in groups if g["below_inv_n"]) / len(groups),
        "frac_empirical_at_n_cap": sum(1 for g in groups
                                       if g["empirical"]["at_n_cap"]) / len(groups),
        "n_k_below_threshold": sum(1 for k in ks if k < threshold_bits),
        "frac_k_below_threshold": sum(1 for k in ks if k < threshold_bits) / len(ks),
        "threshold_bits": threshold_bits,
    }


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #

def run(args: argparse.Namespace) -> Dict[str, Any]:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    samples_path = Path(args.samples_out) if args.samples_out else (
        out_dir / "k_logprobs_samples.jsonl")
    samples_path.parent.mkdir(parents=True, exist_ok=True)

    if getattr(args, "analyze_only", False):
        return analyze_and_write(args, samples_path, out_dir)

    if not args.backend.startswith("local:"):
        raise SystemExit("E6 需要 teacher-forced forward，只支持 --backend local:<model>")
    prompts = load_prompts(args.prompts, args.max_prompts, stratify=not args.no_stratify)
    backend = LocalBackend(args.backend.split(":", 1)[1], device=args.device,
                           load_in_4bit=args.load_in_4bit,
                           chat_template=True)
    temperature = float(args.temperature)

    # 续跑：按 (prompt_id, temperature, sample_index) 去重
    existing: Dict[Tuple[str, float, int], Dict[str, Any]] = {}
    if args.resume and samples_path.exists():
        with samples_path.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                    existing[(str(r["prompt_id"]), float(r["temperature"]),
                              int(r["sample_index"]))] = r
                except Exception:  # noqa: BLE001 - 坏行跳过
                    continue
        print(f"续跑：{len(existing)} 条已有样本", flush=True)

    new_records: List[Dict[str, Any]] = []
    t0 = time.time()
    total_new = 0
    temp_tag = temperature
    for p_i, p in enumerate(prompts):
        pid = str(p.get("id", p_i))
        prompt = p.get("prompt", "")
        label = p.get("label")
        # 温度 0.7 的 N 条
        have = sorted(si for (qid, t, si) in existing
                      if qid == pid and abs(t - temp_tag) < 1e-9)
        if (len(have) >= args.n_samples
                and all((pid, temp_tag, si) in existing
                        for si in range(args.n_samples))):
            gen = [existing[(pid, temp_tag, si)]["gen_ids"] for si in range(args.n_samples)]
            print(f"[{p_i+1}/{len(prompts)}] prompt {pid}: 续跑命中 {len(gen)}", flush=True)
        else:
            gen = sample_ids(backend, prompt, args.n_samples, temperature,
                             args.max_tokens, args.seed, args.gen_batch)
        # 旧记录可能带 batched generate 的 padding；统一截断后再打分/落盘。
        gen = [trim_generation_ids(backend, g) for g in gen]
        scores = score_group(backend, _prompt_ids(backend, prompt), gen,
                             temperature, batch_size=args.score_batch)
        for si, (gids, sc) in enumerate(zip(gen, scores)):
            if si in have:
                continue
            rec = {
                "prompt_id": pid, "prompt": prompt, "label": label,
                "type": p.get("type"),
                "temperature": temp_tag, "sample_index": si,
                "gen_ids": gids,
                "response": backend.tok.decode(gids, skip_special_tokens=True),
                "chars": len(backend.tok.decode(gids, skip_special_tokens=True)),
                "model": backend.name,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            rec.update(sc)
            new_records.append(rec)
            total_new += 1
        print(f"[{p_i+1}/{len(prompts)}] prompt {pid}: {len(gen)} samples, "
              f"{time.time()-t0:.0f}s", flush=True)

        # 贪心对照（每个 prompt 一条）
        if args.greedy:
            key = (pid, 0.0, 0)
            if key not in existing:
                g_gids = sample_ids(backend, prompt, 1, 0.0, args.max_tokens,
                                    args.seed, 1)[0]
                g_sc = score_group(backend, _prompt_ids(backend, prompt), [g_gids],
                                   0.0, batch_size=1)[0]
                rec = {
                    "prompt_id": pid, "prompt": prompt, "label": label,
                    "type": p.get("type"), "temperature": 0.0, "sample_index": 0,
                    "gen_ids": g_gids,
                    "response": backend.tok.decode(g_gids, skip_special_tokens=True),
                    "chars": len(backend.tok.decode(g_gids, skip_special_tokens=True)),
                    "model": backend.name,
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
                rec.update(g_sc)
                new_records.append(rec)
                total_new += 1

    # 落盘（追加；重算时按 key 去重，后写覆盖先写）
    with samples_path.open("a", encoding="utf-8") as fh:
        for rec in new_records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"新增 {total_new} 条样本 → {samples_path}", flush=True)

    return analyze_and_write(args, samples_path, out_dir, n_prompts=len(prompts),
                             model_name=backend.name)


def analyze_and_write(args: argparse.Namespace, samples_path: Path,
                      out_dir: Path, n_prompts: Optional[int] = None,
                      model_name: Optional[str] = None) -> Dict[str, Any]:
    """从 samples JSONL 重算聚合与视图（不加载模型、不重新采样）。

    这也是 ``--analyze-only`` 的实现：改渲染文本时只需重跑这一层，
    数字完全来自样本文件，不需要 GPU。
    """
    if not samples_path.exists():
        raise SystemExit(f"--analyze-only 需要样本文件：{samples_path}")
    temperature = float(args.temperature)

    # 从磁盘重算（续跑 + 新样本统一）
    by_group: Dict[Tuple[str, float], Dict[int, Dict[str, Any]]] = defaultdict(dict)
    meta: Dict[Tuple[str, float], Dict[str, Any]] = {}
    models: Counter = Counter()
    prompt_ids: set = set()
    with samples_path.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            pid = str(r["prompt_id"])
            t = float(r["temperature"])
            by_group[(pid, t)][int(r["sample_index"])] = r
            meta[(pid, t)] = {"prompt_id": pid, "prompt": r.get("prompt"),
                              "label": r.get("label"), "type": r.get("type")}
            models[str(r.get("model") or "unknown")] += 1
            prompt_ids.add(pid)

    groups: List[Dict[str, Any]] = []
    for (pid, t), idx_map in sorted(by_group.items(),
                                    key=lambda kv: (kv[0][1], kv[0][0])):
        samples = [idx_map[i] for i in sorted(idx_map)]
        groups.append(analyze_group(meta[(pid, t)], samples, t))
    main_groups = [g for g in groups
                   if g["temperature"] > 0 and g["n"] and g["n"] >= args.n_samples]
    greedy_groups = [g for g in groups if g["temperature"] <= 0]

    if n_prompts is None:
        n_prompts = len(prompt_ids)
    if model_name is None:
        model_name = models.most_common(1)[0][0] if models else "unknown"

    threshold = math.log2(args.q) + math.log2(1.0 / args.eps)
    result = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "experiment": "E6",
        "backend": args.backend,
        "model": model_name,
        "prompts_file": str(args.prompts),
        "n_prompts": n_prompts,
        "n_samples_per_prompt": args.n_samples,
        "temperature": temperature,
        "max_tokens": args.max_tokens,
        "chat_template": True,
        "seed": args.seed,
        "q": args.q,
        "eps": args.eps,
        "threshold_bits": threshold,
        "samples_file": str(samples_path),
        "token_summation": "assistant new tokens only (chat template); "
                           "prompt tokens excluded",
        "logprob_convention": {
            "primary": "sum of log softmax(logits / T) over generated tokens "
                       "(sampling distribution at temperature T, top_p=1.0)",
            "secondary": "sum of log softmax(logits) over generated tokens "
                         "(model distribution, T=1)",
            "greedy": "p_max=1 by construction; the model-distribution "
                      "probability of the greedy response is also reported",
        },
        "estimator_bias": [
            "p_max_est = max over N sampled sequences of exp(logprob) is a "
            "LOWER bound on the true mode probability (the mode may not be "
            "sampled).",
            "k_est = -log2(p_max_est) is therefore an UPPER bound on the true k.",
            "E1's empirical k = log2(N) when all samples are unique is a "
            "sampling-resolution cap, NOT a lower bound on the true k; the only "
            "strict one-sided statement is k_true <= k_est.",
            "Sequence logprob sums over tokens and shrinks with length; compare "
            "per-token mean logprob across prompts, not raw sums.",
            "This estimates the probability of the EXACT token string, not of a "
            "semantic cluster.",
        ],
        "groups": groups,
        "aggregate": {
            "temperature_gt0": aggregate(main_groups, threshold),
            "greedy_temperature_0": aggregate(greedy_groups, threshold),
        },
        "notes": [
            "Temperature-0 greedy responses are deterministic: p_max=1, k=0; the "
            "model-distribution logprob of the greedy response is reported "
            "separately.",
            "p_max_est < 1/N is expected for exact-sequence probabilities and is "
            "the point: logprobs can measure below the empirical 1/N floor.",
            "p_max_est > 1/N only happens for near-deterministic, short outputs.",
        ],
    }
    (out_dir / "k_logprobs.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out_dir / "k_logprobs.md").write_text(render_md(result), encoding="utf-8")
    return result


def render_md(r: Dict[str, Any]) -> str:
    a = r["aggregate"]["temperature_gt0"]
    ag = r["aggregate"]["greedy_temperature_0"]
    lines = [
        "# 用序列对数概率估计猜测熵 `k`（E6）",
        "",
        f"**生成时间**：{r['generated_at']}  ",
        f"**backend**：`{r['backend']}` → `{r['model']}`  ",
        f"**prompts**：`{r['prompts_file']}`（{r['n_prompts']} 条）  ",
        f"**每 prompt 采样**：{r['n_samples_per_prompt']}  **温度**：{r['temperature']}  ",
        f"**chat template**：开启（单轮 user，只对新 token 求和）  ",
        f"**阈值**：`k >= log2(q)+log2(1/eps)` = **{r['threshold_bits']:.1f} bit** "
        f"(q={r['q']}, eps={r['eps']})",
        "",
        "## 一句话结论",
        "",
    ]
    if a.get("n_groups"):
        lines += [
            f"- 温度 {r['temperature']} 下 {a['n_groups']} 组：`p_max_est` 中位数 "
            f"**{a['p_max_est_median_str']}**，`k_est` 中位数 "
            f"**{a['k_est_bits']['median']:.1f} bit**。",
            f"- `p_max_est > 1/N` 的组：**{a['n_exceeds_inv_n']}/{a['n_groups']}**；"
            f"`p_max_est < 1/N` 的组：**{a['n_below_inv_n']}/{a['n_groups']}**；"
            f"恰好 `=1/N` 的组：**{a['n_equal_inv_n']}/{a['n_groups']}**。",
            f"- 同一批样本的经验（精确字符串）口径：`{a['frac_empirical_at_n_cap']:.0%}` "
            f"的组撞 `1/N` 上限。",
            "- 精确序列概率通常**远低于** `1/N`，因此 `k_est` 远高于 `log2(N)`："
            "logprobs 确实**突破了 E1 的 N 截断**，但方向是给出 `k` 的**上界**"
            "（见下节偏差说明）。",
            "",
        ]
    else:
        lines += ["- 没有可用的温度 > 0 分组。", ""]
    lines += [
        "## 按温度汇总",
        "",
        "| 口径 | 组数 | p_max_est 中位数 | k_est median | k_est min | k_est max | "
        ">1/N 组数 | <1/N 组数 | 经验撞上限比例 | k<阈值 比例 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, s in [("温度 >0（采样分布）", a), ("温度 0（贪心）", ag)]:
        if not s.get("n_groups"):
            continue
        if name.startswith("温度 0"):
            cap = "-"
            n_exc = n_bel = "-"
        else:
            cap = f"{s['frac_empirical_at_n_cap']:.2f}"
            n_exc = str(s["n_exceeds_inv_n"])
            n_bel = str(s["n_below_inv_n"])
        lines.append(
            f"| {name} | {s['n_groups']} | {s['p_max_est_median_str']} | "
            f"{s['k_est_bits']['median']:.2f} | {s['k_est_bits']['min']:.2f} | "
            f"{s['k_est_bits']['max']:.2f} | {n_exc} | {n_bel} | {cap} | "
            f"{s['frac_k_below_threshold']:.2f} |")
    lines += [
        "",
        "## 逐 prompt（温度 > 0）",
        "",
        "| prompt_id | label | N | 经验 p_max | 经验 k | p_max_est | log10 p_max_est | "
        "1/N | p_max_est/(1/N) | k_est (bit) | 每 token 平均 logp (median) | 平均字符数 |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    main_groups = [g for g in r["groups"]
                   if g["temperature"] > 0
                   and g["n"] and g["n"] >= r["n_samples_per_prompt"]]
    for g in main_groups:
        chars = statistics.fmean([s.get("chars", 0) for s in g["samples"]]) \
            if g["samples"] else 0.0
        lines.append(
            f"| {g['prompt_id']} | {g.get('label') or ''} | {g['n']} | "
            f"{g['empirical']['p_max']:.3f} | {g['empirical']['k_bits']:.2f} | "
            f"{g['p_max_est_str']} | {g['p_max_est_log10']:.1f} | "
            f"{g['inv_n']:.4f} | {g['p_max_est_over_inv_n']:.2e} | "
            f"{g['k_est_bits']:.1f} | "
            f"{g['logprob_per_token'].get('median', float('nan')):.3f} | {chars:.0f} |")
    lines += [
        "",
        "## 贪心（温度 0）对照",
        "",
        "| prompt_id | p_max (解码) | k (bit) | 贪心响应的模型概率 exp(logp) | "
        "每 token 平均 logp | 字符数 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    greedy_groups = [g for g in r["groups"] if g["temperature"] <= 0]
    for g in greedy_groups[:50]:
        s0 = g["samples"][0] if g["samples"] else {}
        lines.append(
            f"| {g['prompt_id']} | 1.000 | 0.00 | "
            f"{fmt_sci(g['p_max_est_raw_log10'])} | "
            f"{s0.get('per_token_mean_logprob', float('nan')):.3f} | "
            f"{s0.get('chars', 0)} |")
    lines += [
        "",
        "## 估计器偏差与口径（必读）",
        "",
        "1. **`p_max_est` 是众数概率的下界，`k_est` 是真实 `k` 的严格上界**："
        "`max` 只取已采样的 `N` 条，真实众数可能没被采到，所以 "
        "`p_max_est <= p_max_true`、`k_est >= k_true`，即 `k_true <= k_est`。"
        "E1 的经验 `k=log2(N)`（全唯一时）只是**采样分辨率上限**，不是"
        "`k_true` 的下界。",
        "2. **长度混淆**：序列 `logprob` 是逐 token 求和，长响应天然更小。"
        "跨 prompt 比较请看**每 token 平均 logprob**，不要直接比 `p_max_est`。",
        "3. **温度缩放口径**：主口径 `softmax(logits/T)`，与 "
        "`do_sample=True, temperature=T, top_p=1.0` 的实际采样分布一致；"
        "次口径 `softmax(logits)`（T=1）见 JSON 的 `p_max_est_raw`。"
        "温度 0 是确定性解码，`p_max=1`、`k=0`，另报贪心响应的模型概率。",
        "4. **精确匹配 vs 语义**：这里估的是精确 token 串的概率；语义相同、"
        "措辞不同的响应是两个不同的 `T`，各自概率都极小。本脚本不估计语义簇。",
        "5. **`p_max_est` 可能下溢**：`logprob` 很负时 `exp()` 在 float64 下会变 0；"
        "JSON 同时给 `p_max_est_log10`，以它为准。",
        "",
        "## 判据",
        "",
        "- **`p_max_est > 1/N`**：只有当响应接近确定（短、高度模板化）时才会出现；"
        "这说明 logprobs 给出了比经验计数**更强**的众数信号。",
        "- **`p_max_est < 1/N`**（本实验的常态）：精确序列概率本来就远小于 `1/N`，"
        "`k_est` 远大于 `log2(N)`。这不是负结果，而是**突破了 E1 的可观测上限**："
        "经验计数只能说 `k >= log2(N)`，logprobs 给出 `k <= k_est`，把区间收窄。",
        "",
        "## 复现",
        "",
        "```bash",
        f"python3 bench/bench_k_logprobs.py --backend {r['backend']} "
        f"--prompts {r['prompts_file']} --max-prompts {r['n_prompts']} "
        f"--n-samples {r['n_samples_per_prompt']} --temperature {r['temperature']} "
        f"--max-tokens {r['max_tokens']} --out-dir bench/results "
        f"--samples-out {r['samples_file']} --device cuda",
        "```",
        "",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--prompts", type=Path, default=DEFAULT_PROMPTS)
    ap.add_argument("--out-dir", default=str(REPO / "bench" / "results"))
    ap.add_argument("--samples-out", default=None,
                    help="原始样本 JSONL；默认 <out-dir>/k_logprobs_samples.jsonl")
    ap.add_argument("--backend", default="local:Qwen/Qwen2.5-7B-Instruct")
    ap.add_argument("--max-prompts", type=int, default=50)
    ap.add_argument("--n-samples", type=int, default=20)
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--max-tokens", type=int, default=256)
    ap.add_argument("--seed", type=int, default=20261101)
    ap.add_argument("--q", type=int, default=1 << 20)
    ap.add_argument("--eps", type=float, default=2.0 ** -20)
    ap.add_argument("--device", default="auto", choices=["auto", "cuda", "cpu"])
    ap.add_argument("--load-in-4bit", action="store_true")
    ap.add_argument("--gen-batch", type=int, default=10,
                    help="每次 generate 的并行采样数（控显存）")
    ap.add_argument("--score-batch", type=int, default=8,
                    help="teacher-forced forward 的批大小")
    ap.add_argument("--no-stratify", action="store_true",
                    help="默认按 safe/unsafe 分层取前 max-prompts 条")
    ap.add_argument("--no-greedy", action="store_true",
                    help="跳过每个 prompt 的温度 0 贪心对照")
    ap.add_argument("--resume", action="store_true",
                    help="跳过 (prompt_id, temperature, sample_index) 已存在的样本")
    ap.add_argument("--analyze-only", action="store_true",
                    help="不加载模型/不采样，只从 --samples-out 重算 JSON/MD"
                         "（改渲染文本时用）")
    args = ap.parse_args()
    args.greedy = not args.no_greedy
    result = run(args)
    a = result["aggregate"]["temperature_gt0"]
    if a.get("n_groups"):
        print(f"temp={result['temperature']}: median k_est="
              f"{a['k_est_bits']['median']:.1f} bit, "
              f"p_max_est median={a['p_max_est_median_str']}, "
              f"exceeds 1/N: {a['n_exceeds_inv_n']}/{a['n_groups']}")
    print(f"wrote {Path(args.out_dir) / 'k_logprobs.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
