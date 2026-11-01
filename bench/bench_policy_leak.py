#!/usr/bin/env python3
"""策略枚举攻击基准（BHV 定理 A 策略侧 / 实验 E4a）。

**要证明什么。**
旧实现 ``policy_hash = SHA256(canonical(π))`` 是公开、可离线重算的 ``π`` 的函数；
策略空间小到一个结构化的攻击者可以**枚举候选策略并匹配哈希**。这与响应侧的
``response_binding`` 是同一个数学对象。本脚本构造一个可复现的枚举攻击：

1. 以 ``policy_packs/agent_content_v1.json`` 为模板，生成 N 个只差一个关键词的
   候选策略；
2. 选其中一个作为目标，计算它的 ``policy_hash``；
3. **无盐**：枚举全部候选、逐个编译、比对哈希 —— 应当恢复出目标；
4. **有盐**：给目标加 128-bit ``policy_nonce``，攻击者枚举同样的候选（但不知道盐）
   —— 应当恢复失败；
5. **盐泄露**：把盐给攻击者，再枚举 —— 应当恢复成功（说明盐是唯一的屏障）。

**不证明什么。** 本脚本量的是**公开值通道**；SP1 ``core`` 的证明工件仍可能泄露
``π``（见 ``docs/sp1-zk-audit.md``），那需要 ``groth16/plonk``。规则名 /
``delegated`` 的泄露由 E4b 的披露层级实验处理。

用法::

    python3 bench/bench_policy_leak.py --out-dir bench/results
    python3 bench/bench_policy_leak.py --variants 20000 --out-dir bench/results
"""

from __future__ import annotations

import argparse
import copy
import json
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl.core.compile import compile_policy          # noqa: E402
from policydsl.core.model import Policy                    # noqa: E402
from policydsl.privacy.policy_commit import (              # noqa: E402
    POLICY_NONCE_BYTES, attach_nonce, new_policy_nonce, policy_commitment)

DEFAULT_PACK = REPO / "policy_packs" / "agent_content_v1.json"


def load_pack(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def make_candidates(base: Dict[str, Any], n: int, seed: int) -> List[Dict[str, Any]]:
    """生成 N 个只差一个关键词的候选策略（结构化枚举空间）。"""
    rng = random.Random(seed)
    words = [f"w{rng.randrange(10**9):09d}" for _ in range(n)]
    out: List[Dict[str, Any]] = []
    for w in words:
        pack = copy.deepcopy(base)
        # 找到第一条 keyword_block；没有就退化为「加一条关键词规则」。
        hit = False
        for rule in pack.get("rules", []):
            if rule.get("kind") == "keyword_block":
                rule.setdefault("params", {})["keywords"] = [w, "doxxing", "weaponize"]
                hit = True
                break
        if not hit:
            pack.setdefault("rules", []).append({
                "kind": "keyword_block", "name": "no_bad_topics",
                "params": {"keywords": [w]},
            })
        out.append(pack)
    return out


def _compile_hash(pack: Dict[str, Any]) -> str:
    policy = Policy.from_dict(pack)
    policy.validate()
    return compile_policy(policy)["sha256"]


def enumerate_attack(candidates: List[Dict[str, Any]], target_hash: str,
                     nonce: str | None = None) -> Tuple[bool, int, float]:
    """枚举候选、逐个编译、比对哈希。返回 (是否恢复, 匹配下标, 耗时 ms)。

    ``nonce`` 非空时，给每个候选附加同一个盐（模拟「攻击者知道盐」的对照臂）。
    """
    t0 = time.perf_counter()
    for i, pack in enumerate(candidates):
        p = copy.deepcopy(pack)
        if nonce is not None:
            p["policy_nonce"] = nonce
        if _compile_hash(p) == target_hash:
            return True, i, (time.perf_counter() - t0) * 1000.0
    return False, -1, (time.perf_counter() - t0) * 1000.0


def run(out_dir: Path, n_variants: int, seed: int, base_path: Path) -> Dict[str, Any]:
    base = load_pack(base_path)
    candidates = make_candidates(base, n_variants, seed)
    target_index = n_variants // 2
    target_plain = candidates[target_index]
    target_hash = _compile_hash(target_plain)

    # 1) 无盐：攻击者枚举同一空间。
    rec_plain, idx_plain, ms_plain = enumerate_attack(candidates, target_hash)

    # 2) 有盐：目标带 128-bit 盐；攻击者枚举同样的候选（不带盐 / 带错盐）。
    nonce = new_policy_nonce()
    target_salted = attach_nonce(target_plain, nonce)
    salted_hash = policy_commitment(target_salted)
    wrong_nonce = "00" * POLICY_NONCE_BYTES
    rec_salted, idx_salted, ms_salted = enumerate_attack(
        candidates, salted_hash, nonce=wrong_nonce)

    # 3) 盐泄露对照：攻击者拿到正确的盐 —— 应当恢复。
    rec_leaked, idx_leaked, ms_leaked = enumerate_attack(
        candidates, salted_hash, nonce=nonce)

    result = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "base_pack": str(base_path.relative_to(REPO)),
        "seed": seed,
        "variants": n_variants,
        "target_index": target_index,
        "target_hash": target_hash,
        "unsalted": {
            "recovered": rec_plain,
            "matched_index": idx_plain,
            "elapsed_ms": round(ms_plain, 3),
        },
        "salted": {
            "nonce_bits": POLICY_NONCE_BYTES * 8,
            "recovered": rec_salted,
            "matched_index": idx_salted,
            "elapsed_ms": round(ms_salted, 3),
            "guess_probability_upper_bound": n_variants / float(1 << (POLICY_NONCE_BYTES * 8)),
        },
        "salt_leaked": {
            "recovered": rec_leaked,
            "matched_index": idx_leaked,
            "elapsed_ms": round(ms_leaked, 3),
        },
        "notes": [
            "Salted arm enumerates the same policy space with a wrong nonce; "
            "it models an attacker who does not know the authority-held salt.",
            "salt_leaked models voluntary disclosure / salt compromise, not a "
            "cryptographic break.",
            "This measures the public-value channel only. SP1 core proof artifacts "
            "may still leak the witness; that needs groth16/plonk.",
        ],
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "policy_leak.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out_dir / "policy_leak.md").write_text(render_md(result), encoding="utf-8")
    return result


def render_md(r: Dict[str, Any]) -> str:
    return f"""# 策略枚举攻击基准（BHV 定理 A 策略侧 / E4a）

**生成时间**：{r['generated_at']}
**模板**：`{r['base_pack']}` ｜ **种子**：{r['seed']} ｜ **候选数**：{r['variants']}

## 结果

| 场景 | 恢复目标？ | 匹配下标 | 耗时 (ms) |
|---|---:|---:|---:|
| 无盐 `policy_hash = SHA256(canonical(π))` | **{r['unsalted']['recovered']}** | {r['unsalted']['matched_index']} | {r['unsalted']['elapsed_ms']} |
| 有盐（攻击者不知道盐，用错盐枚举） | **{r['salted']['recovered']}** | {r['salted']['matched_index']} | {r['salted']['elapsed_ms']} |
| 有盐 + 盐泄露（对照组） | **{r['salt_leaked']['recovered']}** | {r['salt_leaked']['matched_index']} | {r['salt_leaked']['elapsed_ms']} |

盐长度：**{r['salted']['nonce_bits']} bit**；攻击者猜中盐的朴素上界：
`{r['salted']['guess_probability_upper_bound']:.3e}`。

## 怎么读

- **无盐**一行是本文的“当前实现漏策略”证据：候选空间是结构化枚举（只差一个
  关键词），攻击者不需要遍历字符串空间，只需要遍历**策略空间**。
- **有盐**一行是定理 D 的最小落地：盐不进证书载荷，攻击者枚举同一策略空间
  仍匹配不上；恢复失败。
- **盐泄露**一行是对照：盐一旦泄露（自愿披露 / 权威被攻破），枚举立刻恢复。
  这说明盐是**唯一**的屏障，不要把有盐承诺说成“策略隐私已解决”。
- 本脚本只测**公开值通道**；SP1 `core` 的证明工件仍可能泄露见证（`docs/sp1-zk-audit.md`），
  规则名 / `delegated` 的泄露由 E4b 的披露层级实验处理。

## 复现

```bash
python3 bench/bench_policy_leak.py --out-dir bench/results
```
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", default=str(REPO / "bench" / "results"))
    ap.add_argument("--variants", type=int, default=2000,
                    help="候选策略数（默认 2000；--full 可用 20000）")
    ap.add_argument("--seed", type=int, default=20261101)
    ap.add_argument("--base-pack", default=str(DEFAULT_PACK))
    args = ap.parse_args()

    result = run(Path(args.out_dir), args.variants, args.seed, Path(args.base_pack))
    print(f"unsalted recovered: {result['unsalted']['recovered']} "
          f"(index {result['unsalted']['matched_index']})")
    print(f"salted   recovered: {result['salted']['recovered']} "
          f"(nonce {result['salted']['nonce_bits']} bit)")
    print(f"salt leaked recovered: {result['salt_leaked']['recovered']}")
    print(f"wrote {Path(args.out_dir) / 'policy_leak.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
