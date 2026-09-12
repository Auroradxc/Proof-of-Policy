#!/usr/bin/env python3
"""Proof-of-Policy 的 cycle 数矩阵（只跑 zkVM 执行、不生成证明）+ 成本模型拟合。

扫描「响应长度 × 规则条数 × 匹配模式」的组合，用 ``pop-script --execute``
记录 zkVM 的 cycle 数。因为省掉了证明生成所以很快，能铺很多采样点；真正（慢
几个数量级）的证明耗时/体积曲线在 ``bench_proofs.py`` 里。

长度默认铺到 **100k 字符**（P2-12 的「真实规模」采样点：越长越接近真实长回复/
多轮拼接的会话文本），并顺手拟合两条成本模型：

* **按规则类拆开**（本文用的）：``cycles ≈ b + |T| · (a_kw·n_kw + a_pat·n_pat)`` ——
  关键词子串扫描与 NFA 扫描的每字符单价本来就不同，混成一个系数是**记账**不是**模型**；
* **计划里的简式**：``cycles ≈ b + a·|T|·rules`` —— 一并报出来，连同它的残差，
  好让「简式够不够用」这件事由数据回答，而不是由我们口头断言。

拟合用纯 Python 的最小二乘（法方程 + 高斯消元），不引入 numpy —— 这个脚本
只依赖标准库与 ``policydsl``，好在任何装得动 Rust 二进制的机器上直接跑。

**语料（P2-12）**：默认 ``--corpus demo`` —— 把仓库里**真跑出来的**工件
（``scripts/examples/out/**`` 的 ``response`` 字段）与示例回复汇总去重后当扫描对象，
替掉以前那串纯合成的 ``the quick brown fox jumps``。命中规则的段落**剔除并记录**
（真实轨迹里本来就有违规的：示例里那个 ``sk-…`` 凭据就会命中 ``pattern_block``），
因为本基准量的是**扫到底**的最坏情况成本，命中即短路会让数字偏低。

结果写到 ``bench/results/cycles.json``，同时在同目录生成一份 .md 表格便于贴文档。

用法：
  python3 bench/bench_cycles.py [--out bench/results/cycles.json]
  python3 bench/bench_cycles.py --lengths 100000 --rules 6        # 只补一个点
  python3 bench/bench_cycles.py --corpus synthetic                # 旧合成串，与旧表逐点对照
  python3 bench/bench_cycles.py --corpus ~/session-transcript.txt  # 自备真实语料
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, NamedTuple

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from policydsl import evaluate, pii  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402
from policydsl.serialize import spec_canonical_text  # noqa: E402

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"
WORK = REPO / "bench" / "work"

EMAIL = pii.PII_PATTERNS["email"]

#: 默认采样长度：200 → 100k（P2-12 把上界从 20k 推到 100k）
DEFAULT_LENGTHS = [200, 2_000, 10_000, 20_000, 50_000, 100_000]
#: 规则条数的采样点。**刻意不是 `[1, 3, 6]`**：那三个点对应的
#: `(n_kw, n_pat)` 是 `(0,0) / (1,1) / (3,2)`，两个解释变量近似成比例 ——
#: 拟合出来的单价会一正一负（实测 `a_kw = -2.7k`，一个物理上不成立的数）。
#: `[1, 2, 3, 4, 6]` 给出 `(0,0) / (1,0) / (1,1) / (2,1) / (3,2)`，
#: 把两类规则的单价解耦开。这是**采样设计**问题，加长度救不了。
DEFAULT_RULE_COUNTS = [1, 2, 3, 4, 6]

#: 每条规则归到哪一类（成本模型的解释变量）。`make_policy` 按 extras 的顺序
#: 取前 rc-1 条，所以「第几条是关键词、第几条是正则」是由构造决定的、可复算的。
EXTRA_KINDS = ["keyword", "pattern", "keyword", "pattern", "keyword"]


def make_policy(rule_count: int, mode: str = "pike") -> Policy:
    """构造 1 条 length_bound + (rule_count-1) 条额外约束（keyword/pattern）。

    固定第一条长度规则，是为了让不同规则数之间只差「扫描量」，便于横向比较；
    ``mode`` 只作用于 pattern_block，用来对比 pike(线性) 与 naive(O(n^2)) 两种匹配。
    """
    rules = [Rule("length_bound", "len", {"min": 1, "max": 10_000_000})]
    extras = [
        Rule("keyword_block", "kw", {"keywords": ["exploit", "weaponize", "doxxing"]}),
        Rule("pattern_block", "pat", {"patterns": [EMAIL], "match_mode": mode}),
        Rule("keyword_block", "kw2", {"keywords": ["terrorism", "child abuse"]}),
        Rule("pattern_block", "pat2", {"patterns": [pii.PII_PATTERNS["secret_key"]], "match_mode": mode}),
        Rule("keyword_block", "kw3", {"keywords": ["leverage"]}),
    ]
    rules.extend(extras[: max(0, rule_count - 1)])
    return Policy("bench", "1", rules=rules)


def kind_counts(rule_count: int) -> tuple[int, int]:
    """``rule_count`` 条规则里各有几条 keyword / pattern（长度规则不计）。

    与 :func:`make_policy` 同源：多出一条新规则时这里会跟着错，所以两者都从
    ``EXTRA_KINDS`` 派生。
    """
    kinds = EXTRA_KINDS[: max(0, rule_count - 1)]
    return kinds.count("keyword"), kinds.count("pattern")


def response(prefix: str, length: int) -> str:
    """生成一个恰好 ``length`` 字符、且不含任何命中词的干净响应文本。

    纯干净（no hits）很重要：只有全部约束都被完整扫描到底，cycle 数才反映
    「最坏情况」的扫描成本，而不是命中即停的短路成本。
    """
    body = (prefix + " ") * ((length // (len(prefix) + 1)) + 1)
    return body[:length]


SYNTHETIC = "the quick brown fox jumps"
#: P2-12：真实轨迹的取处 —— ``demo_e2e`` **真跑出来的**工件的默认位置
DEMO_ARTIFACT = REPO / "scripts" / "examples" / "out" / "e2e" / "zk" / "vectors.json"


#: 基准里规则**最全**的那条策略：任何 rc 的策略都是它的一条前缀（`make_policy`
#: 取 `extras` 的前 rc-1 条），所以「用它查一遍没命中」⇒「对任何 rc 都没命中」。
MAX_RC = len(EXTRA_KINDS) + 1


def trips(text: str) -> list[tuple[str, str]]:
    """``text`` 会不会命中基准规则；命中的话返回 ``[(规则名, 证据), …]``。

    用**宿主**判定（`policydsl.evaluate`，与电路侧由 `cross_validate` 保证一致），
    不跑 zkVM —— 这只是选语料前的体检，秒级。
    """
    res = evaluate.check(make_policy(MAX_RC), text)
    return [(v.rule.name, str(v.evidence)) for v in res.violations]


class Corpus(NamedTuple):
    """一份语料 + 它的出处，以及**被剔掉的那些段落为什么被剔**。"""

    text: str
    sources: list[str]
    excluded: list[dict]


def _responses_in(obj: Any, path: str = "") -> list[tuple[str, str]]:
    """递归捞出 ``obj`` 里所有 ``"response"`` 字符串，返回 ``[(JSON 路径, 文本)]``。

    走到任意深度是因为「响应」在这套工件里出现的位置不统一：顶层 ``vectors[0]``、
    组合证明的 ``infer_vectors``、会话证明的每个成员里都有。与其逐个位置写死，
    不如按字段名捞 —— 名字就是约定。
    """
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "response" and isinstance(v, str):
                out.append((f"{path}/response", v))
            else:
                out.extend(_responses_in(v, f"{path}/{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_responses_in(v, f"{path}[{i}]"))
    return out


def load_corpus(spec: str) -> Corpus:
    """把 ``--corpus`` 解析成 :class:`Corpus`（文本 + 出处 + 剔除记录）。

    三档，都是**如实标注**的：

    * ``synthetic``：老的合成串（``the quick brown fox jumps``）。留着是为了与
      旧表逐点对照 —— 换了语料再比数字，等于把「换语料」和「换规模」混在一起。
    * ``demo``（默认，P2-12 的要求）：从 ``demo_e2e`` **真实跑出来的**工件
      （``scripts/examples/out/e2e/zk/vectors.json`` 里被证明过的那条响应）取文本；
      再并上仓库自带的示例回复 ``scripts/examples/*.txt``。工件不在时**报错并说清
      怎么生成**，而不是悄悄退回合成串 —— 那会让表格里的「真实轨迹」变成一个谎。
    * 其它字符串：当作**文件路径**读入（自备语料，例如某次真实会话导出的转写）。

    **为什么 ``demo`` 会剔除段落**：本基准量的是**最坏情况扫描成本**，要求文本
    不命中任何规则（命中即短路，cycle 数会偏低，那个数字会被误读成「扫到底的代价」）。
    但真实轨迹里**本来就有违规的** —— 仓库自带的 ``finance_agent_reply.txt`` 里就
    写着一个真的 ``sk-…`` 凭据，会命中 ``pattern_block``。这里的处理是：把命中的
    段落**剔掉并逐条记进** ``Corpus.excluded``（规则名 + 证据），而不是
    ——悄悄留着一个会产生假数字的文本，或者把「真实语料」偷偷换成合成串。
    剔除后还会再体检一次平铺文本（分块拼接可能在**接缝**处造出新的命中）。
    """
    if spec == "synthetic":
        return Corpus(SYNTHETIC, ["synthetic"], [])
    if spec != "demo":
        p = Path(spec)
        if not p.exists():
            raise SystemExit(f"--corpus {spec}：既不是 synthetic/demo，也不是存在的文件")
        text = p.read_text(encoding="utf-8")
        hits = trips(text)
        if hits:
            raise SystemExit(
                f"--corpus {spec}：文本命中规则 {hits}，短路会让 cycle 数偏低。"
                f"换一份不含命中词的文本（自备语料不做自动剔除，因为怎么改是你的决定）")
        return Corpus(text, [str(p)], [])

    candidates: list[tuple[str, str]] = []
    for p in sorted((REPO / "scripts" / "examples" / "out").rglob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):   # 落盘的工件不该读不动，但也不值得在这炸掉
            continue
        for path, text in _responses_in(data):
            candidates.append((text, f"{p.relative_to(REPO)}{path}"))
    for p in sorted((REPO / "scripts" / "examples").glob("*.txt")):
        candidates.append((p.read_text(encoding="utf-8").strip(), str(p.relative_to(REPO))))

    # 按**内容**去重：同一个回复会被多个工件重复落盘（公开/私有/链上各一份），
    # 留着只会让「语料有多大」虚高，而且把一个短句的权重悄悄放大
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for text, src in candidates:
        if text and text not in seen:
            seen.add(text)
            unique.append((text, src))
    candidates = unique
    if not candidates:
        raise SystemExit(
            f"--corpus demo 需要真实工件 （``scripts/examples/out/**``） 或 "
            f"``scripts/examples/*.txt``；先跑一次 `python3 scripts/demo_e2e.py`，"
            f"或用 --corpus synthetic / --corpus <文件>")

    kept: list[tuple[str, str]] = []
    excluded: list[dict] = []
    for text, src in candidates:
        hits = trips(text)
        if hits:
            excluded.append({"source": src, "hits": [f"{r}: {ev}" for r, ev in hits]})
        else:
            kept.append((text, src))
    if not kept:
        raise SystemExit(f"--corpus demo：{len(candidates)} 段全部命中规则，没有可用语料")

    text = "\n".join(t for t, _ in kept)
    hits = trips(text)   # 平铺之后复检：拼接接缝处可能造出新的命中
    if hits:
        raise SystemExit(
            f"--corpus demo：拼接后的语料命中规则 "
            f"{[f'{r}: {ev}' for r, ev in hits]}（多半出现在段落接缝处）。"
            f"请用 --corpus <文件> 自备一份干净语料")
    return Corpus(text, [s for _, s in kept], excluded)


def text_of_length(base: str, length: int) -> str:
    """把语料**平铺**到恰好 ``length`` 字符。

    超过语料本身长度之后就是重复 —— 这一点如实写在结果里（``corpus_sources`` +
    ``corpus_sha256``）。这里要量的是**扫描成本对长度的曲线**，不是文本的新颖性；
    用真实文本而不是一行编造的填充串，是为了让字符分布（词长、标点、空白、非 ASCII）
    贴近实际响应。
    """
    if not base:
        raise ValueError("语料为空")
    return (base * (length // len(base) + 1))[:length]


def run_execute(vector: dict) -> dict:
    """把单个向量喂给 ``pop-script --execute``，返回其 JSON 结果。

    走子进程而不是 import，是为了测真实的 CLI 路径（参数解析 + 序列化开销）。
    """
    WORK.mkdir(parents=True, exist_ok=True)
    vp = WORK / "v.json"
    op = WORK / "r.json"
    vp.write_text(json.dumps({"vectors": [vector]}))
    subprocess.run([str(POP_SCRIPT), "--execute", "--vectors", str(vp), "--out", str(op)],
                   cwd=str(REPO), check=True, capture_output=True, text=True)
    return json.loads(op.read_text())[0]


# --------------------------------------------------------------------------
# 最小二乘（纯 Python）
# --------------------------------------------------------------------------

def lstsq(rows: list[list[float]], y: list[float]) -> tuple[list[float], float]:
    """解 ``X·β ≈ y`` 的法方程，返回 ``(β, R²)``。

    只用得上 3 个未知数，所以直接对 ``XᵀX``（3×3）做带部分主元的高斯消元 ——
    引 numpy 进一个只跑执行的评测脚本不划算。奇异时抛 :class:`ValueError`，
    由调用方决定「样本不够就如实说不够」，而不是悄悄给个 NaN。
    """
    n = len(rows[0])
    if len(rows) < n:
        raise ValueError(f"样本 {len(rows)} 个 < 未知数 {n} 个，无法拟合")
    ata = [[sum(r[i] * r[j] for r in rows) for j in range(n)] for i in range(n)]
    aty = [sum(rows[k][i] * y[k] for k in range(len(rows))) for i in range(n)]

    # 高斯消元（部分主元）
    for col in range(n):
        piv = max(range(col, n), key=lambda r: abs(ata[r][col]))
        if abs(ata[piv][col]) < 1e-12:
            raise ValueError("法方程奇异（解释变量线性相关或样本退化）")
        ata[col], ata[piv] = ata[piv], ata[col]
        aty[col], aty[piv] = aty[piv], aty[col]
        for r in range(col + 1, n):
            f = ata[r][col] / ata[col][col]
            for c in range(col, n):
                ata[r][c] -= f * ata[col][c]
            aty[r] -= f * aty[col]

    beta = [0.0] * n
    for i in reversed(range(n)):
        beta[i] = (aty[i] - sum(ata[i][j] * beta[j] for j in range(i + 1, n))) / ata[i][i]

    pred = [sum(r[i] * beta[i] for i in range(n)) for r in rows]
    ybar = sum(y) / len(y)
    ss_res = sum((y[k] - pred[k]) ** 2 for k in range(len(y)))
    ss_tot = sum((v - ybar) ** 2 for v in y)
    r2 = 1.0 - ss_res / ss_tot if ss_tot > 0 else float("nan")
    return beta, r2


def fit_line(pts: list[tuple[float, float]]) -> tuple[float, float, float]:
    """对 ``[(x, y)]`` 做一元线性回归，返回 ``(斜率, 截距, R²)``。

    一元的情形手推闭式解比走 :func:`lstsq` 清楚：斜率是协方差/方差，不会被
    法方程的条件数放大。``x`` 全相同时（只采了一个长度）返回 ``nan`` 斜率。
    """
    n = len(pts)
    sx = sum(p[0] for p in pts)
    sy = sum(p[1] for p in pts)
    sxx = sum(p[0] * p[0] for p in pts)
    sxy = sum(p[0] * p[1] for p in pts)
    den = n * sxx - sx * sx
    if den == 0:
        return float("nan"), sy / n, float("nan")
    a = (n * sxy - sx * sy) / den
    b = (sy - a * sx) / n
    ybar = sy / n
    ss_res = sum((p[1] - (a * p[0] + b)) ** 2 for p in pts)
    ss_tot = sum((p[1] - ybar) ** 2 for p in pts)
    return a, b, (1.0 - ss_res / ss_tot if ss_tot > 0 else float("nan"))


def fit_models(rows: list[dict]) -> dict:
    """**两段式**拟合：先按规则集各自量出「cycles 对长度」的斜率，再解释斜率。

    只剩 pike 点参与：naive 是另一个算法（O(n²)），混在一起等于拟合两件事的
    混合物。naive 的二次退化由消融那组单独给出。

    **为什么必须分两段**（这是踩过坑的地方）：直接拿所有点回归
    ``cycles ≈ b + L·(a_kw·n_kw + a_pat·n_pat)`` 会得到 **负的** ``a_kw``
    （实测 −105）—— 一个物理上不成立的单价。数据本身是干净的：**固定规则集时
    cycles 对长度是精确线性的（R² = 1.0000，见 ``per_rule_set``）**。噪声全在
    「换规则集」这一步：同一批规则换个**顺序**，10k 字符上的 cycle 数就差 17%
    （43.28M vs 35.89M，见 ``order_probe``）。原因是 zkVM 里每次
    ``ascii_lower``/Pike VM 都要分配内存，**分配器的状态依赖先前的分配**，
    于是「多一条规则」既加了它自己的成本、又改了别的规则的成本。

    先把每个规则集自己的斜率量准（第一段），再拿斜率去回归单价（第二段），
    截距（含分配器开销）就不会再污染单价。第二段的残差仍然如实报出来 ——
    它度量的正是「单价不可加」这件事，不该被 R² 盖过去。
    """
    pts = [r for r in rows if r["mode"] == "pike"]
    out: dict = {"n_points": len(pts)}
    if len(pts) < 3:
        out["note"] = "pike 采样点不足 3 个，未拟合"
        return out

    # ---- 第一段：每个规则集各自拟合 cycles = b + a·|T| -------------------
    by_rc: dict[int, list[tuple[float, float]]] = {}
    for r in pts:
        by_rc.setdefault(r["rules"], []).append((float(r["length"]), float(r["cycles"])))
    per_set: dict[str, dict] = {}
    for rc in sorted(by_rc):
        if len(by_rc[rc]) < 2:
            per_set[str(rc)] = {"note": f"该规则集只有 {len(by_rc[rc])} 个长度点，拟合不了斜率"}
            continue
        a, b, r2 = fit_line(sorted(by_rc[rc]))
        n_kw, n_pat = kind_counts(rc)
        per_set[str(rc)] = {"kind_counts": {"keyword": n_kw, "pattern": n_pat},
                            "slope": a, "intercept": b, "r2": r2,
                            "n_points": len(by_rc[rc])}
    out["per_rule_set"] = per_set

    # ---- 第二段：斜率对规则种类回归 —— a ≈ a0 + a_kw·n_kw + a_pat·n_pat ----
    slope_pts = [(int(rc), v) for rc, v in per_set.items()
                 if isinstance(v, dict) and "slope" in v and v["slope"] == v["slope"]]
    if len(slope_pts) >= 3:
        Xa = []
        ys = []
        for rc, v in slope_pts:
            n_kw, n_pat = kind_counts(rc)
            Xa.append([1.0, float(n_kw), float(n_pat)])
            ys.append(v["slope"])
        try:
            (a0, a_kw, a_pat), r2a = lstsq(Xa, ys)
            pred = [a0 + a_kw * x[1] + a_pat * x[2] for x in Xa]
            resid = [round(ys[i] - pred[i], 1) for i in range(len(ys))]
            out["slope_model"] = {
                "form": "slope ≈ a0 + a_kw·n_kw + a_pat·n_pat",
                "a0": a0, "cycles_per_char_per_keyword": a_kw,
                "cycles_per_char_per_pattern": a_pat, "r2": r2a,
                "residual_per_rule_set": {str(slope_pts[i][0]): resid[i]
                                          for i in range(len(slope_pts))},
                "max_abs_residual": max(abs(x) for x in resid),
            }
        except ValueError as exc:
            out["slope_model"] = {"error": str(exc)}
    else:
        out["slope_model"] = {"note": f"能用的斜率只有 {len(slope_pts)} 个，不足以回归"}

    # ---- 计划里的简式：一次回归全部点 —— 一并报出来，好让「够不够用」由数据回答
    Xb = [[1.0, float(r["length"] * r["rules"])] for r in pts]
    try:
        (b2, a), r2b = lstsq(Xb, [float(r["cycles"]) for r in pts])
        out["simple"] = {"form": "cycles ≈ b + a·|T|·rules", "intercept": b2,
                         "cycles_per_char_per_rule": a, "r2": r2b,
                         "note": "把两类规则混成一个单价、且让截距吸收分配器开销 —— 只当参照"}
    except ValueError as exc:
        out["simple"] = {"error": str(exc)}
    return out


def marginal_probe(length: int) -> dict:
    """量「单独加一条规则」的边际成本 —— 补上矩阵采样点缺的那一格。

    矩阵里的规则集是 `extras` 的**前缀**，于是 ``(n_kw, n_pat)`` 只走过
    ``(0,0) / (1,0) / (1,1) / (2,1) / (3,2)``：**「只有正则、没有关键词」这一格
    从没被测过**。少了它，「关键词单价为负」就说不清是测量噪声还是真现象；
    有了它就能直接读出「在已经有 NFA 扫描的策略里，再加一条关键词规则要花多少」。

    五种规则集，全部在同一个长度上、同一个语料上量，先固定顺序再比。
    """
    LEN = Rule("length_bound", "len", {"min": 1, "max": 10_000_000})
    KW = Rule("keyword_block", "kw", {"keywords": ["exploit", "weaponize", "doxxing"]})
    PAT = Rule("pattern_block", "pat", {"patterns": [EMAIL], "match_mode": "pike"})
    sets = {
        "[len]": [LEN],
        "[len,kw]": [LEN, KW],
        "[len,pat]": [LEN, PAT],
        "[len,kw,pat]": [LEN, KW, PAT],
        "[len,pat,kw]": [LEN, PAT, KW],
    }
    corpus = text_of_length(load_corpus("demo").text, length)
    out: dict = {"length": length, "points": {}}
    for tag, rules in sets.items():
        spec = spec_canonical_text(compile_policy(Policy("bench", "1", rules=rules)))
        res = run_execute({"name": f"marginal-{tag}", "response": corpus,
                           "spec_canonical": spec})
        # 从**规则本身**数，不查 kind_counts：那支是按 `extras` 前缀推的，
        # 而这里的规则集刻意不走前缀（比如 [len,pat] 是「0 关键词 + 1 正则」）
        n_kw = sum(1 for r in rules if r.kind == "keyword_block")
        n_pat = sum(1 for r in rules if r.kind == "pattern_block")
        out["points"][tag] = {"cycles": res["cycles"], "passed": res["passed"],
                              "kind_counts": {"keyword": n_kw, "pattern": n_pat}}
        print(f"  {tag:<14} cycles={res['cycles']:>13,}", flush=True)
    if "[len]" in out["points"] and "[len,kw]" in out["points"]:
        out["marginal_kw_alone"] = ((out["points"]["[len,kw]"]["cycles"]
                                     - out["points"]["[len]"]["cycles"]) / length)
    if "[len,pat]" in out["points"] and "[len,kw,pat]" in out["points"]:
        out["marginal_kw_with_pattern"] = ((out["points"]["[len,kw,pat]"]["cycles"]
                                            - out["points"]["[len,pat]"]["cycles"]) / length)
    return out


def order_probe(length: int, rc: int) -> dict:
    """把**同一批规则**换个顺序再量一次，量化「规则顺序也会改 cycle 数」。

    这条探针存在的理由：它是上面两段式拟合的**动机**。没有它，
    ``slope_model`` 里那个非零残差看起来像拟合不好；有了它，就能指出残差的
    来源是 zkVM 内的内存分配器（先分配谁、后分配谁，会让同一批规则的执行
    指令数不同），而不是测量噪声。返回两个顺序下的 cycle 数。
    """
    rules = make_policy(rc, "pike").rules
    corpus = text_of_length(load_corpus("demo").text, length)
    results = {}
    for tag, ordered in (("声明顺序", rules), ("逆序", list(reversed(rules)))):
        if tag == "逆序":   # 长度规则排到最前，否则「逆序」把 length_bound 推到末尾
            ordered = [r for r in rules if r.kind == "length_bound"] + \
                      [r for r in reversed(rules) if r.kind != "length_bound"]
        spec = spec_canonical_text(compile_policy(Policy("bench", "1", rules=list(ordered))))
        out = run_execute({"name": f"order-{tag}", "response": corpus, "spec_canonical": spec})
        results[tag] = {"cycles": out["cycles"], "passed": out["passed"],
                        "order": [r.name for r in ordered]}
    a = results["声明顺序"]["cycles"]
    b = results["逆序"]["cycles"]
    results["delta"] = b - a
    results["delta_pct"] = round((b - a) / a * 100.0, 2) if a else None
    results["length"] = length
    results["rules"] = rc
    return results


def parse_ints(spec: str) -> list[int]:
    """``"1000,10000"`` → ``[1000, 10000]``（命令行里给采样点用）。"""
    return [int(x) for x in spec.replace(",", " ").split()]


def main() -> int:
    """遍历所有采样点，落盘 JSON 结果与 Markdown 表格。"""
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=REPO / "bench" / "results" / "cycles.json")
    ap.add_argument("--lengths", type=parse_ints, default=DEFAULT_LENGTHS,
                    help=f"逗号分隔的长度采样点（默认 {DEFAULT_LENGTHS}）")
    ap.add_argument("--rules", type=parse_ints, default=DEFAULT_RULE_COUNTS,
                    help=f"逗号分隔的规则条数（默认 {DEFAULT_RULE_COUNTS}）")
    ap.add_argument("--corpus", default="demo",
                    help="响应文本的出处：demo（默认，从真实工件回放）/ "
                         "synthetic（老的合成串，便于与旧表对照）/ <文件路径>")
    ap.add_argument("--order-probe", action=argparse.BooleanOptionalAction, default=True,
                    help="在最长采样点上把同一批规则换个顺序再量一次（默认开；"
                         "它跑两次执行，是「单价不可加」这条结论的直接证据）")
    args = ap.parse_args()

    corpus = load_corpus(args.corpus)
    corpus_text = corpus.text
    corpus_sha = hashlib.sha256(corpus_text.encode("utf-8")).hexdigest()
    print(f"corpus={args.corpus}  {len(corpus_text)} 字符  sha256={corpus_sha[:16]}…")
    for s in corpus.sources:
        print(f"  ← {s}")
    for e in corpus.excluded:   # 剔掉了什么、为什么剔，都摆到台面上
        print(f"  ✗ 剔除 {e['source']}：{'；'.join(e['hits'])}")
    # 语料比采样点短是常态（真实回复本来就没那么长）—— 平铺倍数要如实说出来，
    # 否则「100k 字符的实测」会被读成「一段 100k 的真实文本」，那是两回事
    for length in sorted(set(args.lengths)):
        if length > len(corpus_text):
            print(f"  ⓘ L={length} > 语料 {len(corpus_text)} 字符："
                  f"该点是语料平铺 ≈{length / len(corpus_text):.0f} 次的结果")

    lengths = sorted(set(args.lengths))
    rule_counts = sorted(set(args.rules))
    modes = ["pike", "naive"]

    # 起飞前体检：平铺到**每一个**目标长度后都不许命中规则。放在跑之前做，是因为
    # 命中是**长度相关**的（重复拼接在接缝处可能造出新命中），跑一半才炸会白等一场；
    # 而且这条一旦漏掉，那个偏低的 cycle 数会被读成「最坏情况扫描成本」，是硬伤。
    texts: dict[int, str] = {}
    for length in lengths:
        text = text_of_length(corpus_text, length)
        hits = trips(text)
        if hits:
            raise SystemExit(
                f"L={length}：平铺后的语料命中规则 "
                f"{[f'{r}: {ev}' for r, ev in hits]}，短路会让 cycle 数偏低。"
                f"换一份不含命中词的语料（--corpus）")
        texts[length] = text

    rows = []
    for length in lengths:
        for rc in rule_counts:
            for mode in modes:
                # naive 匹配是 O(n^2)，长文本会把执行时间炸掉，只在短长度上跑
                if mode == "naive" and length > 2_000:
                    continue
                policy = make_policy(rc, mode)
                spec = compile_policy(policy)
                out = run_execute({"name": f"L{length}-R{rc}-{mode}",
                                   "response": texts[length],
                                   "spec_canonical": spec_canonical_text(spec)})
                # 兜底：真跑出来没过，说明上面的体检漏了什么，宁可当场停也不要假数字
                if not out["passed"]:
                    raise SystemExit(
                        f"L={length} rules={rc} mode={mode}：电路侧报未通过（"
                        f"{out.get('violations')}），与宿主侧体检不一致 —— "
                        f"先把两边对齐再谈成本")
                rows.append({"length": length, "rules": rc, "mode": mode,
                             "cycles": out["cycles"], "passed": out["passed"]})
                print(f"L={length:>6} rules={rc} mode={mode:<5} cycles={out['cycles']:,}",
                      flush=True)

    # 两条探针。它们不是「补充材料」：两段式拟合的残差有多大、为什么有，
    # 全靠它们给出可复现的证据（见 fit_models 与 marginal_probe 的说明）。
    probe_len = max(lengths)
    order = marginal = None
    if args.order_probe:
        print(f"\n=== 顺序探针：L={probe_len} rules={rule_counts[-1]} 换个顺序再量 ===",
              flush=True)
        order = order_probe(probe_len, rule_counts[-1])
        print(f"声明顺序 {order['声明顺序']['cycles']:,}  vs  逆序 "
              f"{order['逆序']['cycles']:,}  ⇒ {order['delta_pct']:+.2f}%", flush=True)
        print(f"\n=== 边际探针：L={probe_len} 单独加一条规则要多少 ===", flush=True)
        marginal = marginal_probe(probe_len)
        print(f"关键词单独加 {marginal['marginal_kw_alone']:+.1f} cycles/字符；"
              f"在有正则的策略里加 {marginal['marginal_kw_with_pattern']:+.1f} cycles/字符",
              flush=True)

    fit = fit_models(rows)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    result = {"corpus": {"name": args.corpus, "sources": corpus.sources,
                         "excluded": corpus.excluded,
                         "chars": len(corpus_text), "sha256": corpus_sha},
              "order_probe": order, "marginal_probe": marginal,
              "rows": rows, "fit": fit}
    args.out.write_text(json.dumps(result, indent=2))

    # 同时输出 Markdown 表格，方便直接贴进 README/报告
    md = ["# Cycle-count matrix (zkVM execution, no proof)", "",
          f"语料 `{args.corpus}`：**{len(corpus_text)} 字符**，sha256 `{corpus_sha[:16]}…`，"
          f"来自 {len(corpus.sources)} 段真实回复（出处见 `cycles.json` 的 `corpus.sources`）。"
          f"**长于语料的点是把它平铺重复得到的**（100k ≈ {100_000 / len(corpus_text):.0f} 次），"
          f"如实标注：这里量的是扫描成本的**曲线**，不是「一段 100k 的真实文本」。", ""]
    if corpus.excluded:
        md.append(f"被剔除的 {len(corpus.excluded)} 段（命中规则 ⇒ 会短路，数字不可用）：")
        for e in corpus.excluded:
            md.append(f"- `{e['source']}` —— {'；'.join(e['hits'])}")
        md.append("")
    md += ["| length | rules | mode | cycles |", "|---:|---:|:--|---:|"]
    for r in rows:
        md.append(f"| {r['length']} | {r['rules']} | {r['mode']} | {r['cycles']:,} |")
    md += ["", "## 成本模型（仅 pike 点）", "",
           "### 第一段：固定规则集时，cycles 对长度是精确线性的", "",
           "| 规则数 | keyword | pattern | 斜率 (cycles/字符) | 截距 | R² |",
           "|---:|---:|---:|---:|---:|---:|"]
    for rc, v in sorted(fit.get("per_rule_set", {}).items(), key=lambda kv: int(kv[0])):
        if "slope" not in v:
            md.append(f"| {rc} | — | — | — | — | {v.get('note', '')} |")
            continue
        kc = v["kind_counts"]
        md.append(f"| {rc} | {kc['keyword']} | {kc['pattern']} | {v['slope']:.1f} | "
                  f"{v['intercept']:,.0f} | {v['r2']:.4f} |")
    md.append("")
    sm = fit.get("slope_model", {})
    if "cycles_per_char_per_keyword" in sm:
        md += [f"### 第二段：把斜率拆成单价 —— `{sm['form']}`", "",
               f"`a0 = {sm['a0']:.1f}`，`a_kw = {sm['cycles_per_char_per_keyword']:.1f}`，"
               f"`a_pat = {sm['cycles_per_char_per_pattern']:.1f}`，R² = {sm['r2']:.4f}；"
               f"**最大残差 {sm['max_abs_residual']:.1f} cycles/字符**（逐规则集见 `cycles.json`）。", "",
               "残差非零是**结论不是瑕疵**：单价不可加 —— 同一批规则换个**顺序**，"
               "执行指令数就会变（zkVM 内每次 `ascii_lower`/Pike VM 都要分配内存，"
               "分配器状态依赖先前的分配）。按规则集的斜率（上表）才是可直接引用的数。", ""]
    else:
        md.append(f"第二段未拟合（{sm.get('error') or sm.get('note')}）\n")
    if order:
        md += ["### 顺序探针", "",
               f"同一批规则、同一段文本（L={order['length']}，{order['rules']} 条规则）："
               f"声明顺序 **{order['声明顺序']['cycles']:,}** vs 逆序 "
               f"**{order['逆序']['cycles']:,}** ⇒ **{order['delta_pct']:+.2f}%**。"
               f"两条的 `passed` 都是 {order['声明顺序']['passed']}/{order['逆序']['passed']}"
               f" —— **判定的语义与顺序无关，成本不是**。", ""]
    if marginal:
        md += [f"### 边际探针（L={marginal['length']}）", "",
               "矩阵的规则集只走 `extras` 的前缀，所以「**只有正则、没有关键词**」这一格"
               "从没被测过。补上它：", "",
               "| 规则集 | keyword | pattern | cycles |", "|:--|---:|---:|---:|"]
        for tag, v in marginal["points"].items():
            kc = v["kind_counts"]
            md.append(f"| `{tag}` | {kc['keyword']} | {kc['pattern']} | {v['cycles']:,} |")
        md += ["",
               f"于是「再加一条关键词规则」的边际单价有两个不同的答案："
               f"**单独加 {marginal['marginal_kw_alone']:+.1f} cycles/字符**，"
               f"**在已经有 NFA 正则的策略里加 {marginal['marginal_kw_with_pattern']:+.1f} "
               f"cycles/字符**。单价不是规则的属性，是「规则 + 上下文」的属性。", ""]
    sp = fit.get("simple", {})
    if "cycles_per_char_per_rule" in sp:
        md += ["### 计划里的简式（参照）", "",
               f"`cycles ≈ {sp['intercept']:,.0f} + {sp['cycles_per_char_per_rule']:.1f}·|T|·rules`，"
               f"R² = {sp['r2']:.4f} —— {sp.get('note', '')}", ""]
    else:
        md.append(f"计划简式：未拟合（{sp.get('error') or sp.get('note')}）\n")
    (args.out.with_suffix(".md")).write_text("\n".join(md) + "\n")
    print(f"\nwrote {args.out} and {args.out.with_suffix('.md')}")
    print("fit:", json.dumps(fit, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
