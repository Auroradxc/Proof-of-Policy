"""P2-03 差分模糊测试：Pike VM vs Python ``re``（G-1 / V1-2 已修复）。

**要证的命题**：`policydsl.core.nfa` 的 Pike VM 在**受支持子集**上与 Python
``re.search`` 判定一致；否则 Python 参考评估器与 SP1 电路会对同一条响应给出
不同结论。Rust 二进制可用时再加一层 Python↔Rust 对拍。

三层：

1. **固定 + 随机生成的模式 × 穷举/随机文本**：逐例比较
   ``nfa.match_search`` 与 ``bool(re.search(...))``；同时比较 Pike 与朴素匹配器
   （``match_search_naive``）—— 消融实验的可比性依赖这一条。
2. **空字符类契约**（原 G-1，T3 `docs/proofs/theorem-d-g.md` §12.3）：
   ``[^\\d\\D]`` 的语言按定义是 ∅。修复选择是 **fail-closed**：解析器在
   解析期抛 ``RegexSyntaxError``，不再把空语言编译成 ``Lit([])``（后者只表示
   空连接 ε）。因此 Python ``re`` **接受**该模式、本仓 NFA **拒绝**它 ——
   这是有意的子集边界，由 ``docs/blockers/Core.md`` 记录。
3. **Python↔Rust 对拍**（``POP_SCRIPT`` 可用时）：同一份 NFA spec 喂给
   ``pop-script --check``，比较 Rust 的匹配结论。Rust 侧只解释编译后的 spec
   （不解析正则），空字符类在编译期就被 Python 拒绝，不会到达电路。

另外单独覆盖 V1-2（``a{0}`` / ``a{0,0}`` 等价于 ε）。

固定种子（``SEED``），stdlib + ``unittest`` 可跑，不依赖 Hypothesis。
结果写到 ``bench/results/fuzz.json`` 与同目录的 ``fuzz.md``（由
``tearDownModule`` 在整模块跑完后落盘）。
"""

from __future__ import annotations

import itertools
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl.core import nfa                                    # noqa: E402
from policydsl.core.compile import compile_policy                 # noqa: E402
from policydsl.core.model import Policy, PolicyError, Rule    # noqa: E402
from policydsl.core.serialize import spec_canonical_text         # noqa: E402
from policydsl.paths import POP_SCRIPT                            # noqa: E402

SEED = 20261101

#: 穷举文本用的字母表（小，保证长度 ≤ 3 的全空间可枚举）。
EXHAUSTIVE_ALPHABET = "ab01 "
#: 随机文本用的字母表：加入空格、换行与其它字符，覆盖 ``.`` / ``\s`` / 取反类。
RANDOM_ALPHABET = "ab01xyz \n"

#: 固定模式：真实 PII 形状 + 各类语法构造（全部在受支持子集内）。
FIXED_PATTERNS = [
    r"a+b",
    r"[\w.+-]+@[\w-]+\.[\w.]+",
    r"sk-[A-Za-z0-9]{10,}",
    r"\+\d[\d\s-]{6,}",
    r"a+", r"colou?r", r"(cat|dog)s?", r"b{2,4}",
    r"[^0-9]+", r"\d{2,4}-\d{2,4}", r"a.*b", r"[a-c]+x?",
    r"\$[0-9]+(\.[0-9]{2})?",
    r"(ab|cd)+", r"[a-c]{2,4}x?", r"\d{2}-\d{3}", r".*a.{2}",
    r"(a|b){1,3}c", r"\w+@\w+", r"[ \t]+x", r"(ab?)*b", r"a{1}b",
    r"[^a-c]+", r"\W+", r"\S+", r"(x|y)?z",
]

#: 随机模式的原子。**不含空字符类** —— 那一条单独由 G-1 测试覆盖。
ATOMS = [
    "a", "b", "0", "1", "x", " ", ".", r"\d", r"\D", r"\w", r"\W",
    r"\s", r"\S", "[ab]", "[^a]", "[a-c]", "[0-9]", "[^0-9]", r"\.", r"\-",
]
QUANTIFIERS = ["", "", "", "*", "+", "?", "{2}", "{1,2}", "{0,2}"]

#: 原 T3 §12.3 的 G-1：取反后为空的字符类。修复后**解析器拒绝**这些模式
#: （fail-closed 契约），见 ``docs/blockers/Core.md``。
G1_PATTERNS = [
    r"[^\d\D]",
    r"[^\w\W]",
    r"[^\s\S]",
    r"([^\d\D])+",
    r"([^\d\D]){1,2}",
]
#: 空字符类的边界形式：Python 与本仓 NFA 都拒绝（只是报错类型不同）。
EMPTY_BRACKET_PATTERNS = [r"[]", r"[^]"]

#: V1-2 的零次重复：必须等价于 ε（匹配空串，且不消耗任何字符）。
ZERO_REPEAT_PATTERNS = [r"a{0}", r"a{0,0}", r"(ab){0}", r"(a|b){0,0}"]

TARGETED_TEXTS = [
    "", "a", "b", "aaab", "ab", "0", " ", "\n", "xyz", "a" * 32, "ab" * 8,
    "0" * 8, "a@b.com", "sk-abcdefghijklmnop", "+1 234 5678901",
    "the quick brown fox", "A1_b-2", "$1.25", "a\nb", "a b",
]

RUST_SAMPLE_LIMIT = 160


# --------------------------------------------------------------------------- #
# 生成
# --------------------------------------------------------------------------- #

def _random_atom(rng: random.Random) -> str:
    return rng.choice(ATOMS)


def _plain_seq(rng: random.Random) -> str:
    """分组内部：只由**不带量词**的原子组成。"""
    return "".join(_random_atom(rng) for _ in range(rng.randint(1, 2)))


def _random_pattern(rng: random.Random) -> str:
    """按受支持子集的小文法生成模式。

    **刻意不嵌套量词**：像 ``(a*)*`` 这种模式会让 *Python 的* 回溯引擎在
    ``"a" * 32`` 上指数爆炸（差分测试等的是语义，不是给 `re` 做 DoS）。
    因此分组内部只放不带量词的原子，分组本身也不再叠量词；量词只作用在
    单字符原子上。
    """
    def seq() -> str:
        pieces: List[str] = []
        for _ in range(rng.randint(1, 3)):
            if rng.random() < 0.20:
                inner = _plain_seq(rng)
                if rng.random() < 0.5:
                    inner += "|" + _plain_seq(rng)
                pieces.append("(" + inner + ")")          # 分组不再叠量词
            else:
                pieces.append(_random_atom(rng) + rng.choice(QUANTIFIERS))
        return "".join(pieces)

    left = seq()
    if rng.random() < 0.30:
        return left + "|" + seq()
    return left


def _compiles_both(pattern: str) -> bool:
    """Python ``re`` 与本仓 NFA 都能编译（受支持子集的必要条件）。

    空字符类（原 G-1）现在由本仓解析器**主动拒绝**，因此会在这里被过滤掉；
    这是有意的子集边界，不是测试噪声（见 ``docs/blockers/Core.md``）。
    零次重复（V1-2）已经修复，不再需要额外吞掉 ``AttributeError``。
    """
    try:
        re.compile(pattern)
        nfa.compile_pattern(pattern)
        return True
    except (re.error, nfa.RegexSyntaxError):
        return False


def build_patterns(count: int = 120) -> List[str]:
    """固定模式 + 固定种子随机生成，过滤到两端都能编译。"""
    rng = random.Random(SEED)
    out = list(FIXED_PATTERNS)
    seen = set(out)
    guard = 0
    while len(out) < count and guard < count * 50:
        guard += 1
        p = _random_pattern(rng)
        if p in seen or not _compiles_both(p):
            continue
        seen.add(p)
        out.append(p)
    return out


def build_texts(count: int = 280) -> List[str]:
    """长度 ≤ 3 的全枚举 + 固定种子随机 + 定向样例。"""
    texts: List[str] = []
    for k in range(4):
        texts.extend("".join(t) for t in itertools.product(EXHAUSTIVE_ALPHABET, repeat=k))
    rng = random.Random(SEED ^ 0x5EED)
    for _ in range(count):
        length = rng.randint(0, 8)
        texts.append("".join(rng.choice(RANDOM_ALPHABET) for _ in range(length)))
    texts.extend(TARGETED_TEXTS)
    # 去重但保序
    seen = set()
    uniq: List[str] = []
    for t in texts:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


# --------------------------------------------------------------------------- #
# 判定
# --------------------------------------------------------------------------- #

def _re_match(pattern: str, text: str) -> Optional[bool]:
    try:
        return re.search(pattern, text) is not None
    except re.error:
        return None


def _rust_binary() -> Optional[Path]:
    cand = Path(os.environ.get("POP_SCRIPT", str(POP_SCRIPT)))
    return cand if cand.is_file() else None


_REPORT: Optional[Dict[str, Any]] = None


def run_sweep() -> Dict[str, Any]:
    """跑完整差分扫描；结果缓存在模块级，供各测试与 tearDownModule 共用。"""
    global _REPORT
    if _REPORT is not None:
        return _REPORT

    patterns = build_patterns()
    texts = build_texts()
    mismatches: List[Dict[str, Any]] = []
    naive_mismatches: List[Dict[str, Any]] = []
    comparisons = 0

    for pattern in patterns:
        spec = nfa.compile_pattern(pattern)
        for text in texts:
            comparisons += 1
            pike = nfa.match_search(spec, text)
            naive = nfa.match_search_naive(spec, text)
            expected = _re_match(pattern, text)
            if pike != naive:
                naive_mismatches.append(
                    {"pattern": pattern, "text": text, "pike": pike, "naive": naive})
            if expected is not None and pike != expected:
                mismatches.append({
                    "pattern": pattern, "text": text,
                    "pike": pike, "re": expected, "known_gap": False,
                    "kind": "pike_vs_re",
                })

    # 原 G-1：修复后空字符类必须在解析期被拒绝（fail-closed）。
    g1_patterns: List[Dict[str, Any]] = []
    for pattern in G1_PATTERNS:
        entry: Dict[str, Any] = {"pattern": pattern}
        try:
            nfa.compile_pattern(pattern)
        except nfa.RegexSyntaxError as exc:
            entry.update({
                "status": "rejected_by_parser",
                "error_type": "RegexSyntaxError",
                "error": str(exc),
                "python_re": "accepts (language = empty set)",
                "source": "docs/proofs/theorem-d-g.md §12.3 / G-1; docs/blockers/Core.md",
            })
        else:  # pragma: no cover —— 修复回退了才会走到这里
            entry.update({"status": "ACCEPTED_REGRESSION",
                          "error_type": None, "error": None,
                          "python_re": "accepts (language = empty set)"})
        g1_patterns.append(entry)

    zero_repeat: List[Dict[str, Any]] = []
    for pattern in ZERO_REPEAT_PATTERNS:
        spec = nfa.compile_pattern(pattern)
        zero_repeat.append({
            "pattern": pattern,
            "id": "V1-2",
            "nfa": "compiled as epsilon (matches empty string)",
            "match_empty": nfa.match_search(spec, ""),
            "consumes_a": nfa.anchored_full_match(spec, "a", 0, 1),
            "python_re_fullmatch_a": re.fullmatch(pattern, "a") is not None,
            "source": "policydsl/core/nfa.py::_Builder._chain (empty fragment list)",
            "status": "fixed (zero repeat = epsilon)",
        })

    _REPORT = {
        "task": "P2-03 differential fuzz (Pike VM vs Python re)",
        "generated_by": "tests/test_fuzz_rules.py",
        "seed": SEED,
        "patterns": patterns,
        "texts": texts,
        "counts": {
            "patterns": len(patterns),
            "texts": len(texts),
            "comparisons": comparisons,
        },
        "mismatches": mismatches,
        "pike_vs_naive_mismatches": naive_mismatches,
        "g1": {
            "patterns": G1_PATTERNS,
            "entries": g1_patterns,
            "rejected_count": sum(1 for e in g1_patterns
                                  if e["status"] == "rejected_by_parser"),
            "status": ("fixed: empty character classes are rejected at parse time "
                       "(fail-closed); Python re accepts them as the empty language"),
        },
        "empty_brackets": {
            "patterns": EMPTY_BRACKET_PATTERNS,
            "note": "Python 与本仓 NFA 都拒绝；这是边界对照，不是语义分歧。",
        },
        "zero_repeat": {
            "patterns": ZERO_REPEAT_PATTERNS,
            "entries": zero_repeat,
            "status": "fixed: zero repetition compiles to epsilon",
        },
        "rust": {"status": "not_run", "available": False},
        "notes": [],
    }
    return _REPORT


def run_rust_parity(report: Dict[str, Any]) -> Dict[str, Any]:
    """可选的 Python↔Rust 对拍：同一批 (pattern, text) 喂给 ``pop-script --check``。"""
    binary = _rust_binary()
    if binary is None:
        result = {"status": "skipped", "available": False,
                  "reason": f"pop-script not found: {POP_SCRIPT}（可设 $POP_SCRIPT 覆盖）"}
        report["rust"] = result
        return result

    patterns = report["patterns"][:24]
    texts = report["texts"][:8]
    sample = [(p, t) for p in patterns for t in texts][:RUST_SAMPLE_LIMIT]
    # 显式把「零次重复 = ε」的样例塞进 Rust 样本（V1-2 修复的跨层验证）。
    # 空字符类不再进入样本：它们在 Python 编译器就被拒绝，到不了 Rust。
    sample += [(p, t) for p in ZERO_REPEAT_PATTERNS for t in ["", "a", "abc"]]
    vectors = []
    compiled: Dict[str, str] = {}
    for pattern, text in sample:
        if pattern not in compiled:
            spec = compile_policy(Policy("fuzz", "1", rules=[
                Rule("pattern_block", "pb", {"patterns": [pattern]})]))
            compiled[pattern] = spec_canonical_text(spec)
        vectors.append({"name": f"{len(vectors)}", "response": text,
                        "spec_canonical": compiled[pattern]})

    with tempfile.TemporaryDirectory() as td:
        vp, op = Path(td) / "vectors.json", Path(td) / "out.json"
        vp.write_text(json.dumps({"vectors": vectors}, ensure_ascii=False), encoding="utf-8")
        proc = subprocess.run([str(binary), "--check", "--vectors", str(vp), "--out", str(op)],
                              capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            result = {"status": "error", "available": True, "binary": str(binary),
                      "returncode": proc.returncode,
                      "stderr_tail": proc.stderr[-800:]}
            report["rust"] = result
            return result
        rows = json.loads(op.read_text(encoding="utf-8"))

    mismatches: List[Dict[str, Any]] = []
    re_mismatches: List[Dict[str, Any]] = []
    for (pattern, text), row in zip(sample, rows):
        spec = nfa.compile_pattern(pattern)
        pike = nfa.match_search(spec, text)
        rust_matched = bool(row.get("violations"))
        py_re = _re_match(pattern, text)
        if rust_matched != pike:
            mismatches.append({"pattern": pattern, "text": text,
                               "pike": pike, "rust": rust_matched})
        if py_re is not None and rust_matched != py_re:
            re_mismatches.append({"pattern": pattern, "text": text,
                                  "rust": rust_matched, "re": py_re})

    result = {
        "status": "ok",
        "available": True,
        "binary": str(binary),
        "comparisons": len(sample),
        "python_vs_rust_mismatches": mismatches,
        "rust_vs_re_mismatches": re_mismatches,
        "note": ("python_vs_rust 为 0 表示两种实现判据一致；修复后 rust_vs_re "
                 "也应为 0（空字符类在编译期就被拒绝，不再产生共有缺口）。"),
    }
    report["rust"] = result
    return result


# --------------------------------------------------------------------------- #
# 报告
# --------------------------------------------------------------------------- #

def render_md(report: Dict[str, Any]) -> str:
    counts = report["counts"]
    rust = report["rust"]
    lines = [
        "# 差分模糊测试：Pike VM vs Python `re`（P2-03）",
        "",
        f"固定种子 `{report['seed']}`；{counts['patterns']} 个模式 × "
        f"{counts['texts']} 条文本 = **{counts['comparisons']:,}** 次比较。",
        "",
        "| 比较 | mismatch 数 | 说明 |",
        "|---|---:|---|",
        f"| Pike (`match_search`) vs Python `re.search` | "
        f"**{len(report['mismatches'])}** | 受支持子集；期望 0 |",
        f"| Pike vs 朴素 (`match_search_naive`) | "
        f"**{len(report['pike_vs_naive_mismatches'])}** | 消融实验的可比性前提；期望 0 |",
        f"| 空字符类（原 G-1） | **{report['g1']['rejected_count']}** | "
        f"{len(report['g1']['patterns'])} 个模式全部被解析器拒绝（fail-closed） |",
        f"| 零次重复 `a{{0}}`（原 V1-2） | **0** | "
        f"{len(report['zero_repeat']['patterns'])} 个模式均编译为 ε |",
        "",
        "## 空字符类契约（原 G-1，已修复：fail-closed）",
        "",
        "`[^\\d\\D]` 等取反字符类在求补后区间为空，其语言按定义是 **空集 ∅**。"
        "修复选择是让**解析器直接拒绝**空字符类，而不是引入新的 AST 节点：",
        "",
        "```",
        "nfa.compile_pattern(r\"[^\\d\\D]\")   # RegexSyntaxError",
        "re.compile(r\"[^\\d\\D]\")             # 接受（语言 = ∅，永不匹配）",
        "```",
        "",
        "这是**有意的子集边界**：本仓把空字符类归入「受支持子集」之外，"
        "由 [`docs/blockers/Core.md`](../../docs/blockers/Core.md) 记录解析器契约。"
        "Rust 侧不解析正则、只解释编译后的 spec，因此该模式在编译期就被拦下，"
        "不会到达电路。",
        "",
        "### 边界对照",
        "",
        "| 模式 | Python `re.compile` | NFA `compile_pattern` | 结论 |",
        "|---|---|---|---|",
    ]
    for p in report["empty_brackets"]["patterns"]:
        lines.append(f"| `{p}` | 拒绝 | 拒绝 | 两端一致（都 fail closed） |")

    lines += [
        "",
        "## 零次重复 `a{0}`（原 V1-2，已修复）",
        "",
        "| 模式 | NFA `compile_pattern` | 匹配空串 | 消耗 `a` |",
        "|---|---|---|---|",
    ]
    for c in report["zero_repeat"]["entries"]:
        lines.append(
            f"| `{c['pattern']}` | {c['nfa']} | {c['match_empty']} | "
            f"{c['consumes_a']} |")
    lines += [
        "",
        "`_Builder._chain([])`（零次重复展开后为空）现在返回一个显式的 ε 片段"
        "（`s --ε--> t`），并修掉了原先指向不存在方法 `_build` 的笔误。"
        "注意 `match_search` 是 **search** 语义：零宽匹配会让 `a{0}` 在 `\"a\"` "
        "上也返回真，但它**不消耗**任何字符（`anchored_full_match` 为假）。",
        "",
        "",
        "## Python ↔ Rust 对拍",
        "",
    ]
    if rust.get("available"):
        lines += [
            f"驱动：`{rust['binary']}`；样本 {rust.get('comparisons', 0)} 对。",
            "",
            "| 比较 | mismatch 数 |",
            "|---|---:|",
            f"| Python Pike vs Rust `--check` | "
            f"**{len(rust.get('python_vs_rust_mismatches', []))}** |",
            f"| Rust vs Python `re` | "
            f"**{len(rust.get('rust_vs_re_mismatches', []))}** |",
            "",
            "修复后两种实现与 Python `re` 均一致（空字符类在编译期被拒绝，"
            "零次重复编译为 ε）。",
        ]
    else:
        lines.append(f"未跑：{rust.get('reason', rust.get('status'))}")

    lines += [
        "",
        "## 复现",
        "",
        "```bash",
        "python3 -m unittest tests.test_fuzz_rules -v",
        "# 有构建产物时加 Rust 对拍：",
        "POP_SCRIPT=/path/to/pop-script python3 -m unittest tests.test_fuzz_rules -v",
        "```",
        "",
    ]
    return "\n".join(lines) + "\n"


def write_report(report: Dict[str, Any]) -> None:
    out_dir = REPO / "bench" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "fuzz.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "fuzz.md").write_text(render_md(report), encoding="utf-8")


# --------------------------------------------------------------------------- #
# 测试
# --------------------------------------------------------------------------- #

class TestDifferentialPikeVsRe(unittest.TestCase):
    """受支持子集上，Pike VM 与 Python ``re.search`` 必须逐例一致。"""

    def test_no_unexpected_mismatch(self):
        report = run_sweep()
        unexpected = [m for m in report["mismatches"] if not m["known_gap"]]
        self.assertEqual(
            [], unexpected,
            "Pike VM 与 Python re 在受支持子集上出现分歧（前 5 条）：\n"
            + "\n".join(str(m) for m in unexpected[:5]))

    def test_pike_equals_naive(self):
        report = run_sweep()
        self.assertEqual(
            [], report["pike_vs_naive_mismatches"],
            "Pike 与朴素匹配器判定不一致 —— 消融实验的比值不再可比：\n"
            + "\n".join(str(m) for m in report["pike_vs_naive_mismatches"][:5]))

    def test_report_artifact(self):
        report = run_sweep()
        write_report(report)
        out_json = REPO / "bench" / "results" / "fuzz.json"
        out_md = REPO / "bench" / "results" / "fuzz.md"
        self.assertTrue(out_json.is_file())
        self.assertTrue(out_md.is_file())
        self.assertGreater(report["counts"]["comparisons"], 1000)


class TestEmptyCharacterClassContract(unittest.TestCase):
    """原 G-1：空字符类必须被解析器**拒绝**（fail-closed 子集契约）。"""

    def test_empty_class_rejected_by_parser(self):
        """``[^\\d\\D]`` 等取反后为空的字符类抛 ``RegexSyntaxError``。"""
        for pattern in G1_PATTERNS:
            with self.subTest(pattern=pattern):
                with self.assertRaises(nfa.RegexSyntaxError):
                    nfa.compile_pattern(pattern)

    def test_python_re_accepts_but_nfa_rejects(self):
        """有意分歧：Python 把空字符类当空语言，本仓把它排除出受支持子集。"""
        for pattern in G1_PATTERNS:
            with self.subTest(pattern=pattern):
                re.compile(pattern)          # Python：合法，语言为 ∅
                with self.assertRaises(nfa.RegexSyntaxError):
                    nfa.compile_pattern(pattern)

    def test_compile_policy_fails_closed(self):
        """策略编译层把 ``RegexSyntaxError`` 包成 ``PolicyError``（不是崩溃）。"""
        with self.assertRaises(PolicyError):
            compile_policy(Policy("fuzz", "1", rules=[
                Rule("pattern_block", "pb", {"patterns": [r"[^\d\D]"]})]))

    def test_report_records_rejection(self):
        report = run_sweep()
        entries = report["g1"]["entries"]
        self.assertEqual(len(G1_PATTERNS), len(entries), "空字符类样例没有跑全")
        for e in entries:
            with self.subTest(pattern=e["pattern"]):
                self.assertEqual("rejected_by_parser", e["status"], e)
                self.assertEqual("RegexSyntaxError", e["error_type"], e)
        self.assertEqual(len(G1_PATTERNS), report["g1"]["rejected_count"])

    def test_empty_brackets_rejected_by_both(self):
        """``[]`` / ``[^]`` 是边界对照：两端都必须拒绝，不能一边接受一边拒绝。"""
        for pattern in EMPTY_BRACKET_PATTERNS:
            with self.subTest(pattern=pattern):
                with self.assertRaises(re.error):
                    re.compile(pattern)
                with self.assertRaises(nfa.RegexSyntaxError):
                    nfa.compile_pattern(pattern)


class TestZeroRepeatIsEpsilon(unittest.TestCase):
    """原 V1-2：``a{0}`` / ``a{0,0}`` 等价于 ε，不再崩溃。"""

    def test_zero_repeat_matches_empty_string(self):
        for pattern in ZERO_REPEAT_PATTERNS:
            with self.subTest(pattern=pattern):
                spec = nfa.compile_pattern(pattern)
                self.assertTrue(nfa.match_search(spec, ""))
                self.assertTrue(nfa.match_search_naive(spec, ""))

    def test_zero_repeat_consumes_nothing(self):
        """零宽匹配：``re.search`` 会返回真，但 ``a`` 不会被消耗。

        用 ``anchored_full_match`` / ``find_spans`` 断言「不匹配 a」——它们要求
        一次性消耗 ≥ 1 个字符；这比 ``re.search`` 的布尔值更能区分 ε 与 ``a``。
        """
        for pattern in ZERO_REPEAT_PATTERNS:
            with self.subTest(pattern=pattern):
                spec = nfa.compile_pattern(pattern)
                self.assertFalse(nfa.anchored_full_match(spec, "a", 0, 1))
                self.assertEqual([], nfa.find_spans(spec, "a"))
                self.assertIsNone(re.fullmatch(pattern, "a"))

    def test_zero_repeat_in_concatenation(self):
        """``x a{0} y`` ≡ ``xy``；``x a{0} y`` 不匹配 ``xay``。"""
        spec = nfa.compile_pattern(r"xa{0}y")
        self.assertTrue(nfa.match_search(spec, "xy"))
        self.assertFalse(nfa.match_search(spec, "xay"))

    def test_report_records_fix(self):
        report = run_sweep()
        entries = report["zero_repeat"]["entries"]
        self.assertEqual(len(ZERO_REPEAT_PATTERNS), len(entries))
        for e in entries:
            with self.subTest(pattern=e["pattern"]):
                self.assertTrue(e["match_empty"], e)
                self.assertFalse(e["consumes_a"], e)
                self.assertFalse(e["python_re_fullmatch_a"], e)


@unittest.skipUnless(_rust_binary() is not None,
                     f"pop-script not found: {POP_SCRIPT}（可设 $POP_SCRIPT 覆盖）")
class TestRustParity(unittest.TestCase):
    """可选的 Python↔Rust 对拍：同一份 NFA spec 的两种实现必须同判。"""

    def test_python_rust_parity_on_sample(self):
        report = run_sweep()
        rust = run_rust_parity(report)
        write_report(report)
        self.assertEqual("ok", rust["status"], rust)
        self.assertEqual([], rust["python_vs_rust_mismatches"],
                         "Python Pike 与 Rust 实现判定不一致：\n"
                         + "\n".join(str(m) for m in rust["python_vs_rust_mismatches"][:5]))

    def test_empty_class_rejected_before_rust(self):
        """空字符类在编译期就被 Python 拒绝，不会生成坏 spec 送到 Rust。"""
        with self.assertRaises(nfa.RegexSyntaxError):
            nfa.compile_pattern(r"[^\d\D]")
        with self.assertRaises(PolicyError):
            compile_policy(Policy("fuzz", "1", rules=[
                Rule("pattern_block", "pb", {"patterns": [r"[^\d\D]"]})]))

    def test_rust_naive_zero_repeat_matches_empty(self):
        """``mode=naive`` 下 ``a{0}`` 对空文本也必须判违规（Rust 侧 ε 修复）。"""
        binary = _rust_binary()
        self.assertIsNotNone(binary)
        spec = compile_policy(Policy("fuzz", "1", rules=[
            Rule("pattern_block", "pb",
                 {"patterns": [r"a{0}"], "match_mode": "naive"})]))
        vectors = [{"name": "empty", "response": "",
                    "spec_canonical": spec_canonical_text(spec)}]
        with tempfile.TemporaryDirectory() as td:
            vp, op = Path(td) / "vectors.json", Path(td) / "out.json"
            vp.write_text(json.dumps({"vectors": vectors}), encoding="utf-8")
            proc = subprocess.run([str(binary), "--check", "--vectors", str(vp),
                                   "--out", str(op)],
                                  capture_output=True, text=True, timeout=120)
            self.assertEqual(0, proc.returncode, proc.stderr[-500:])
            row = json.loads(op.read_text(encoding="utf-8"))[0]
        self.assertTrue(row["violations"],
                        "Rust naive 匹配器把空文本上的 a{0} 判成了不匹配 —— "
                        "ε 语义未同步")

    def test_rust_treats_empty_ranges_as_empty_language(self):
        """Rust 解释器对 ``ranges: []`` 的边不匹配任何字符（∅，而不是 ε）。

        空字符类已不可能经由编译器产生 spec；这条直接构造一份「空区间边」的
        spec，钉住 Rust 侧的解释语义与 Python ``Lit([]) → ε`` 的旧 bug 不同。
        """
        binary = _rust_binary()
        self.assertIsNotNone(binary)
        spec = {
            "spec_version": "v1", "policy_id": "g1", "policy_version": "1",
            "semantic": "and",
            "constraints": [{
                "kind": "pattern_block", "name": "pb",
                "patterns": [r"[^\d\D]"],
                "nfa": {"compiled": [{
                    "start": 0, "accept": [1],
                    "states": [
                        {"eps": [], "edges": [{"to": 1, "ranges": []}]},
                        {"eps": [], "edges": []},
                    ],
                }]},
            }],
        }
        vectors = [{"name": "empty", "response": "",
                    "spec_canonical": spec_canonical_text(spec)}]
        with tempfile.TemporaryDirectory() as td:
            vp, op = Path(td) / "vectors.json", Path(td) / "out.json"
            vp.write_text(json.dumps({"vectors": vectors}), encoding="utf-8")
            proc = subprocess.run([str(binary), "--check", "--vectors", str(vp),
                                   "--out", str(op)],
                                  capture_output=True, text=True, timeout=120)
            self.assertEqual(0, proc.returncode, proc.stderr[-500:])
            row = json.loads(op.read_text(encoding="utf-8"))[0]
        self.assertFalse(row["violations"],
                         "Rust 把空区间边当成了 ε —— 与「空类 = ∅」的契约不符")


def tearDownModule() -> None:
    """整模块跑完后落盘最终报告（含 Rust 对拍结果）。"""
    if _REPORT is not None:
        write_report(_REPORT)


if __name__ == "__main__":
    unittest.main()
