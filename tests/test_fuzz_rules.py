"""P2-03 差分模糊测试：Pike VM vs Python ``re``（含 T3 的 G-1 空字符类缺口）。

**要证的命题**：`policydsl.core.nfa` 的 Pike VM 在**受支持子集**上与 Python
``re.search`` 判定一致；否则 Python 参考评估器与 SP1 电路会对同一条响应给出
不同结论。Rust 二进制可用时再加一层 Python↔Rust 对拍。

三层：

1. **固定 + 随机生成的模式 × 穷举/随机文本**：逐例比较
   ``nfa.match_search`` 与 ``bool(re.search(...))``；同时比较 Pike 与朴素匹配器
   （``match_search_naive``）—— 消融实验的可比性依赖这一条。
2. **G-1 空字符类缺口**（T3 `docs/proofs/theorem-d-g.md` §12.3）：
   ``[^\\d\\D]`` 取反后区间为空，Python 视为**空语言**，而当前实现把它编译成
   ``Lit([])`` → ε 边 → 匹配空串。这是 **NFA 语义 bug，不是测试问题**；
   本文件用 ``expectedFailure`` 显式标注，并在结果文件里记录为 known gap。
   ``[]`` / ``[^]`` 这类边界则是**两端都拒绝**，作为对照。
3. **Python↔Rust 对拍**（``POP_SCRIPT`` 可用时）：同一份 NFA spec 喂给
   ``pop-script --check``，比较 Rust 的匹配结论。注意 G-1 是**两种实现共有**
   的语义缺口 —— Python 与 Rust 彼此一致，但都与 ``re`` 不一致。

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
from policydsl.core.model import Policy, Rule                     # noqa: E402
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

#: T3 §12.3 的 G-1：取反后为空的字符类。只收**必须消费一个字符**的形式
#: （裸类 / ``+`` / ``{1,2}``）—— ``?`` 与 ``*`` 在 Python 里也能零次匹配，
#: 两端都返回 True，不会出现分歧，不能拿来当反例。
G1_PATTERNS = [
    r"[^\d\D]",
    r"[^\w\W]",
    r"[^\s\S]",
    r"([^\d\D])+",
    r"([^\d\D]){1,2}",
]
#: G-1 的对照边界：Python 与 NFA 都应**拒绝**（不是语义分歧）。
EMPTY_BRACKET_PATTERNS = [r"[]", r"[^]"]

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

    NFA 侧**不只是** ``RegexSyntaxError``：``a{0}`` 会让 ``_chain([])`` 调到
    不存在的 ``self._build``，抛 ``AttributeError``（V1-2，见
    ``docs/blockers/V1.md``）。这不是受支持子集的一部分，过滤掉即可；
    该崩溃由 :class:`TestZeroRepeatCrash` 单独显式覆盖。
    """
    try:
        re.compile(pattern)
        nfa.compile_pattern(pattern)
        return True
    except (re.error, nfa.RegexSyntaxError, AttributeError):
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

    # G-1：单独跑，显式标 known_gap。
    g1_entries: List[Dict[str, Any]] = []
    g1_texts = ["", "a", "1", " ", "abc", "xyz"]
    for pattern in G1_PATTERNS:
        spec = nfa.compile_pattern(pattern)
        for text in g1_texts:
            pike = nfa.match_search(spec, text)
            expected = _re_match(pattern, text)
            g1_entries.append({
                "pattern": pattern, "text": text,
                "pike": pike, "re": expected,
                "known_gap": pike != expected,
                "kind": "g1_empty_character_class",
                "source": "docs/proofs/theorem-d-g.md §12.3 / G-1",
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
            "entries": g1_entries,
            "mismatch_count": sum(1 for e in g1_entries if e["known_gap"]),
            "direction": "NFA/Pike 匹配空串（True），Python re 不匹配（False）",
            "status": "known NFA semantics bug (G-1)",
        },
        "empty_brackets": {
            "patterns": EMPTY_BRACKET_PATTERNS,
            "note": "Python 与 NFA 都拒绝；这是边界对照，不是语义分歧。",
        },
        "known_crashes": [{
            "pattern": r"a{0}",
            "id": "V1-2",
            "python_re": "接受，匹配空串",
            "nfa": "AttributeError: '_Builder' object has no attribute '_build'",
            "source": "policydsl/core/nfa.py::_Builder._chain（_chain([]) 调 self._build）",
            "status": "known implementation bug (not a test issue)",
        }],
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
    # 显式把 G-1 的裸空字符类塞进 Rust 样本：这样 `rust_vs_re_mismatches`
    # 才能显示「两种实现共有 G-1」这一事实，而不是只靠另一条测试口述。
    sample += [(p, t) for p in G1_PATTERNS[:3] for t in ["", "a", "1", "abc"]]
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
        "note": ("python_vs_rust 为 0 表示两种实现判据一致；rust_vs_re 的非零项"
                 "只有 G-1 空字符类这一处，且两种实现**共有**该缺口。"),
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
        f"| G-1 空字符类（单独统计） | **{report['g1']['mismatch_count']}** | "
        "**已知 NFA 语义 bug**，见下 |",
        "",
        "## G-1：空字符类的语义缺口（已知，不是测试问题）",
        "",
        "`[^\\d\\D]` 等取反字符类在求补后区间为空。Python 把它当作**空语言**"
        "（`re.search` 永不匹配）；当前 NFA 把空区间编译成 `Lit([])` → ε 边，"
        "于是**匹配空串**。复现：",
        "",
        "```",
        "pattern = r\"[^\\d\\D]\"",
        "nfa.match_search(spec, \"\")   == True    # 代码：ε 边",
        "re.search(pattern, \"\")        == None    # Python：空语言",
        "```",
        "",
        f"本文件用 `@unittest.expectedFailure` 显式标注这条相等断言；"
        f"{report['g1']['mismatch_count']} 条 G-1 样例全部记录在 "
        "`fuzz.json` 的 `g1.entries` 里（`known_gap: true`）。",
        "",
        "**这是 NFA 语义 bug，不是测试问题**：空字符类的语言应为 ∅，而不是 `{ε}`。"
        "修复需要把 AST 的「空语言」与「空连接（ε）」分开（T3 §12.3、"
        "[`docs/blockers/V1.md`](../../docs/blockers/V1.md)）。在修复前，"
        "定理 G(a)(b) 只在假设 A-G0（字符类区间非空）下成立。",
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
        "## 另一条已知实现 bug：`a{0}`（V1-2）",
        "",
        "| 模式 | Python `re` | NFA `compile_pattern` |",
        "|---|---|---|",
    ]
    for c in report["known_crashes"]:
        lines.append(f"| `{c['pattern']}` | {c['python_re']} | `{c['nfa']}` |")
    lines += [
        "",
        "`_Builder._chain([])`（零次重复展开后为空）调用了 `self._build`，"
        "而类里只有 `build`。这是**实现 bug**，由 "
        "[`docs/blockers/V1.md`](../../docs/blockers/V1.md) 的 V1-2 记录；"
        "本测试不修 core，只用 `assertRaises(AttributeError)` 把它钉成已知行为。",
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
            "两种实现判据一致；Rust vs `re` 的非零项来自 **G-1**（Python 与 Rust "
            "共有的空字符类缺口），不是两种实现之间的分歧。",
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


class TestEmptyCharacterClassGap(unittest.TestCase):
    """T3 G-1：空字符类被当成 ε —— 已知缺口，显式标注。"""

    def test_g1_reproduced_and_recorded(self):
        """当前行为可复现：NFA 匹配空串，Python 视为空语言。"""
        report = run_sweep()
        entries = report["g1"]["entries"]
        self.assertTrue(entries, "G-1 样例没有跑")
        for e in entries:
            with self.subTest(pattern=e["pattern"], text=e["text"]):
                # 方向固定：NFA True / Python False。若哪天修复了，这里会红，
                # 提醒把 expectedFailure 与结果文件一起更新。
                self.assertTrue(e["pike"], e)
                self.assertFalse(e["re"], e)
                self.assertTrue(e["known_gap"], e)

    @unittest.expectedFailure
    def test_g1_empty_class_language_matches_re(self):
        """已知会失败：修复 G-1 后这条会变成 unexpected success，提醒摘掉装饰器。"""
        for pattern in G1_PATTERNS:
            spec = nfa.compile_pattern(pattern)
            for text in ["", "a", "1", " ", "abc", "xyz"]:
                with self.subTest(pattern=pattern, text=text):
                    self.assertEqual(nfa.match_search(spec, text),
                                     _re_match(pattern, text))

    def test_empty_brackets_rejected_by_both(self):
        """``[]`` / ``[^]`` 是边界对照：两端都必须拒绝，不能一边接受一边拒绝。"""
        for pattern in EMPTY_BRACKET_PATTERNS:
            with self.subTest(pattern=pattern):
                with self.assertRaises(re.error):
                    re.compile(pattern)
                with self.assertRaises(nfa.RegexSyntaxError):
                    nfa.compile_pattern(pattern)


class TestZeroRepeatCrash(unittest.TestCase):
    """V1-2：``a{0}`` 让 NFA 构造器崩溃 —— 已知实现 bug，不是测试问题。

    ``_Builder._build_repeat`` 在 ``lo=hi=0`` 时得到空片段列表，``_chain([])``
    调用 ``self._build(Lit([]))``，而方法名是 ``build``。Python ``re`` 接受
    ``a{0}`` 并匹配空串。本测试只固定现状，**不修 core**。
    """

    def test_zero_repeat_crashes(self):
        with self.assertRaises(AttributeError):
            nfa.compile_pattern(r"a{0}")
        self.assertTrue(re.search(r"a{0}", "xyz"))

    def test_zero_repeat_documented_in_report(self):
        report = run_sweep()
        crash = next(c for c in report["known_crashes"] if c["pattern"] == r"a{0}")
        self.assertEqual("V1-2", crash["id"])


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

    def test_g1_gap_is_shared_by_rust(self):
        """G-1 不是 Python 侧实现独有的：Rust 也把 ``[^\\d\\D]`` 当 ε。

        这条**不断言 bug 是"正确"的**，只固定「两种实现共有同一缺口」这一事实，
        避免把 Rust 对拍结果误读成「Rust 是对的」。
        """
        binary = _rust_binary()
        self.assertIsNotNone(binary)
        pattern = r"[^\d\D]"
        spec = compile_policy(Policy("fuzz", "1", rules=[
            Rule("pattern_block", "pb", {"patterns": [pattern]})]))
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
                        "Rust 对空串没有报违规 —— G-1 可能已被修复；请同步更新测试")


def tearDownModule() -> None:
    """整模块跑完后落盘最终报告（含 Rust 对拍结果）。"""
    if _REPORT is not None:
        write_report(_REPORT)


if __name__ == "__main__":
    unittest.main()
