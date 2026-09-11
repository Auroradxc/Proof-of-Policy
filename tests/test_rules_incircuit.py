"""电路内规则（format_check / tool_arg_guard / budget_bound）的覆盖测试。

两类对齐，缺一不可：

1. **判定对齐**：Python golden 评估器与 Rust ``pop-script --check`` 对同一
   spec + 输入必须给出相同的违规集合（kind 一致、passed 一致）。Python 是
   参考语义，Rust 是真正进电路的那份实现，二者分叉就意味着「链下说违规、
   链上说通过」（或反之）。
2. **证据承诺对齐**（私有模式）：违规证据要序列化成**规范的**证据字符串再哈希，
   两端必须逐字节相同，否则承诺对不上、审计无法复现。

`format_check` 采用严格规范子集（拒绝 Python 里能解析但语义含糊的写法，如
``1_000`` / ``nan`` / 超长整数），这里的边界用例就是在钉死这个子集。
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl import commit, trace  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402
from policydsl.serialize import spec_canonical_text  # noqa: E402

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"

#: 固定时间戳的一次性网关 —— 让向量里的回执链可复现。
GW_TS = "2026-01-01T00:00:00+00:00"


def chain(*calls: tuple) -> list:
    """把 ``[(tool, args, result), ...]`` 签成网关回执链（JSON 形状，P1-5）。"""
    return trace.receipts_to_json(
        trace.make_chain(list(calls), gateway=trace.ToolGateway(ts=GW_TS)))


def broken(calls: tuple) -> list:
    """签一条链再把某一条的 ``seq`` 改坏 —— 结构校验必须挡住它。"""
    import dataclasses

    items = chain(calls)
    items[0] = dataclasses.asdict(
        dataclasses.replace(trace.ToolReceipt.from_dict(items[0]), seq=99))
    return items


def run_check(vector: dict) -> dict:
    """把单个向量喂给 Rust ``pop-script --check``，返回它给出的检查结果。

    走 CLI 而非 FFI，是为了测到与生产完全相同的代码路径（含 serde 反序列化）。
    """
    with tempfile.TemporaryDirectory() as tmp:
        vp, op = Path(tmp) / "v.json", Path(tmp) / "r.json"
        vp.write_text(json.dumps({"vectors": [vector]}))
        subprocess.run([str(POP_SCRIPT), "--check", "--vectors", str(vp), "--out", str(op)],
                       cwd=str(REPO), check=True, capture_output=True, text=True)
        return json.loads(op.read_text())[0]


def spec_of(rules):
    """把一组规则编译成 ConstraintSpec（本文件反复用到的简写）。"""
    return compile_policy(Policy("t", "1", rules=rules))


@unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built")
class TestRulesInCircuit(unittest.TestCase):
    """Python golden 与电路内 Rust 实现的逐点判定对齐。"""

    # 一次性建好各规则的最小 spec，避免每个用例重复编译。
    def setUp(self):
        self.fmt = spec_of([Rule("format_check", "must_be_json", {"format": "json"})])
        self.tool = spec_of([Rule("tool_arg_guard", "no_secret_args",
                                  {"forbidden_fields": ["password", "token"]})])
        self.budget = spec_of([Rule("budget_bound", "call_budget",
                                    {"budget": 2, "unit": "calls"})])
        self.tokens = spec_of([Rule("budget_bound", "token_budget",
                                    {"budget": 100, "unit": "tokens"})])

    # 对齐断言的核心：golden 与 Rust 两边的违规 kind 集合、以及 passed 都要相同。
    def _parity(self, spec, response, golden_kinds, extras=None):
        vector = {"name": "t", "response": response,
                  "spec_canonical": spec_canonical_text(spec)}
        vector.update(extras or {})
        got = run_check(vector)
        canon = commit.canonical_violations(spec, response,
                                            (extras or {}).get("receipts"))
        self.assertEqual(sorted(v["kind"] for v in canon), sorted(golden_kinds))
        self.assertEqual(sorted(v["kind"] for v in got["violations"]), sorted(golden_kinds))
        self.assertEqual(got["passed"], not golden_kinds)
        return got

    # json 格式：合法 JSON 放行、非 JSON 判违规（最基本的一条）。
    def test_format_json(self):
        self._parity(self.fmt, '{"a": 1}', [])
        self._parity(self.fmt, "not json", ["format_check"])

    # 整数格式只接受**规范**写法：两侧空白与负号可以，但下划线分隔、超出
    # 19 位（i64/u64 有效范围）等歧义写法一律判违规，保证两端解析无分歧。
    def test_format_int_canonical_subset(self):
        intspec = spec_of([Rule("format_check", "must_be_int", {"format": "int"})])
        self._parity(intspec, " 42 ", [])
        self._parity(intspec, "-7", [])
        self._parity(intspec, "1_000", ["format_check"])      # 不允许下划线分隔
        self._parity(intspec, "9" * 20, ["format_check"])     # 超过 19 位不允许
        self._parity(intspec, "12a", ["format_check"])

    # 浮点同理：只接受规范十进制/科学计数；nan/inf/下划线分隔属于非规范写法，
    # 且 NaN 等在各语言比较语义不同，必须拒掉。
    def test_format_float_canonical_subset(self):
        fspec = spec_of([Rule("format_check", "must_be_float", {"format": "float"})])
        self._parity(fspec, "3.14", [])
        self._parity(fspec, "1e5", [])
        self._parity(fspec, "nan", ["format_check"])
        self._parity(fspec, "inf", ["format_check"])
        self._parity(fspec, "1_0.5", ["format_check"])

    # Python 的 json.loads 默认接受 NaN/Infinity，而标准 JSON 不允许；
    # 这里钉死「按标准 JSON 判」，防止 Python 侧的宽松解析造成两端分叉。
    def test_json_rejects_non_finite(self):
        self._parity(self.fmt, "NaN", ["format_check"])

    # 工具参数守卫：命中禁用字段（password/token）即违规；无工具调用时不误报。
    # P1-5 起判的是**网关回执链**（不是自填的 tool_calls）。
    def test_tool_arg_guard(self):
        self._parity(self.tool, "", [], {"receipts": chain(("s", {"q": "x"}, "ok"))})
        self._parity(self.tool, "", ["tool_arg_guard"],
                     {"receipts": chain(("s", {"q": "x", "token": "t"}, "ok"))})

    # ``tools`` 白名单把守卫限定到指定工具：非白名单工具即使带禁用字段也不该被拦，
    # 否则策略会越权误伤（这是最容易写反的一处）。
    def test_tool_arg_guard_tools_restriction(self):
        spec = spec_of([Rule("tool_arg_guard", "g",
                             {"forbidden_fields": ["token"], "tools": ["search_kb"]})])
        self._parity(spec, "", [], {"receipts": chain(("other", {"token": "t"}, "ok"))})
        self._parity(spec, "", ["tool_arg_guard"],
                     {"receipts": chain(("search_kb", {"token": "t"}, "ok"))})

    # 链结构不自洽（这里把第 0 条的 seq 改坏）时，工具规则**两端都**必须
    # fail-closed 记 trace_unbound —— 而不是「读不出来就当作零次调用」。
    def test_broken_chain_fails_closed_in_both(self):
        self._parity(self.tool, "", ["trace_unbound"],
                     {"receipts": broken(("s", {"q": "x"}, "ok"))})
        self._parity(self.budget, "", ["trace_unbound"],
                     {"receipts": broken(("a", {}, "ok"))})

    # 预算约束两种单位（calls / tokens）的判定：未超出上限放行，超出即违规。
    # 判据是「total > budget」（恰好等于预算视为通过），这里取未超与超出两点。
    # tokens 那一支现在数的是**响应**的确定性 token 数（P1-5 语义变更）。
    def test_budget_calls_and_tokens(self):
        self._parity(self.budget, "", [], {"receipts": chain(("a", {}, "ok"))})
        self._parity(self.budget, "", ["budget_bound"],
                     {"receipts": chain(("a", {}, "1"), ("b", {}, "2"), ("c", {}, "3"))})
        self._parity(self.tokens, " ".join(["w"] * 50), [])
        self._parity(self.tokens, " ".join(["w"] * 150), ["budget_bound"])


@unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built")
class TestEvidenceCommitmentParity(unittest.TestCase):
    """私有模式下，违规证据的承诺必须与 Rust 的规范证据串逐字节一致。

    私有模式不公开原始证据，只公开「证据的哈希承诺」；因此承诺串的拼装规则
    是跨语言契约，任何空格/分隔符/字段顺序差异都会导致承诺对不上，链上无法复核。
    """

    # 一次覆盖 format_check 与 tool_arg_guard 两条规则的证据：比较 (rule, kind,
    # 承诺) 三元组，确保差异定位到具体规则而不只是「整体不等」。
    def test_tool_and_format_commitments(self):
        spec = compile_policy(Policy("t", "1", rules=[
            Rule("format_check", "must_be_json", {"format": "json"}),
            Rule("tool_arg_guard", "no_secret_args", {"forbidden_fields": ["password", "token"]}),
        ]))
        response = "not json"
        calls = chain(("search_kb", {"query": "x", "token": "s"}, "ok"))
        vector = {"name": "p", "response": response, "private": True,
                  "spec_canonical": spec_canonical_text(spec), "receipts": calls}
        got = run_check(vector)

        canon = commit.canonical_violations(spec, response, calls)
        expected = sorted((v["rule"], v["kind"], commit.evidence_commitment(v["evidence"]))
                          for v in canon)
        seen = sorted((v["rule"], v["kind"], v["evidence_commitment"])
                      for v in got["violations"])
        self.assertEqual(seen, expected)
        self.assertFalse(got["passed"])


if __name__ == "__main__":
    unittest.main()
