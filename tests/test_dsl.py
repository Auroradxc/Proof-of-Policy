"""Proof-of-Policy DSL 的单元测试（基于标准库 unittest，无第三方依赖）。

覆盖两条主链路：``check`` 是 Python 参考评估器的语义基准；``compile_policy``
产出的规范要与 Rust/SP1 侧逐字节对齐。两者都必须行为稳定、可复现。
"""

import dataclasses
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl import trace  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.evaluate import check  # noqa: E402
from policydsl.model import Policy, PolicyError, Rule, Transcript  # noqa: E402

#: 固定时间戳的一次性网关 —— 让测试里的回执链可复现。
GW_TS = "2026-01-01T00:00:00+00:00"


def signed(calls: list) -> list:
    """把 ``[(tool, args), ...]`` 签成网关回执链（P1-5）。"""
    return trace.make_chain(calls, gateway=trace.ToolGateway(ts=GW_TS))


class TestKeywordBlock(unittest.TestCase):
    """keyword_block：命中任一关键词即违规（策略语义是「禁止」）。"""

    def test_hit_is_violation(self):
        # 命中即判失败，且证据要能溯源到具体的关键词与规则类型。
        p = Policy("t", "1", rules=[Rule("keyword_block", "kb", {"keywords": ["bitcoin", "leverage"]})])
        r = check(p, "Buy bitcoin now!")
        self.assertFalse(r.passed)
        self.assertEqual(r.violations[0].evidence_kind, "keyword")
        self.assertIn("bitcoin", r.violations[0].evidence)

    def test_clean_passes(self):
        # 不含任何关键词的文本应当放行，避免过度拦截。
        p = Policy("t", "1", rules=[Rule("keyword_block", "kb", {"keywords": ["bitcoin", "leverage"]})])
        self.assertTrue(check(p, "Safe financial advice").passed)


class TestLengthBound(unittest.TestCase):
    """length_bound：文本长度上下界，越界即违规。"""

    def test_too_long(self):
        # 超出 max 必须失败。
        p = Policy("t", "1", rules=[Rule("length_bound", "lb", {"min": 1, "max": 10})])
        self.assertFalse(check(p, "x" * 11).passed)

    def test_within_bounds(self):
        # 落在 [min, max] 区间内则通过。
        p = Policy("t", "1", rules=[Rule("length_bound", "lb", {"min": 1, "max": 10})])
        self.assertTrue(check(p, "short").passed)


class TestPatternBlock(unittest.TestCase):
    """pattern_block：文本命中正则模式即违规（底层走可序列化的 NFA 引擎）。"""

    def test_email_detected(self):
        # 文本含邮箱形状的子串 -> 违规。
        p = Policy("t", "1", rules=[Rule("pattern_block", "pb", {"patterns": [r"[\w.+-]+@[\w-]+\.[\w.]+"]})])
        self.assertFalse(check(p, "contact me at a@b.com").passed)

    def test_no_pattern_passes(self):
        # 无任何匹配子串 -> 放行。
        p = Policy("t", "1", rules=[Rule("pattern_block", "pb", {"patterns": [r"sk-[A-Za-z0-9]{20,}"]})])
        self.assertTrue(check(p, "no secrets here").passed)


class TestAndSemantics(unittest.TestCase):
    """一条策略内多条规则是「与」语义：全部通过才算整条策略通过。"""

    def test_all_rules_required(self):
        p = Policy(
            "t", "1",
            rules=[
                Rule("keyword_block", "kb", {"keywords": ["bad"]}),
                Rule("length_bound", "lb", {"min": 1, "max": 5}),
            ],
        )
        self.assertFalse(check(p, "bad word here").passed)      # 命中关键词规则
        self.assertFalse(check(p, "this is too long").passed)   # 命中长度规则
        self.assertTrue(check(p, "ok").passed)                  # 两条规则均通过


class TestCompile(unittest.TestCase):
    """compile_policy：把 Policy 编译为规范（spec），产出需结构固定且确定可复现。"""

    def test_spec_shape(self):
        # 规范结构固定：版本号 + 约束列表 + 内容哈希。
        p = Policy("p", "0.1", rules=[Rule("keyword_block", "kb", {"keywords": ["a", "B"]})])
        s = compile_policy(p)
        self.assertEqual(s["spec_version"], "v1")
        self.assertEqual(s["constraints"][0]["keywords"], ["a", "b"])  # 关键词归一化为小写并排序，保证跨语言一致
        self.assertEqual(len(s["sha256"]), 64)

    def test_spec_is_deterministic(self):
        # 同一策略多次编译必须得到同一 sha256：电路与链上锚定都依赖这份确定性。
        p = Policy("p", "0.1", rules=[Rule("keyword_block", "kb", {"keywords": ["a", "B"]})])
        self.assertEqual(compile_policy(p)["sha256"], compile_policy(p)["sha256"])


class TestValidation(unittest.TestCase):
    """策略校验：非法参数应在编译前快速失败（fail-fast），而非延迟到求值期。"""

    def test_missing_keywords(self):
        # keywords 为空没有语义，应当报 PolicyError。
        with self.assertRaises(PolicyError):
            Policy("p", "1", rules=[Rule("keyword_block", "kb", {"keywords": []})]).validate()

    def test_bad_length_range(self):
        # min > max 是非法区间。
        with self.assertRaises(PolicyError):
            Policy("p", "1", rules=[Rule("length_bound", "lb", {"min": 5, "max": 1})]).validate()


class TestFormatCheck(unittest.TestCase):
    """format_check：校验文本本身是否为指定格式（json / int）。"""

    def test_json_ok(self):
        # 合法 JSON 文本通过。
        p = Policy("t", "1", rules=[Rule("format_check", "fc", {"format": "json"})])
        self.assertTrue(check(p, '{"ok": true}').passed)

    def test_json_bad(self):
        # 非 JSON 文本违规，证据类型为 format。
        p = Policy("t", "1", rules=[Rule("format_check", "fc", {"format": "json"})])
        r = check(p, "not a json document")
        self.assertFalse(r.passed)
        self.assertEqual(r.violations[0].evidence_kind, "format")

    def test_int_ok_and_bad(self):
        # int 解析应容忍首尾空白，但拒绝非数字文本。
        ok = Policy("t", "1", rules=[Rule("format_check", "fc", {"format": "int"})])
        bad = Policy("t", "1", rules=[Rule("format_check", "fc", {"format": "int"})])
        self.assertTrue(check(ok, " 42 ").passed)
        self.assertFalse(check(bad, "forty two").passed)

    def test_unknown_format_rejected(self):
        # 未支持的格式枚举（yaml）在 validate 阶段即拒绝。
        with self.assertRaises(PolicyError):
            Policy("t", "1", rules=[Rule("format_check", "fc", {"format": "yaml"})]).validate()


class TestToolArgGuard(unittest.TestCase):
    """tool_arg_guard：工具调用参数黑名单，防止密钥等敏感字段被带出。"""

    def test_forbidden_field_present(self):
        # 参数中出现 password -> 违规，证据需指出具体字段名，便于审计定位。
        p = Policy("t", "1", rules=[
            Rule("tool_arg_guard", "tag", {"forbidden_fields": ["password", "token"]})])
        tx = Transcript(receipts=signed([("search", {"q": "hi", "password": "secret"})]))
        r = check(p, tx)
        self.assertFalse(r.passed)
        self.assertEqual(r.violations[0].evidence_kind, "tool_arg")
        self.assertEqual(r.violations[0].evidence["field"], "password")

    def test_clean_passes(self):
        # 参数中不含敏感字段则通过。
        p = Policy("t", "1", rules=[
            Rule("tool_arg_guard", "tag", {"forbidden_fields": ["password", "token"]})])
        tx = Transcript(receipts=signed([("search", {"q": "hi"})]))
        self.assertTrue(check(p, tx).passed)

    def test_tools_restriction(self):
        # tools 白名单只检查指定工具的调用；此处违规字段出现在未受检的工具上，故仍通过。
        p = Policy("t", "1", rules=[
            Rule("tool_arg_guard", "tag",
                 {"forbidden_fields": ["token"], "tools": ["search"]})])
        tx = Transcript(receipts=signed(
            [("http_get", {"url": "https://x?a", "token": "t"})]))
        self.assertTrue(check(p, tx).passed)

    def test_broken_chain_fails_closed(self):
        # P1-5：链结构不自洽时工具规则一律不通过 —— 不能退化成「读不出来就当没调用」。
        p = Policy("t", "1", rules=[
            Rule("tool_arg_guard", "tag", {"forbidden_fields": ["password"]})])
        chain = signed([("search", {"q": "hi"})])
        broken = [dataclasses.replace(chain[0], seq=7)]
        r = check(p, Transcript(receipts=broken))
        self.assertFalse(r.passed)
        self.assertEqual(r.violations[0].evidence_kind, "trace_unbound")


class TestBudgetBound(unittest.TestCase):
    """budget_bound：按调用次数或 token 数设定的预算上界。"""

    def test_call_count_over(self):
        # 3 次调用超过预算 2 -> 违规，证据里给出实际总次数以便核对。
        p = Policy("t", "1", rules=[
            Rule("budget_bound", "bb", {"budget": 2, "unit": "calls"})])
        tx = Transcript(receipts=signed([("a", {}), ("b", {}), ("c", {})]))
        r = check(p, tx)
        self.assertFalse(r.passed)
        self.assertEqual(r.violations[0].evidence["total"], 3)

    def test_call_count_at_budget_passes(self):
        # 恰好用满预算不算超支（上界取闭区间）。
        p = Policy("t", "1", rules=[
            Rule("budget_bound", "bb", {"budget": 2, "unit": "calls"})])
        tx = Transcript(receipts=signed([("a", {}), ("b", {})]))
        self.assertTrue(check(p, tx).passed)

    def test_token_budget_is_computed_not_declared(self):
        # P1-5：tokens 语义改为「响应按固定空白集合切分后的 run 数」，在电路内
        # 自算。Transcript 里已经没有可以自填的 token_count 了 —— 超限只能靠
        # 真的写出这么多 token 来触发（下面 150 个 run > 预算 100）。
        p = Policy("t", "1", rules=[
            Rule("budget_bound", "bb", {"budget": 100, "unit": "tokens"})])
        self.assertFalse(check(p, " ".join(["w"] * 150)).passed)
        self.assertTrue(check(p, "only three words").passed)
        # 边界取闭区间：恰好 100 个 run 不算超
        self.assertTrue(check(p, " ".join(["w"] * 100)).passed)

    def test_bad_budget(self):
        # 负预算无意义，属非法配置。
        with self.assertRaises(PolicyError):
            Policy("t", "1", rules=[
                Rule("budget_bound", "bb", {"budget": -1, "unit": "calls"})]).validate()


class TestCompileExtendedKinds(unittest.TestCase):
    """后加入的三种约束类型也应被 compile_policy 正确编译进规范。"""

    def test_new_kinds_compile(self):
        # 约束顺序与规则声明顺序一致，各类型的关键参数原样保留。
        p = Policy(
            "p", "0.1", rules=[
                Rule("format_check", "fc", {"format": "json"}),
                Rule("tool_arg_guard", "tag",
                     {"forbidden_fields": ["password", "token"], "tools": ["http_get"]}),
                Rule("budget_bound", "bb", {"budget": 5, "unit": "calls"}),
            ])
        s = compile_policy(p)
        kinds = [c["kind"] for c in s["constraints"]]
        self.assertEqual(kinds, ["format_check", "tool_arg_guard", "budget_bound"])
        self.assertEqual(s["constraints"][1]["forbidden_fields"], ["password", "token"])
        self.assertEqual(s["constraints"][2]["budget"], 5)


if __name__ == "__main__":
    unittest.main()
