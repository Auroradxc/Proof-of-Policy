"""私有模式原语（policydsl.commit）的单元测试。

这里验证的是 SP1 私有模式程序（``pop-types::evaluate_private``）参考实现的
对外契约：承诺、选择性披露、带见证的脱敏、以及证据开示。这些语义必须与电路
内实现逐字节一致，否则链下证明与链上校验会对不上。
"""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl import commit, nfa, pii  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.evaluate import check  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402


def _spec(rules):
    """把规则列表编译成规范 spec（链下与电路侧共享的中间表示）。"""
    return compile_policy(Policy("t", "1", rules=rules))


class TestCommitment(unittest.TestCase):
    """承诺必须是标准的 SHA-256 十六进制串：链下承诺要能被链上/审计方独立复算。"""

    # 用 hashlib 直接算作参照，确认实现没有做额外加工（加盐/截断/大小写转换）。
    def test_matches_hashlib_and_is_hex32(self):
        t = "hello world"
        self.assertEqual(commit.commitment(t), hashlib.sha256(t.encode()).hexdigest())
        self.assertEqual(len(commit.commitment(t)), 64)

    # 绑定性（binding）：不同输入必须给出不同承诺，同一输入必须稳定复现。
    def test_binding_distinct_inputs(self):
        self.assertNotEqual(commit.commitment("a"), commit.commitment("b"))
        # 确定性：同一输入必须复现同一承诺
        self.assertEqual(commit.commitment("a"), commit.commitment("a"))


class TestSpansAndMask(unittest.TestCase):
    """掩码（mask）与脱敏（redaction）：PII 定位必须精确到字符下标。"""

    # 掩码下标由正则匹配位置决定；这里锁定 email 在文本中的确切区间 [5,20)。
    def test_email_span_and_mask(self):
        text = "ping dev@example.com now"
        mask = commit.mask_from_patterns([pii.PII_PATTERNS["email"]], text)
        self.assertEqual(mask, list(range(5, 20)))  # "dev@example.com" 长 15 字符，位于 [5,20)

    # VDR 风格脱敏：等长、掩码位为 '*'、其余位不变。任何越界改动都必须被拒。
    def test_redaction_roundtrip(self):
        text = "ping dev@example.com now"
        mask = commit.mask_from_patterns([pii.PII_PATTERNS["email"]], text)
        red = commit.redact(text, mask)
        self.assertTrue(commit.redaction_ok(text, red, mask))
        # 掩码位一律填 '*'
        self.assertEqual(red[5:20], "*" * 15)
        # 在掩码之外动一个字符就不算合法脱敏（防止借脱敏之名篡改原文）
        bad = red[:0] + "X" + red[1:]
        self.assertFalse(commit.redaction_ok(text, bad, mask))
        # 长度不等
        self.assertFalse(commit.redaction_ok(text, red + "!", mask))
        # 掩码位没有填掩码字符
        bad2 = red[:5] + "d" + red[6:]
        self.assertFalse(commit.redaction_ok(text, bad2, mask))


class TestCanonicalViolations(unittest.TestCase):
    """规范违规（canonical violations）：与 ``evaluate.check`` 的判定结果必须完全一致。"""

    # 关键一致性测试：同一份 spec 与响应，链下 canonical_violations 与
    # evaluate.check 必须给出同一组 (规则, 类型)；证据字符串也要按规范生成
    # （关键词取 ASCII 小写后的命中词、长度记 "len=N"、正则记模式串本身）。
    def test_matches_evaluate_semantics(self):
        p = Policy("t", "1", rules=[
            Rule("keyword_block", "kb", {"keywords": ["exploit", "DOXXING"]}),
            Rule("length_bound", "lb", {"min": 1, "max": 10}),
            Rule("pattern_block", "pb", {"patterns": [pii.PII_PATTERNS["email"]]}),
        ])
        spec = compile_policy(p)
        resp = "DOXXING someone at a@b.com"  # 共 26 字符，因此长度上限也会被触发
        golden = check(p, resp)
        kind_map = {"keyword": "keyword_block", "length": "length_bound", "pattern": "pattern_block"}
        cset = sorted({(v.rule.name, kind_map[v.evidence_kind]) for v in golden.violations})
        canon = commit.canonical_violations(spec, resp)
        self.assertEqual(sorted({(v["rule"], v["kind"]) for v in canon}), cset)
        self.assertEqual(len(canon), 3)  # 关键词、长度、正则三类同时被触发
        # 每类违规的规范证据字符串
        ev = {v["rule"]: v["evidence"] for v in canon}
        self.assertEqual(ev["kb"], "doxxing")     # 已 ASCII 小写化，且取 spec 顺序下的首个命中词
        self.assertEqual(ev["lb"], "len=26")
        self.assertEqual(ev["pb"], pii.PII_PATTERNS["email"])


class TestPrivateOutput(unittest.TestCase):
    """私有输出：对外只暴露承诺，绝不泄露响应明文或规则名（选择性披露的核心）。"""

    # 未授权时只能看到承诺（64 位十六进制）与通过与否，明文证据不得出现在输出里。
    def test_shape_and_no_leak(self):
        p = Policy("t", "1", rules=[Rule("pattern_block", "no_email",
                                         {"patterns": [pii.PII_PATTERNS["email"]]})])
        spec = compile_policy(p)
        resp = "Contact a@b.com for details"
        out = commit.private_output(spec, resp)
        self.assertFalse(out["passed"])
        self.assertEqual(out["response_commitment"], commit.commitment(resp))
        # 违规条目里只有证据承诺，没有任何证据明文（也无法反推规则名）
        blob = json.dumps(out)
        self.assertNotIn("a@b.com", blob)
        self.assertNotIn("no_email", "".join(v["evidence_commitment"] for v in out["violations"]))
        self.assertEqual(len(out["violations"][0]["evidence_commitment"]), 64)
        self.assertIsNone(out["redaction"])

    # 带脱敏的私有输出：除承诺外再附脱敏结果与覆盖性证明，供审计方核验「只遮了 PII」。
    def test_private_output_with_redaction(self):
        p = Policy("t", "1", rules=[Rule("pattern_block", "no_email",
                                         {"patterns": [pii.PII_PATTERNS["email"]]})])
        spec = compile_policy(p)
        resp = "Contact a@b.com for details"
        mask = commit.mask_from_patterns([pii.PII_PATTERNS["email"]], resp)
        red = commit.redact(resp, mask)
        spans = commit.spec_spans(spec, resp)
        out = commit.private_output(spec, resp, mask, red, spans)
        self.assertEqual(out["redaction"]["mask_count"], len(mask))
        self.assertTrue(out["redaction"]["redaction_ok"])
        self.assertTrue(out["redaction"]["mask_covered"])
        self.assertEqual(out["redaction"]["redacted_commitment"], commit.commitment(red))


class TestMaskCoverage(unittest.TestCase):
    """掩码覆盖性：脱敏必须由「真实匹配区间」背书，不能凭空宣告一段区间。"""

    def _case(self):
        """共享夹具：一条 pattern_block 规则 + 一句含邮箱的响应。"""
        p = Policy("t", "1", rules=[Rule("pattern_block", "no_email",
                                         {"patterns": [pii.PII_PATTERNS["email"]]})])
        spec = compile_policy(p)
        resp = "Contact a@b.com for details"
        return spec, resp

    # 正常路径：见证区间来自真实匹配，因此通过校验且能覆盖掩码。
    def test_real_span_valid_and_covers(self):
        spec, resp = self._case()
        spans = commit.spec_spans(spec, resp)
        self.assertTrue(commit.spans_valid(spec, resp, spans))
        mask = commit.mask_from_patterns([pii.PII_PATTERNS["email"]], resp)
        self.assertTrue(commit.mask_covered(mask, spans))

    # 伪造见证：区间不是任何模式的真实完整匹配时必须被拒绝（否则可随意宣称已遮盖）。
    def test_fabricated_span_invalid(self):
        spec, resp = self._case()
        # "Contact"（0..7）并非 email 匹配，这个区间必须被拒
        bad = [(0, 7)]
        self.assertFalse(commit.spans_valid(spec, resp, bad))
        # 空见证无法覆盖任何被掩码的下标
        self.assertFalse(commit.mask_covered([0, 1], []))

    # 端到端防线：私有输出必须把「掩码超出见证」判为未覆盖，不能放行假见证。
    def test_private_output_rejects_mask_outside_spans(self):
        spec, resp = self._case()
        mask = commit.mask_from_patterns([pii.PII_PATTERNS["email"]], resp)
        spans = commit.spec_spans(spec, resp)
        red = commit.redact(resp, mask)
        # 给一个覆盖不到掩码的（伪造的、过短的）区间
        out = commit.private_output(spec, resp, mask, red, [(0, 1)])
        self.assertFalse(out["redaction"]["mask_covered"])
        # 空见证同样覆盖不了非空掩码
        out2 = commit.private_output(spec, resp, mask, red, [])
        self.assertFalse(out2["redaction"]["mask_covered"])


class TestEvidenceOpening(unittest.TestCase):
    """证据开示：授权后可用明文「打开」承诺，审计方据此对照证明核验。"""

    # 承诺是一次性绑定的：只有原片段能打开，其它任何片段（含空串）都打不开。
    def test_open_matches_and_rejects(self):
        frag = "dev@example.com"
        c = commit.evidence_commitment(frag)
        self.assertTrue(commit.open_evidence(c, frag))
        self.assertFalse(commit.open_evidence(c, "other@example.com"))
        self.assertFalse(commit.open_evidence(c, ""))

    # 证据包往返：逐条承诺与明文自洽时通过，篡改任一条明文即失效。
    def test_bundle_roundtrip(self):
        p = Policy("t", "1", rules=[
            Rule("keyword_block", "kb", {"keywords": ["exploit"]}),
            Rule("pattern_block", "pb", {"patterns": [pii.PII_PATTERNS["email"]]}),
        ])
        spec = compile_policy(p)
        bundle = commit.evidence_bundle(spec, "exploit a@b.com")
        self.assertEqual(len(bundle), 2)
        self.assertTrue(commit.verify_bundle(bundle))
        # 篡改披露出来的证据明文，承诺就对不上了
        bundle[0]["evidence"] = "tampered"
        self.assertFalse(commit.verify_bundle(bundle))


if __name__ == "__main__":
    unittest.main()
