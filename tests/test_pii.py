"""PII 模式与校验位校验器（policydsl.pii）的测试。

这些模式会被 PII 策略包直接复用，因此分两层验证：底层是正则/校验位本身的
检出准确度（含误报控制），上层是接入策略后的端到端违规判定。
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl.evaluate import check  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402
from policydsl import pii  # noqa: E402


class TestPatternDetection(unittest.TestCase):
    """各类 PII 正则在正/负样本上的检出能力（负例用于控制误报）。"""

    def test_email(self):
        # 邮箱：能识别常规地址，且对无邮箱的纯文本不误报。
        self.assertTrue(pii.contains("email", "reach dev@example.com"))
        self.assertFalse(pii.contains("email", "no address here"))

    def test_phone(self):
        # 电话：兼容国际区号与括号/连字符等常见书写形式。
        self.assertTrue(pii.contains("phone", "call +1 234 567 8901"))
        self.assertTrue(pii.contains("phone", "fax (555) 123-4567 x"))
        self.assertFalse(pii.contains("phone", "plain text without digits"))

    def test_secret_key(self):
        # 密钥：前缀大小写敏感（只认小写 sk-），长度不足的也不认。
        self.assertTrue(pii.contains("secret_key", "export sk-abcdefghijklmnopqrstuvwxy"))
        self.assertFalse(pii.contains("secret_key", "export SK-abcdefghijklmnopqrstuvwxy"))
        self.assertFalse(pii.contains("secret_key", "sk-tiny"))

    def test_bearer_token(self):
        # Bearer token：对长度设下限，避免把 "Bearer short" 之类的普通词误判。
        self.assertTrue(pii.contains("bearer_token",
                                     "Authorization: Bearer abcdefghijklmnop1234567"))
        self.assertFalse(pii.contains("bearer_token", "Bearer short"))


class TestIban(unittest.TestCase):
    """IBAN 依赖 mod-97 校验位：格式对但校验位错的必须被拒（这是它区别于普通正则的价值）。"""

    VALID = ["GB82WEST12345698765432", "DE89 3704 0044 0532 0130 00", "GB29NWBK60161331926819"]

    def test_valid_ibans(self):
        # 带空格与不带空格的写法都应通过（校验前会做归一化）。
        for iban in self.VALID:
            with self.subTest(iban=iban):
                self.assertTrue(pii.is_valid_iban(iban))

    def test_invalid_ibans(self):
        # 两位校验位被改错、或长度明显不足的，都必须拒绝。
        for iban in ["GB00WEST12345698765432", "DE89 3704 0044 0532 0130 01", "short"]:
            with self.subTest(iban=iban):
                self.assertFalse(pii.is_valid_iban(iban))


class TestPiiPolicyPack(unittest.TestCase):
    """把 PII 模式接入 PII 策略包后的端到端行为。"""

    def test_pack_rules_detect_violations(self):
        # 每条 PII 模式生成一条 pattern_block 规则，规则名用于定位命中的类别。
        rules = [Rule("pattern_block", f"no_{n}", {"patterns": [pii.PII_PATTERNS[n]]})
                 for n in ["email", "phone", "secret_key", "bearer_token"]]
        policy = Policy("pii", "1", rules=rules)
        # 文本含邮箱 -> 违规，且能定位到 no_email 这条规则。
        r = check(policy, "My details: a@b.com")
        self.assertFalse(r.passed)
        self.assertEqual(r.violations[0].rule.name, "no_email")
        # 干净文本 -> 通过（不含任何 PII 形状的子串）。
        self.assertTrue(check(policy, "This is a plain advisory with no identifiers.").passed)

    def test_all_patterns_compile_within_subset(self):
        # pii 模块在导入时即编译全部模式；能取到名字就说明它们都编译成功了。
        self.assertIn("email", pii.pattern_names())


if __name__ == "__main__":
    unittest.main()
