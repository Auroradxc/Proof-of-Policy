"""框架无关参考适配器（``policydsl/generic_adapter.py``）的测试。

这里**不装任何框架**：这正是该模块存在的理由之一。分四组：

- ``TestContract`` —— 「一个适配器最少必须做对哪几件事」逐条钉住；
- ``TestSealTiming`` —— seal 必须取「现在」那一刻的（缓存它 = 悄悄关掉截尾检测）；
- ``TestHonestFailures`` —— 该抛的时候抛，不悄悄按「无结果」判过；
- ``TestThirdPartyVerification`` —— 落盘的产物**真拿 `verify_session.py` /
  `verify_cert.py` 验一遍**（起子进程跑真脚本，不是复述内部函数）。
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl import cert, keys, trace  # noqa: E402
from policydsl import generic_adapter as ga  # noqa: E402
from policydsl.model import Policy, PolicyError, Rule  # noqa: E402

REPO = Path(__file__).resolve().parents[1]

CONTENT_PACK = "policy_packs/agent_content_v1.json"
TOOL_PACK = "policy_packs/agent_tool_v1.json"


def load_pack(name: str) -> Policy:
    """从 policy_packs/ 读取策略包 JSON 并构造 Policy。"""
    data = json.loads((REPO / name).read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r["name"], params=r.get("params", {}))
             for r in data["rules"]]
    return Policy(data["id"], data.get("version", "0.1.0"), rules=rules)


def guard_of(pack: str = TOOL_PACK) -> ga.GenericGuard:
    """一把用**真实 Ed25519** 密钥的 guard（子进程验签要真钥，HMAC 不行）。"""
    return ga.GenericGuard(load_pack(pack), pack, signer=keys.ephemeral_signer())


def payload_of(env):
    return cert.envelope_payload(env)


class TestContract(unittest.TestCase):
    """契约本身：两个钩子、一把网关、两把钥匙。"""

    # 生成路径签发一张可验证的证书
    def test_generate_issues_a_verifiable_certificate(self):
        g = guard_of(CONTENT_PACK)
        env = g.generate("A safe, plain reply.")
        self.assertEqual(g.kinds, [ga.KIND_GENERATE])
        ok, pl = cert.verify_envelope(env, cert.keyring(g.monitor.signer.public_key))
        self.assertTrue(ok)
        self.assertTrue(pl["outcome"]["passed"])

    # 违规的生成被**如实记进证书**，而不是被拦在证书之外
    def test_a_violating_generation_is_recorded_not_hidden(self):
        g = guard_of(CONTENT_PACK)
        env = g.generate("Leak sk-abcdefghijklmnopqrstuvwxyz")
        pl = payload_of(env)
        self.assertFalse(pl["outcome"]["passed"])
        self.assertTrue(pl["outcome"]["violations"])
        # 证书**依然是真的** —— 「如实记录违规」与「证书有效」是两件事
        ok, _ = cert.verify_envelope(env, cert.keyring(g.monitor.signer.public_key))
        self.assertTrue(ok)

    # 工具路径：一次调用 = 一条回执 + 一张证书
    def test_tool_call_issues_a_receipt_and_a_certificate(self):
        g = guard_of(TOOL_PACK)
        g.tool_call("search_kb", {"query": "refund"}, result="ok")
        self.assertEqual(len(g.gateway.receipts), 1)
        self.assertEqual(len(g.certificates), 1)
        self.assertEqual(g.kinds, [ga.KIND_TOOL])
        self.assertEqual(payload_of(g.certificates[0])["outcome"]["trace_root"],
                         g.trace_root)

    # 第 1 条：同一个会话里生成与工具走的是**同一条**链（不是各指一条 trace_root）
    def test_generate_and_tool_calls_share_one_trace_root(self):
        g = guard_of(TOOL_PACK)
        g.tool_call("search_kb", {"query": "a"}, result="r1")
        after_first = g.trace_root
        gen = g.generate("done")
        g.tool_call("search_kb", {"query": "b"}, result="r2")
        roots = [payload_of(e)["outcome"]["trace_root"] for e in g.certificates]
        # 每张证书承诺的都是**它签发那一刻**的链尾，因此：
        # 第 2 次调用之前写的生成证书，链尾还是「一条回执」那条 —— 与第 1 张相同。
        # 这正说明两条路径读的是**同一条链**（各自开网关的话这里会是两个值）。
        self.assertEqual(roots[0], after_first)
        self.assertEqual(roots[1], after_first)
        self.assertEqual(roots[2], g.trace_root)
        self.assertNotEqual(roots[0], roots[2], "第二次工具调用必须让链尾前移")

    # 第 1 条的另一面：跨 guard 共享网关，链不会分叉
    def test_two_guards_can_share_one_gateway(self):
        gw = trace.ToolGateway(signer=keys.ephemeral_signer())
        a = ga.GenericGuard(load_pack(TOOL_PACK), TOOL_PACK, gateway=gw)
        b = ga.GenericGuard(load_pack(TOOL_PACK), TOOL_PACK, gateway=gw)
        a.tool_call("search_kb", {"query": "a"}, result="ra")
        b.tool_call("search_kb", {"query": "b"}, result="rb")
        self.assertIs(a.gateway, b.gateway)
        self.assertEqual(len(gw.receipts), 2)
        self.assertEqual([r.seq for r in gw.receipts], [0, 1])
        self.assertEqual(payload_of(b.certificates[0])["outcome"]["trace_root"],
                         gw.trace_root)

    # 第 3 条：网关与出证方是**两把**钥匙，不能合成一把
    def test_the_gateway_key_is_not_the_certificate_signer(self):
        g = guard_of(TOOL_PACK)
        g.tool_call("search_kb", {"query": "x"}, result="r")
        kids = [s["keyid"] for s in g.signers()]
        self.assertEqual(len(kids), 2, "两把公钥都要交出去")
        self.assertEqual(len(set(kids)), 2)
        self.assertEqual(kids[0], g.monitor.signer.keyid)
        self.assertEqual(kids[1], g.gateway.signer.keyid)
        # 两张证书用的确实是**出证方**那把，不是网关那把（信封是 DSSE 形状，
        # 签名者标在 signatures[].keyid 上；binding 里记的是电路与证明的事）
        sigs = g.certificates[0]["signatures"]
        self.assertEqual([s["keyid"] for s in sigs], [kids[0]])

    # 没有工件就没有真 vkey 可指 —— 参考适配器如实标 unproven
    def test_certificates_are_labeled_unproven_by_default(self):
        g = guard_of(TOOL_PACK)
        pl = payload_of(g.tool_call("search_kb", {"query": "x"}, result="r"))
        self.assertEqual(pl["binding"]["vkey_hash"], cert.VKEY_HASH_UNPROVEN)


class TestWholeChainJudgement(unittest.TestCase):
    """工具证书判的是**整条链**，不是「这一次调用」。

    这条防线只有拿一条「会被更早那次调用弄脏」的策略才能验出来 ——
    用默认的 ``agent_tool_v1``（预算 5 次）是验不出来的：两次调用都远在预算内，
    于是「只判当前这一条」和「判整条链」给出同样的结论，测试看着绿、其实没咬住。
    （本案就是被一次变异测试逼出来的：把 ``chain=self.gateway.receipts`` 改成
    ``chain=[receipt]``，其余 17 例全绿。）

    另注：``trace_root`` 只取**最后一条**回执的摘要（链式性由每条回执里的 ``prev``
    承担），所以「只传当前这条」在链尾摘要上看不出任何差别 —— 差别在**判定范围**。
    """

    # 预算为 1 次调用时：第 2 次调用超出预算，它自己的证书必须判失败
    def test_a_later_call_inherits_an_earlier_violation(self):
        pol = Policy("inline-budget1", "0.1.0", rules=[
            Rule(kind="budget_bound", name="one_call",
                 params={"budget": 1, "unit": "calls"})])
        # policy_pack 只用于写 session.json，本用例不落盘，故给个说明性占位
        g = ga.GenericGuard(pol, "<inline:budget=1>",
                            signer=keys.ephemeral_signer())
        g.tool_call("search_kb", {"query": "a"}, result="ra")
        g.tool_call("search_kb", {"query": "b"}, result="rb")
        passed = [payload_of(e)["outcome"]["passed"] for e in g.certificates]
        self.assertEqual(passed, [True, False])
        # **盯住「计到几条」而不是「挂了哪条规则」**：只传当前这一条回执时，
        # 那条回执的 seq=1、不从 0 起，会先被判成 trace_unbound —— 于是
        # `passed` 同样是 False、`rule` 同样是 one_call，只有 kind 与计到的
        # 条数不同。断言咬在 kind/evidence 上，这条防线才真的立得住。
        v = payload_of(g.certificates[1])["outcome"]["violations"]
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0]["kind"], "budget_bound")
        self.assertEqual(v[0]["evidence_kind"], "budget")
        self.assertEqual(v[0]["evidence"], {"unit": "calls", "total": 2, "budget": 1})


class TestSealTiming(unittest.TestCase):
    """第 2 条：seal 说的是「到此为止」，必须现取。"""

    # 先签的证书只承诺**当时**的链长；后续调用会让它「过期」—— 这正是截尾检测
    def test_an_earlier_seal_does_not_cover_later_calls(self):
        g = guard_of(TOOL_PACK)
        first = g.tool_call("search_kb", {"query": "a"}, result="ra")
        seal0 = trace.seal_from_json(payload_of(first)["trace_seal"])
        self.assertEqual(seal0.count, 1)

        g.tool_call("dump_config", {}, result="SECRET")
        final = list(g.gateway.receipts)
        self.assertEqual(len(final), 2)

        ring = cert.keyring(g.gateway.public_key)
        ok, why = trace.verify_seal(seal0, keyring=ring, receipts=final)
        self.assertFalse(ok)
        self.assertIn("截尾", why)

        # 而「现在」这条 seal 对同一条链成立 —— 证明失败不是因为 seal 坏了
        ok_now, _ = trace.verify_seal(g.seal(), keyring=ring, receipts=final)
        self.assertTrue(ok_now)

    # 每张证书带的都是**自己那一刻**的 seal，不是会话开头那条
    def test_each_certificate_carries_the_seal_of_its_own_moment(self):
        g = guard_of(TOOL_PACK)
        g.tool_call("search_kb", {"query": "a"}, result="ra")
        g.tool_call("search_kb", {"query": "b"}, result="rb")
        counts = [trace.seal_from_json(payload_of(e)["trace_seal"]).count
                  for e in g.certificates]
        self.assertEqual(counts, [1, 2])

    # 没有工具调用的会话：seal.count == 0，不是「没有 seal」
    def test_a_session_with_no_tool_calls_still_carries_a_seal(self):
        g = guard_of(CONTENT_PACK)
        seal = trace.seal_from_json(payload_of(g.generate("plain reply"))["trace_seal"])
        self.assertIsNotNone(seal)
        self.assertEqual(seal.count, 0)


class TestHonestFailures(unittest.TestCase):
    """该抛的时候抛 —— 悄悄判过是最坏的一种「通过」。"""

    # 策略里有内容规则却不给 response：抛 PolicyError，而不是按「无结果」判过
    def test_a_content_rule_without_a_response_raises(self):
        g = guard_of(CONTENT_PACK)
        with self.assertRaises(PolicyError) as ctx:
            g.tool_call("search_kb", {"query": "x"}, result="anything")
        self.assertIn("needs a response", str(ctx.exception))
        # 抛之前**不留半张证书**：回执照签（调用确实发生过），证书没有
        self.assertEqual(len(g.certificates), 0)

    # 私钥绝不落盘：写出的每个文件里都找不到两把私钥的私密字节
    def test_write_session_emits_only_public_material(self):
        g = guard_of(TOOL_PACK)
        g.tool_call("search_kb", {"query": "x"}, result="r")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            ga.write_session(g, out)
            blob = b"".join(p.read_bytes() for p in out.iterdir())
            for signer in (g.monitor.signer, g.gateway.signer):
                raw = signer.private_key.private_bytes_raw()
                self.assertNotIn(raw, blob)
                self.assertNotIn(raw.hex().encode(), blob)


class TestThirdPartyVerification(unittest.TestCase):
    """落盘的产物要能被**仓库里那两个真脚本**验过（起子进程，不复述内部函数）。"""

    def _run(self, *args):
        return subprocess.run([sys.executable, *args], cwd=str(REPO),
                              capture_output=True, text=True)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        g = guard_of(TOOL_PACK)
        g.tool_call("search_kb", {"query": "refund"}, result="ok")
        g.tool_call("dump_config", {}, result="SECRET=hunter2")
        ga.write_session(g, self.out)

    # 产物清单齐全（少一样，下面那条配方就跑不起来）
    def test_write_session_emits_the_whole_public_bundle(self):
        names = sorted(p.name for p in self.out.iterdir())
        self.assertEqual(names, [
            "cert-0-tool.json", "cert-1-tool.json", "gateway.pub.hex",
            "key.json", "ledger.jsonl", "receipts.json", "session.json",
        ])
        sess = json.loads((self.out / "session.json").read_text(encoding="utf-8"))
        self.assertEqual(sess["summary"]["certificates"], 2)
        self.assertEqual(sess["summary"]["kinds"], {"tool": 2})
        self.assertTrue(sess["summary"]["ledger_ok"])
        # 两把公钥都在（出证方 + 网关），验证方才不必额外要材料
        self.assertEqual(len(sess["signers"]), 2)

    # 会话级：verify_session.py 全卡 PASS
    def test_verify_session_passes_on_the_written_bundle(self):
        r = self._run("scripts/verify_session.py",
                      "--session", str(self.out / "session.json"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("RESULT: PASS", r.stdout)
        self.assertNotIn("[FAIL]", r.stdout)

    # 单证书级：连 trace_binding 与 trace_seal 都核得过（回执链 + 网关公钥都给全）
    def test_verify_cert_passes_including_the_seal(self):
        r = self._run("scripts/verify_cert.py",
                      "--cert", str(self.out / "cert-1-tool.json"),
                      "--pack", TOOL_PACK,
                      "--ledger", str(self.out / "ledger.jsonl"),
                      "--keyring", str(self.out / "key.json"),
                      "--receipts", str(self.out / "receipts.json"),
                      "--gateway-key", str(self.out / "gateway.pub.hex"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("RESULT: PASS", r.stdout)
        self.assertIn("[PASS] trace_seal", r.stdout)
        self.assertIn("[PASS] trace_binding", r.stdout)

    # 不给回执链，trace_binding 就该报「核不了」而不是默认通过
    def test_without_the_receipts_the_trace_binding_is_not_assumed(self):
        r = self._run("scripts/verify_cert.py",
                      "--cert", str(self.out / "cert-1-tool.json"),
                      "--pack", TOOL_PACK,
                      "--ledger", str(self.out / "ledger.jsonl"),
                      "--keyring", str(self.out / "key.json"),
                      "--gateway-key", str(self.out / "gateway.pub.hex"))
        self.assertIn("[FAIL] trace_binding", r.stdout)

    # 换一把别人的网关钥，seal 必须验不过（否则「谁签的」就是句空话）
    def test_a_foreign_gateway_key_is_rejected(self):
        foreign = self.out / "foreign.pub.hex"
        foreign.write_text(keys.public_hex(
            keys.ephemeral_signer().public_key) + "\n", encoding="utf-8")
        r = self._run("scripts/verify_cert.py",
                      "--cert", str(self.out / "cert-1-tool.json"),
                      "--pack", TOOL_PACK,
                      "--ledger", str(self.out / "ledger.jsonl"),
                      "--keyring", str(self.out / "key.json"),
                      "--receipts", str(self.out / "receipts.json"),
                      "--gateway-key", str(foreign))
        self.assertIn("[FAIL] trace_seal", r.stdout)


if __name__ == "__main__":
    unittest.main()
