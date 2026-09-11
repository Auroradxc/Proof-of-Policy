"""P1-5 轨迹绑定（工具回执链）的验收测试。

审稿人问的第一个问题一定是「我凭什么相信这条轨迹」。P1-5 之前 ``tool_calls``
是证明者自己填的，所以 ``tool_arg_guard`` 只是"如果轨迹如我所述则通过"——
把列表填空即可通过。现在轨迹由**工具网关**签发的回执链承载，agent 只能转发。

本文件按 ``docs/plan-p0p1p2.md`` §P1-5 的四条验收标准组织：

  ① 完整链通过；
  ② 删 / 换 / 重排一条回执 → 失败；
  ③ **负例**：伪造一条"参数不含被禁字段"的回执（但真实调用带了违规参数）
     → 验签失败；
  ④ 旧路径（自填 ``tool_calls``）**不再被接受**。

每条都在**两个层面**各验一遍：Python 参考层（``policydsl.trace``）与电路内
Rust 实现（``pop-script --check``，即 ``pop_types::evaluate``）。二者分叉就意味着
「链下说违规、链上说通过」，所以同一组用例必须两边都过。

边界（本文件刻意把它们测成**明确的**行为，而不是含糊过去）：

- 电路内只验**结构**（``seq`` 连续、``prev`` 咬合），不验 Ed25519；
- 因此**改动链尾那条回执的内容**，电路内察觉不到 —— 抓住它的是链下验签。
  这一条被写成显式用例 ``test_last_element_tamper_is_caught_by_signature_only``，
  免得读者以为电路内已经把篡改全堵死了。
"""

import dataclasses
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl import anchor, cert, keys, trace  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.evaluate import check  # noqa: E402
from policydsl.model import Policy, Rule, Transcript  # noqa: E402
from policydsl.serialize import spec_canonical_text  # noqa: E402

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"

#: 固定时间戳 —— 让回执与向量可复现（网关时间戳不进判定，只进摘要）。
GW_TS = "2026-01-01T00:00:00+00:00"


def gateway() -> trace.ToolGateway:
    """一次性网关（进程内临时 Ed25519 钥 + 固定时间戳）。"""
    return trace.ToolGateway(ts=GW_TS)


def chain3() -> tuple:
    """一条三条的链 + 它的网关：``[(tool, args, result), ...]``。"""
    gw = gateway()
    gw.issue("search_kb", {"query": "refund"}, "hit")
    gw.issue("http_get", {"url": "https://example.com", "token": "s"}, "leak")
    gw.issue("write_file", {"path": "/tmp/x"}, "ok")
    return gw, gw.receipts


def policy_for(fields=None) -> Policy:
    """``tool_arg_guard`` 策略（验收用例默认禁用 password/token/api_key）。"""
    return Policy("t", "1", rules=[
        Rule("tool_arg_guard", "no_secret_args",
             {"forbidden_fields": fields or ["password", "token", "api_key"]})])


def run_check(vector: dict) -> dict:
    """把单个向量喂给 ``pop-script --check``（与生产同一条反序列化路径）。"""
    with tempfile.TemporaryDirectory() as tmp:
        vp, op = Path(tmp) / "v.json", Path(tmp) / "r.json"
        vp.write_text(json.dumps({"vectors": [vector]}))
        subprocess.run([str(POP_SCRIPT), "--check", "--vectors", str(vp), "--out", str(op)],
                       cwd=str(REPO), check=True, capture_output=True, text=True)
        return json.loads(op.read_text())[0]


def vector_for(policy: Policy, receipts, response: str = "") -> dict:
    """构造一个带回执链的向量（与 ``scripts/cross_validate.py`` 同形）。"""
    return {"name": "t", "response": response,
            "spec_canonical": spec_canonical_text(compile_policy(policy)),
            "receipts": trace.receipts_to_json(receipts)}


# --------------------------------------------------------------------------- #
# 编码层：规范字节 / 摘要 / 链尾
# --------------------------------------------------------------------------- #

class TestReceiptEncoding(unittest.TestCase):
    """回执的规范字节编码是跨语言契约，必须唯一、确定、无歧义。"""

    # 空链的链尾是 "genesis"；单条链的链尾就是那一条的摘要。
    def test_genesis_and_root(self):
        self.assertEqual(trace.trace_root([]), trace.GENESIS)
        gw = gateway()
        r = gw.issue("t", {"a": "b"}, result="x")
        self.assertEqual(trace.trace_root([r]), trace.receipt_digest(r))
        self.assertEqual(trace.trace_root(gw.receipts), gw.trace_root)

    # 长度前缀存在的理由：没有它，("ab","cd") 与 ("abcd","") 会编码成同一串字节，
    # 两条语义不同的回执就会撞出同一个摘要 —— 链随即失去意义。
    def test_length_prefix_kills_concatenation_ambiguity(self):
        a = trace.ToolReceipt(seq=0, tool="ab", args={}, result_digest="cd")
        b = trace.ToolReceipt(seq=0, tool="abcd", args={}, result_digest="")
        self.assertNotEqual(trace.receipt_digest(a), trace.receipt_digest(b))

    # 参数按键升序编码：字典的插入顺序不该影响摘要（否则同一调用会算出两个摘要）。
    def test_arg_order_does_not_matter(self):
        a = trace.ToolReceipt(seq=0, tool="t", args={"b": "2", "a": "1"})
        b = trace.ToolReceipt(seq=0, tool="t", args={"a": "1", "b": "2"})
        self.assertEqual(trace.receipt_digest(a), trace.receipt_digest(b))

    # keyid 也在被签的字节里：换 keyid（比如换成 ring 里另一把可用的钥匙）
    # 必须改变摘要，否则「谁签的」就能被无声替换。
    def test_keyid_is_covered(self):
        a = trace.ToolReceipt(seq=0, tool="t", keyid="ed25519:aaaaaaaa")
        b = trace.ToolReceipt(seq=0, tool="t", keyid="ed25519:bbbbbbbb")
        self.assertNotEqual(trace.receipt_digest(a), trace.receipt_digest(b))

    # 反过来，六个 ASCII 空白一个都不能漏 —— 漏一个就会两头数出不同的数。
    def test_all_six_ascii_white_bytes_split(self):
        for ws in " \t\n\x0b\x0c\r":
            with self.subTest(ws=repr(ws)):
                self.assertEqual(trace.token_count(f"a{ws}b"), 2)
                self.assertEqual(trace.token_count(f"{ws}a{ws}"), 1)

    # 非字符串参数统一字符串化（电路侧是 String），且字符串化结果本身是确定的。
    def test_arg_str_is_deterministic(self):
        self.assertEqual(trace.arg_str("x"), "x")
        self.assertEqual(trace.arg_str({"b": 1, "a": 2}), '{"a":2,"b":1}')

    # 分词白名单是**取死的六个字节**，不是 Unicode White_Space：不断掉这个区别，
    # 换一个 Unicode 版本就可能换一个 token 数。
    def test_token_count_uses_fixed_ascii_space(self):
        self.assertEqual(trace.token_count(""), 0)
        self.assertEqual(trace.token_count("   "), 0)
        self.assertEqual(trace.token_count("a b\tc\nd"), 4)
        # U+00A0（NBSP）与 U+3000（全角空格）**不**算分隔符 —— 它们是 token 的一部分
        self.assertEqual(trace.token_count("a b"), 1)
        self.assertEqual(trace.token_count("a　b"), 1)


# --------------------------------------------------------------------------- #
# 验收 ①②：完整链通过，改动一条即失败
# --------------------------------------------------------------------------- #

class TestChainAcceptance(unittest.TestCase):
    """验收项 ① 与 ②（Python 参考层）。"""

    def setUp(self):
        self.policy = policy_for()

    # ① 完整链：结构自洽 + 逐条验签通过 + 策略判定通过。
    def test_full_chain_accepted(self):
        gw, rs = chain3()
        self.assertEqual(trace.chain_ok(rs), (True, ""))
        self.assertEqual(trace.verify_chain(rs, gw.keyring()), (True, ""))
        res = check(self.policy, Transcript(receipts=rs))
        # 第二条（http_get 带 token）确实违规 —— 说明这条链不是"恰好干净"才通过
        self.assertFalse(res.passed)

        # 真·干净链：三条都无禁用字段，才算「完整链通过」
        gw2 = gateway()
        gw2.issue("search_kb", {"query": "refund"}, "hit")
        gw2.issue("http_get", {"url": "https://example.com"}, "ok")
        self.assertEqual(trace.verify_chain(gw2.receipts, gw2.keyring()), (True, ""))
        self.assertTrue(check(self.policy, Transcript(receipts=gw2.receipts)).passed)
        # 空链也合法（一次工具都没调用）
        self.assertEqual(trace.chain_ok([]), (True, ""))
        self.assertTrue(check(self.policy, Transcript(receipts=[])).passed)

    # ② 三种改动：删一条、交换相邻两条、把首条挪到中间 —— 全都必须失败。
    def test_mutation_delete_swap_reorder_fails(self):
        gw, rs = chain3()

        mutated = {
            "delete_middle": [rs[0], rs[2]],           # 少一条：下标 1 处 seq=2 != 1
            "swap_adjacent": [rs[0], rs[2], rs[1]],    # 交换 1/2：下标 1 处 seq=2 != 1
            "rotate": [rs[1], rs[0], rs[2]],           # 错位：下标 0 处 seq=1 != 0
        }
        for label, ms in mutated.items():
            with self.subTest(mutation=label):
                ok, why = trace.chain_ok(ms)
                self.assertFalse(ok, f"{label} 不该通过结构校验")
                self.assertTrue(why)
                # 判定层也必须跟着失败（fail-closed），而不是当无事发生
                res = check(self.policy, Transcript(receipts=ms))
                self.assertFalse(res.passed)
                self.assertEqual(res.violations[0].evidence_kind, "trace_unbound")

    # ② 的"换"一条：替换**中间那条的内容**，而且刻意把 seq/prev 也对齐（一个
    # 用心的伪造者会做的事）。它仍然过不去：**下一条**的 prev 是对被换掉那条的
    # 承诺，改内容就改了摘要 —— 攻击者要抹平这一处，就得连后面每条一起重签。
    def test_mutation_replace_middle_fails(self):
        gw, rs = chain3()
        forged = dataclasses.replace(rs[1], args={"url": "https://clean.example"},
                                     seq=1, prev=trace.receipt_digest(rs[0]))
        ms = [rs[0], forged, rs[2]]
        self.assertNotEqual(trace.receipt_digest(forged), trace.receipt_digest(rs[1]))
        self.assertEqual(trace.chain_ok(ms), (False, "receipt 2: prev mismatch"))
        # 结构层与验签层都拒绝它
        self.assertFalse(trace.verify_chain(ms, gw.keyring())[0])
        self.assertFalse(check(self.policy, Transcript(receipts=ms)).passed)

    # ② 的另一种"换"：拿同一网关签过的**另一条**回执来顶包（攻击者手上确实
    # 有真回执，只是想调换次序/隐瞒某次调用）。序号当场对不上。
    def test_mutation_substitute_sibling_fails(self):
        gw, rs = chain3()
        self.assertEqual(trace.chain_ok([rs[0], rs[1], rs[1]]),
                         (False, "receipt 2: seq=1 != 2"))
        self.assertEqual(trace.chain_ok([rs[0], rs[0], rs[2]]),
                         (False, "receipt 1: seq=0 != 1"))

    # 边界（如实标注）：电路只验结构，所以**改动链尾那条的内容**结构上仍然自洽
    # —— 抓住它的是链下验签。这条用例存在的意义是钉死这个边界，而不是掩盖它。
    def test_last_element_tamper_is_caught_by_signature_only(self):
        gw, rs = chain3()
        tampered = dataclasses.replace(rs[2], args={"path": "/etc/shadow"})
        ms = [rs[0], rs[1], tampered]
        self.assertEqual(trace.chain_ok(ms), (True, ""))          # 结构层：看不出
        ok, why = trace.verify_chain(ms, gw.keyring())            # 验签层：抓住了
        self.assertFalse(ok)
        self.assertEqual(why, "receipt 2: 签名验证失败")


# --------------------------------------------------------------------------- #
# 验收 ③：伪造回执 —— 结构可以完美，签名骗不过去
# --------------------------------------------------------------------------- #

class TestForgedReceipt(unittest.TestCase):
    """验收项 ③：伪造一条"参数干净"的回执，但真实调用带了违规参数。"""

    def setUp(self):
        self.policy = policy_for()

    # 攻击场景（P1-5 之前**必成**）：真实调用 ``{"query":"x","token":"secret"}``，
    # 但把回执里的参数改写成 ``{"query":"x"}`` —— 电路看到的就是一条干净调用。
    # P1-5 之后：回执被网关签过，改一个字节验签就炸。
    def test_forged_clean_args_fails_signature(self):
        gw = gateway()
        real = gw.issue("search_kb", {"query": "x", "token": "secret"}, "leaked")

        forged = dataclasses.replace(real, args={"query": "x"})
        # 伪造版在**内容**上确实骗得过参数守卫（这正是攻击者的目的）：
        self.assertTrue(check(self.policy, Transcript(receipts=[forged])).passed)
        # 但验签过不去：
        ok, why = trace.verify_chain([forged], gw.keyring())
        self.assertFalse(ok)
        self.assertEqual(why, "receipt 0: 签名验证失败")

    # 换个思路：攻击者拿**自己的**密钥重签一条干净回执（内容与结构都自洽），
    # 于是电路内无懈可击 —— 但它的 keyid 不在验证方的 keyring 里。
    def test_resigned_with_attacker_key_rejected(self):
        attacker = gateway()                      # 攻击者自己的临时钥
        forged = attacker.issue("search_kb", {"query": "x"}, "ok")
        self.assertEqual(trace.chain_ok([forged]), (True, ""))            # 结构没问题
        ok, why = trace.verify_chain([forged], gateway().keyring())       # 网关的 ring
        self.assertFalse(ok)
        self.assertIn("不在 keyring 里", why)

    # 历史/陌生方案前缀结构性拒绝：把 keyid 换成不允许的前缀，ring 里就算
    # 恰好放了同名钥匙也没用（与 P0-3 对证书信封的处理一致）。
    def test_disallowed_keyid_scheme_rejected(self):
        gw = gateway()
        real = gw.issue("t", {"a": "b"}, "x")
        forged = dataclasses.replace(real, keyid="demo-hmac-sha256:deadbeef")
        ring = dict(gw.keyring())
        ring["demo-hmac-sha256:deadbeef"] = gw.public_key   # 钥匙都给足了
        ok, why = trace.verify_chain([forged], ring)
        self.assertFalse(ok)
        self.assertIn("不接受的 keyid 方案", why)

    # 签名被截断/写字面垃圾不能算通过（验签实现要走真实密码学，不是比字符串）。
    def test_garbage_signature_rejected(self):
        gw = gateway()
        real = gw.issue("t", {"a": "b"}, "x")
        for bad in ["", "zz", "00" * 64]:
            with self.subTest(sig=bad):
                forged = dataclasses.replace(real, sig=bad)
                self.assertFalse(trace.verify_chain([forged], gw.keyring())[0])


# --------------------------------------------------------------------------- #
# 验收 ④：旧的自述式路径不再被接受
# --------------------------------------------------------------------------- #

class TestLegacyPathRejected(unittest.TestCase):
    """验收项 ④：``tool_calls`` / ``token_count`` 这两个自填字段必须彻底失效。"""

    # Python 层：Transcript 里已经**没有**可自填的 token 数；旧调用直接 TypeError，
    # 而不是"传了但被忽略"（后者会让人以为还在生效）。
    def test_transcript_has_no_self_declared_fields(self):
        with self.assertRaises(TypeError):
            Transcript(response="x", token_count=150)
        with self.assertRaises(TypeError):
            Transcript(response="x", tool_calls=[])
        from policydsl import model
        self.assertFalse(hasattr(model, "ToolCall"))

    # 预算规则改判**算出来的** token 数：超限只能靠真的写出这么多 run 来触发。
    def test_token_budget_cannot_be_declared_away(self):
        p = Policy("t", "1", rules=[
            Rule("budget_bound", "bb", {"budget": 10, "unit": "tokens"})])
        self.assertFalse(check(p, " ".join(["w"] * 50)).passed)
        self.assertTrue(check(p, "only a few words").passed)


# --------------------------------------------------------------------------- #
# 电路内（Rust）对照 —— 上面每条结论都必须在真正进电路的那份实现里成立
# --------------------------------------------------------------------------- #

@unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built")
class TestTraceInCircuit(unittest.TestCase):
    """与 ``pop_types::evaluate`` 的逐点对齐（走 CLI，含 serde 反序列化）。"""

    def setUp(self):
        self.policy = policy_for()

    # ① 完整链在电路内通过：passed 为真，且公开值里的 trace_root 与 Python 的
    # 逐字节相同 —— 这是 canonical_receipt_bytes 跨语言一致的**实测**证据
    # （trace_root = sha256(规范字节)，只要有一处编码不同就对不上）。
    def test_full_chain_parity(self):
        gw = gateway()
        gw.issue("search_kb", {"query": "refund"}, "hit")
        gw.issue("http_get", {"url": "https://example.com"}, "ok")
        got = run_check(vector_for(self.policy, gw.receipts))
        self.assertTrue(got["passed"])
        self.assertEqual(got["trace_root"], trace.trace_root(gw.receipts))

    # ① 带违规参数的那条回执：电路内必须判出来（工具规则真的在读回执的参数）。
    def test_violating_receipt_caught_in_circuit(self):
        gw = gateway()
        gw.issue("search_kb", {"query": "x", "token": "secret"}, "leaked")
        got = run_check(vector_for(self.policy, gw.receipts))
        self.assertFalse(got["passed"])
        self.assertEqual([(v["rule"], v["kind"]) for v in got["violations"]],
                         [("no_secret_args", "tool_arg_guard")])

    # ② 删 / 换 / 重排：电路内一律 fail-closed 记 trace_unbound（而不是当作
    # "读不出来 = 零次调用"放行）——并且这个判定必须与 Python 参考层一致。
    def test_mutations_fail_closed_in_circuit(self):
        gw, rs = chain3()
        forged = dataclasses.replace(rs[1], args={"url": "https://clean.example"},
                                     seq=1, prev=trace.receipt_digest(rs[0]))
        mutated = {
            "delete_middle": [rs[0], rs[2]],
            "swap_adjacent": [rs[0], rs[2], rs[1]],
            "rotate": [rs[1], rs[0], rs[2]],
            "replace_middle": [rs[0], forged, rs[2]],
        }
        for label, ms in mutated.items():
            with self.subTest(mutation=label):
                got = run_check(vector_for(self.policy, ms))
                self.assertFalse(got["passed"])
                self.assertIn("trace_unbound", [v["kind"] for v in got["violations"]])
                # 与 golden 对齐：两边都必须不通过
                self.assertFalse(check(self.policy, Transcript(receipts=ms)).passed)

    # ③ 的电路内一半：伪造（被改写内容的）**链尾**回执，电路内看不出来 ——
    # 因为电路不验签。这不是缺陷，是已标注的边界；配套的链下验签负责堵它。
    def test_in_circuit_blind_to_last_element_forgery(self):
        # 这条链必须**本身干净**，否则前面的回执会以别的理由（参数违规）把
        # 判定带失败，让本用例变成恒真。
        gw = gateway()
        gw.issue("search_kb", {"query": "refund"}, "hit")
        gw.issue("http_get", {"url": "https://example.com"}, "ok")
        gw.issue("write_file", {"path": "/tmp/x"}, "ok")
        rs = gw.receipts
        self.assertTrue(run_check(vector_for(self.policy, rs))["passed"])  # 基准
        forged = dataclasses.replace(rs[2], args={"path": "/etc/shadow"})
        ms = [rs[0], rs[1], forged]
        got = run_check(vector_for(self.policy, ms))
        self.assertTrue(got["passed"], "电路内只验结构，看不出链尾内容被改")
        self.assertFalse(trace.verify_chain(ms, gw.keyring())[0],
                         "链下验签必须抓住它")

    # ④ 旧向量（带 tool_calls / token_count）必须**整个被拒**，而不是退化成
    # "零次工具调用"照样出证 —— 那会让 P1-5 看起来生效了、实际一提就破。
    def test_legacy_vector_is_rejected(self):
        entry = vector_for(self.policy, [])
        entry["tool_calls"] = [{"name": "search_kb", "args": {"token": "secret"}}]
        with tempfile.TemporaryDirectory() as tmp:
            vp, op = Path(tmp) / "v.json", Path(tmp) / "r.json"
            vp.write_text(json.dumps({"vectors": [entry]}))
            proc = subprocess.run([str(POP_SCRIPT), "--check", "--vectors", str(vp),
                                   "--out", str(op)],
                                  cwd=str(REPO), capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0, "旧格式向量不该被接受")
        self.assertIn("unknown field", proc.stderr)
        self.assertFalse(op.exists())


# --------------------------------------------------------------------------- #
# 验证方一侧：`verify_cert.py --receipts --gateway-key`
# --------------------------------------------------------------------------- #

class TestVerifyCertTraceBinding(unittest.TestCase):
    """端到端：第三方拿**网关侧回执**跑 ``verify_cert.py``，必须能独立核对轨迹。

    这一组用例回答的是「``trace_root`` 进公开值到底有什么用」：没有这条路径，
    证书里那个摘要只能证明出证方**前后自洽**，证明不了链里到底有什么。有了它，
    验证方拿自己手上的回执重算链尾即可 —— 与 ``--response`` 之于响应对称。
    """

    def _issue(self, tmp: Path, receipts) -> Path:
        """签一张带 trace_root 的证书（无证明，host-check 层足以验证绑定）并锚定。"""
        spec = compile_policy(policy_for())
        outcome = {"policy_hash": spec["sha256"],
                   "trace_root": trace.trace_root(receipts),
                   "passed": True, "violations": []}
        payload = cert.build_payload("t", "1", spec, "public", outcome,
                                     vkey_hash="unproven", ts="2026-01-01T00:00:00Z")
        signer = cert.Ed25519Signer.generate()
        (tmp / "key.json").write_text(json.dumps(keys.public_record(signer.public_key)))
        (tmp / "cert.json").write_text(json.dumps(cert.sign_payload(payload, signer)))
        (tmp / "pack.json").write_text(json.dumps({
            "id": "t", "version": "1",
            "rules": [{"kind": r.kind, "name": r.name, "params": r.params}
                      for r in policy_for().rules]}))
        anchor.append_anchor(tmp / "ledger.jsonl", cert.cert_digest(payload))
        return tmp / "cert.json"

    def _verify(self, tmp: Path, cert_file: Path, receipts, gateway, extra=None):
        """跑 verify_cert.py；``receipts`` 是验证方**自己手上**的回执（JSON 形状）。"""
        (tmp / "receipts.json").write_text(json.dumps(trace.receipts_to_json(receipts)))
        (tmp / "gw.pub.hex").write_text(gateway.signer.public_hex)
        return subprocess.run(
            [sys.executable, str(REPO / "scripts" / "verify_cert.py"),
             "--cert", str(cert_file), "--pack", str(tmp / "pack.json"),
             "--ledger", str(tmp / "ledger.jsonl"),
             "--receipts", str(tmp / "receipts.json"),
             "--gateway-key", str(tmp / "gw.pub.hex"),
             *(extra or [])],
            cwd=str(REPO), capture_output=True, text=True)

    # ① 完整链：摘要重算对得上 + 逐条验签通过 ⇒ 两卡都 PASS。
    def test_matching_chain_passes(self):
        gw = trace.ToolGateway(ts=GW_TS)
        gw.issue("search_kb", {"query": "refund"}, "hit")
        gw.issue("http_get", {"url": "https://example.com"}, "ok")
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cert_file = self._issue(tmp, gw.receipts)
            proc = self._verify(tmp, cert_file, gw.receipts, gw)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[PASS] trace_binding", proc.stdout)
        self.assertIn("[PASS] receipt_chain", proc.stdout)
        self.assertIn("网关侧 2 条回执重算", proc.stdout)

    # ② 换一条链（内容不同、签名有效）：摘要当场对不上 —— 说明证明绑的不是这条链。
    def test_different_chain_is_rejected(self):
        gw = trace.ToolGateway(ts=GW_TS)
        gw.issue("search_kb", {"query": "refund"}, "hit")
        other = trace.ToolGateway(ts=GW_TS)
        other.issue("search_kb", {"query": "别的"}, "hit")
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cert_file = self._issue(tmp, gw.receipts)      # 证书绑的是 gw 的链
            proc = self._verify(tmp, cert_file, other.receipts, other)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("[FAIL] trace_binding", proc.stdout)
        self.assertIn("对不上", proc.stdout)

    # ③ 重排：结构校验（链下那一半）先炸 —— 摘要同时也对不上。
    def test_reordered_chain_is_rejected(self):
        gw = trace.ToolGateway(ts=GW_TS)
        gw.issue("a", {"q": "1"}, "x")
        gw.issue("b", {"q": "2"}, "y")
        shuffled = [gw.receipts[1], gw.receipts[0]]
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cert_file = self._issue(tmp, gw.receipts)
            proc = self._verify(tmp, cert_file, shuffled, gw)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("[FAIL] receipt_chain", proc.stdout)
        self.assertIn("seq=1 != 0", proc.stdout)

    # ④ 负例的完整形态：链结构完好、摘要也对得上，但**链尾内容被改过**。
    #    电路内对这一条是盲的（`test_in_circuit_blind_to_last_element_forgery`），
    #    于是验签成为仅剩的那道关 —— 而且它抓的是**另一件事**：摘要比对回答
    #    「是不是同一条链」，验签回答「这条链是不是网关签的」。两者不可互替。
    def test_forged_last_element_caught_by_gateway_key(self):
        gw = trace.ToolGateway(ts=GW_TS)
        gw.issue("search_kb", {"query": "x"}, "hit")
        gw.issue("http_get", {"url": "https://example.com", "token": "s"}, "leak")
        forged = dataclasses.replace(gw.receipts[1], args={"url": "https://clean.example"})
        chain = [gw.receipts[0], forged]
        self.assertEqual(trace.chain_ok(chain), (True, ""), "结构上确实看不出来")
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cert_file = self._issue(tmp, chain)     # 证书绑的是**伪造后**的链
            proc = self._verify(tmp, cert_file, chain, gw)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("[FAIL] receipt_chain", proc.stdout)
        self.assertIn("签名验证失败", proc.stdout)
        # 摘要那一路反而是对得上的（证书与检材是同一份）—— 正说明「一致性」与
        # 「来源」是两道关：这一步只证明后者。
        self.assertIn("[PASS] trace_binding", proc.stdout)

    # 只给 --receipts 不给 --gateway-key：如实说明「签名未验」，不假装验过。
    def test_without_gateway_key_reports_unverified(self):
        gw = trace.ToolGateway(ts=GW_TS)
        gw.issue("search_kb", {"query": "refund"}, "hit")
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cert_file = self._issue(tmp, gw.receipts)
            (tmp / "receipts.json").write_text(
                json.dumps(trace.receipts_to_json(gw.receipts)))
            proc = subprocess.run(
                [sys.executable, str(REPO / "scripts" / "verify_cert.py"),
                 "--cert", str(cert_file), "--pack", str(tmp / "pack.json"),
                 "--ledger", str(tmp / "ledger.jsonl"),
                 "--receipts", str(tmp / "receipts.json")],
                cwd=str(REPO), capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("回执签名未验", proc.stdout)


if __name__ == "__main__":
    unittest.main()
