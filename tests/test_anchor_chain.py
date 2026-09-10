"""P7-c 链上锚定：入库合约、后端抽象、cast 客户端、以及（有 anvil 时的）真链端到端。

离线用例用**假 RPC 客户端**（可注入）覆盖后端逻辑；真链用例在检测到 `anvil`
时自动起一条本地链跑 `deploy → anchor → get → 本地账本回写`，否则跳过。
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl import anchor  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
ANVIL = shutil.which("anvil") or str(Path.home() / ".foundry" / "bin" / "anvil")
HAVE_ANVIL = Path(ANVIL).exists()


class FakeChain:
    """离线假链：与 `CastRpc` 同接口，行为是确定的内存字典。"""

    def __init__(self):
        self.anchored = {}
        self.sends = 0
        self.fail_with = None

    def send_anchor(self, contract, digest_b32, private_key):
        if self.fail_with:
            raise anchor.AnchorError(self.fail_with)
        self.sends += 1
        key = digest_b32.lower()
        self.anchored[key] = {"ts": 1700000000 + self.sends, "by": "0xfake000000000000000000000000000000000001",
                              "tx": "0xtx%02d" % self.sends, "block": 100 + self.sends}
        return {"tx_hash": self.anchored[key]["tx"], "block": self.anchored[key]["block"]}

    def call_uint(self, contract, sig, *args):
        if sig.startswith("anchoredAt"):
            rec = self.anchored.get(args[0].lower())
            return rec["ts"] if rec else 0
        if sig.startswith("count"):
            return len(self.anchored)
        raise AssertionError(f"unexpected call {sig}")

    def call_address(self, contract, sig, *args):
        rec = self.anchored.get(args[0].lower())
        return rec["by"] if rec else "0x0000000000000000000000000000000000000000"

    def address_of_key(self, private_key):
        return "0xfake000000000000000000000000000000000001"


class TestArtifact(unittest.TestCase):
    """入库的 contracts/Anchor.json 必须自洽（运行期靠它部署，不靠 solc）。"""

    def test_artifact_shape(self):
        art = anchor.load_artifact()
        self.assertEqual(art["contractName"], "Anchor")
        fns = {e["name"] for e in art["abi"] if e["type"] == "function"}
        self.assertEqual(fns, {"anchor", "anchoredAt", "anchoredBy", "isAnchored", "count"})
        self.assertIn("Anchored", {e["name"] for e in art["abi"] if e["type"] == "event"})
        self.assertTrue(art["bytecode"].startswith("0x"))
        self.assertGreater((len(art["bytecode"]) - 2) // 2, 100, "bytecode too short")

    def test_abi_anchor_takes_bytes32(self):
        art = anchor.load_artifact()
        fn = next(e for e in art["abi"] if e.get("name") == "anchor")
        self.assertEqual(fn["inputs"][0]["type"], "bytes32")


class TestDigestEncoding(unittest.TestCase):
    def test_roundtrip(self):
        d = "ab" * 32
        self.assertEqual(anchor.digest_to_bytes32(d), "0x" + d)
        self.assertEqual(anchor.digest_to_bytes32("0x" + d), "0x" + d)
        self.assertEqual(anchor.bytes32_to_digest("0x" + d), d)

    def test_rejects_non_32_bytes(self):
        for bad in ("", "abc", "0x" + "ab" * 31, "z" * 64):
            with self.assertRaises(ValueError):
                anchor.digest_to_bytes32(bad)


class TestBackendSelection(unittest.TestCase):
    def test_needs_config_when_required(self):
        with self.assertRaises(anchor.AnchorError):
            anchor.backend_from_env(Path("l.jsonl"), require=True)

    def test_file_backend_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            for k in (anchor.ENV_RPC, anchor.ENV_CONTRACT):
                os.environ.pop(k, None)
            b = anchor.backend_from_env(Path(tmp) / "l.jsonl")
            self.assertIsInstance(b, anchor.FileLedgerBackend)

    def test_env_selects_rpc_backend(self):
        old = dict(os.environ)
        os.environ[anchor.ENV_RPC] = "http://127.0.0.1:1"
        os.environ[anchor.ENV_CONTRACT] = "0x" + "11" * 20
        try:
            b = anchor.backend_from_env(Path("l.jsonl"))
            self.assertIsInstance(b, anchor.RpcAnchorBackend)
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_unconfigured_hook_raises(self):
        for k in (anchor.ENV_RPC, anchor.ENV_CONTRACT):
            os.environ.pop(k, None)
        with self.assertRaises(NotImplementedError):
            anchor.anchor_on_chain("ab" * 32)


class TestFileBackend(unittest.TestCase):
    def test_anchor_and_get(self):
        with tempfile.TemporaryDirectory() as tmp:
            led = Path(tmp) / "l.jsonl"
            b = anchor.FileLedgerBackend(led)
            rec = b.anchor("d1", {"kind": "llm"})
            self.assertEqual(rec["backend"], "file")
            self.assertEqual(rec["seq"], 0)
            self.assertEqual(b.get("d1")["meta"]["kind"], "llm")
            self.assertIsNone(b.get("nope"))
            self.assertTrue(anchor.verify_ledger(led)[0])


class TestRpcBackendOffline(unittest.TestCase):
    """RpcAnchorBackend 的行为（幂等、竞态、账本回写、健康检查）用假链覆盖。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.led = Path(self.tmp.name) / "l.jsonl"
        self.chain = FakeChain()
        self.b = anchor.RpcAnchorBackend("http://fake:8545", "0x" + "22" * 20,
                                         private_key="0xkey", ledger_path=self.led,
                                         client=self.chain)
        self.d = "ab" * 32

    def tearDown(self):
        self.tmp.cleanup()

    def test_anchor_then_get(self):
        rec = self.b.anchor(self.d, {"kind": "zk"})
        self.assertEqual(rec["status"], "anchored")
        self.assertEqual(rec["tx_hash"], "0xtx01")
        self.assertEqual(rec["block"], 101)
        self.assertEqual(rec["anchored_by"], "0xfake000000000000000000000000000000000001")
        got = self.b.get(self.d)
        self.assertEqual(got["chain_ts"], rec["chain_ts"])
        self.assertEqual(got["contract"], "0x" + "22" * 20)
        self.assertIsNone(self.b.get("cd" * 32))

    def test_idempotent_second_anchor_does_not_send(self):
        self.b.anchor(self.d)
        again = self.b.anchor(self.d)
        self.assertEqual(again["status"], "already_anchored")
        self.assertEqual(self.chain.sends, 1, "duplicate anchor must not send another tx")
        self.assertEqual(len(anchor.read_ledger(self.led)), 1)

    def test_race_already_anchored_revert_is_idempotent(self):
        # 模拟：查询时还没有，发送时链上已存在（别人抢先登记）
        first = anchor.RpcAnchorBackend("http://fake", "0x" + "22" * 20, client=self.chain)
        first.anchor(self.d)
        self.chain.fail_with = "cast send failed: execution reverted: Anchor: already anchored"
        rec = self.b.anchor(self.d)
        self.assertEqual(rec["status"], "already_anchored")

    def test_other_revert_propagates(self):
        self.chain.fail_with = "cast send failed: insufficient funds"
        with self.assertRaises(anchor.AnchorError):
            self.b.anchor(self.d)
        self.assertEqual(anchor.read_ledger(self.led), [], "no ledger entry on failed tx")

    def test_ledger_meta_records_chain_evidence(self):
        self.b.anchor(self.d, {"kind": "tool-args"})
        entry = anchor.find_anchor(self.led, self.d)
        oc = entry["meta"]["on_chain"]
        self.assertEqual(oc["tx_hash"], "0xtx01")
        self.assertEqual(oc["contract"], "0x" + "22" * 20)
        self.assertEqual(oc["chain_ts"], 1700000001)
        self.assertEqual(oc["chain_ts_iso"], "2023-11-14T22:13:21Z")
        self.assertTrue(anchor.verify_ledger(self.led)[0], "chain link must stay valid")

    def test_missing_config_errors(self):
        with self.assertRaises(anchor.AnchorError):
            anchor.RpcAnchorBackend("", "0x" + "22" * 20)
        with self.assertRaises(anchor.AnchorError):
            anchor.RpcAnchorBackend("http://fake", "")

    def test_bad_digest_errors_before_rpc(self):
        with self.assertRaises(ValueError):
            self.b.anchor("nothex")

    def test_verify_digest_on_chain_helper(self):
        self.b.anchor(self.d)
        rec = anchor.verify_digest_on_chain(self.d, "http://fake", "0x" + "22" * 20, client=self.chain)
        self.assertIsNotNone(rec)
        self.assertIsNone(anchor.verify_digest_on_chain("cd" * 32, "http://fake",
                                                       "0x" + "22" * 20, client=self.chain))


class TestCastCommandLines(unittest.TestCase):
    """`cast` 的参数顺序很讲究（--create 会吞掉其后的 flag 作位置参数）。"""

    def _capture(self, fn):
        seen = {}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd

            class P:
                returncode = 0
                stdout = '{"transactionHash":"0xt","blockNumber":"0x1","contractAddress":"0xA"}'
                stderr = ""
            return P()

        real = anchor.subprocess.run
        anchor.subprocess.run = fake_run
        try:
            fn()
        finally:
            anchor.subprocess.run = real
        return seen["cmd"]

    def test_rpc_url_comes_before_create(self):
        cli = anchor.CastRpc("http://rpc", cast_bin="cast")
        cmd = self._capture(lambda: cli.deploy("0xdead", "0xkey"))
        self.assertEqual(cmd[:2], ["cast", "send"])
        self.assertIn("--rpc-url", cmd)
        self.assertLess(cmd.index("--rpc-url"), cmd.index("--create"))
        self.assertEqual(cmd[-1], "0xdead", "bytecode must be the trailing positional")

    def test_send_anchor_puts_digest_last(self):
        cli = anchor.CastRpc("http://rpc", cast_bin="cast")
        cmd = self._capture(lambda: cli.send_anchor("0xC", "0x" + "ab" * 32, "0xkey"))
        self.assertEqual(cmd[1], "send")
        self.assertEqual(cmd[-1], "0x" + "ab" * 32)
        self.assertIn("anchor(bytes32)", cmd)

    def test_wallet_address_has_no_rpc_url(self):
        cli = anchor.CastRpc("http://rpc", cast_bin="cast")
        cmd = self._capture(lambda: cli.address_of_key("0xkey"))
        self.assertEqual(cmd[:2], ["cast", "wallet"])
        self.assertNotIn("--rpc-url", cmd, "cast wallet is local and rejects --rpc-url")

    def test_call_parses_decimal_with_suffix(self):
        cli = anchor.CastRpc("http://rpc", cast_bin="cast")

        def fake_run(cmd, **kw):
            class P:
                returncode = 0
                stdout = "1789041583 [1.789e9]\n"
                stderr = ""
            return P()

        real = anchor.subprocess.run
        anchor.subprocess.run = fake_run
        try:
            self.assertEqual(cli.call_uint("0xC", "anchoredAt(bytes32)(uint256)", "0xd"), 1789041583)
        finally:
            anchor.subprocess.run = real


@unittest.skipUnless(HAVE_ANVIL, "anvil (foundry) not installed")
class TestAnvilEndToEnd(unittest.TestCase):
    """真链端到端：起 anvil → 用入库 bytecode 部署 → 锚定 → 读回 → 本地账本。"""

    PORT = int(os.environ.get("POP_TEST_ANVIL_PORT", "8577"))
    RPC = f"http://127.0.0.1:{PORT}"

    @classmethod
    def setUpClass(cls):
        cls.proc = subprocess.Popen([ANVIL, "--port", str(cls.PORT), "--silent"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cli = anchor.CastRpc(cls.RPC, cast_bin=shutil.which("cast"))
        for _ in range(60):
            try:
                cli.block_number()
                break
            except anchor.AnchorError:
                time.sleep(0.25)
        else:
            cls.proc.kill()
            raise unittest.SkipTest("anvil did not start")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            cls.proc.kill()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.led = Path(self.tmp.name) / "l.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    def test_deploy_anchor_readback(self):
        info = anchor.deploy_anchor_contract(self.RPC)
        self.assertTrue(info["address"].startswith("0x"))
        self.assertEqual(info["chain_id"], 31337)

        b = anchor.RpcAnchorBackend(self.RPC, info["address"], ledger_path=self.led)
        self.assertEqual(b.healthy(), (True, "ok"))
        digest = "12" * 32
        rec = b.anchor(digest, {"kind": "zk", "policy": "test"})
        self.assertEqual(rec["status"], "anchored")
        self.assertGreater(rec["chain_ts"], 0)

        # 读回：独立客户端也能看到同一条登记（公共可验证）
        other = anchor.RpcAnchorBackend(self.RPC, info["address"])
        got = other.get(digest)
        self.assertEqual(got["chain_ts"], rec["chain_ts"])
        self.assertIsNone(other.get("34" * 32))

        # 幂等：不再发第二笔交易
        self.assertEqual(b.anchor(digest)["status"], "already_anchored")
        self.assertEqual(b.get(digest)["chain_ts"], rec["chain_ts"])

        # 本地账本记下了链上证据，且哈希链仍自洽
        entry = anchor.find_anchor(self.led, digest)
        self.assertEqual(entry["meta"]["on_chain"]["tx_hash"], rec["tx_hash"])
        self.assertTrue(anchor.verify_ledger(self.led)[0])

        # 合约的 count 与登记数一致
        self.assertEqual(b.client.call_uint(info["address"], "count()(uint256)"), 1)


if __name__ == "__main__":
    unittest.main()
