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
# anvil 优先从 PATH 找，其次退回 foundry 默认安装目录
ANVIL = shutil.which("anvil") or str(Path.home() / ".foundry" / "bin" / "anvil")
HAVE_ANVIL = Path(ANVIL).exists()


class FakeChain:
    """离线假链：与 `CastRpc` 同接口，行为是确定的内存字典。"""

    def __init__(self):
        self.anchored = {}    # digest(小写) -> 链上记录
        self.sends = 0        # 已发送的交易数，用于断言「幂等时不再发交易」
        self.fail_with = None  # 置为非空字符串则模拟 send 失败（revert）

    def send_anchor(self, contract, digest_b32, private_key):
        """模拟 anchor(bytes32) 交易：登记摘要并返回 tx_hash/block。"""
        if self.fail_with:
            raise anchor.AnchorError(self.fail_with)
        self.sends += 1
        key = digest_b32.lower()
        self.anchored[key] = {"ts": 1700000000 + self.sends, "by": "0xfake000000000000000000000000000000000001",
                              "tx": "0xtx%02d" % self.sends, "block": 100 + self.sends}
        return {"tx_hash": self.anchored[key]["tx"], "block": self.anchored[key]["block"]}

    def call_uint(self, contract, sig, *args):
        """模拟 uint256 view 调用：只支持 anchoredAt / count 两种签名。"""
        if sig.startswith("anchoredAt"):
            rec = self.anchored.get(args[0].lower())
            return rec["ts"] if rec else 0
        if sig.startswith("count"):
            return len(self.anchored)
        raise AssertionError(f"unexpected call {sig}")

    def call_address(self, contract, sig, *args):
        """模拟 address view 调用（anchoredBy）；未登记返回零地址。"""
        rec = self.anchored.get(args[0].lower())
        return rec["by"] if rec else "0x0000000000000000000000000000000000000000"

    def address_of_key(self, private_key):
        """固定返回同一个假地址，便于断言登记人字段。"""
        return "0xfake000000000000000000000000000000000001"


class TestArtifact(unittest.TestCase):
    """入库的 contracts/Anchor.json 必须自洽（运行期靠它部署，不靠 solc）。"""

    # 产物形状：ABI 函数集合与事件名必须与后端调用的签名一一对应（写错名字=运行期才炸）。
    def test_artifact_shape(self):
        art = anchor.load_artifact()
        self.assertEqual(art["contractName"], "Anchor")
        fns = {e["name"] for e in art["abi"] if e["type"] == "function"}
        self.assertEqual(fns, {"anchor", "anchoredAt", "anchoredBy", "isAnchored", "count"})
        self.assertIn("Anchored", {e["name"] for e in art["abi"] if e["type"] == "event"})
        self.assertTrue(art["bytecode"].startswith("0x"))
        self.assertGreater((len(art["bytecode"]) - 2) // 2, 100, "bytecode too short")

    # 参数类型必须是 bytes32：证书摘要是 32 字节，类型不符会导致编码歧义。
    def test_abi_anchor_takes_bytes32(self):
        art = anchor.load_artifact()
        fn = next(e for e in art["abi"] if e.get("name") == "anchor")
        self.assertEqual(fn["inputs"][0]["type"], "bytes32")


class TestDigestEncoding(unittest.TestCase):
    """摘要（64 位十六进制）与合约 bytes32 字面量之间的互转。"""

    # 往返一致：带不带 0x 前缀都能规范化成 0x + 小写十六进制。
    def test_roundtrip(self):
        d = "ab" * 32
        self.assertEqual(anchor.digest_to_bytes32(d), "0x" + d)
        self.assertEqual(anchor.digest_to_bytes32("0x" + d), "0x" + d)
        self.assertEqual(anchor.bytes32_to_digest("0x" + d), d)

    # 非法长度/非十六进制必须在使用前就报错，别让坏字节流进 RPC 调用。
    def test_rejects_non_32_bytes(self):
        for bad in ("", "abc", "0x" + "ab" * 31, "z" * 64):
            with self.assertRaises(ValueError):
                anchor.digest_to_bytes32(bad)


class TestBackendSelection(unittest.TestCase):
    """后端选择：显式要求上链却配置不全时必须报错，不能静默退化成文件账本。"""

    # require=True 表示调用方明确要求上链；缺配置应报错而不是悄悄写本地文件。
    def test_needs_config_when_required(self):
        with self.assertRaises(anchor.AnchorError):
            anchor.backend_from_env(Path("l.jsonl"), require=True)

    # 默认（无环境变量）走文件账本，保证离线也能锚定与验证。
    def test_file_backend_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            for k in (anchor.ENV_RPC, anchor.ENV_CONTRACT):
                os.environ.pop(k, None)
            b = anchor.backend_from_env(Path(tmp) / "l.jsonl")
            self.assertIsInstance(b, anchor.FileLedgerBackend)

    # 配好 RPC 与合约地址后自动切到链上后端（环境变量是部署时的唯一开关）。
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

    # 便捷钩子同理：未配置就抛 NotImplementedError，明确告知调用方锚定并未发生。
    def test_unconfigured_hook_raises(self):
        for k in (anchor.ENV_RPC, anchor.ENV_CONTRACT):
            os.environ.pop(k, None)
        with self.assertRaises(NotImplementedError):
            anchor.anchor_on_chain("ab" * 32)


class TestFileBackend(unittest.TestCase):
    """文件后端：``anchor``/``get`` 契约与文件账本一致（上层可无感换后端）。"""

    # 写入后立即读回，meta 被保留，且哈希链仍然自洽。
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


class TestLedgerTail(unittest.TestCase):
    """账本尾部缓存：``append_anchor`` 从 O(n) 全表重读变成 O(1) 摊销。

    这一条不是「优化」而是正确性的一部分：``/v1/check`` **每调用一次就锚定一条**，
    全表重读意味着账本越长、这个毫秒级接口越慢。
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.led = Path(self.tmp.name) / "l.jsonl"
        # 每个用例从干净的缓存开始：缓存是**模块级**的（服务里多个作业共用），
        # 不清的话上一个用例的戳记会漏进来，测的就不是这里造的场景了。
        with anchor._TAIL_LOCK:
            anchor._TAIL_CACHE.clear()

    def tearDown(self):
        with anchor._TAIL_LOCK:
            anchor._TAIL_CACHE.clear()
        self.tmp.cleanup()

    def test_missing_file_is_genesis(self):
        self.assertEqual(anchor.ledger_tail(self.led), (0, anchor.GENESIS, False))

    def test_append_then_tail_hits_the_cache(self):
        """**判据是命中**，不只是「答案对」。

        只断言「尾部值正确」的用例，在缓存从未生效时也会通过 —— 那样的测试守不住
        任何东西。所以这里同时断言 ``hit=True``，并且下一例直接数
        ``read_ledger`` 被调了几次。
        """
        for i in range(3):
            anchor.append_anchor(self.led, f"d{i}")
        count, last, hit = anchor.ledger_tail(self.led)
        self.assertEqual(count, 3)
        self.assertTrue(hit)
        self.assertEqual(last, anchor.read_ledger(self.led)[-1]["hash"])
        self.assertTrue(anchor.verify_ledger(self.led)[0])       # 链仍然自洽

    def test_cached_tail_does_not_read_the_file_at_all(self):
        """数调用次数：命中的那次**一次都不该读全表**。

        这是「O(1)」唯一站得住的证据 —— 光看返回值分不出「读了一遍又算出同样的
        结果」和「压根没读」。
        """
        for i in range(3):
            anchor.append_anchor(self.led, f"d{i}")
        calls = []
        real = anchor.read_ledger

        def counting(path):
            calls.append(path)
            return real(path)

        anchor.read_ledger = counting
        try:
            anchor.ledger_tail(self.led)
        finally:
            anchor.read_ledger = real
        self.assertEqual(calls, [], "命中的尾部仍然把整个账本读了一遍")

    def test_external_append_invalidates_the_cache(self):
        """**别人的进程**追加之后，缓存必须失效 —— 否则会写出重复的 ``seq``。

        这是这个缓存唯一危险的地方：拿旧尾部的 hash 当 ``prev``，哈希链就断了。
        这里绕过 ``append_anchor`` 直接写文件，模拟另一个进程。
        """
        anchor.append_anchor(self.led, "d0")
        anchor.ledger_tail(self.led)                             # 先把缓存暖起来
        other = {"seq": 1, "prev": anchor.read_ledger(self.led)[-1]["hash"],
                 "digest": "d1", "ts": "2026-01-01T00:00:00Z", "meta": {}}
        other["hash"] = anchor._entry_hash(other)
        with self.led.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(other, sort_keys=True) + "\n")
        count, last, hit = anchor.ledger_tail(self.led)
        self.assertEqual((count, hit), (2, False))               # 老实重读了
        self.assertEqual(last, other["hash"])
        # 缓存失效这件事**要能反映到写入上**：接着追加的那条 seq 必须是 2
        rec = anchor.append_anchor(self.led, "d2")
        self.assertEqual(rec["seq"], 2)
        self.assertTrue(anchor.verify_ledger(self.led)[0])

    def test_rewriting_shorter_invalidates_too(self):
        """截断（比如归档）之后也不能拿旧尾部 —— 尾部必须跟着**变短**。"""
        for i in range(3):
            anchor.append_anchor(self.led, f"d{i}")
        anchor.ledger_tail(self.led)                              # 先把缓存暖起来
        kept = self.led.read_text(encoding="utf-8").splitlines()[0]
        self.led.write_text(kept + "\n", encoding="utf-8")        # 模拟另一个进程归档
        count, last, hit = anchor.ledger_tail(self.led)
        self.assertEqual((count, hit), (1, False))
        self.assertEqual(last, json.loads(kept)["hash"])


class TestRpcBackendOffline(unittest.TestCase):
    """RpcAnchorBackend 的行为（幂等、竞态、账本回写、健康检查）用假链覆盖。"""

    def setUp(self):
        # 注入假链：离线覆盖 RPC 后端逻辑，不依赖 foundry/网络
        self.tmp = tempfile.TemporaryDirectory()
        self.led = Path(self.tmp.name) / "l.jsonl"
        self.chain = FakeChain()
        self.b = anchor.RpcAnchorBackend("http://fake:8545", "0x" + "22" * 20,
                                         private_key="0xkey", ledger_path=self.led,
                                         client=self.chain)
        self.d = "ab" * 32

    def tearDown(self):
        self.tmp.cleanup()

    # 上链成功后返回完整记录（tx/区块/登记人），读回时链上字段与写入时一致。
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

    # 幂等锚定：重复登记同一摘要不再发第二笔交易，本地账本也只留一条记录。
    def test_idempotent_second_anchor_does_not_send(self):
        self.b.anchor(self.d)
        again = self.b.anchor(self.d)
        self.assertEqual(again["status"], "already_anchored")
        self.assertEqual(self.chain.sends, 1, "duplicate anchor must not send another tx")
        self.assertEqual(len(anchor.read_ledger(self.led)), 1)

    # 竞态：查询时链上还没有，发送时已被别人抢先登记。此时合约 revert
    # "already anchored"，后端应据此判定为幂等成功，而不是把错误抛给调用方。
    def test_race_already_anchored_revert_is_idempotent(self):
        # 模拟：查询时还没有，发送时链上已存在（别人抢先登记）
        first = anchor.RpcAnchorBackend("http://fake", "0x" + "22" * 20, client=self.chain)
        first.anchor(self.d)
        self.chain.fail_with = "cast send failed: execution reverted: Anchor: already anchored"
        rec = self.b.anchor(self.d)
        self.assertEqual(rec["status"], "already_anchored")

    # 非竞态类 revert（如余额不足）必须原样抛出，且失败时不留本地账本记录。
    def test_other_revert_propagates(self):
        self.chain.fail_with = "cast send failed: insufficient funds"
        with self.assertRaises(anchor.AnchorError):
            self.b.anchor(self.d)
        self.assertEqual(anchor.read_ledger(self.led), [], "no ledger entry on failed tx")

    # 链上证据回写本地账本：tx/合约/链上时间戳都要落在 meta.on_chain，且哈希链保持自洽。
    def test_ledger_meta_records_chain_evidence(self):
        self.b.anchor(self.d, {"kind": "tool-args"})
        entry = anchor.find_anchor(self.led, self.d)
        oc = entry["meta"]["on_chain"]
        self.assertEqual(oc["tx_hash"], "0xtx01")
        self.assertEqual(oc["contract"], "0x" + "22" * 20)
        self.assertEqual(oc["chain_ts"], 1700000001)
        self.assertEqual(oc["chain_ts_iso"], "2023-11-14T22:13:21Z")
        self.assertTrue(anchor.verify_ledger(self.led)[0], "chain link must stay valid")

    # 构造期就校验配置：缺 rpc_url 或合约地址直接报错，别留到发交易时才失败。
    def test_missing_config_errors(self):
        with self.assertRaises(anchor.AnchorError):
            anchor.RpcAnchorBackend("", "0x" + "22" * 20)
        with self.assertRaises(anchor.AnchorError):
            anchor.RpcAnchorBackend("http://fake", "")

    # 摘要格式错误应在任何 RPC 调用之前就抛 ValueError（快速失败，省一次网络往返）。
    def test_bad_digest_errors_before_rpc(self):
        with self.assertRaises(ValueError):
            self.b.anchor("nothex")

    # 只读核对接口：已登记返回记录，未登记返回 None（供 verify_session --rpc 使用）。
    def test_verify_digest_on_chain_helper(self):
        self.b.anchor(self.d)
        rec = anchor.verify_digest_on_chain(self.d, "http://fake", "0x" + "22" * 20, client=self.chain)
        self.assertIsNotNone(rec)
        self.assertIsNone(anchor.verify_digest_on_chain("cd" * 32, "http://fake",
                                                       "0x" + "22" * 20, client=self.chain))


class TestCastCommandLines(unittest.TestCase):
    """`cast` 的参数顺序很讲究（--create 会吞掉其后的 flag 作位置参数）。"""

    def _capture(self, fn):
        """临时替换 subprocess.run 以捕获实际拼出的命令行，不真的执行 cast。"""
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

    # --rpc-url 必须排在 --create 之前：--create 之后的 flag 会被当成位置参数而解析失败。
    def test_rpc_url_comes_before_create(self):
        cli = anchor.CastRpc("http://rpc", cast_bin="cast")
        cmd = self._capture(lambda: cli.deploy("0xdead", "0xkey"))
        self.assertEqual(cmd[:2], ["cast", "send"])
        self.assertIn("--rpc-url", cmd)
        self.assertLess(cmd.index("--rpc-url"), cmd.index("--create"))
        self.assertEqual(cmd[-1], "0xdead", "bytecode must be the trailing positional")

    # 摘要作为末位位置参数传入，函数签名必须是完整形式 anchor(bytes32)。
    def test_send_anchor_puts_digest_last(self):
        cli = anchor.CastRpc("http://rpc", cast_bin="cast")
        cmd = self._capture(lambda: cli.send_anchor("0xC", "0x" + "ab" * 32, "0xkey"))
        self.assertEqual(cmd[1], "send")
        self.assertEqual(cmd[-1], "0x" + "ab" * 32)
        self.assertIn("anchor(bytes32)", cmd)

    # cast wallet 是纯本地子命令，带上 --rpc-url 会被拒绝，因此不能统一拼 URL。
    def test_wallet_address_has_no_rpc_url(self):
        cli = anchor.CastRpc("http://rpc", cast_bin="cast")
        cmd = self._capture(lambda: cli.address_of_key("0xkey"))
        self.assertEqual(cmd[:2], ["cast", "wallet"])
        self.assertNotIn("--rpc-url", cmd, "cast wallet is local and rejects --rpc-url")

    # cast call 会给大整数附人类可读后缀（"1789041583 [1.789e9]"），解析时只取首个 token。
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

    # 固定端口便于排查，且可用环境变量覆盖以避开端口冲突
    PORT = int(os.environ.get("POP_TEST_ANVIL_PORT", "8577"))
    RPC = f"http://127.0.0.1:{PORT}"

    @classmethod
    def setUpClass(cls):
        # 起本地链并轮询 block-number 等待就绪（anvil 启动是异步的）
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
        # 先温和终止，超时才强杀，避免留下僵尸 anvil 占用端口
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            cls.proc.kill()

    def setUp(self):
        # 每个用例独立的临时账本，互不干扰
        self.tmp = tempfile.TemporaryDirectory()
        self.led = Path(self.tmp.name) / "l.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    # 端到端主链路：部署入库 bytecode → 锚定 → 独立客户端读回 → 幂等 → 本地账本回写。
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


    # 服务层与真链的接线。上面几条测的是 ``RpcAnchorBackend`` 这个**对象**，
    # 这一条测的是服务真的把它用起来之后那条路 —— 中间隔着 ``backend_from_env``
    # 的选择、``_require_healthy_chain`` 的前置检查、``issue_certificate`` 里
    # 「先锚定再落证书文件」的顺序，以及账本锁。任何一处接错，锚定都不会发生，
    # 而在假客户端下**看不出来**（假客户端本来就不碰链）。
    def test_the_service_anchors_through_a_real_chain(self):
        from policydsl import cert, service                # noqa: PLC0415

        info = anchor.deploy_anchor_contract(self.RPC)
        svc_dir = Path(self.tmp.name) / "svc"
        reg = service.registry_from_paths([REPO / "policy_packs" / "agent_content_v1.json"])
        svc = service.ProofService(reg, svc_dir, host_check=True,
                                   rpc_url=self.RPC, contract=info["address"])

        # ① 后端选对了，且**真的**探到链（不是「配了就当连上」）
        self.assertEqual(svc.backend.name, "rpc")
        self.assertEqual(svc.backend.contract, info["address"])
        self.assertTrue(svc.chain_health(refresh=True)["healthy"])

        # ② 走完一次真实作业（host_check ⇒ 毫秒级，不出证明）
        svc.start()
        try:
            job = svc.submit("agent-content-v1", "This reply says nothing incriminating.")
            deadline = time.time() + 60
            while job.state not in service.STATE_TERMINAL_STATES and time.time() < deadline:
                time.sleep(0.05)
        finally:
            svc.stop()
        self.assertEqual(job.state, service.STATE_DONE, getattr(job, "error", ""))

        # ③ 证书摘要**真的**在链上 —— 用一个独立的只读客户端核对，
        #    而不是读服务自己记的那份记录（读自己的记录等于什么都没验）
        digest = cert.cert_digest(job.issued.payload)
        from_chain = anchor.verify_digest_on_chain(digest, self.RPC, info["address"])
        self.assertIsNotNone(from_chain, "证书摘要没上链")
        self.assertEqual(from_chain["contract"], info["address"])

        # ④ 服务落盘的 anchor.json 记的是**链上的那一条**：链上时间戳与一次
        #    全新只读查询对得上。只断言「有个 tx_hash」是不够的 —— 本地凭空写
        #    一个哈希也能过。
        written = json.loads((job.issued.out_dir / "anchor.json").read_text())
        self.assertEqual(written["contract"], info["address"])
        self.assertEqual(written["chain_ts"], from_chain["chain_ts"])
        self.assertRegex(written["tx_hash"], r"^0x[0-9a-f]{64}$")
        self.assertGreater(written["block"], 0)

        # ⑤ 本地账本那条记录带着同一个 tx，且哈希链仍自洽
        entry = anchor.find_anchor(svc.ledger, digest)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["meta"]["on_chain"]["tx_hash"], written["tx_hash"])
        self.assertTrue(anchor.verify_ledger(svc.ledger)[0])


if __name__ == "__main__":
    unittest.main()
