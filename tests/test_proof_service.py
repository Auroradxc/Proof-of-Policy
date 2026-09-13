"""证明服务（``policydsl/service.py`` + ``scripts/proof_service.py``）的测试。

分三层，**默认全跑**（除了最后一层）：

1. **判定层**（``host_outcome``）—— 产出必须与电路公开值**同形**，且两套推导
   （参考评估器 / 规范违规列表）结论一致；
2. **队列层**（``ProofService``）—— 队列满拒收而不是无限收下、排队的作业真的
   会被执行、作业失败不带走工作线程、拒绝的请求不吃队列位。这一层**不跑真
   证明**：把出证步骤换成「睡一下再走真流程」，几秒钟就能覆盖状态机；
3. **HTTP 层**（``scripts/proof_service.py``）—— 真起一个 ``ThreadingHTTPServer``
   （端口 0 让内核分配），用 urllib/``http.client`` 打真实请求。

真 SP1 证明那一条进 ``POP_TEST_PROOF=1`` 门控（~2.5 分钟 + ~10.2 GiB）。
"""

import contextlib
import http.client
import json
import os
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl import anchor, auth, cert, challenge, commit, evaluate, keys, service  # noqa: E402
from policydsl import trace  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402
from policydsl.service import ProofService  # noqa: E402

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"
CONTENT_PACK = REPO / "policy_packs" / "agent_content_v1.json"
TOOL_PACK = REPO / "policy_packs" / "agent_tool_v1.json"
SEMANTIC_PACK = REPO / "policy_packs" / "semantic_demo_v1.json"

#: 一条命中 ``agent-content-v1`` 的 ``no_secret`` 规则的响应（sk- + 16 位以上）。
LEAKY = "Leak sk-abcdefghijklmnopqrstuvwxyz now"
#: 一条干净响应。
CLEAN = "This reply says nothing incriminating."


@contextlib.contextmanager
def _slow_issue(delay=0.35):
    """把出证步骤换成「睡 ``delay`` 秒再走真流程」。

    队列机制只有在作业**真的会卡住**时才看得出来。host-check 下每个作业 4 ms，
    队列永远填不满 —— 那样的测试会通过，但理由落空（它没验到任何排队行为）。
    """
    real = service.issue_certificate

    def slow(*args, **kwargs):
        time.sleep(delay)
        return real(*args, **kwargs)

    with mock.patch.object(service, "issue_certificate", slow):
        yield


def _wait_for(getter, predicate, timeout=10.0, interval=0.02):
    """轮询 ``getter()`` 直到 ``predicate`` 为真；超时返回最后一次取值。

    ``ProofService`` 的作业状态由工作线程改写，测试只能轮询 —— 这里不做「睡够
    时间它就该好了」的假设，那类断言在慢机器上会假失败、在快机器上会掩盖竞态。
    """
    deadline = time.time() + timeout
    value = getter()
    while not predicate(value) and time.time() < deadline:
        time.sleep(interval)
        value = getter()
    return value


def _packs():
    return sorted((REPO / "policy_packs").glob("*.json"))


class TestRegistry(unittest.TestCase):
    """策略注册表：点名取包 / 跳过坏包 / 标注不可出证的策略。"""

    def test_loads_every_pack_in_the_repo(self):
        reg = service.registry_from_paths(_packs())
        self.assertIn("agent-content-v1", reg.ids())
        self.assertIn("semantic-demo-v1", reg.ids())

    def test_unknown_policy_names_the_ones_that_exist(self):
        reg = service.registry_from_paths([CONTENT_PACK])
        with self.assertRaises(service.UnknownPolicy) as ctx:
            reg.get("nope")
        # 报错要**列出有哪些**，否则调用方还得再去读一遍目录
        self.assertIn("agent-content-v1", str(ctx.exception))

    def test_semantic_policy_is_marked_unserviceable(self):
        reg = service.registry_from_paths([SEMANTIC_PACK, CONTENT_PACK])
        rows = {r["id"]: r for r in reg.summaries()}
        # 注册表里就写着「这条出不了证」—— 不是等调用时才炸
        self.assertFalse(rows["semantic-demo-v1"]["serviceable"])
        self.assertEqual(rows["semantic-demo-v1"]["unserviceable_rules"],
                         ["low_harm_probability"])
        self.assertTrue(rows["agent-content-v1"]["serviceable"])
        self.assertEqual(rows["agent-content-v1"]["unserviceable_rules"], [])

    def test_same_id_different_content_is_refused(self):
        reg = service.PolicyRegistry()
        reg.add(service.pack_policy(service.load_policy(CONTENT_PACK), CONTENT_PACK))
        # 同名不同内容会让「证书里的 policy_hash」指哪一份变成看运气 —— 注册表
        # 宁可起不来也要拦下（同一个 id **重复注册同一份**是允许的，幂等）
        reg.add(service.pack_policy(service.load_policy(CONTENT_PACK), CONTENT_PACK))
        clash = Policy("agent-content-v1", "9.9.9",
                       rules=[Rule("keyword_block", "r0", {"keywords": ["x"]})])
        with self.assertRaises(service.ServiceError):
            reg.add(service.pack_policy(clash))

    def test_broken_pack_is_reported_not_swallowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.json"
            bad.write_text("{ not json", encoding="utf-8")
            skipped = []
            reg = service.registry_from_paths([CONTENT_PACK, bad],
                                              on_skip=lambda p, e: skipped.append((p, e)))
            self.assertEqual(reg.ids(), ["agent-content-v1"])
            self.assertEqual(len(skipped), 1)          # 跳过但不是悄悄跳过
            with self.assertRaises(Exception):
                service.registry_from_paths([bad])      # 没人接手就直接抛


class TestHostOutcome(unittest.TestCase):
    """``host_outcome``：与电路公开值同形，且两套推导一致。"""

    @classmethod
    def setUpClass(cls):
        cls.packed = service.pack_policy(service.load_policy(CONTENT_PACK), CONTENT_PACK)

    def test_shape_matches_the_circuit_public_values(self):
        nonce = challenge.new_nonce()
        out = service.host_outcome(self.packed, CLEAN, nonce=nonce)
        # 逐字段照抄 pop-script 写下的那份（results.json 去掉 name/mode）。
        # 这两个形状一旦分叉，/v1/check 与 /v1/attest 出的证书会「同一条响应、
        # 两种写法」，而没有任何东西提示读者两次说的是同一件事。
        self.assertEqual(set(out), {"passed", "policy_hash", "response_binding",
                                    "trace_root", "violations", "delegated"})
        self.assertEqual(out["policy_hash"], self.packed.policy_hash)
        self.assertEqual(out["response_binding"], commit.response_binding(nonce, CLEAN))
        self.assertEqual(out["trace_root"], "genesis")

    def test_violations_mirror_canonical_violations(self):
        out = service.host_outcome(self.packed, LEAKY)
        self.assertFalse(out["passed"])
        self.assertEqual(out["violations"],
                         [{"rule": "no_secret", "kind": "pattern_block",
                           "evidence": "sk-[A-Za-z0-9]{16,}"}])

    @unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built（宿主校验本身就要它）")
    def test_receipts_reach_the_circuit(self):
        """回执必须进 vectors，否则电路按**空链**判定而证书照样签得出来。

        这是本模块第一版真实踩过的坑：``_write_vectors`` 手抄字段名抄漏了
        ``receipts``，证书的 ``trace_root`` 写着 ``genesis``，验证方拿回执一重算
        就 MISMATCH。修法是改用 ``serialize.vector_entry``（它存在的理由就是防
        这种事）。这里锁住的是**结果**：电路算出的链尾必须等于本地重算的。
        """
        packed = service.pack_policy(service.load_policy(TOOL_PACK), TOOL_PACK)
        receipts = [{"seq": 0, "tool": "search_kb", "args": {"query": "refund"},
                     "prev": "genesis"}]
        want = trace.trace_root(trace.receipts_from_json(receipts))
        self.assertNotEqual(want, "genesis")            # 非恒真：链确实非空
        with tempfile.TemporaryDirectory() as tmp:
            store = Path(tmp) / "cert"
            issued = service.issue_certificate(
                store, packed, CLEAN, challenge.new_nonce(), _signer(), _backend(tmp),
                prove=False, receipts=receipts)
            # 断言留在 with 里 —— 出了这个块临时目录就没了（这一条踩过）
            self.assertEqual(issued.payload["outcome"]["trace_root"], want)
            # 回执旁证落盘：verify_cert.py --receipts 才有的可比
            self.assertTrue((store / "receipts.json").exists())
            self.assertEqual(issued.receipts_path, store / "receipts.json")

    def test_two_derivations_disagreeing_stops_the_certificate(self):
        """参考评估器与规范违规列表打架时**停证**。

        出哪一张证书都会误导一半读者：``outcome`` 只能是电路那份形状，而
        ``passed`` 是给调用方读的布尔值。这里把参考评估器打桩成「判过了」，
        规范违规列表仍会说违规 —— 两套推导当场对不上。
        """
        wrong = evaluate.CheckResult(passed=True, violations=[], notes=[], delegated=[])
        with mock.patch.object(evaluate, "check", return_value=wrong):
            with self.assertRaises(service.VerdictMismatch) as ctx:
                service.host_outcome(self.packed, LEAKY)
        self.assertIn("no_secret", str(ctx.exception))

    def test_semantic_constraints_do_not_block_the_mirror(self):
        """语义约束被摘掉之后再问违规列表 —— 电路也不会为它产出 violation。"""
        packed = service.pack_policy(service.load_policy(SEMANTIC_PACK), SEMANTIC_PACK)
        out = service.host_outcome(packed, CLEAN)
        self.assertEqual(out["violations"], [])
        # 它进的是 delegated（「这条我没判」），不是 violations
        self.assertEqual([d["name"] for d in out["delegated"]], ["low_harm_probability"])


def _signer():
    """临时签名器：快，且**不落盘**（测试不该去碰 ``.pop-keys/`` 那把真钥）。"""
    return keys.ephemeral_signer()


def _backend(tmp):
    return anchor.FileLedgerBackend(Path(tmp) / "ledger.jsonl")


class TestFailureReason(unittest.TestCase):
    """失败必须翻成一句运维能照着做的话。

    这一条是**被真事逼出来的**：本机跑 ``POP_TEST_PROOF=1`` 的验收用例时，
    ``pop-script`` 被 OOM killer 杀了，作业记下的原文是
    ``CalledProcessError: Command '[.../tmp/tmpidq5b550/jobs/job-b3ba.../vectors.json]'
    died with <Signals.SIGKILL: 9>`` —— 一屏临时路径，唯独没说「内存不够」。
    """

    def _killed(self, sig):
        return subprocess.CalledProcessError(-sig, ["pop-script", "--out", "/tmp/x"])

    def test_sigkill_names_the_memory_ceiling(self):
        msg = service.failure_reason(self._killed(9))
        self.assertIn("SIGKILL", msg)
        self.assertIn("内存", msg)
        # 给出可核实的方法与已知的地板数字，而不是一句「失败了」
        self.assertIn("dmesg", msg)
        self.assertIn("10.15 GiB", msg)

    def test_other_signals_do_not_claim_memory(self):
        """别的信号不许甩锅给内存 —— 诊断说错方向比不说更费时间。"""
        msg = service.failure_reason(self._killed(15))
        self.assertIn("15", msg)
        self.assertNotIn("10.15 GiB", msg)

    def test_ordinary_failure_is_unchanged(self):
        self.assertEqual(service.failure_reason(RuntimeError("prover exploded")),
                         "RuntimeError: prover exploded")


@unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built（宿主校验本身就要它）")
class TestServiceQueue(unittest.TestCase):
    """队列：排队而非 OOM、失败不带走工作线程、拒绝不吃队列位。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)
        reg = service.registry_from_paths([CONTENT_PACK, TOOL_PACK, SEMANTIC_PACK])
        self.svc = ProofService(reg, self.out, host_check=True, concurrency=1, max_queue=1)
        self.addCleanup(self.svc.stop)

    def test_capacity_is_prover_plus_queue(self):
        self.assertEqual(self.svc.capacity, 2)

    def test_second_request_queues_instead_of_being_refused(self):
        """验收判据：并发第二个出证请求**排队**，不是被拒、更不是 OOM。"""
        self.svc.start()
        with _slow_issue():
            first = self.svc.submit("agent-content-v1", CLEAN)
            _wait_for(lambda: self.svc.get(first.job_id).state,
                      lambda s: s == service.STATE_PROVING)
            second = self.svc.submit("agent-content-v1", CLEAN)
            self.assertEqual(second.state, service.STATE_QUEUED)
            self.assertEqual(self.svc.queue_position(second), 0)
            # 正在证的那个不占「排队位」，排第二的人前面只有 0 个没开工的
            self.assertEqual(self.svc.get(first.job_id).state, service.STATE_PROVING)
        for job in (first, second):
            done = _wait_for(lambda j=job: self.svc.get(j.job_id),
                             lambda j: j.state in service.STATE_TERMINAL_STATES)
            self.assertEqual(done.state, service.STATE_DONE, done.error)
        self.assertEqual(self.svc.queue_depth(), 0)     # 名额都还回来了

    def test_queue_full_is_refused_not_accepted(self):
        self.svc.start()
        with _slow_issue():
            self.svc.submit("agent-content-v1", CLEAN)      # 正在证
            self.svc.submit("agent-content-v1", CLEAN)      # 排队
            with self.assertRaises(service.QueueFull) as ctx:
                self.svc.submit("agent-content-v1", CLEAN)
            # 拒绝说的是「满了」，不是「服务坏了」—— HTTP 层据此回 429 而不是 503
            self.assertIn("队列已满", str(ctx.exception))
            self.assertEqual(self.svc.queue_depth(), 2)     # 被拒的那个不占位

    def test_refused_policy_does_not_eat_a_queue_slot(self):
        """不可出证的策略当场拒，且**不占**队列位。

        反例是很容易写出来的那种：先 ``_reserve()`` 再校验参数，一次参数错误
        永久吃掉一个队列位，服务越跑越满且没有任何日志解释为什么。
        """
        self.svc.start()
        with self.assertRaises(service.PolicyNotServiceable):
            self.svc.submit("semantic-demo-v1", CLEAN)
        with self.assertRaises(service.UnknownPolicy):
            self.svc.submit("no-such-policy", CLEAN)
        self.assertEqual(self.svc.queue_depth(), 0)
        self.assertEqual(self.svc.capacity, 2)              # 名额原封不动

    def test_failing_job_does_not_kill_the_worker(self):
        """一个作业炸了不能带走工作线程 —— 否则后面的作业永远停在 queued。"""
        self.svc.start()
        with mock.patch.object(service, "issue_certificate",
                               side_effect=RuntimeError("prover exploded")):
            bad = self.svc.submit("agent-content-v1", CLEAN)
            done = _wait_for(lambda: self.svc.get(bad.job_id),
                             lambda j: j.state in service.STATE_TERMINAL_STATES)
        self.assertEqual(done.state, service.STATE_FAILED)
        self.assertIn("prover exploded", done.error)
        self.assertEqual(self.svc.queue_depth(), 0)         # 名额照样还回来
        # 线程还活着：下一个作业照跑
        good = self.svc.submit("agent-content-v1", CLEAN)
        done2 = _wait_for(lambda: self.svc.get(good.job_id),
                          lambda j: j.state in service.STATE_TERMINAL_STATES)
        self.assertEqual(done2.state, service.STATE_DONE, done2.error)

    def test_oom_kill_reaches_the_operator_as_a_sentence(self):
        """证明器被 OOM 杀时，``job.error`` 要能直接被读到，而不是一屏命令行。"""
        self.svc.start()
        boom = subprocess.CalledProcessError(-9, ["pop-script", "--vectors", "/tmp/x.json"])
        with mock.patch.object(service, "issue_certificate", side_effect=boom):
            job = self.svc.submit("agent-content-v1", CLEAN)
            done = _wait_for(lambda: self.svc.get(job.job_id),
                             lambda j: j.state in service.STATE_TERMINAL_STATES)
        self.assertEqual(done.state, service.STATE_FAILED)
        self.assertIn("内存", done.error)
        self.assertEqual(done.public()["error"], done.error)   # HTTP 层原样透出

    def test_stop_drains_pending_jobs(self):
        """``stop()`` 缺省把手上的活干完 —— 停在 queued 等于判了个永不执行的刑。"""
        svc = ProofService(service.registry_from_paths([CONTENT_PACK]), self.out,
                           host_check=True, concurrency=1, max_queue=2)
        svc.start()
        jobs = [svc.submit("agent-content-v1", CLEAN) for _ in range(3)]
        svc.stop()                                          # drain=True
        for job in jobs:
            self.assertEqual(job.state, service.STATE_DONE, job.error)
        self.assertEqual(svc.queue_depth(), 0)

    def test_job_public_hides_the_certificate_until_it_is_done(self):
        self.svc.start()
        job = self.svc.submit("agent-content-v1", CLEAN)
        public = job.public(0)
        self.assertNotIn("cert", public)                    # 还没好就不给半个产物
        self.assertIn("queue_position", public)
        done = _wait_for(lambda: self.svc.get(job.job_id),
                         lambda j: j.state in service.STATE_TERMINAL_STATES)
        self.assertIn("cert", done.public())
        self.assertIn("verify_hint", self.svc.public_job(job.job_id))


@unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built（宿主校验本身就要它）")
class TestCheckCertificate(unittest.TestCase):
    """``/v1/check`` 的产物：诚实标注 unproven，并且**真的验得过**。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)
        reg = service.registry_from_paths([CONTENT_PACK, TOOL_PACK])
        self.svc = ProofService(reg, self.out, host_check=True)

    def test_verdict_carries_the_challenge_nonce(self):
        nonce = challenge.new_nonce()
        out = self.svc.check("agent-content-v1", LEAKY, nonce)
        self.assertFalse(out["passed"])
        self.assertEqual(out["nonce"], challenge.nonce_hex(nonce))
        payload = cert.envelope_payload(out["cert"])
        # 挑战块把 nonce 与证明承诺的绑定一并公开（P0-2）
        self.assertEqual(payload["challenge"]["nonce"], challenge.nonce_hex(nonce))
        self.assertEqual(payload["challenge"]["response_binding"],
                         commit.response_binding(nonce, LEAKY))

    def test_uncprovable_fields_are_labelled_not_faked(self):
        """没有工件 ⇒ ``proof_mode``/``vkey_hash`` 只能是 ``unproven``。

        硬塞一个真 vkey 哈希比占位符更坏：占位符一眼看得出是替身，真哈希会让它
        看起来像「由 pop-program 判定过」——那是过度声明（P0-4）。
        """
        out = self.svc.check("agent-content-v1", CLEAN)
        self.assertFalse(out["proved"])
        self.assertEqual(out["proof_mode"], cert.PROOF_MODE_UNPROVEN)
        self.assertEqual(out["vkey_hash"], cert.VKEY_HASH_UNPROVEN)
        bind = cert.envelope_payload(out["cert"])["binding"]
        self.assertIsNone(bind["proof_sha256"])
        self.assertEqual(bind["vkey_hash"], cert.VKEY_HASH_UNPROVEN)

    def test_issued_files_pass_verify_cert(self):
        """产物交给 ``verify_cert.py`` **独立**验一遍 —— 全 PASS 才算数。

        用工具包 + 回执：这样 ``trace_binding`` 有第二个来源（回执重算）而不是
        如实报「uncheckable」。没有回执的那条路本来就不可能验（证明没在手上、
        回执也没有），那是事实不是缺陷，见 runbook。
        """
        receipts = [{"seq": 0, "tool": "search_kb", "args": {"query": "refund"},
                     "prev": "genesis"}]
        out = self.svc.check("agent-tool-v1", CLEAN, challenge.new_nonce(), receipts)
        proc = subprocess.run(shlex.split(out["verify_hint"]), cwd=str(REPO),
                              capture_output=True, text=True)
        self.assertIn("RESULT: PASS", proc.stdout, proc.stdout + proc.stderr)
        # 非恒真：这一行确实打印了，且不是被某个 skip 掩盖的
        self.assertIn("[PASS] trace_binding", proc.stdout)

    def test_certificate_is_anchored_in_the_ledger(self):
        out = self.svc.check("agent-content-v1", CLEAN)
        ok, why = anchor.verify_ledger(self.svc.ledger)
        self.assertTrue(ok, why)
        self.assertIsNotNone(anchor.find_anchor(self.svc.ledger, out["cert_digest"]))

    def test_every_anchored_certificate_stays_on_disk(self):
        """账本里锚定的每一个摘要，磁盘上都得**还有**那份证书。

        用两个不同的 nonce 造出两张不同的证书（这正是两段式流程的真实用法：
        同一个 T，每次出题一个 nonce）。如果按内容哈希当**目录名且不带子目录**，
        后一张会把前一张的 ``cert.json`` 盖掉，而账本里那条锚定记录还在指向它 ——
        磁盘上就留下一个「有账无据」的摘要，且没有任何东西会报错。
        """
        a = self.svc.check("agent-content-v1", CLEAN, challenge.new_nonce())
        b = self.svc.check("agent-content-v1", CLEAN, challenge.new_nonce())
        self.assertNotEqual(a["cert_digest"], b["cert_digest"])   # 非恒真
        self.assertNotEqual(a["dir"], b["dir"])
        for out in (a, b):
            self.assertIsNotNone(anchor.find_anchor(self.svc.ledger, out["cert_digest"]))
            on_disk = json.loads(Path(out["dir"], "cert.json").read_text(encoding="utf-8"))
            self.assertEqual(cert.cert_digest(cert.envelope_payload(on_disk)),
                             out["cert_digest"])

    def test_semantic_policy_is_refused_with_a_reason(self):
        reg = service.registry_from_paths([SEMANTIC_PACK])
        svc = ProofService(reg, self.out, host_check=True)
        with self.assertRaises(service.PolicyNotServiceable) as ctx:
            svc.check("semantic-demo-v1", CLEAN)
        msg = str(ctx.exception)
        self.assertIn("low_harm_probability", msg)
        # 说清楚**怎么办**，否则调用方只知道被拒
        self.assertIn("issue_cert.py", msg)


@unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built（宿主校验本身就要它）")
class TestHttpEndpoint(unittest.TestCase):
    """HTTP 层：真起服务器，用真请求打。"""

    @classmethod
    def setUpClass(cls):
        from scripts.proof_service import make_server  # noqa: PLC0415
        cls.tmp = tempfile.TemporaryDirectory()
        reg = service.registry_from_paths([CONTENT_PACK, TOOL_PACK, SEMANTIC_PACK])
        # concurrency=1 + max_queue=1 ⇒ 容量 2，队列满的行为在 HTTP 上也测得到
        cls.svc = ProofService(reg, Path(cls.tmp.name), host_check=True,
                               concurrency=1, max_queue=1)
        cls.httpd = make_server(cls.svc, "127.0.0.1", 0)
        cls.host, cls.port = cls.httpd.server_address
        cls.svc.start()
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.svc.stop()
        cls.tmp.cleanup()

    # -------------------------------------------------------------- 工具

    def _call(self, method, path, body=None):
        """返回 ``(status, payload)``；4xx/5xx 也当正常响应读回来。"""
        url = f"http://{self.host}:{self.port}{path}"
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    # -------------------------------------------------------------- 用例

    def test_health_reports_the_hard_limit(self):
        code, body = self._call("GET", "/v1/health")
        self.assertEqual(code, 200)
        self.assertEqual(body["status"], "ok")
        # 并发上限是**硬事实**（~10.2 GiB 地板），所以要出现在对外可见的地方
        self.assertEqual(body["concurrency"], 1)
        self.assertEqual(body["capacity"], 2)
        self.assertEqual(body["proof_mode"], "unproven")

    def test_policies_lists_serviceable_flag(self):
        code, body = self._call("GET", "/v1/policies")
        self.assertEqual(code, 200)
        rows = {r["id"]: r for r in body["policies"]}
        self.assertFalse(rows["semantic-demo-v1"]["serviceable"])
        self.assertTrue(rows["agent-content-v1"]["serviceable"])

    def test_check_then_attest_then_poll(self):
        """三段接口串起来：check（毫秒）→ attest（入队）→ 轮询 done。"""
        code, checked = self._call("POST", "/v1/check",
                                   {"policy_id": "agent-content-v1", "response": LEAKY})
        self.assertEqual(code, 200)
        self.assertFalse(checked["passed"])

        code, job = self._call("POST", "/v1/attest",
                               {"policy_id": "agent-content-v1", "response": LEAKY,
                                "nonce": checked["nonce"]})
        self.assertEqual(code, 202)
        self.assertIn(job["state"], (service.STATE_QUEUED, service.STATE_PROVING))
        self.assertEqual(job["nonce"], checked["nonce"])    # 两段绑的是同一条 T

        got = _wait_for(
            lambda: self._call("GET", f"/v1/attest/{job['job_id']}")[1],
            lambda b: b["state"] in service.STATE_TERMINAL_STATES)
        self.assertEqual(got["state"], service.STATE_DONE, got.get("error"))
        self.assertEqual(got["proof_mode"], cert.PROOF_MODE_UNPROVEN)
        # 作业判的也是同一条响应：与 /v1/check 的结论一致
        self.assertFalse(cert.envelope_payload(got["cert"])["outcome"]["passed"])

    def test_queue_full_returns_429_not_503(self):
        with _slow_issue():
            self._call("POST", "/v1/attest",
                       {"policy_id": "agent-content-v1", "response": CLEAN})
            self._call("POST", "/v1/attest",
                       {"policy_id": "agent-content-v1", "response": CLEAN})
            code, body = self._call("POST", "/v1/attest",
                                    {"policy_id": "agent-content-v1", "response": CLEAN})
        self.assertEqual(code, 429)
        self.assertIn("队列已满", body["error"])
        # 429 而不是 503：服务是好的，只是不想把活儿收下之后 OOM
        self.assertNotEqual(code, 503)

    def test_bad_requests_are_4xx_with_a_readable_reason(self):
        cases = [
            ({"response": "x"}, 400, "policy_id"),
            ({"policy_id": "agent-content-v1"}, 400, "response"),
            ({"policy_id": "nope", "response": "x"}, 404, "nope"),
            ({"policy_id": "semantic-demo-v1", "response": "x"}, 400, "companion"),
            ({"policy_id": "agent-content-v1", "response": "x",
              "receipts": "not-a-list"}, 400, "receipts"),
        ]
        for body, want, needle in cases:
            with self.subTest(body=body):
                code, resp = self._call("POST", "/v1/check", body)
                self.assertEqual(code, want, resp)
                self.assertIn(needle, resp["error"])

    def test_unknown_route_and_job_are_404(self):
        self.assertEqual(self._call("GET", "/v1/nope")[0], 404)
        code, body = self._call("GET", "/v1/attest/job-does-not-exist")
        self.assertEqual(code, 404)
        self.assertIn("job-does-not-exist", body["error"])

    def test_oversized_body_is_refused_before_reading_it(self):
        """``Content-Length`` 超出上限时**不读请求体**就回 413。

        这是防御而不是配额：``http.server`` 会把声明的字节全读进内存，没有上限
        时一个坏掉的（或恶意的）客户端就能把服务打爆。这里只发头部、不发正文 ——
        服务器仍然要能当场把连接了结。
        """
        conn = http.client.HTTPConnection(self.host, self.port, timeout=10)
        try:
            conn.putrequest("POST", "/v1/check")
            conn.putheader("Content-Length", str(64 * 1024 * 1024))
            conn.endheaders()
            resp = conn.getresponse()
            self.assertEqual(resp.status, 413)
            self.assertIn("超出上限", json.loads(resp.read())["error"])
        finally:
            conn.close()


# --------------------------------------------------------------------------- #
# 账本 RPC 后端（加固②）
# --------------------------------------------------------------------------- #

CONTRACT = "0x" + "33" * 20


class _DeadClient:
    """连不上的 RPC：每个调用都抛 ``AnchorError``，**不带任何兜底返回值**。

    刻意做成「全挂」而不是「部分挂」：如果某个方法偷偷返回了默认值，
    这次测试就会变成在验一个不存在的场景。
    """

    def __init__(self, how="connection refused"):
        self.how = how
        self.calls = []

    def _fail(self, name):
        self.calls.append(name)
        raise anchor.AnchorError(f"cast {name}: {self.how}")

    def call_uint(self, *a):
        return self._fail("call anchoredAt")

    def call_address(self, *a):
        return self._fail("call anchoredBy")

    def send_anchor(self, *a):
        return self._fail("send anchor")

    def address_of_key(self, *a):
        return self._fail("wallet address")

    def _run(self, *a, **kw):
        return self._fail("rpc")


def _dead_rpc(*, ledger=None, how="connection refused"):
    """真的 ``RpcAnchorBackend`` + 挂掉的客户端 —— 用生产对象，不用替身。"""
    return anchor.RpcAnchorBackend("http://127.0.0.1:1", CONTRACT, ledger_path=ledger,
                                   client=_DeadClient(how))


class _LiveClient(_DeadClient):
    """**只读活**的链：``code`` 有返回（合约在），写不动（登记必挂）。"""

    def _run(self, *a, **kw):
        self.calls.append("code")
        return "0x60806040"

    def send_anchor(self, *a):
        return self._fail("send anchor")


def _live_rpc(*, ledger=None):
    return anchor.RpcAnchorBackend("http://127.0.0.1:1", CONTRACT, ledger_path=ledger,
                                   client=_LiveClient())


@contextlib.contextmanager
def _no_chain_env():
    """把 ``POP_ANCHOR_*`` 摘干净。

    没有它，「不配链上 → 走文件账本」这条会在**恰好设了这几个环境变量**的
    机器上翻车 —— 而 CI/开发机恰恰是最容易残留这种变量的地方。
    """
    strip = {k: "" for k in (anchor.ENV_RPC, anchor.ENV_CONTRACT, anchor.ENV_KEY)}
    with mock.patch.dict(os.environ, strip):
        for k in strip:
            os.environ.pop(k, None)
        yield


class TestChainBackendWiring(unittest.TestCase):
    """链上后端接线：**配了链上就必须配全**，以及 health 要报得出来。"""

    def _svc(self, **kw):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        reg = service.registry_from_paths([CONTENT_PACK])
        with _no_chain_env():
            return ProofService(reg, Path(tmp.name), host_check=True, **kw)

    def test_rpc_without_contract_refuses_to_start(self):
        """**这是本次修掉的真 bug**：``--rpc`` 而忘带 ``--contract`` 以前会
        静默退回文件账本 —— 运维以为自己上链了，其实只有本机一个文件。

        这种错最坏的地方是它**没有症状**：证书照样签得出来、账本照样自洽、
        ``/v1/health`` 也照样说 ok。等到有人去链上查那份摘要，才发现从来没有过。
        """
        with self.assertRaises(anchor.AnchorError) as ctx:
            self._svc(rpc_url="http://127.0.0.1:8545", contract=None)
        self.assertIn("--contract", str(ctx.exception))     # 报错要说清缺哪个

    def test_contract_without_rpc_refuses_too(self):
        with self.assertRaises(anchor.AnchorError):
            self._svc(rpc_url=None, contract=CONTRACT)

    def test_env_supplied_chain_config_is_accepted(self):
        """走环境变量的那条路也得通 —— 拒绝逻辑不该把正确配置一起拦掉。"""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        reg = service.registry_from_paths([CONTENT_PACK])
        with mock.patch.dict(os.environ, {anchor.ENV_RPC: "http://127.0.0.1:1",
                                          anchor.ENV_CONTRACT: CONTRACT}):
            svc = ProofService(reg, Path(tmp.name), host_check=True,
                               rpc_url="http://127.0.0.1:1")   # 只给了 rpc，合约来自环境
        self.assertEqual(svc.backend.name, "rpc")
        self.assertEqual(svc.backend.contract, CONTRACT)

    def test_no_chain_config_still_gives_the_file_ledger(self):
        """没点名链上就照常走文件账本 —— 上面那条拒绝**不该**顺手把本机用法也拦掉。"""
        svc = self._svc()
        self.assertEqual(svc.backend.name, "file")
        self.assertFalse(svc.backend.remote)

    def test_health_names_the_backend(self):
        """账本落在哪儿是运维第一眼要看的：本地文件与链上在「谁能改」上是两回事。"""
        snap = self._svc().snapshot()
        self.assertEqual(snap["anchor_backend"], "file")
        # 本地后端**没有** chain 这一段：没有可断的东西，报健康只是噪声
        self.assertNotIn("chain", snap)

    def test_health_reports_chain_health_for_a_remote_backend(self):
        svc = self._svc(backend=_live_rpc())
        snap = svc.snapshot()
        self.assertEqual(snap["anchor_backend"], "rpc")
        self.assertTrue(snap["chain"]["healthy"])
        self.assertEqual(snap["chain"]["contract"], CONTRACT)

    def test_unhealthy_chain_is_reported_as_unhealthy(self):
        """链挂了要**说出来**，而不是让 /v1/health 继续说 ok。

        判据是「是否如实」而不是「是否可用」：一个说 ok 但链已经断了的 health
        比没有 health 更糟 —— 它会把排查引到别的方向去。
        """
        snap = self._svc(backend=_dead_rpc()).snapshot()
        self.assertFalse(snap["chain"]["healthy"])
        self.assertIn("connection refused", snap["chain"]["detail"])

    def test_backend_without_a_health_probe_says_so_instead_of_ok(self):
        """**不知道**要报成不知道。``healthy()`` 的默认真值不能是 True。

        一个报 ok 而从未自检过的后端，会让 ``chain.healthy=true`` 变成一句
        没有信息量的话 —— 而这句话正是运维决定「要不要信这次签发的账本」的依据。
        """
        class Opaque(anchor.AnchorBackend):
            name = "opaque"
            remote = True

        snap = self._svc(backend=Opaque()).snapshot()
        self.assertFalse(snap["chain"]["healthy"])
        self.assertIn("不支持连通性自检", snap["chain"]["detail"])

    def test_chain_health_is_cached_not_recomputed_per_request(self):
        """自检要起一个 ``cast`` 子进程（秒级），不能挂在每次 /v1/health 上。"""
        client = _LiveClient()
        backend = anchor.RpcAnchorBackend("http://127.0.0.1:1", CONTRACT, client=client)
        svc = self._svc(backend=backend)
        for _ in range(5):
            svc.snapshot()
        self.assertEqual(client.calls, ["code"], "每次都重新自检，health 会变成负载")

    def test_cached_health_says_how_old_it_is(self):
        """**看不出多旧**的健康值比没有更糟：会把「十分钟前是好的」读成「是好的」。"""
        svc = self._svc(backend=_live_rpc())
        chain = svc.snapshot()["chain"]
        self.assertIn("checked_at", chain)
        self.assertFalse(chain["stale"])
        self.assertGreaterEqual(chain["age"], 0.0)

    def test_an_expired_cache_is_refreshed(self):
        """TTL 是真会过期的 —— 否则上面那条缓存测试在「永不刷新」时也通过。"""
        client = _LiveClient()
        backend = anchor.RpcAnchorBackend("http://127.0.0.1:1", CONTRACT, client=client)
        svc = self._svc(backend=backend)
        svc.snapshot()
        with mock.patch.object(service, "CHAIN_HEALTH_TTL", 0.0):
            svc.snapshot()
        self.assertEqual(client.calls, ["code", "code"])


class TestStartupRefusals(unittest.TestCase):
    """配置写错要在**启动时**变成一句人话 + 退出码 2。

    这一条是被真事逼出来的：``--rpc`` 忘带 ``--contract`` 时，``ProofService``
    构造里抛的 ``AnchorError`` 一路冒出 ``main()``，运维看到的是**一段 Python
    回溯**、退出码 1。在 systemd 的日志里，那和一个真的崩溃长得一模一样 —— 而
    实际只是少了一个参数。退出码 1 还会让「配置错」与「运行中崩了」在监控上
    无法区分。
    """

    def _run(self, *argv):
        return subprocess.run(
            [sys.executable, str(REPO / "scripts" / "proof_service.py"),
             "--pack", str(CONTENT_PACK), "--out-dir", str(Path(self.tmp.name) / "o"), *argv],
            cwd=str(REPO), capture_output=True, text=True, timeout=120)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_chain_config_missing_a_half_is_a_clean_refusal(self):
        for argv in (["--rpc", "http://127.0.0.1:1"], ["--contract", "0x" + "11" * 20]):
            with self.subTest(argv=argv):
                proc = self._run(*argv)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertIn("账本后端配置有误", proc.stderr)
                # 关键的否定断言：不是回溯
                self.assertNotIn("Traceback", proc.stderr)

    def test_an_auth_file_that_does_not_exist_is_a_clean_refusal(self):
        proc = self._run("--auth-file", str(Path(self.tmp.name) / "nope.txt"))
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_require_auth_without_tokens_is_refused(self):
        proc = self._run("--require-auth")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("--require-auth", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_a_good_config_still_starts_and_serves(self):
        """**非恒真对照**：同样的调用方式配全了就真的起得来。

        少了这一条，上面三条在「脚本根本跑不起来」时也会全绿。
        """
        proc = subprocess.Popen(
            [sys.executable, str(REPO / "scripts" / "proof_service.py"),
             "--pack", str(CONTENT_PACK), "--out-dir", str(Path(self.tmp.name) / "ok"),
             "--port", "0"],
            cwd=str(REPO), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.addCleanup(proc.wait, 30)
        self.addCleanup(proc.kill)
        self.addCleanup(proc.stdout.close)     # 清理按后进先出 ⇒ 关管道在最前
        # --port 0 会绑定一个随机端口，横幅里印的就是真实地址
        line = proc.stdout.readline()
        self.assertIn("proof service on http://127.0.0.1:", line)


class TestAnchorFailureIsFailClosed(unittest.TestCase):
    """锚定失败时：**磁盘上不该出现一份看起来签好了的证书**。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.packed = service.pack_policy(service.load_policy(CONTENT_PACK), CONTENT_PACK)
        self.ledger = self.root / "ledger.jsonl"

    def test_failed_anchor_leaves_no_certificate(self):
        """``cert.json`` / ``payload.json`` / ``key.json`` 一个都不该有。

        顺序是刻意的（先锚定、再落证书文件）：锚定是唯一会**对外失败**的一步，
        反过来的顺序会让一次链上故障留下一份完整、带签名的证书 —— verify_cert
        确实会判 FAIL（fail-closed），但**它已经发得出去了**，而发证书的人未必
        会先跑一遍验证。
        """
        with self.assertRaises(anchor.AnchorError):
            service.issue_certificate(self.root / "cert", self.packed, CLEAN,
                                      challenge.new_nonce(), _signer(),
                                      _live_rpc(ledger=self.ledger), prove=False)
        for name in ("cert.json", "payload.json", "key.json", "anchor.json"):
            self.assertFalse((self.root / "cert" / name).exists(), f"{name} 不该存在")
        # 本地账本也不该有半条：链上没成功就**不落账**，否则本机会凭空多出一条
        # 「已锚定」的记录，而链上查不到 —— 这比没有记录更难查
        self.assertFalse(self.ledger.exists())

    def test_a_working_backend_still_writes_everything(self):
        """**非恒真对照**：同一份输入、后端是好的时候四个文件都在。

        少了这一条，上面那个用例在「issue_certificate 整个坏掉了」时也会通过。
        """
        out = self.root / "ok"
        issued = service.issue_certificate(out, self.packed, CLEAN, challenge.new_nonce(),
                                           _signer(), _backend(self.tmp.name), prove=False)
        for name in ("cert.json", "payload.json", "key.json", "anchor.json"):
            self.assertTrue((out / name).exists(), f"{name} 该存在")
        self.assertTrue(anchor.verify_ledger(self.ledger)[0])

    def test_job_error_says_no_certificate_was_issued(self):
        """作业失败时那句话要说清「没有证书」，否则读的人会去目录里找。

        这里用的是 ``_live_rpc``（自检说连通、登记才挂）—— 因为**已知**链断的
        情况在 ``submit()`` 就被拦掉了，走不到工作线程。这一条测的正是剩下那种
        更麻烦的情况：自检那一刻链是好的，证明烧完之后登记才失败。
        """
        reg = service.registry_from_paths([CONTENT_PACK])
        svc = ProofService(reg, self.root / "svc", host_check=True, backend=_live_rpc())
        svc.start()
        self.addCleanup(svc.stop)
        job = svc.submit("agent-content-v1", CLEAN)
        done = _wait_for(lambda: svc.get(job.job_id),
                         lambda j: j.state in service.STATE_TERMINAL_STATES)
        self.assertEqual(done.state, service.STATE_FAILED)
        self.assertIn("没有签发证书", done.error)
        self.assertIn("chain.healthy", done.error)          # 给出核实方法
        self.assertFalse((self.root / "svc" / "jobs" / job.job_id / "cert.json").exists())

    def test_submit_is_refused_up_front_when_the_chain_is_known_down(self):
        """链已知断了就**不收作业** —— 不排上队再失败。

        真证明要 ~2.5 分钟 + ~10.2 GiB，而锚定在证明**之后**：让调用方等完这一程
        才发现链是断的，是用最贵的一段路去回答一个启动时就答得出来的问题。
        """
        reg = service.registry_from_paths([CONTENT_PACK])
        svc = ProofService(reg, self.root / "svc", host_check=True, backend=_dead_rpc())
        svc.start()
        self.addCleanup(svc.stop)
        with self.assertRaises(anchor.AnchorError) as ctx:
            svc.submit("agent-content-v1", CLEAN)
        self.assertIn("没有入队", str(ctx.exception))
        # 队列位必须**还回来**：一次上游故障不该把容量越用越少
        self.assertEqual(svc.queue_depth(), 0)
        self.assertEqual(svc.snapshot()["outstanding"], 0)

    def test_check_is_refused_too_because_it_also_anchors(self):
        """``/v1/check`` 也要锚定（它签的是一张**真的**证书，只是 unproven）。

        容易以为「check 是纯本地的」，于是给链上后端加个仅 attest 的旁路 ——
        那样 check 会签出一份链上查不到的证书，而它恰恰是最常被调用的那条路。
        """
        reg = service.registry_from_paths([CONTENT_PACK])
        svc = ProofService(reg, self.root / "svc", host_check=True, backend=_dead_rpc())
        with self.assertRaises(anchor.AnchorError):
            svc.check("agent-content-v1", CLEAN)
        self.assertEqual(list((self.root / "svc" / "checks").rglob("cert.json")), [])
        self.assertFalse(self.ledger.exists())

    def test_an_anchor_failure_leaves_a_work_dir_but_no_certificate(self):
        """**如实记下上一条的边界**：锚定失败时工作目录是**会**留下的。

        ``_write_vectors`` 在建目录时就把 ``checks/<前缀>/<随机>/`` 建出来了，
        ``vectors.json`` / ``results.json`` 都躺在里面 —— 而 cert / payload /
        key / anchor 四个都不在。这四个之间的区别才是有意义的那个：前两者是**输入
        与中间结果**（谁都能重算），后四者合起来才是一份「可转交、可独立验证」的
        产物。所以这里断言的不是「目录不存在」，而是「没有产物」。

        反过来说，这也意味着磁盘上会攒下一些无主的工作目录 —— 已知、可接受
        （它们不含签名、不含证书、重跑即可），但清理策略是运维的事。
        """
        reg = service.registry_from_paths([CONTENT_PACK])
        svc = ProofService(reg, self.root / "svc", host_check=True, backend=_dead_rpc())
        with self.assertRaises(anchor.AnchorError):
            svc.check("agent-content-v1", CLEAN)
        work = sorted((self.root / "svc" / "checks").rglob("vectors.json"))
        self.assertTrue(work, "工作目录本该留下（这条用例存在的意义就是记下这件事）")
        for name in ("cert.json", "payload.json", "key.json", "anchor.json"):
            self.assertEqual(list((self.root / "svc" / "checks").rglob(name)), [],
                             f"{name} 不该存在")


class TestChainDownOverHttp(unittest.TestCase):
    """链上后端挂掉时，调用方在**第一次调用**就得到 503。

    这是「两级时间尺度」里最难受的一种故障：``/v1/attest`` 立刻回 202（证明确实
    要 2.5 分钟），而锚定发生在证明**之后** —— 故障要等到作业跑完才浮现。如果只把
    作业标成 failed，调用方得先学会轮询、再看懂 ``error`` 字段，才知道坏的是
    **外部依赖**而不是自己的输入。503 让这件事在收下作业之前就成立。
    """

    @classmethod
    def setUpClass(cls):
        from scripts.proof_service import make_server  # noqa: PLC0415
        cls.tmp = tempfile.TemporaryDirectory()
        reg = service.registry_from_paths([CONTENT_PACK])
        cls.svc = ProofService(reg, Path(cls.tmp.name), host_check=True,
                               backend=_dead_rpc())
        cls.httpd = make_server(cls.svc, "127.0.0.1", 0)
        cls.host, cls.port = cls.httpd.server_address
        cls.svc.start()
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.svc.stop()
        cls.tmp.cleanup()

    def _call(self, method, path, body=None):
        url = f"http://{self.host}:{self.port}{path}"
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_health_tells_the_truth_about_a_broken_chain(self):
        """先决条件：health 已经说了链是断的。否则上面那句 503 只是碰巧。"""
        code, body = self._call("GET", "/v1/health")
        self.assertEqual(code, 200)
        self.assertEqual(body["anchor_backend"], "rpc")
        self.assertFalse(body["chain"]["healthy"])

    def test_attest_is_503_not_a_202_that_never_finishes(self):
        code, body = self._call("POST", "/v1/attest",
                                {"policy_id": "agent-content-v1", "response": CLEAN})
        self.assertEqual(code, 503, body)
        self.assertIn("没有签发证书", body["error"])
        self.assertIn("chain.healthy", body["error"])

    def test_check_is_503_too_and_points_at_the_products_dir_not_a_job(self):
        """``/v1/check`` 也锚定，所以它也 503 —— 但产物目录不是「作业目录」。

        这两条路的产物落点不一样（``checks/`` 下的一次性目录 vs ``jobs/<id>/``），
        一句话套两个入口会指向一个不存在的路径，而这句话正是调用方**据以去找
        产物**的那句。
        """
        code, body = self._call("POST", "/v1/check",
                                {"policy_id": "agent-content-v1", "response": LEAKY})
        self.assertEqual(code, 503, body)
        self.assertIn("产物目录", body["error"])
        self.assertNotIn("作业目录", body["error"])

    def test_no_job_was_created_and_nothing_was_written(self):
        """被 503 拒掉的请求不该留下**看起来像证书**的东西，也不该占队列位。"""
        self._call("POST", "/v1/attest",
                   {"policy_id": "agent-content-v1", "response": CLEAN})
        for d in (Path(self.tmp.name) / "jobs").glob("job-*"):
            for name in ("cert.json", "payload.json"):
                self.assertFalse((d / name).exists(), f"{d.name}/{name} 不该存在")
        code, health = self._call("GET", "/v1/health")
        self.assertEqual(code, 200)
        self.assertEqual(health["outstanding"], 0, "被拒的请求吃掉了容量")


# --------------------------------------------------------------------------- #
# 鉴权层（policydsl/auth.py + HTTP 驱动里的接线）
# --------------------------------------------------------------------------- #

#: 测试用 token：够长（≥ MIN_SECRET_LEN）而且是**读得出来源**的字符串 ——
#: 用 "a"*32 这种会让「哪个测试挂了」变得难查。
ALICE = "alice-token-0123456789abcdef"
BOB = "bob-token-0123456789abcdef"


class TestAuthTokens(unittest.TestCase):
    """token 的定义与解析：写错**当场**报，不要留到调用时才 401。"""

    def test_label_and_secret_are_split(self):
        t = auth.parse_token_spec(f"alice:{ALICE}")
        self.assertEqual((t.label, t.secret), ("alice", ALICE))

    def test_bare_secret_gets_a_derived_label(self):
        """不强制起名字，但派生出来的标签**不含 secret 本身**。

        派生标签是 secret 的哈希前 8 位 —— 它要能出现在日志与 ``/v1/health`` 里，
        所以绝不能是 secret 原样。这里正面锁住「标签里没有 secret 的子串」。
        """
        t = auth.parse_token_spec(ALICE)
        self.assertTrue(t.label.startswith("key-"))
        self.assertNotIn(ALICE[:12], t.label)

    def test_short_secret_is_refused_with_the_reason(self):
        with self.assertRaises(auth.AuthError) as ctx:
            auth.parse_token_spec("weak:short")
        msg = str(ctx.exception)
        self.assertIn("16", msg)          # 说出下限是多少
        self.assertIn("穷举", msg)         # 也说出**为什么**有下限

    def test_secret_with_whitespace_is_refused(self):
        """含空白的 secret 在 Authorization 头里根本传不进来。"""
        with self.assertRaises(auth.AuthError) as ctx:
            auth.parse_token_spec(f"alice:{ALICE} extra")
        self.assertIn("空白", str(ctx.exception))

    def test_duplicate_label_is_refused(self):
        """两个身份共用一个标签 → 日志与配额都会悄悄合并。"""
        with self.assertRaises(auth.AuthError) as ctx:
            auth.Authenticator.from_sources([f"alice:{ALICE}", f"alice:{BOB}"])
        self.assertIn("标签", str(ctx.exception))

    def test_one_secret_under_two_labels_is_refused(self):
        """一次泄露会同时拿到两个身份 —— 与其如此，不如只有一把。"""
        with self.assertRaises(auth.AuthError) as ctx:
            auth.Authenticator.from_sources([f"alice:{ALICE}", f"bob:{ALICE}"])
        self.assertIn("secret", str(ctx.exception))

    def test_token_file_and_env_are_merged_not_overridden(self):
        """三处来源**合起来**。后者覆盖前者会让「文件里的常备钥」凭空消失。"""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "tokens"
            p.write_text(f"# 常备钥\nfilekey:{ALICE}\n\n", encoding="utf-8")
            a = auth.Authenticator.from_sources(
                [f"clikey:{BOB}"], path=p, env="envkey:" + "c" * 32)
        self.assertEqual(sorted(a.labels), ["clikey", "envkey", "filekey"])

    def test_token_file_bad_line_names_the_line_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "tokens"
            p.write_text(f"ok:{ALICE}\nbroken:{BOB}\nnope\n", encoding="utf-8")
            with self.assertRaises(auth.AuthError) as ctx:
                auth.load_token_file(p)
            self.assertIn(":3:", str(ctx.exception))

    def test_admin_label_marks_the_token(self):
        a = auth.Authenticator.from_sources([f"ops:{ALICE}", f"app:{BOB}"],
                                            admin_labels=["ops"])
        self.assertTrue(a.authenticate(f"Bearer {ALICE}").admin)
        self.assertFalse(a.authenticate(f"Bearer {BOB}").admin)

    def test_health_snapshot_never_contains_a_secret(self):
        a = auth.Authenticator.from_sources([f"alice:{ALICE}"])
        blob = json.dumps(a.snapshot())
        self.assertIn("alice", blob)
        # 这是这个模块最要紧的一条：``/v1/health` 是**不鉴权也能问**的那种接口，
        # 一旦把 secret 漏进去，鉴权就成了一个幌子。
        self.assertNotIn(ALICE, blob)


class TestAuthDecisions(unittest.TestCase):
    """401 的三种由来 + 令牌桶。不碰 HTTP。"""

    def setUp(self):
        self.a = auth.Authenticator.from_sources(
            [f"alice:{ALICE}", f"bob:{BOB}"], admin_labels=["bob"],
            rate=2.0, burst=2)

    def test_missing_header_says_what_to_send(self):
        with self.assertRaises(auth.Unauthorized) as ctx:
            self.a.authenticate(None)
        self.assertIn("Authorization", str(ctx.exception))

    def test_wrong_scheme_is_told_apart_from_wrong_token(self):
        """「格式错」与「token 错」分开报 —— 否则 401 会把人引向错误的方向。"""
        with self.assertRaises(auth.Unauthorized) as ctx:
            self.a.authenticate("Token " + ALICE)
        self.assertIn("Bearer", str(ctx.exception))
        with self.assertRaises(auth.Unauthorized) as ctx2:
            self.a.authenticate("Bearer " + "z" * 32)
        self.assertNotIn("Bearer", str(ctx2.exception))

    def test_the_error_never_echoes_what_was_sent(self):
        """猜错的 token 不能被回显 —— 日志经常被转发到别的地方去。"""
        guess = "guess-" + "q" * 32
        with self.assertRaises(auth.Unauthorized) as ctx:
            self.a.authenticate("Bearer " + guess)
        self.assertNotIn(guess, str(ctx.exception))

    def test_a_late_token_in_the_list_still_matches(self):
        """比较不提前退出（命中第几个不该体现在耗时上）；行为上先锁住「命中得了」。"""
        pk = self.a.authenticate(f"Bearer {BOB}")
        self.assertEqual(pk.label, "bob")

    def test_oversized_header_is_refused(self):
        with self.assertRaises(auth.Unauthorized) as ctx:
            self.a.authenticate("Bearer " + "x" * (auth.MAX_HEADER_LEN + 1))
        self.assertIn("超过", str(ctx.exception))

    def test_bucket_allows_burst_then_rate_limits(self):
        p = self.a.authenticate(f"Bearer {ALICE}")
        self.a.consume(p)
        self.a.consume(p)                      # burst=2 → 两次通过
        with self.assertRaises(auth.RateLimited) as ctx:
            self.a.consume(p)
        # Retry-After 不能是 0：那会被读成「立刻重试」，于是变成忙等
        self.assertGreaterEqual(ctx.exception.retry_after, 1)

    def test_buckets_are_per_token_not_global(self):
        """一个人打满配额，不能把另一个人饿死 —— 这是按 token 分桶的全部意义。"""
        pa = self.a.authenticate(f"Bearer {ALICE}")
        self.a.consume(pa)
        self.a.consume(pa)
        with self.assertRaises(auth.RateLimited):
            self.a.consume(pa)
        # alice 已满，bob 是管理员 → 豁免（事故里运维要能一直读 health）
        self.a.consume(self.a.authenticate(f"Bearer {BOB}"))

    def test_open_mode_allows_everything_and_says_so(self):
        op = auth.Authenticator.open()
        self.assertEqual(op.mode, "none")       # 不假装有鉴权
        self.assertTrue(op.authenticate(None).owns("anyone"))
        op.consume(op.authenticate(None))       # 不限流，不抛


class _AuthHttpCase(unittest.TestCase):
    """HTTP 层鉴权测试的公共骨架：真起服务器，真发头。"""

    TOKENS = (f"alice:{ALICE}", f"bob:{BOB}")
    ADMINS = ("bob",)
    RATE = 0.0                                  # 0 = 不限流；要测限流的类自己覆盖

    @classmethod
    def setUpClass(cls):
        from scripts.proof_service import make_server  # noqa: PLC0415
        cls.tmp = tempfile.TemporaryDirectory()
        reg = service.registry_from_paths([CONTENT_PACK])
        cls.svc = ProofService(reg, Path(cls.tmp.name), host_check=True,
                               concurrency=1, max_queue=4)
        cls.authn = auth.Authenticator.from_sources(
            cls.TOKENS, admin_labels=cls.ADMINS, rate=cls.RATE, burst=4)
        cls.httpd = make_server(cls.svc, "127.0.0.1", 0, cls.authn)
        cls.host, cls.port = cls.httpd.server_address
        cls.svc.start()
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.svc.stop()
        cls.tmp.cleanup()

    def _call(self, method, path, body=None, token=ALICE, scheme="Bearer", headers=None):
        """返回 ``(status, payload, headers)``。``token=None`` ⇒ 不发 Authorization。"""
        url = f"http://{self.host}:{self.port}{path}"
        data = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if token is not None:
            req.add_header("Authorization", f"{scheme} {token}")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read()), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}"), dict(exc.headers)


class TestAuthOverHttp(_AuthHttpCase):
    """401 的形状 + 作业归属。"""

    def test_no_token_is_401_with_www_authenticate(self):
        code, body, headers = self._call("GET", "/v1/health", token=None)
        self.assertEqual(code, 401)
        # 机器可读的「你该换哪种凭据」—— 401 不带它，调用方只能靠猜
        self.assertEqual(headers.get("WWW-Authenticate"),
                         'Bearer realm="pop-proof-service"')
        self.assertIn("Authorization", body["error"])

    def test_wrong_token_is_401_and_says_nothing_else(self):
        code, body, _ = self._call("GET", "/v1/health", token="z" * 32)
        self.assertEqual(code, 401)
        self.assertNotIn("z" * 32, body["error"])

    def test_health_reports_bearer_not_none(self):
        """「到底有没有在鉴权」必须能从外部问出来。"""
        code, body, _ = self._call("GET", "/v1/health")
        self.assertEqual(code, 200)
        self.assertEqual(body["auth"]["mode"], "bearer")
        self.assertEqual(sorted(body["auth"]["tokens"]), ["alice", "bob"])
        self.assertNotIn(ALICE, json.dumps(body))

    def test_a_job_is_visible_to_the_token_that_submitted_it(self):
        """**读别人的作业**这条（docstring 里点名的那条）真的被关上了。

        这一例测「自己的读得到」，下一例测「别人的读不到」，再下一例测「管理员
        读得到」—— 三例缺一，都可能是「全放开」或「全锁死」而看不出来。
        """
        _, job, _ = self._call("POST", "/v1/attest",
                               {"policy_id": "agent-content-v1", "response": CLEAN},
                               token=ALICE)
        job_id = job["job_id"]
        self.assertEqual(job.get("submitted_by"), "alice")

        mine = _wait_for(lambda: self._call("GET", f"/v1/attest/{job_id}", token=ALICE)[1],
                         lambda b: b["state"] in service.STATE_TERMINAL_STATES)
        self.assertEqual(mine["state"], service.STATE_DONE, mine.get("error"))

    def test_an_admin_token_can_read_any_job(self):
        """运维的出口：作业挂了之后总得有人能翻开看。"""
        _, job, _ = self._call("POST", "/v1/attest",
                               {"policy_id": "agent-content-v1", "response": CLEAN},
                               token=ALICE)
        job_id = job["job_id"]
        got = _wait_for(lambda: self._call("GET", f"/v1/attest/{job_id}", token=BOB)[1],
                        lambda b: b["state"] in service.STATE_TERMINAL_STATES)
        self.assertEqual(got["state"], service.STATE_DONE, got.get("error"))
        self.assertEqual(got.get("submitted_by"), "alice")   # 谁提的一目了然

    def test_someone_elses_job_is_404_and_indistinguishable_from_missing(self):
        """**404 而不是 403**：403 等于确认「这个 job_id 存在」。

        判据不只是状态码相同，而是**措辞相同** —— 只要两者能被分开读出，
        它就是一个探测别家 job_id 的预言机。
        """
        _, job, _ = self._call("POST", "/v1/attest",
                               {"policy_id": "agent-content-v1", "response": CLEAN},
                               token=BOB)
        other = job["job_id"]
        # alice 不是 admin → 看不到 bob 的作业
        code_a, body_a, _ = self._call("GET", f"/v1/attest/{other}", token=ALICE)
        code_m, body_m, _ = self._call("GET", "/v1/attest/job-does-not-exist",
                                       token=ALICE)
        self.assertEqual((code_a, code_m), (404, 404))

        def _shape(err, jid):
            return err.replace(jid, "<id>")

        self.assertEqual(_shape(body_a["error"], other),
                         _shape(body_m["error"], "job-does-not-exist"))

    def test_unauthenticated_requests_cannot_submit(self):
        code, _, _ = self._call("POST", "/v1/attest",
                                {"policy_id": "agent-content-v1", "response": CLEAN},
                                token=None)
        self.assertEqual(code, 401)


class TestRateLimitOverHttp(_AuthHttpCase):
    """429 的形状（一个**不开**限流的类里测不出限流）。"""

    RATE = 0.5          # 0.5 次/秒、burst 4 → 头 4 次过，第 5 次 429
    ADMINS = ("bob",)
    TOKENS = (f"alice:{ALICE}", f"bob:{BOB}")

    def test_rate_limit_returns_429_with_retry_after(self):
        codes = []
        for _ in range(6):
            code, body, headers = self._call(
                "POST", "/v1/check",
                {"policy_id": "agent-content-v1", "response": CLEAN})
            codes.append(code)
            if code == 429:
                self.assertGreaterEqual(int(headers["Retry-After"]), 1)
                self.assertIn("配额", body["error"])
        self.assertIn(429, codes)
        self.assertEqual(codes[0], 200)         # 头一次一定过

    def test_admin_token_is_exempt_from_the_quota(self):
        """事故里运维要能一直读 health，而那正是配额最可能被自己打满的时候。"""
        for _ in range(8):
            code, _, _ = self._call("GET", "/v1/health", token=BOB)
            self.assertEqual(code, 200)


@unittest.skipUnless(os.environ.get("POP_TEST_PROOF") == "1",
                     "set POP_TEST_PROOF=1 to run the real SP1 attest test（~2.5 分钟 / "
                     "峰值 ~10.2 GiB，本机 12 GB 上同一时刻只能有一个证明器）")
class TestRealProofAttest(unittest.TestCase):
    """真 SP1 证明那一段：``/v1/attest`` 的作业带**真 vkey**，证书验得过。"""

    def test_attested_certificate_carries_a_real_vkey(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        reg = service.registry_from_paths([CONTENT_PACK])
        with ProofService(reg, Path(tmp.name)) as svc:      # host_check=False ⇒ 真证明
            job = svc.submit("agent-content-v1", CLEAN, challenge.new_nonce())
            done = _wait_for(lambda: svc.get(job.job_id),
                             lambda j: j.state in service.STATE_TERMINAL_STATES,
                             timeout=900, interval=1.0)
            self.assertEqual(done.state, service.STATE_DONE, done.error)
            self.assertTrue(done.proved)
            # 真 vkey：不是 "unproven"，也不是演示脚本里那种占位符
            self.assertNotEqual(done.issued.vkey_hash, cert.VKEY_HASH_UNPROVEN)
            self.assertEqual(done.issued.proof_mode, "core")

            handle = svc.public_job(job.job_id)
            proc = subprocess.run(shlex.split(handle["verify_hint"]), cwd=str(REPO),
                                  capture_output=True, text=True)
            self.assertIn("RESULT: PASS", proc.stdout, proc.stdout + proc.stderr)
            self.assertIn("[PASS] proof", proc.stdout)


if __name__ == "__main__":
    unittest.main()
