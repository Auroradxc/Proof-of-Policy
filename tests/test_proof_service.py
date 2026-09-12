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

from policydsl import anchor, cert, challenge, commit, evaluate, keys, service  # noqa: E402
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
