"""T3 回归编排器（``scripts/regression_prove.py``）的单元测试。

**这些用例证的是什么、不证什么** —— 先说清楚，免得被误读：

    证：编排层。追加不覆盖、成败判定、两条腿**分开记**、出证腿挂了时验证腿
        不许被当成通过、留痕字段（git / host / 驱动指纹）真的落盘。
    不证：证明本身。整轮跑的是**替身驱动**（下面 `FAKE_DRIVER`），一个字节的
        密码学都没算。

为什么必须用替身：真跑一次全量是 **≈45 分钟**，且要 ~10.15 GiB 峰值内存。
把编排逻辑的回归绑在那种时长上，等于没有回归。替身驱动的意义是让「9 分钟内
改坏了追加逻辑」当场变红，而不是等下周一凌晨的定时任务。

替身驱动靠 ``POP_SCRIPT`` 环境变量注入（``cross_validate.py` 的两个**非破坏性**
口子之一，见该文件 docstring）—— 因此这套用例**不需要 Rust 工具链**。
"""

import contextlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

import cross_validate as cv  # noqa: E402
import regression_prove as rp  # noqa: E402


#: 替身驱动。它**只做 pop-script 的契约**（读 vectors.json → 写 results 数组；
#: `--proof-out` 存产物；`--verify` 报 verified），一个密码学操作都没有。
#:
#: `POP_FAKE_EXPECTED` 指向一份 `{向量名: golden}` 的表 —— 由测试用**真的**
#: `cross_validate.golden()` 现算，所以替身不是「自己跟自己比」：
#: 一旦 golden 变了而替身输出没跟上，出证腿会立刻 FAIL。
#:
#: `POP_FAKE_FAIL` 是故障注入开关：
#:   ``prove``       出证时**真的自杀**（SIGKILL）—— 复刻 OOM killer 的样子：
#:                   无末行、无输出、returncode = -9。这比 `exit(1)` 更接近真相。
#:   ``verify``      验证时如实回 `verified: false`（退出码 0）。
#:   ``verify-exit`` 验证时非零退出（加载不了证明的样子）。
FAKE_DRIVER = r'''#!/usr/bin/env python3
"""pop-script 的替身：只复刻契约，不算密码学。测试专用。"""
import json
import os
import signal
import sys
from pathlib import Path


def flag(name):
    a = sys.argv[1:]
    return a[a.index(name) + 1] if name in a else None


fail = os.environ.get("POP_FAKE_FAIL", "")
out = Path(flag("--out"))

if "--verify" in sys.argv[1:]:
    if fail == "verify-exit":
        sys.exit(4)
    if fail == "verify":
        out.write_text(json.dumps({"verified": False, "vkey_hash": "00" * 32}))
        sys.exit(0)
    proof = Path(flag("--proof"))
    if not proof.exists():
        sys.exit(3)
    out.write_text(json.dumps({"verified": True, "vkey_hash": "ab" * 32,
                               "setup_seconds": 0.25,
                               "verify_times_seconds": [0.01, 0.02]}))
    sys.exit(0)

if fail == "prove":
    # 复刻 OOM killer：无 stdout、无 stderr、被信号杀死。
    os.kill(os.getpid(), signal.SIGKILL)

expected = json.loads(Path(os.environ["POP_FAKE_EXPECTED"]).read_text())
vectors = json.loads(Path(flag("--vectors")).read_text())["vectors"]
rows = []
for v in vectors:
    g = expected[v["name"]]
    rows.append({"passed": g["passed"],
                 "violations": [{"rule": r, "kind": k} for r, k in g["violations"]]})
out.write_text(json.dumps(rows, indent=2))
proof_out = flag("--proof-out")
if proof_out:
    Path(proof_out).write_bytes(b"FAKE-PROOF-NOT-A-REAL-PROOF")
'''


class RegressionCase(unittest.TestCase):
    """公共脚手架：搭替身驱动 + 期望表 + 私有临时目录。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="pop-regression-test-"))
        cls.driver = cls.tmp / "fake-pop-script"
        cls.driver.write_text(FAKE_DRIVER, encoding="utf-8")
        cls.driver.chmod(cls.driver.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)

        # 期望表用**真的** golden 现算 —— 替身的输出因此受真 golden 约束。
        cls.expected_path = cls.tmp / "expected.json"
        expected = {}
        for name, policy, response, extras in cv.vectors():
            expected[name] = cv.golden(policy, response, extras)
        cls.expected_path.write_text(json.dumps(expected), encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="pop-regression-work-", dir=self.tmp))
        self.history = self.work / "history.jsonl"
        self._env = os.environ.copy()
        os.environ["POP_FAKE_EXPECTED"] = str(self.expected_path)
        os.environ.pop("POP_FAKE_FAIL", None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env)
        shutil.rmtree(self.work, ignore_errors=True)

    def run_cli(self, *extra):
        """跑一次 CLI，返回 (退出码, 历史记录列表)，并吞掉它的 stdout/stderr。

        吞输出不只是为了干净：CLI 会印「预计 45 min」这类**面向真实运行**的话，
        混在测试输出里会让人误以为真的在出证。
        """
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = rp.main(["--pop-script", str(self.driver), "--chunk", "4",
                          "--work-dir", str(self.work / "wd"),
                          "--history", str(self.history), *extra])
        self.cli_output = buf.getvalue()
        return rc, rp.read_history(self.history)


#: 变异测试记要（每个断言都得能被证伪，否则它守不住任何东西）。
#:
#: 杀掉：
#:   M1 ``append_history`` 的 ``"a"`` → ``"w"``（覆盖写） → 追加用例红
#:   M2 出证挂了时把验证腿标成 ``ok=True``              → skipped 用例红
#:   M3 去掉 ``strip_time_report``                      → 证据用例红
#:   M5 ``result`` 只看出证腿、忽略验证腿               → 归因用例红（2 条）
#:   M6 驱动指纹 ``sha256`` 置 None                     → 留痕用例红
#:
#: **存活一个，且是等价变异**（如实登记，不当作漏测）：
#:   M4 把 ``ok=(returncode == 0 and verdict == "PASS")`` 削成 ``ok=(returncode == 0)``
#:      —— 两处证据（进程退出码 / stdout 末行）当前**总是同时成立**：
#:      ``cross_validate`` 判 FAIL 时必以 1 退出，所以退出码 0 ⇒ 末行必是 PASS。
#:      要证伪它就得让 ``cross_validate`` **自报 PASS 却非零退出**，那需要改造被
#:      编排方本身，不是本文件的测试能构造的状态。合取仍然保留：它防的是将来
#:      ``cross_validate`` 在打印末行之后才崩（比如写盘失败）——那时两处证据分家，
#:      只有合取能拦住一次「印了 PASS 但没跑完」被记成通过。


class TestHonestRun(RegressionCase):
    """顺利的一轮：两条腿都过、记录字段齐全、退出码 0。"""

    def test_both_legs_pass(self):
        rc, rows = self.run_cli()
        self.assertEqual(rc, 0)
        self.assertEqual(len(rows), 1)
        rec = rows[0]
        self.assertEqual(rec["result"], "PASS")
        self.assertTrue(rec["prove_leg"]["ok"])
        self.assertTrue(rec["verify_leg"]["ok"])

    # 出证腿必须真的解析 cross_validate 的末行，而不是「退出码 0 就算过」。
    def test_prove_leg_reports_full_match(self):
        _, rows = self.run_cli()
        leg = rows[0]["prove_leg"]
        self.assertEqual(leg["host_matched"], leg["host_total"])
        self.assertEqual(leg["host_total"], len(cv.vectors()))
        self.assertEqual(leg["prove"], f"{len(cv.vectors())}/{len(cv.vectors())}")

    # 验证腿要跨进程 —— 记的是新进程 `--verify` 回的那份结果，不是出证时的自检。
    def test_verify_leg_reads_separate_process_output(self):
        _, rows = self.run_cli()
        leg = rows[0]["verify_leg"]
        self.assertTrue(leg["ok"])
        self.assertEqual(leg["vkey_hash"], "ab" * 32)   # 只有 --verify 那条路会写
        self.assertEqual(leg["verify_times_seconds"], [0.01, 0.02])
        self.assertGreater(leg["proof_bytes"], 0)
        self.assertIn(leg["vector"], [n for n, *_ in cv.vectors()])
        # 只覆盖 1 个向量这件事必须写在记录里，不装作全量。
        self.assertIn("只覆盖 1 个向量", leg["note"])

    # 留痕要能回答「这批数字出自哪份源码、哪台机器、哪份二进制」。
    def test_record_pins_source_host_and_driver(self):
        _, rows = self.run_cli()
        rec = rows[0]
        self.assertTrue(rec["git"]["sha"])                      # 真实 git sha
        self.assertIn("dirty", rec["git"])
        self.assertTrue(rec["host"]["hostname"])
        self.assertTrue(rec["host"]["cpu_model"])
        self.assertIsNotNone(rec["host"]["mem_total_mb"])
        self.assertEqual(rec["vectors"], len(cv.vectors()))
        self.assertEqual(rec["chunk"], 4)
        # 驱动指纹对着**真**的替身文件重算一遍，不是照抄路径。
        self.assertTrue(rec["driver"]["exists"])
        self.assertEqual(rec["driver"]["bytes"], self.driver.stat().st_size)
        self.assertEqual(rec["driver"]["sha256"], _sha256(self.driver))


class TestAppendOnlyHistory(RegressionCase):
    """历史**只追加**。这是本文件对 T3 的核心承诺，也是最容易被改坏的一处。"""

    def test_second_run_appends_and_keeps_first(self):
        _, rows1 = self.run_cli("--label", "first")
        after_first = self.history.read_bytes()
        _, rows2 = self.run_cli("--label", "second")

        self.assertEqual(len(rows1), 1)
        self.assertEqual(len(rows2), 2)
        # 关键：第二次跑完之后，第一次那一次的内容**逐字节没变**。
        self.assertTrue(self.history.read_bytes().startswith(after_first),
                        "第二次运行改写了历史 —— 追加语义被破坏")
        self.assertEqual([r["label"] for r in rows2], ["first", "second"])
        # 第一条记录**逐字段没被改写**（比上面那句 bytes 断言更结实：它同时挡住
        # 「重写整个文件但内容恰好前缀相同」这种情形）。
        self.assertEqual(rows1[0], rows2[0])
        # 注意这里**不**断言两次 ts 不同：utc_now() 是秒级，同一秒内跑两次本来就
        # 会相同。断言它不等等于把用例绑在机器快慢上 —— 那是会偶发变红的假用例。
        # 两条记录是否独立，由上面的 label 与 len==2 已经钉住。

    def test_dry_run_writes_nothing(self):
        rc, rows = self.run_cli("--dry-run")
        self.assertEqual(rc, 0)
        self.assertEqual(rows, [])
        self.assertFalse(self.history.exists(), "--dry-run 不该创建历史文件")

    # 坏行不能让 `--print` 崩掉 —— 定时任务的历史文件是长期累积的。
    def test_history_survives_a_corrupt_line(self):
        self.run_cli("--label", "good")
        with self.history.open("a", encoding="utf-8") as fh:
            fh.write("{ 这不是 JSON\n")
        rows = rp.read_history(self.history)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]["result"], "UNREADABLE")
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            self.assertIsNone(rp.print_history(self.history))  # 不抛
        # 坏行被如实标成不可读，好行照常打印 —— 不静默跳过、也不整表作废。
        self.assertIn("本次记录不可读", buf.getvalue())
        self.assertIn("合计 1/2 PASS", buf.getvalue())


class TestFailureAttribution(RegressionCase):
    """失败要**分得清是哪条腿**，且都不能被静默吞掉。"""

    # OOM 被杀：cross_validate 不会有末行。这必须判 FAIL，理由要写明「没有 RESULT」，
    # 而不是「没跑」——本机 12 GB 证不了这么多，那是一个**结论**。
    #
    # 记的 returncode 是 **1 不是 -9**，这是对的而不是 bug：被 SIGKILL 的是**孙进程**
    # （替身驱动），它的父进程 cross_validate 走 `subprocess.run(check=True)`，
    # 收到 CalledProcessError 后自己以 1 退出，于是 `time`/我们的直接子进程退出码是 1。
    # 所以这里**不能**拿 -9 当判据 —— 判「跑没跑到底」的判据是**有没有 RESULT 末行**。
    def test_prove_leg_killed_reports_fail_with_reason(self):
        os.environ["POP_FAKE_FAIL"] = "prove"
        rc, rows = self.run_cli()
        self.assertEqual(rc, 1)
        leg = rows[0]["prove_leg"]
        self.assertFalse(leg["ok"])
        self.assertIn("RESULT", leg["reason"])
        # 结构差异：解析不出 prove 计数，正是「没跑到底」的样子。
        self.assertNotIn("prove", leg)
        self.assertEqual(rows[0]["result"], "FAIL")

    # 失败记录里必须留得下**原因**。这里钉的是一个真踩过的坑：`time -v` 的报告打在
    # 子进程输出**之后**，取「末尾 30 行」会整段取到它的样板，把 traceback 挤掉 ——
    # 最需要证据的那种失败，证据反而最看不见。
    def test_failure_record_keeps_the_real_cause_not_time_boilerplate(self):
        os.environ["POP_FAKE_FAIL"] = "prove"
        _, rows = self.run_cli()
        log = rows[0]["prove_leg"]["log_tail"]
        self.assertIn("CalledProcessError", log)        # 真因：子进程非零退出
        self.assertNotIn("Average resident set size", log)  # 样板已剥离
        self.assertNotIn("Command being timed", log)
        # 峰值 RSS 没丢：它被单独解析成结构字段，不靠那段样板留在日志里。
        self.assertIsNotNone(rows[0]["prove_leg"].get("peak_rss_mb"))

    # 出证腿挂了就没有可信产物可验 —— 验证腿必须记 skipped 且 ok=False，
    # 绝不能因为「没跑」而被算成通过。
    def test_verify_leg_skipped_is_not_a_pass(self):
        os.environ["POP_FAKE_FAIL"] = "prove"
        _, rows = self.run_cli()
        vg = rows[0]["verify_leg"]
        self.assertTrue(vg["skipped"])
        self.assertFalse(vg["ok"])
        self.assertIn("跳过", vg["reason"])

    # 验证腿自己挂了（出证是好的）：两条腿必须**分开记** ——
    # 这正是「出证过 ≠ 验证过」在记录上的样子。
    def test_verify_leg_failure_is_attributed_to_verify_only(self):
        os.environ["POP_FAKE_FAIL"] = "verify"
        rc, rows = self.run_cli()
        self.assertEqual(rc, 1)
        rec = rows[0]
        self.assertTrue(rec["prove_leg"]["ok"], "出证腿本来是好的，不该被连坐")
        self.assertFalse(rec["verify_leg"]["ok"])
        self.assertIn("verified=false", rec["verify_leg"]["reason"])
        self.assertEqual(rec["result"], "FAIL")

    def test_verify_leg_nonzero_exit_is_caught(self):
        os.environ["POP_FAKE_FAIL"] = "verify-exit"
        rc, rows = self.run_cli()
        self.assertEqual(rc, 1)
        self.assertFalse(rows[0]["verify_leg"]["ok"])
        self.assertEqual(rows[0]["verify_leg"]["returncode"], 4)

    def test_no_verify_flag_records_none(self):
        rc, rows = self.run_cli("--no-verify")
        self.assertEqual(rc, 0)
        self.assertIsNone(rows[0]["verify_leg"])

    # 驱动不存在时要在跑之前就说清楚，且不留下一条会把「没跑」当「跑过了」的记录。
    def test_missing_driver_exits_2_without_history(self):
        with contextlib.redirect_stderr(io.StringIO()) as buf:
            rc = rp.main(["--pop-script", str(self.work / "nope"),
                          "--history", str(self.history)])
        self.assertEqual(rc, 2)
        self.assertIn("驱动不存在", buf.getvalue())
        self.assertFalse(self.history.exists())


class TestSummarizeAndPrint(RegressionCase):
    """给人看的那一行。定时任务失败时，第一眼看到的就是它。"""

    def test_summarize_shows_both_legs_and_rss(self):
        _, rows = self.run_cli()
        line = rp.summarize(rows[0])
        self.assertIn("[PASS]", line)
        self.assertIn("出证 OK", line)
        self.assertIn("验证 OK", line)

    def test_print_history_on_empty_file(self):
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(rp.main(["--print", "--history", str(self.history)]), 0)
        self.assertIn("还没有任何记录", buf.getvalue())


def _sha256(p: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


if __name__ == "__main__":
    unittest.main()
