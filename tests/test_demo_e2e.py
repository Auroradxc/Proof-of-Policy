"""端到端演示（scripts/demo_e2e.py）的集成测试。

跑一遍「一条命令」的演示（host-check 模式，不生成 SP1 证明，换取速度），然后
用 scripts/verify_session.py **独立**校验产出的会话包。关键在「独立」二字：
验证脚本只读会话包本身，不信任演示进程的内存状态，因此这条用例真正检验的是
产物自洽性，而不是演示脚本「自己说自己通过了」。

依赖 langchain/langgraph/mcp 框架，未安装时整体跳过（这些是演示层的可选依赖）。
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import openai_sse_stub as stub  # noqa: E402

from policydsl import cert  # noqa: E402


def deps_available() -> bool:
    """探测演示所需的框架依赖是否可用（用于 skipUnless）。"""
    try:
        import langchain_core  # noqa: F401
        import langgraph  # noqa: F401
        import mcp  # noqa: F401

        return True
    except Exception:
        return False


def openai_stub_available() -> bool:
    """``--model openai:`` 那条路要真的 langchain_openai（桩只替后端，不替客户端）。"""
    try:
        import langchain_openai  # noqa: F401

        return True
    except Exception:
        return False


@unittest.skipUnless(deps_available(), "framework deps not installed")
class TestEndToEndDemo(unittest.TestCase):
    """演示 → 产物 → 独立验证 的闭环，以及报告产物渲染。"""

    # 演示退出码为 0 只说明它自认成功；这里再让 verify_session.py 独立复核，
    # 并确认三条被拦截路径（流式输出 / 工具结果 / zk 证明）都真实被走过，
    # 否则「演示通过」可能只是没触发任何策略。
    def test_demo_then_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "e2e"
            demo = subprocess.run(
                [sys.executable, str(REPO / "scripts" / "demo_e2e.py"),
                 "--no-prove", "--out-dir", str(out)],
                cwd=str(REPO), capture_output=True, text=True)
            self.assertEqual(demo.returncode, 0, demo.stdout + demo.stderr)

            session = out / "session.json"
            self.assertTrue(session.exists())
            verify = subprocess.run(
                [sys.executable, str(REPO / "scripts" / "verify_session.py"),
                 "--session", str(session)],
                cwd=str(REPO), capture_output=True, text=True)
            self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
            self.assertIn("RESULT: PASS", verify.stdout)
            # 三条路径都被演示覆盖到了
            self.assertIn("stream", verify.stdout)
            self.assertIn("tool-result", verify.stdout)
            self.assertIn("zk_proof", verify.stdout)
            # P0-4：每张证书都带证据档位标注，且 `--no-prove` 下只能是 unproven
            # （0 predate = 没有靠「字段缺失」蒙混过去的证书）。
            self.assertIn("[PASS] certificates_proof_mode", verify.stdout)
            self.assertIn("unproven", verify.stdout)
            session = json.loads(session.read_text())
            modes = {cert.envelope_payload(e["envelope"])["binding"]["proof_mode"]
                     for e in session["certificates"]}
            self.assertEqual(modes, {"unproven"}, "host-check 演示不该出现声称有证据的证书")

    # 会话包之外还要产出可给人看的证据（HTML/SVG/PNG）：报告是审计交付物的一部分，
    # 缺文件即视为交付不完整。
    def test_make_shots_renders_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "e2e"
            subprocess.run(
                [sys.executable, str(REPO / "scripts" / "demo_e2e.py"),
                 "--no-prove", "--out-dir", str(out)],
                cwd=str(REPO), check=True, capture_output=True, text=True)
            shots_dir = Path(tmp) / "shots"
            shots = subprocess.run(
                [sys.executable, str(REPO / "scripts" / "make_shots.py"),
                 "--session", str(out / "session.json"), "--out-dir", str(shots_dir)],
                cwd=str(REPO), capture_output=True, text=True)
            self.assertEqual(shots.returncode, 0, shots.stdout + shots.stderr)
            for name in ("session_report.html", "session_report.svg",
                         "session_summary.png", "verify_result.png"):
                self.assertTrue((shots_dir / name).exists(), f"missing {name}")


def _fingerprint(session: dict) -> list:
    """一份会话**与密钥无关**的形状：每张证书的 (kind, passed, 违规条数)。

    临时密钥与 nonce 每次都不同（本来也不该相同），所以逐字节比对没有意义。
    要比的是「换了模型之后，同一套策略还判出同一件事没有」。
    """
    return [(e["kind"],
             cert.envelope_payload(e["envelope"])["outcome"]["passed"],
             len(cert.envelope_payload(e["envelope"])["outcome"]["violations"]))
            for e in session["certificates"]]


@unittest.skipUnless(deps_available(), "framework deps not installed")
@unittest.skipUnless(openai_stub_available(), "langchain_openai not installed")
class TestDemoWithRealModelClient(unittest.TestCase):
    """``demo_e2e.py --model``：真实客户端接进来，产物与离线桩**同构**。

    桩（``tests/openai_sse_stub.py``）实现 OpenAI 的流式协议，所以这里跑的是
    **真的** ``langchain_openai`` 客户端 + 真的 HTTP 传输，只是端点在本机 ——
    既不需要网络与真 key，也不动使用者的额度。

    验收（dev-plan §5.1.3）：产物与 fake 路径同构、``verify_session.py`` 全 PASS。
    「同构」在断言里落成「两份会话的形状逐条相同」，而不是一个写死的数字：
    写死的数字在假路径改动之后不会报错，只会静默地变成另一件事。
    """

    def _run_demo(self, out: Path, extra: list, env: dict = None):
        import os

        e = dict(os.environ, **(env or {}))
        return subprocess.run(
            [sys.executable, str(REPO / "scripts" / "demo_e2e.py"),
             "--no-prove", "--out-dir", str(out)] + extra,
            cwd=str(REPO), capture_output=True, text=True, env=e)

    def test_model_run_is_isomorphic_to_the_offline_stub(self):
        clean = ["A safe reply ", "about the refund policy."]
        server = stub.StubServer(router=stub.echo_router(clean)).start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                fake_out, real_out = Path(tmp) / "fake", Path(tmp) / "real"
                fake = self._run_demo(fake_out, [])
                self.assertEqual(fake.returncode, 0, fake.stdout + fake.stderr)

                real = self._run_demo(
                    real_out, ["--model", "openai:stub-model"],
                    env={"OPENAI_API_KEY": "stub-key",
                         "OPENAI_BASE_URL": server.base_url})
                self.assertEqual(real.returncode, 0, real.stdout + real.stderr)

                a = json.loads((fake_out / "session.json").read_text())
                b = json.loads((real_out / "session.json").read_text())

                # ① 形状同构：同样 13 张、同样次序、同样判定
                self.assertEqual(_fingerprint(a), _fingerprint(b))
                self.assertEqual(len(_fingerprint(b)), 13)

                # ② 早停实测：真客户端下也真的掐断了，密钥没到达调用方
                es = b["summary"]["early_stop"]
                self.assertEqual(es["model_spec"], "openai:stub-model")
                self.assertTrue(es["aborted"], "真客户端下早停没发作")
                self.assertFalse(es["leak_delivered"], "密钥到达了调用方")
                # 桩报了它写出去了几片 —— 少于服务端打算写的总数即「传输层真断了」
                self.assertIsNone(es["full_len"], "真模型下 full_len 必须是 None（全长不可知）")

                # ③ 第三方独立复核仍然全绿
                verify = subprocess.run(
                    [sys.executable, str(REPO / "scripts" / "verify_session.py"),
                     "--session", str(real_out / "session.json")],
                    cwd=str(REPO), capture_output=True, text=True)
                self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
                self.assertIn("RESULT: PASS", verify.stdout)

                # ④ 缺省路径仍然是离线桩 —— 一条真模型产物不该悄悄污染默认行为
                self.assertEqual(a["summary"]["early_stop"]["model"], "fake (offline)")
                self.assertEqual(a["summary"]["early_stop"]["model_spec"], "")
        finally:
            server.stop()

    def test_bad_model_spec_fails_loudly(self):
        # 规格写错必须**报错**，绝不静默退回离线桩 —— 静默退回会让一份
        # 「真模型演示」的产物其实来自写死的字符串，而且没人看得出来。
        with tempfile.TemporaryDirectory() as tmp:
            r = self._run_demo(Path(tmp) / "x", ["--model", "gemini:flash"])
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("gemini", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
