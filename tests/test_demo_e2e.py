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


if __name__ == "__main__":
    unittest.main()
