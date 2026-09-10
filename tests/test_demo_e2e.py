"""Integration test for the end-to-end demo (scripts/demo_e2e.py).

Runs the one-command demo in host-check mode (no SP1 proof, for speed) and then
independently verifies the session bundle with scripts/verify_session.py.
Skipped unless the framework deps (langchain/langgraph/mcp) are installed.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def deps_available() -> bool:
    try:
        import langchain_core  # noqa: F401
        import langgraph  # noqa: F401
        import mcp  # noqa: F401

        return True
    except Exception:
        return False


@unittest.skipUnless(deps_available(), "framework deps not installed")
class TestEndToEndDemo(unittest.TestCase):
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
            # the demo exercised all three paths
            self.assertIn("stream", verify.stdout)
            self.assertIn("tool-result", verify.stdout)
            self.assertIn("zk_proof", verify.stdout)


if __name__ == "__main__":
    unittest.main()
