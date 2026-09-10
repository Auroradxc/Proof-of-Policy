"""Tests for the anchor ledger (policydsl.anchor)."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl import anchor  # noqa: E402


class TestAnchorLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = Path(self.tmp.name) / "ledger.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    def test_append_and_verify_chain(self):
        e1 = anchor.append_anchor(self.ledger, "d1", {"policy": "p"}, "t1")
        e2 = anchor.append_anchor(self.ledger, "d2", ts="t2")
        e3 = anchor.append_anchor(self.ledger, "d3", ts="t3")
        self.assertEqual(e1["prev"], anchor.GENESIS)
        self.assertEqual(e2["prev"], e1["hash"])
        self.assertEqual(e3["seq"], 2)
        ok, reason = anchor.verify_ledger(self.ledger)
        self.assertTrue(ok, reason)
        self.assertEqual(len(anchor.read_ledger(self.ledger)), 3)

    def test_find_anchor(self):
        anchor.append_anchor(self.ledger, "d1")
        anchor.append_anchor(self.ledger, "d2")
        self.assertIsNotNone(anchor.find_anchor(self.ledger, "d2"))
        self.assertIsNone(anchor.find_anchor(self.ledger, "nope"))

    def test_tamper_detected(self):
        anchor.append_anchor(self.ledger, "d1")
        anchor.append_anchor(self.ledger, "d2")
        raw = self.ledger.read_text(encoding="utf-8").splitlines()
        raw[0] = raw[0].replace('"d1"', '"dX"')  # edit history
        self.ledger.write_text("\n".join(raw) + "\n", encoding="utf-8")
        ok, reason = anchor.verify_ledger(self.ledger)
        self.assertFalse(ok)
        self.assertIn("tampered", reason)

    def test_on_chain_stub_raises(self):
        with self.assertRaises(NotImplementedError):
            anchor.anchor_on_chain("digest")


if __name__ == "__main__":
    unittest.main()
