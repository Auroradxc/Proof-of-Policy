"""证书层披露层级（P1-05，L0/L1/L2）的单元与端到端测试。

**边界**：这里测的是**证书层**披露，不是电路级隐藏。电路公开值仍是 raw
``rule`` / ``kind``；验证方按证书声明的级别重投影后比对。见
``docs/blockers/C1.md`` 与 ``policydsl/evidence/disclosure.py`` 的模块文档。

覆盖四件事：

1. 三级映射：L0 保留 rule+kind、L1 聚合类别+计数、L2 只留承诺；
2. 旧证书兼容：没有 ``disclosure_level`` 的载荷逐字节不变、验证照过；
3. 篡改被拒：改了级别但没重签 → 签名失败；带 L1/L2 标签却残留 raw 字段 →
   披露检查失败；
4. 未知级别：出证时抛错，验证时 fail closed。
"""

import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl.core.compile import compile_policy  # noqa: E402
from policydsl.core.model import Policy, Rule  # noqa: E402
from policydsl.evidence import anchor, cert, disclosure, keys  # noqa: E402

POLICY = Policy("disc", "1.0.0", rules=[
    Rule("keyword_block", "no-secret", {"keywords": ["secret"]}),
    Rule("length_bound", "bounded", {"min": 1, "max": 200}),
])
#: 同时触发两条规则的响应：一条 content、一条 length。
BAD_T = "secret " + "x" * 250


def _outcome() -> dict:
    spec = compile_policy(POLICY)
    return {
        "policy_hash": spec["sha256"],
        "passed": False,
        "violations": [
            {"rule": "no-secret", "kind": "keyword_block", "evidence": "secret"},
            {"rule": "bounded", "kind": "length_bound", "evidence": "len=257"},
        ],
    }


def _pack_dict() -> dict:
    return {
        "id": POLICY.id, "version": POLICY.version,
        "rules": [{"kind": r.kind, "name": r.name, "params": r.params}
                  for r in POLICY.rules],
    }


class TestThreeLevels(unittest.TestCase):
    """三级投影的形状：L0 名+类型、L1 类别+数、L2 仅承诺。"""

    def test_l0_keeps_rule_and_kind_but_not_plaintext_evidence(self):
        raw = _outcome()["violations"]
        got = disclosure.project_violations(raw, "L0")
        self.assertEqual([v["rule"] for v in got], ["no-secret", "bounded"])
        self.assertEqual([v["kind"] for v in got], ["keyword_block", "length_bound"])
        for v in got:
            self.assertIn("evidence_commitment", v)
            self.assertNotIn("evidence", v)  # 明文证据不进入证书层

    def test_l1_aggregates_categories_and_count(self):
        raw = _outcome()["violations"]
        got = disclosure.project_violations(raw, "L1")
        self.assertEqual(got, [{"category": "content", "count": 1},
                               {"category": "length", "count": 1}])
        # 只保留类别，不允许 rule/kind 漏回去
        for v in got:
            self.assertNotIn("rule", v)
            self.assertNotIn("kind", v)
        projected = disclosure.project_outcome(_outcome(), "L1")
        self.assertEqual(projected["violation_count"], 2)
        self.assertNotIn("rule", json.dumps(projected))

    def test_l2_keeps_only_opaque_commitments(self):
        got = disclosure.project_violations(_outcome()["violations"], "L2")
        self.assertEqual(len(got), 2)
        for v in got:
            self.assertEqual(set(v), {"evidence_commitment"})
            self.assertEqual(len(v["evidence_commitment"]), 64)
        projected = disclosure.project_outcome(_outcome(), "L2")
        self.assertNotIn("violation_count", projected)
        self.assertEqual(projected["violations"],
                         sorted(projected["violations"], key=lambda v: v["evidence_commitment"]))

    def test_level_from_policy_dict_and_instance(self):
        self.assertEqual(disclosure.level_from_policy({"disclosure_level": "l1"}), "L1")
        self.assertEqual(disclosure.level_from_policy({}), "L0")
        p = Policy("x", "1")
        self.assertEqual(disclosure.level_from_policy(p), "L0")
        p.disclosure_level = "L2"   # dataclass 没有 slots，可动态挂载
        self.assertEqual(disclosure.level_from_policy(p), "L2")


class TestBackwardCompatibility(unittest.TestCase):
    """没有 ``disclosure_level`` 的旧证书：字段不出现、outcome 不投影。"""

    def test_field_absent_when_not_requested(self):
        spec = compile_policy(POLICY)
        outcome = _outcome()
        payload = cert.build_payload(POLICY.id, POLICY.version, spec, "private",
                                     outcome, vkey_hash="unproven",
                                     ts="2026-01-01T00:00:00Z")
        self.assertNotIn("disclosure_level", payload)
        # build_payload 不改入参、不投影旧路径
        self.assertEqual(payload["outcome"], outcome)

    def test_declared_level_projects_outcome(self):
        spec = compile_policy(POLICY)
        payload = cert.build_payload(POLICY.id, POLICY.version, spec, "private",
                                     _outcome(), vkey_hash="unproven",
                                     ts="2026-01-01T00:00:00Z",
                                     disclosure_level="L1")
        self.assertEqual(payload["disclosure_level"], "L1")
        self.assertEqual(payload["outcome"]["violations"],
                         [{"category": "content", "count": 1},
                          {"category": "length", "count": 1}])
        self.assertEqual(payload["outcome"]["violation_count"], 2)

    def test_check_without_field_is_l0_behavior(self):
        spec = compile_policy(POLICY)
        outcome = _outcome()
        payload = cert.build_payload(POLICY.id, POLICY.version, spec, "private",
                                     outcome, vkey_hash="unproven", ts="TS")
        ok, detail = disclosure.check_outcome_disclosure(payload, outcome)
        self.assertTrue(ok, detail)
        self.assertIn("predates", detail)


class TestFailClosed(unittest.TestCase):
    """未知级别与「标签与形状不一致」都必须失败。"""

    def test_unknown_level_rejected_at_normalize(self):
        for bad in ("L3", "l0 ", "LEVEL1", 1, ""):
            with self.subTest(bad=bad):
                with self.assertRaises(disclosure.DisclosureError):
                    disclosure.normalize_level(bad)

    def test_unknown_level_rejected_at_issuance(self):
        spec = compile_policy(POLICY)
        with self.assertRaises(disclosure.DisclosureError):
            cert.build_payload(POLICY.id, POLICY.version, spec, "private",
                               _outcome(), vkey_hash="unproven", ts="TS",
                               disclosure_level="L9")

    def test_l1_label_with_raw_fields_rejected(self):
        spec = compile_policy(POLICY)
        payload = cert.build_payload(POLICY.id, POLICY.version, spec, "private",
                                     _outcome(), vkey_hash="unproven", ts="TS",
                                     disclosure_level="L1")
        # 攻击者把 raw rule 塞回 L1 载荷（签名另说）—— 形状检查必须拒绝
        payload["outcome"]["violations"][0]["rule"] = "no-secret"
        ok, why = disclosure.check_outcome_disclosure(payload, None)
        self.assertFalse(ok)
        self.assertIn("L1", why)

    def test_unknown_declared_level_fails_check(self):
        spec = compile_policy(POLICY)
        payload = cert.build_payload(POLICY.id, POLICY.version, spec, "private",
                                     _outcome(), vkey_hash="unproven", ts="TS",
                                     disclosure_level="L2")
        payload["disclosure_level"] = "L9"
        ok, why = disclosure.check_outcome_disclosure(payload, None)
        self.assertFalse(ok)
        self.assertIn("fail closed", why)

    def test_proof_projection_mismatch_rejected(self):
        spec = compile_policy(POLICY)
        payload = cert.build_payload(POLICY.id, POLICY.version, spec, "private",
                                     _outcome(), vkey_hash="unproven", ts="TS",
                                     disclosure_level="L1")
        raw = _outcome()
        ok, _ = disclosure.check_outcome_disclosure(payload, raw)
        self.assertTrue(ok)
        raw["violations"].append({"rule": "extra", "kind": "format_check",
                                  "evidence": "json"})
        ok, why = disclosure.check_outcome_disclosure(payload, raw)
        self.assertFalse(ok)
        self.assertIn("projection", why)

    def test_delegated_blocks_l1_l2(self):
        outcome = _outcome()
        outcome["delegated"] = [{"name": "sem", "system": "ezkl-halo2"}]
        spec = compile_policy(POLICY)
        for level in ("L1", "L2"):
            with self.subTest(level=level):
                with self.assertRaises(disclosure.DisclosureError):
                    cert.build_payload(POLICY.id, POLICY.version, spec, "private",
                                       outcome, vkey_hash="unproven", ts="TS",
                                       disclosure_level=level)


class TestVerifyCertCli(unittest.TestCase):
    """端到端：签一张带披露级别的证书，跑 ``verify_cert.py``。"""

    def _issue(self, tmp: Path, level: str | None, outcome: dict | None = None) -> Path:
        spec = compile_policy(POLICY)
        payload = cert.build_payload(
            POLICY.id, POLICY.version, spec, "private", outcome or _outcome(),
            vkey_hash="unproven", ts="2026-01-01T00:00:00Z",
            disclosure_level=level)
        signer = cert.Ed25519Signer.generate()
        (tmp / "key.json").write_text(json.dumps(keys.public_record(signer.public_key)))
        (tmp / "cert.json").write_text(json.dumps(cert.sign_payload(payload, signer)))
        (tmp / "pack.json").write_text(json.dumps(_pack_dict()))
        anchor.append_anchor(tmp / "ledger.jsonl", cert.cert_digest(payload))
        return tmp / "cert.json"

    def _verify(self, tmp: Path, cert_file: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(REPO / "scripts" / "verify" / "verify_cert.py"),
             "--cert", str(cert_file), "--pack", str(tmp / "pack.json"),
             "--ledger", str(tmp / "ledger.jsonl")],
            cwd=str(REPO), capture_output=True, text=True)

    def test_l1_certificate_passes(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            proc = self._verify(tmp, self._issue(tmp, "L1"))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[PASS] disclosure_level", proc.stdout)
        self.assertIn("L1", proc.stdout)
        self.assertIn("RESULT: PASS", proc.stdout)

    def test_old_certificate_without_field_still_passes(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            proc = self._verify(tmp, self._issue(tmp, None))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("predates the field", proc.stdout)
        self.assertIn("RESULT: PASS", proc.stdout)

    def test_tampered_level_without_resigning_fails_signature(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cert_file = self._issue(tmp, "L1")
            env = json.loads(cert_file.read_text())
            payload = json.loads(base64.b64decode(env["payload"]))
            payload["disclosure_level"] = "L0"   # 想把 L1 悄悄降成 L0
            env["payload"] = base64.b64encode(cert.canonical(payload)).decode()
            cert_file.write_text(json.dumps(env))
            proc = self._verify(tmp, cert_file)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[FAIL] signature", proc.stdout)

    def test_declared_level_mismatching_payload_fails(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            # 用 L0 的 raw outcome，却把标签写成 L2 —— 形状检查必须拒绝。
            cert_file = self._issue(tmp, "L2", outcome=_outcome())
            env = json.loads(cert_file.read_text())
            payload = json.loads(base64.b64decode(env["payload"]))
            payload["outcome"] = _outcome()      # 塞回 raw rule/kind
            signer = cert.Ed25519Signer.generate()
            # 重新签：签名有效，但披露层级与形状不一致
            (tmp / "key.json").write_text(json.dumps(keys.public_record(signer.public_key)))
            cert_file.write_text(json.dumps(cert.sign_payload(payload, signer)))
            anchor.append_anchor(tmp / "ledger.jsonl", cert.cert_digest(payload))
            proc = self._verify(tmp, cert_file)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[FAIL] disclosure_level", proc.stdout)


if __name__ == "__main__":
    unittest.main()
