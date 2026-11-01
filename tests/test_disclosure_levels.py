"""电路级披露 coarsening（C2 / pop-pv-v2，L0/L1/L2）的单元与端到端测试。

**边界**：这里测的是**电路级**披露，不是证书层投影。v2 公开值本身只含该级别
允许的字段；验证方只做形状检查与逐字段相等，不再调用 ``project_outcome``。
旧 v1 证明默认拒绝（``--legacy-v1`` 仅放行 L0）。见
``docs/experiments/circuit-disclosure.md`` 与 ``docs/blockers/C2.md``。

覆盖：

1. 跨语言承诺 golden（``tests/vectors/disclosure_v2.json``，Rust 侧同一份）；
2. 主矩阵：L0/L1/L2 × public/private × delegated 空/非空；
3. v2 形状 fail closed：未知 schema/级别、级别不一致、raw 字段回流、
   L1 计数不符、L2 乱序、delegated 非空、私有模式带 delegated；
4. 旧 v1 三种组合与 ``--legacy-v1`` 标签；
5. ``verify_cert.py`` 端到端：v2 L1 通过、v1 无证明按旧路径标注、
   级别篡改（重签后）失败；
6. 构建了 ``pop-script`` 时，真跑 Rust ``--check`` 与 Python 逐字段对拍。
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
from policydsl.core.serialize import spec_canonical_text  # noqa: E402
from policydsl.evidence import anchor, cert, disclosure, keys  # noqa: E402
from policydsl.paths import POP_SCRIPT  # noqa: E402

POLICY = Policy("disc", "1.0.0", rules=[
    Rule("keyword_block", "no-secret", {"keywords": ["secret"]}),
    Rule("length_bound", "bounded", {"min": 1, "max": 200}),
])
#: 同时触发两条规则的响应：一条 content、一条 length。
BAD_T = "secret " + "x" * 250
SPEC = compile_policy(POLICY)

#: golden 用的固定盐（与 tests/vectors/disclosure_v2.json 相同）。
RB = "0123456789abcdef" * 4


def _fixture() -> dict:
    return json.loads((REPO / "tests" / "vectors" / "disclosure_v2.json")
                      .read_text(encoding="utf-8"))


def _raw_violations() -> list:
    return [
        {"rule": "no-secret", "kind": "keyword_block", "evidence": "secret"},
        {"rule": "bounded", "kind": "length_bound", "evidence": "len=250"},
    ]


def _disclosed_violations(level: str) -> tuple:
    """按电路语义从原始违规生成 (violations, violation_count)。"""
    raw = _raw_violations()
    if level == "L0":
        return ([{"shape": "raw", "rule": v["rule"], "kind": v["kind"],
                  "evidence_commitment": disclosure.item_commitment_v2(v["evidence"], RB)}
                 for v in raw], None)
    if level == "L1":
        buckets = {}
        for v in raw:
            cat = disclosure.category_for_kind(v["kind"])
            buckets.setdefault(cat, []).append(
                disclosure.item_commitment_v2(v["evidence"], RB))
        out = []
        for cat in sorted(buckets, key=lambda c: disclosure.CATEGORY_IDS[c]):
            items = buckets[cat]
            out.append({"shape": "category", "category": cat, "count": len(items),
                        "evidence_commitment": disclosure.bucket_commitment_v2(cat, items, RB)})
        return out, sum(v["count"] for v in out)
    commits = sorted(disclosure.item_commitment_v2(v["evidence"], RB) for v in raw)
    return ([{"shape": "opaque", "evidence_commitment": c} for c in commits], None)


def _delegated() -> list:
    return [{"name": "sem-pii", "system": "ezkl-halo2", "model_vkey": "vk",
             "onnx_sha256": "onnx", "threshold_bp": 7000, "direction": "le"}]


def _outcome(level: str, *, private: bool = False, delegated=None,
             schema: str = disclosure.PUBLIC_VALUE_SCHEMA_V2) -> dict:
    violations, count = _disclosed_violations(level)
    out = {
        "mode": "private" if private else "public",
        "policy_hash": SPEC["sha256"],
        "response_binding": RB,
        "passed": not violations,
        "public_value_schema": schema,
        "disclosure_level": level,
        "violations": violations,
        "delegated": delegated or [],
        "delegated_buckets": [],
    }
    if private:
        out["response_commitment"] = "0" * 64
        out["redaction"] = None
    if count is not None:
        out["violation_count"] = count
    return out


def _legacy_outcome() -> dict:
    """v1：无 schema，raw rule/kind/evidence。"""
    return {"mode": "public", "policy_hash": SPEC["sha256"], "response_binding": RB,
            "passed": False,
            "violations": _raw_violations(), "delegated": []}


def _pack_dict() -> dict:
    return {
        "id": POLICY.id, "version": POLICY.version,
        "rules": [{"kind": r.kind, "name": r.name, "params": r.params}
                  for r in POLICY.rules],
    }


class TestCrossLanguageGolden(unittest.TestCase):
    """Python 与 Rust 读同一份 fixture，逐字节对拍。"""

    def test_item_commitments_match_fixture(self):
        for row in _fixture()["items"]:
            self.assertEqual(
                disclosure.item_commitment_v2(row["evidence"], RB), row["commitment"],
                row["evidence"])

    def test_bucket_commitments_match_fixture(self):
        for row in _fixture()["buckets"]:
            items = [disclosure.item_commitment_v2(e, RB) for e in row["evidence"]]
            self.assertEqual(disclosure.bucket_commitment_v2(row["category"], items, RB),
                             row["commitment"])
            self.assertEqual(disclosure.CATEGORY_IDS[row["category"]], row["category_id"])

    def test_delegated_commitments_match_fixture(self):
        for row in _fixture()["rule_names"]:
            self.assertEqual(disclosure.rule_name_commitment_v2(row["rule"], RB),
                             row["commitment"])
        names = _fixture()["names"]
        self.assertEqual(disclosure.names_commitment_v2(names["rules"], RB),
                         names["commitment"])

    def test_category_map_covers_every_kind(self):
        self.assertEqual(disclosure.category_for_kind("retrieval_guard"), "tool_arguments")
        self.assertEqual(disclosure.category_for_kind("trace_unbound"), "trace_integrity")
        self.assertEqual(disclosure.category_for_kind("future_kind"), "other")


class TestV2Shapes(unittest.TestCase):
    """三级公开值的形状与 fail-closed 判据。"""

    def test_l0_has_no_plaintext_evidence(self):
        out = _outcome("L0")
        ok, why = disclosure.validate_outcome_v2(out, "L0")
        self.assertTrue(ok, why)
        text = json.dumps(out)
        self.assertNotIn('"evidence"', text)
        for v in out["violations"]:
            self.assertEqual(set(v), {"shape", "rule", "kind", "evidence_commitment"})

    def test_l1_counts_and_category_order(self):
        out = _outcome("L1")
        ok, why = disclosure.validate_outcome_v2(out, "L1")
        self.assertTrue(ok, why)
        self.assertEqual(out["violation_count"], 2)
        self.assertEqual([v["category"] for v in out["violations"]], ["content", "length"])
        self.assertNotIn("rule", json.dumps(out))

    def test_l2_only_opaque_sorted(self):
        out = _outcome("L2")
        ok, why = disclosure.validate_outcome_v2(out, "L2")
        self.assertTrue(ok, why)
        commits = [v["evidence_commitment"] for v in out["violations"]]
        self.assertEqual(commits, sorted(commits))
        self.assertNotIn("violation_count", out)

    def test_matrix_level_mode_delegated(self):
        """L0/L1/L2 × public/private × delegated 空/非空。"""
        for level in ("L0", "L1", "L2"):
            for private in (False, True):
                for has_del in (False, True):
                    with self.subTest(level=level, private=private, delegated=has_del):
                        out = _outcome(level, private=private,
                                       delegated=_delegated() if has_del else None)
                        ok, why = disclosure.validate_outcome_v2(out, level)
                        # 非空 delegated 只有「public × L0」这一格合法；
                        # private×delegated 是既有电路拒绝格（evaluate_private panic）。
                        want = True if not has_del else (level == "L0" and not private)
                        self.assertEqual(ok, want, why)

    def test_unknown_schema_rejected(self):
        out = _outcome("L0", schema="pop-pv-v3")
        ok, why = disclosure.validate_outcome_v2(out, "L0")
        self.assertFalse(ok)
        self.assertIn("public_value_schema", why)

    def test_unknown_level_rejected(self):
        out = _outcome("L0")
        out["disclosure_level"] = "L9"
        ok, why = disclosure.validate_outcome_v2(out, "L0")
        self.assertFalse(ok)

    def test_level_mismatch_rejected(self):
        ok, why = disclosure.validate_outcome_v2(_outcome("L1"), "L2")
        self.assertFalse(ok)
        self.assertIn("committed", why)

    def test_l1_count_tampering_rejected(self):
        out = _outcome("L1")
        out["violation_count"] = 99
        ok, why = disclosure.validate_outcome_v2(out, "L1")
        self.assertFalse(ok)
        self.assertIn("violation_count", why)

    def test_l1_category_order_rejected(self):
        out = _outcome("L1")
        out["violations"].reverse()
        out["violation_count"] = 2
        ok, why = disclosure.validate_outcome_v2(out, "L1")
        self.assertFalse(ok)
        self.assertIn("increasing", why)

    def test_l2_order_rejected(self):
        out = _outcome("L2")
        out["violations"].reverse()
        # 两条承诺的大小关系未必相反；显式构造一个确定乱序。
        out["violations"] = [
            {"shape": "opaque", "evidence_commitment": "f" * 64},
            {"shape": "opaque", "evidence_commitment": "a" * 64},
        ]
        ok, why = disclosure.validate_outcome_v2(out, "L2")
        self.assertFalse(ok)
        self.assertIn("non-decreasing", why)

    def test_l1_with_raw_field_rejected(self):
        out = _outcome("L1")
        out["violations"][0]["rule"] = "no-secret"
        ok, why = disclosure.validate_outcome_v2(out, "L1")
        self.assertFalse(ok)
        self.assertIn("banned", why)

    def test_delegated_buckets_rejected_until_implemented(self):
        out = _outcome("L1")
        out["delegated_buckets"] = [{"category": "semantic"}]
        ok, why = disclosure.validate_outcome_v2(out, "L1")
        self.assertFalse(ok)
        self.assertIn("not implemented", why)


class TestLegacyV1(unittest.TestCase):
    """旧 v1 三种组合：默认拒绝，``--legacy-v1`` 只放行 L0。"""

    def _payload(self, outcome: dict, *, schema: str | None = None,
                 level: str | None = None) -> dict:
        binding = {"vkey_hash": "unproven", "proof_sha256": None,
                   "public_values_sha256": None, "proof_mode": "unproven"}
        if schema is not None:
            binding["public_value_schema"] = schema
        p = {"outcome": outcome, "binding": binding}
        if level is not None:
            p["disclosure_level"] = level
        return p

    def test_v1_cert_v1_proof_default_rejected(self):
        p = self._payload(_legacy_outcome())
        ok, why = disclosure.check_outcome_disclosure(p, _legacy_outcome())
        self.assertFalse(ok)
        self.assertIn("rejected by default", why)

    def test_v1_cert_v1_proof_legacy_l0_accepted(self):
        p = self._payload(_legacy_outcome())
        ok, why = disclosure.check_outcome_disclosure(
            p, _legacy_outcome(), allow_legacy_v1=True)
        self.assertTrue(ok, why)
        self.assertIn("legacy-v1", why)

    def test_v1_cert_v2_proof_rejected(self):
        p = self._payload(_legacy_outcome())
        ok, why = disclosure.check_outcome_disclosure(
            p, _outcome("L0"), allow_legacy_v1=True)
        self.assertFalse(ok)
        self.assertIn("schema mismatch", why)

    def test_v2_cert_v1_proof_rejected(self):
        p = self._payload(_outcome("L0"), schema=disclosure.PUBLIC_VALUE_SCHEMA_V2,
                          level="L0")
        ok, why = disclosure.check_outcome_disclosure(
            p, _legacy_outcome(), allow_legacy_v1=True)
        self.assertFalse(ok)
        self.assertIn("masquerade", why)

    def test_v1_cert_cannot_claim_v2_level(self):
        p = self._payload(_legacy_outcome(), level="L1")
        ok, why = disclosure.check_outcome_disclosure(p, None, allow_legacy_v1=True)
        self.assertFalse(ok)

    def test_unproven_v1_cert_still_accepted_but_tagged(self):
        p = self._payload(_legacy_outcome())
        ok, why = disclosure.check_outcome_disclosure(p, None)
        self.assertTrue(ok, why)
        self.assertIn("not circuit-level", why)


class TestCertPayload(unittest.TestCase):
    """``build_payload`` 不再投影：v2 outcome 原样存，v1 拒绝冒充级别。"""

    def test_v2_outcome_is_stored_and_bound(self):
        out = _outcome("L1")
        payload = cert.build_payload(POLICY.id, POLICY.version, SPEC, "private", out,
                                     vkey_hash="unproven", ts="TS")
        self.assertEqual(payload["outcome"], out)
        self.assertEqual(payload["disclosure_level"], "L1")
        self.assertEqual(payload["binding"]["public_value_schema"], "pop-pv-v2")

    def test_explicit_level_must_match_committed_level(self):
        with self.assertRaises(disclosure.DisclosureError):
            cert.build_payload(POLICY.id, POLICY.version, SPEC, "private",
                               _outcome("L1"), vkey_hash="unproven", ts="TS",
                               disclosure_level="L2")

    def test_v1_outcome_cannot_be_issued_as_level(self):
        with self.assertRaises(disclosure.DisclosureError):
            cert.build_payload(POLICY.id, POLICY.version, SPEC, "private",
                               _legacy_outcome(), vkey_hash="unproven", ts="TS",
                               disclosure_level="L1")

    def test_v1_outcome_without_level_keeps_legacy_payload(self):
        out = _legacy_outcome()
        payload = cert.build_payload(POLICY.id, POLICY.version, SPEC, "private", out,
                                     vkey_hash="unproven", ts="TS")
        self.assertNotIn("disclosure_level", payload)
        self.assertNotIn("public_value_schema", payload["binding"])
        self.assertEqual(payload["outcome"], out)

    def test_malformed_v2_outcome_rejected(self):
        out = _outcome("L1")
        out["violations"][0]["rule"] = "no-secret"
        with self.assertRaises(disclosure.DisclosureError):
            cert.build_payload(POLICY.id, POLICY.version, SPEC, "private", out,
                               vkey_hash="unproven", ts="TS")


class TestVerifyCertCli(unittest.TestCase):
    """端到端：签 v2/v1 证书，跑 ``verify_cert.py``。"""

    def _issue(self, tmp: Path, *, outcome: dict, level: str | None,
               binding_schema: bool = True) -> Path:
        payload = cert.build_payload(
            POLICY.id, POLICY.version, SPEC, "private", outcome,
            vkey_hash="unproven", ts="2026-01-01T00:00:00Z",
            disclosure_level=level)
        if not binding_schema:
            payload["binding"].pop("public_value_schema", None)
        signer = cert.Ed25519Signer.generate()
        (tmp / "key.json").write_text(json.dumps(keys.public_record(signer.public_key)))
        (tmp / "cert.json").write_text(json.dumps(cert.sign_payload(payload, signer)))
        (tmp / "pack.json").write_text(json.dumps(_pack_dict()))
        anchor.append_anchor(tmp / "ledger.jsonl", cert.cert_digest(payload))
        return tmp / "cert.json"

    def _verify(self, tmp: Path, cert_file: Path, extra: list | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(REPO / "scripts" / "verify" / "verify_cert.py"),
             "--cert", str(cert_file), "--pack", str(tmp / "pack.json"),
             "--ledger", str(tmp / "ledger.jsonl"), *(extra or [])],
            cwd=str(REPO), capture_output=True, text=True)

    def test_v2_l1_certificate_passes(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            proc = self._verify(tmp, self._issue(tmp, outcome=_outcome("L1"), level="L1"))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[PASS] disclosure_level", proc.stdout)
        self.assertIn("L1", proc.stdout)
        self.assertIn("RESULT: PASS", proc.stdout)

    def test_v1_certificate_without_proof_passes_but_tagged(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            proc = self._verify(tmp, self._issue(
                tmp, outcome=_legacy_outcome(), level=None, binding_schema=False))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("legacy v1", proc.stdout)
        self.assertIn("RESULT: PASS", proc.stdout)

    def test_tampered_level_without_resigning_fails_signature(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cert_file = self._issue(tmp, outcome=_outcome("L1"), level="L1")
            env = json.loads(cert_file.read_text())
            payload = json.loads(base64.b64decode(env["payload"]))
            payload["disclosure_level"] = "L0"
            env["payload"] = base64.b64encode(cert.canonical(payload)).decode()
            cert_file.write_text(json.dumps(env))
            proc = self._verify(tmp, cert_file)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[FAIL] signature", proc.stdout)

    def test_resigned_level_mismatch_fails_disclosure(self):
        """重签一张「顶层 L2、公开值 L1」的证书：签名有效，但披露卡必须 FAIL。"""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cert_file = self._issue(tmp, outcome=_outcome("L1"), level="L1")
            env = json.loads(cert_file.read_text())
            payload = json.loads(base64.b64decode(env["payload"]))
            payload["disclosure_level"] = "L2"
            signer = cert.Ed25519Signer.generate()
            (tmp / "key.json").write_text(json.dumps(keys.public_record(signer.public_key)))
            cert_file.write_text(json.dumps(cert.sign_payload(payload, signer)))
            anchor.append_anchor(tmp / "ledger.jsonl", cert.cert_digest(payload))
            proc = self._verify(tmp, cert_file)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[FAIL] disclosure_level", proc.stdout)

    def test_v1_proof_rejected_without_legacy_flag(self):
        """无 proof 工件时 v1 证书仍接受；这条锁的是「有 v1 证明时必须拒绝」。"""
        p = {"binding": {"proof_mode": "core"}, "outcome": _legacy_outcome()}
        ok, why = disclosure.check_outcome_disclosure(p, _legacy_outcome())
        self.assertFalse(ok)
        self.assertIn("rejected by default", why)


@unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built")
class TestRustParity(unittest.TestCase):
    """真跑 ``pop-script --check``，与 Python 生成的 v2 公开值逐字段对拍。"""

    def _check(self, level: str, private: bool = False) -> dict:
        vector = {"name": "t", "response": BAD_T,
                  "spec_canonical": spec_canonical_text(SPEC),
                  "disclosure_level": level}
        if private:
            vector["private"] = True
        with tempfile.TemporaryDirectory() as tmp:
            vp, op = Path(tmp) / "v.json", Path(tmp) / "r.json"
            vp.write_text(json.dumps({"vectors": [vector]}))
            proc = subprocess.run(
                [str(POP_SCRIPT), "--check", "--vectors", str(vp), "--out", str(op)],
                cwd=str(REPO), capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            return json.loads(op.read_text())[0]

    def _python_expected(self, level: str, rb: str) -> dict:
        raw = _raw_violations()
        # 电路里 length_bound 的证据是实际码点长度（BAD_T = 257 个字符）。
        raw[1]["evidence"] = f"len={len(BAD_T)}"
        if level == "L0":
            return {"violations": [
                {"shape": "raw", "rule": v["rule"], "kind": v["kind"],
                 "evidence_commitment": disclosure.item_commitment_v2(v["evidence"], rb)}
                for v in raw], "violation_count": None}
        if level == "L1":
            buckets = {}
            for v in raw:
                buckets.setdefault(disclosure.category_for_kind(v["kind"]), []).append(
                    disclosure.item_commitment_v2(v["evidence"], rb))
            out = []
            for cat in sorted(buckets, key=lambda c: disclosure.CATEGORY_IDS[c]):
                items = buckets[cat]
                out.append({"shape": "category", "category": cat, "count": len(items),
                            "evidence_commitment": disclosure.bucket_commitment_v2(cat, items, rb)})
            return {"violations": out, "violation_count": sum(v["count"] for v in out)}
        commits = sorted(disclosure.item_commitment_v2(v["evidence"], rb) for v in raw)
        return {"violations": [{"shape": "opaque", "evidence_commitment": c} for c in commits],
                "violation_count": None}

    def test_public_levels_match_python(self):
        for level in ("L0", "L1", "L2"):
            with self.subTest(level=level):
                got = self._check(level)
                want = self._python_expected(level, got["response_binding"])
                self.assertEqual(got["public_value_schema"], "pop-pv-v2")
                self.assertEqual(got["disclosure_level"], level)
                self.assertEqual(got["violations"], want["violations"])
                if want["violation_count"] is None:
                    self.assertNotIn("violation_count", got)
                else:
                    self.assertEqual(got["violation_count"], want["violation_count"])

    def test_private_levels_have_same_shapes(self):
        for level in ("L0", "L1", "L2"):
            with self.subTest(level=level):
                got = self._check(level, private=True)
                want = self._python_expected(level, got["response_binding"])
                self.assertEqual(got["disclosure_level"], level)
                self.assertEqual(got["violations"], want["violations"])


if __name__ == "__main__":
    unittest.main()
