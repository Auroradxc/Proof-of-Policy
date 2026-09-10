"""verifier-only 路径（``pop-verify``，只依赖 sp1-verifier、不构造证明器）的测试。

为什么要有这条路：第三方审计方没有、也不该有证明器环境，但仍需独立复核证明。
因此 ``pop-verify`` 只在 SP1 的验证端点上做校验，环境依赖极轻、耗时也远低于
重新出证——这里既验证它能验通真证明，也验证它会明确拒绝不可这样验的模式。

重量级 fixture（一份 compressed 证明）由 ``scripts/make_audit_proof.sh`` 生成到
``circuits/testdata/audit_proof/``；二进制或 fixture 缺失时干净地跳过（前者说明
没构建，后者说明还没出证，都不该算失败）。
"""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
POP_VERIFY = REPO / "circuits" / "target" / "release" / "pop-verify"
FIXTURE = REPO / "circuits" / "testdata" / "audit_proof"


class TestVerifierOnly(unittest.TestCase):
    """对真实证明产物的验证：验得通、拒绝得明确、且不依赖证明器环境。"""

    # 核心用例：compressed 证明必须验通，公值哈希要和边车指向的原始公值文件对得上
    # （防止「验的是另一份公值」），且整程应在秒级完成——这正是快路径的意义。
    @unittest.skipUnless(POP_VERIFY.exists(), "pop-verify not built (cargo build -p pop-verify)")
    def test_compressed_fixture_verifies_fast_and_light(self):
        sidecar = FIXTURE / "proof.verify.json"
        if not sidecar.exists():
            self.skipTest("no compressed fixture; run scripts/make_audit_proof.sh")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "res.json"
            t0 = time.perf_counter()
            r = subprocess.run([str(POP_VERIFY), "--meta", str(sidecar), "--out", str(out)],
                               capture_output=True, text=True, cwd=str(REPO))
            secs = time.perf_counter() - t0
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            v = json.loads(out.read_text())
            self.assertTrue(v["verified"])
            self.assertEqual(v["proof_mode"], "compressed")
            # 公值哈希要与边车指向的原始公值文件一致（绑定被验内容）
            meta = json.loads(sidecar.read_text())
            pv = Path(meta["public_values_file"]).read_bytes()
            self.assertEqual(v["public_values_sha256"], hashlib.sha256(pv).hexdigest())
            # verifier-only 无需证明器，应该很快（阈值放宽以兼容 CI 机器）
            self.assertLess(secs, 20, f"pop-verify took {secs:.1f}s (unexpectedly slow)")

    # core 证明没有可供第三方核验的递归工件；此时必须**明确报错**（exit 3 + 可读
    # 提示），而不是默默返回「验证通过」——静默通过等同于伪造审计结论。
    @unittest.skipUnless(POP_VERIFY.exists(), "pop-verify not built")
    def test_core_mode_is_rejected_with_clear_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            meta = Path(tmp) / "fake.verify.json"
            meta.write_text(json.dumps({"proof_mode": "core", "proof_bytes_file": "x",
                                        "public_values_file": "y"}))
            r = subprocess.run([str(POP_VERIFY), "--meta", str(meta)],
                               capture_output=True, text=True, cwd=str(REPO))
            self.assertEqual(r.returncode, 3)
            self.assertIn("not verifier-only verifiable", r.stderr)

    @unittest.skipUnless(POP_VERIFY.exists(), "pop-verify not built")
    def test_pop_verify_does_not_need_sp1_env(self):
        """不构造证明器：因此不能依赖 SP1_PROVER 或证明器相关依赖。

        这里刻意把 SP1_PROVER 从环境里摘掉再跑，若实现里混入了证明器初始化，
        就会在此暴露——这也是审计方能实际用起来的前提。
        """
        sidecar = FIXTURE / "proof.verify.json"
        if not sidecar.exists():
            self.skipTest("no compressed fixture")
        env = {k: v for k, v in __import__("os").environ.items() if k != "SP1_PROVER"}
        r = subprocess.run([str(POP_VERIFY), "--meta", str(sidecar)],
                           capture_output=True, text=True, cwd=str(REPO), env=env)
        self.assertEqual(r.returncode, 0, r.stderr)


class TestVerifierOnlySelection(unittest.TestCase):
    """verifier-only 快路径的判定是个纯函数（可离线测试，不需要证明产物）。"""

    # 判定必须**同时**满足：二进制存在 + 边车存在 + 边车声明 verifier-only 模式。
    # 只看边车存在会把 core 证明误选为快路径，随后 pop-verify 会拒绝（见上一类）。
    def test_prefer_verifier_only_requires_binary_and_sidecar(self):
        sys.path.insert(0, str(REPO / "scripts"))
        from verify_session import prefer_verifier_only

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            proof = tmp / "proof.bin"
            proof.write_bytes(b"x")
            binary = tmp / "pop-verify"
            sidecar = Path(str(proof) + ".verify.json")
            # 二进制与边车都没有 → 不快路径
            self.assertFalse(prefer_verifier_only(proof, binary))
            # 只有边车、缺二进制 → 仍不快路径（没程序可跑）
            sidecar.write_text(json.dumps({"proof_mode": "compressed"}))
            self.assertFalse(prefer_verifier_only(proof, binary))
            # 两者齐备 → 走快路径
            binary.write_text("#!/bin/sh\n")
            self.assertTrue(prefer_verifier_only(proof, binary))

    def test_core_sidecar_does_not_take_the_fast_path(self):
        """core 证明也会写边车，但 core 不能被 pop-verify 验证 → 必须回落到 pop-script。"""
        sys.path.insert(0, str(REPO / "scripts"))
        from verify_session import prefer_verifier_only

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            proof = tmp / "proof.bin"
            proof.write_bytes(b"x")
            binary = tmp / "pop-verify"
            binary.write_text("#!/bin/sh\n")
            sidecar = Path(str(proof) + ".verify.json")
            sidecar.write_text(json.dumps({"proof_mode": "core"}))
            self.assertFalse(prefer_verifier_only(proof, binary))
            # 三种 verifier-only 可验证模式都应被接受
            for mode in ("compressed", "groth16", "plonk"):
                sidecar.write_text(json.dumps({"proof_mode": mode}))
                self.assertTrue(prefer_verifier_only(proof, binary))
            # 边车损坏/无 proof_mode → 不冒险走快路径
            sidecar.write_text("{}")
            self.assertFalse(prefer_verifier_only(proof, binary))


if __name__ == "__main__":
    unittest.main()
