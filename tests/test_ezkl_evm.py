"""T2 回归：ezkl ``create_evm_verifier()`` 的 ``RuntimeError: no running event loop``。

这个报错从 P2-9 立项起就被记成「ezkl 12.x 才能解 / 或得绕开该 API 手写 Solidity
verifier」的硬阻塞。**两条备选都不需要** —— 真因是调用方式：

  ezkl 23.0.5 的这组函数是 pyo3 的 ``#[pyfunction]``，签名里全是 ``str``/``bool``，
  看起来同步，内部却走 ``pyo3-async-runtimes``：调用时**立刻**向 Python 事件循环
  注册回调并返回 ``asyncio.Future``。没有运行中的循环时，它内部的
  ``pyo3_async_runtimes::get_running_loop()`` 转发到 CPython 的
  ``asyncio.get_running_loop()``，于是抛 ``RuntimeError: no running event loop``。

所以本文件的用例分两半：

- :class:`TestRunHelper`（**不依赖 ezkl**，永远跑）：``ezkl_evm.run`` 对同步/异步
  可调用对象都成立；
- :class:`TestEzklEvmVerifier`（装了就跑，没装 skip）：把「裸调用必抛 → 包一层
  就通过」这个事实钉死，并核对产物形状。

其中 ``test_raw_call_outside_loop_still_raises`` 是**故意**断言上游的坏行为：
上游哪天把它改成真同步（或改成标准 ``async def``），这条会失败 —— 那不是回归，
是提醒我们删掉 :mod:`policydsl.ezkl_evm` 里的绕行说明。
"""

import asyncio
import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl import ezkl_evm  # noqa: E402


def _importable(name: str) -> bool:
    """模块是否可导入（不触发副作用）。"""
    return importlib.util.find_spec(name) is not None


#: 造 fixture 需要 ezkl（跑验证器）+ torch（导出 ONNX）；缺任一个就跳过整组。
_NEED = [n for n in ("ezkl", "torch") if not _importable(n)]
_SKIP = f"缺可选依赖 {', '.join(_NEED)}（P2-9 用；pip install ezkl torch）" if _NEED else ""


class TestRunHelper(unittest.TestCase):
    """:func:`policydsl.ezkl_evm.run` 本身的行为 —— 纯标准库，无 ezkl 依赖。"""

    def test_sync_callable(self):
        """普通同步函数：原样返回其返回值。"""
        self.assertEqual(ezkl_evm.run(lambda a, b: a + b, 2, 3), 5)

    def test_sync_callable_with_kwargs(self):
        """关键字参数照样透传。"""
        self.assertEqual(ezkl_evm.run(lambda *, x: x * 2, x=21), 42)

    def test_async_callable_is_awaited(self):
        """``async def``（即真·协程函数）：被 await 而不是返回协程对象。"""
        async def twice(x):
            await asyncio.sleep(0)
            return x * 2

        self.assertEqual(ezkl_evm.run(twice, 21), 42)

    def test_future_like_is_awaited(self):
        """ezkl 的实际形状：**同步**调用返回一个 ``asyncio.Future``。"""
        def fn():
            loop = asyncio.get_running_loop()
            fut = loop.create_future()
            loop.call_soon(fut.set_result, "done")
            return fut

        self.assertEqual(ezkl_evm.run(fn), "done")

    def test_available_is_a_bool(self):
        """``available()`` 探测失败也不抛（未装 ezkl 的环境必须能导入本模块）。"""
        self.assertIsInstance(ezkl_evm.available(), bool)


@unittest.skipIf(_NEED, _SKIP)
class TestEzklEvmVerifier(unittest.TestCase):
    """真实 ezkl：裸调用抛错、包一层通过、产物成形。"""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls._tmp.name)
        cls._build_fixture(cls.dir)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    # ---- fixture：一个 8→8→1 的极小 MLP，编译 + setup 约 7 s ----
    #
    # 不把 vk/srs 入库：体积可观且随 ezkl 版本漂移，现造更诚实（也测到了真实链路）。
    #
    # logrows=17 而不是更省的 12：**reusable 变体对电路规模敏感** —— 实测 logrows=12
    # 时 ezkl 内部直接 panic（`ezkl-verifier/src/codegen/pcs.rs: The bit counter for the
    # pairing input computations exceeds 256 bits`），17 则通过。本文件要覆盖 reusable，
    # 所以取 17。这是一次实测观察，不是"logrows 必须 ≥17"的一般规律。
    # 代价是 setup 产出的 pk.key 有 ~640 MB —— 用完立刻删（EVM 路径只用 vk/settings/srs）。
    @staticmethod
    def _build_fixture(d: Path, logrows: int = 17) -> None:
        import torch
        import torch.nn as nn
        import ezkl

        class TinyHead(nn.Module):
            def __init__(self):
                super().__init__()
                self.net = nn.Sequential(nn.Linear(8, 8), nn.ReLU(),
                                         nn.Linear(8, 1), nn.Sigmoid())

            def forward(self, x):
                return self.net(x)

        x = torch.rand(1, 8)
        # 不带 dynamic_axes：EZKL 的 tract 前端要求所有维度是常量
        torch.onnx.export(TinyHead().eval(), x, str(d / "model.onnx"),
                          input_names=["input"], output_names=["output"],
                          opset_version=17, dynamo=False)
        (d / "input.json").write_text(json.dumps(
            {"input_data": [x.flatten().tolist()], "input_shapes": [[1, 8]]}))

        ezkl.gen_settings(model=str(d / "model.onnx"), output=str(d / "settings.json"))
        s = json.loads((d / "settings.json").read_text(encoding="utf-8"))
        s["run_args"]["logrows"] = logrows
        (d / "settings.json").write_text(json.dumps(s))

        ezkl.compile_circuit(model=str(d / "model.onnx"),
                             compiled_circuit=str(d / "model.compiled"),
                             settings_path=str(d / "settings.json"))
        ezkl.gen_srs(str(d / "kzg.srs"), logrows)
        ezkl.setup(model=str(d / "model.compiled"), vk_path=str(d / "vk.key"),
                   pk_path=str(d / "pk.key"), srs_path=str(d / "kzg.srs"))
        (d / "pk.key").unlink()          # ~640 MB 的证明密钥，EVM 路径用不到

    def setUp(self):
        self.sol = self.dir / "verifier.sol"
        self.abi = self.dir / "verifier.abi"
        for p in (self.sol, self.abi):
            p.unlink(missing_ok=True)

    # ---- ① 把坏行为钉死：裸调用（无事件循环）必抛 ----
    def test_raw_call_outside_loop_still_raises(self):
        """上游的坏行为：没有事件循环时抛 ``no running event loop``。

        **这条用例故意断言上游的缺陷。** 它若失败，说明 ezkl 改了这组 API 的形态
        （改成真同步或标准 ``async def``），届时 :mod:`policydsl.ezkl_evm` 里的
        绕行说明就该删掉 —— 不是回归，是提醒。
        """
        import ezkl

        with self.assertRaises(RuntimeError) as cm:
            ezkl.create_evm_verifier(str(self.dir / "vk.key"),
                                     str(self.dir / "settings.json"),
                                     str(self.sol), str(self.abi),
                                     str(self.dir / "kzg.srs"), False)
        self.assertEqual(str(cm.exception), "no running event loop")
        self.assertFalse(self.sol.exists(), "抛错时不应留下半成品")

    # ---- ② 包一层就通过，且产物成形 ----
    def test_wrapper_produces_verifier_artifacts(self):
        ok = ezkl_evm.create_verifier(self.dir / "vk.key", self.dir / "settings.json",
                                      self.sol, self.abi, self.dir / "kzg.srs")
        self.assertTrue(ok)
        src = self.sol.read_text(encoding="utf-8")
        self.assertIn("pragma solidity ^0.8.0;", src)
        self.assertIn("contract Halo2Verifier", src)
        abi = json.loads(self.abi.read_text(encoding="utf-8"))
        names = [f["name"] for f in abi if f.get("type") == "function"]
        self.assertIn("verifyProof", names, "EVM 验证器的入口必须是 verifyProof")

    # ---- ③ 每次调用各起一个事件循环：连着调互不影响 ----
    def test_repeated_calls_use_independent_loops(self):
        outs = []
        for i in range(3):
            sol, abi = self.dir / f"rep{i}.sol", self.dir / f"rep{i}.abi"
            self.assertTrue(ezkl_evm.create_verifier(
                self.dir / "vk.key", self.dir / "settings.json", sol, abi,
                self.dir / "kzg.srs"))
            outs.append(sol.read_text(encoding="utf-8"))
        self.assertEqual(len(outs), 3)
        self.assertEqual(len(set(outs)), 1, "同一份 vk 应产出逐字相同的源码")

    # ---- ④ reusable 变体与 VK artifact ----
    def test_reusable_variant_and_vka(self):
        sol_ru = self.dir / "verifier_ru.sol"
        abi_ru = self.dir / "verifier_ru.abi"
        vka = self.dir / "vka.json"
        self.assertTrue(ezkl_evm.create_verifier(
            self.dir / "vk.key", self.dir / "settings.json", sol_ru, abi_ru,
            self.dir / "kzg.srs", reusable=True))
        self.assertTrue(ezkl_evm.create_vka(self.dir / "vk.key",
                                            self.dir / "settings.json", vka,
                                            self.dir / "kzg.srs"))
        self.assertTrue(sol_ru.exists() and abi_ru.exists() and vka.exists())
        # 可复用变体把 VK 外置，源码必然与一次性版本不同
        self.assertNotEqual(sol_ru.read_text(encoding="utf-8"),
                            self.dir / "verifier.sol".read_text(encoding="utf-8")
                            if (self.dir / "verifier.sol").exists() else "")
        # 名字叫 .json 但它**不是 JSON**：bincode 序列化的 VkArtifact（开头是小端
        # 长度前缀，其后接 G1/G2 点）。P2-9 部署时要用它，别顺手 json.load。
        raw = vka.read_bytes()
        self.assertGreater(len(raw), 0)
        with self.assertRaises(ValueError, msg="vka 若变成 JSON，请同步更新 P2-9 的部署路径"):
            json.loads(raw.decode("utf-8"))

    # ---- ⑤ solc 不在 PATH 也照样通过（纠正 docstring 的说法） ----
    def test_does_not_need_solc(self):
        """把 ``PATH`` 剥空也要过 —— 这条路径不调用 solc。

        ``create_evm_verifier`` 的 docstring 说 "you will need solc installed"，
        T2 原先也据此把它当成依赖问题。实测该说法对这条路径不成立：ezkl 只是把
        Halo2 模板的常量填好写文件。剥掉 PATH 后仍通过即证明这一点。
        """
        # 只剥 PATH，其余环境照旧 —— 不能动 HOME：ezkl 装在用户 site-packages
        # （~/.local/lib/python3.*/site-packages），改 HOME 会让它 import 不到。
        env = dict(os.environ, PATH="")
        code = (
            "import sys; sys.path.insert(0, {repo!r});"
            "from policydsl import ezkl_evm;"
            "ok = ezkl_evm.create_verifier({vk!r}, {st!r}, {sol!r}, {abi!r}, {srs!r});"
            "print('WROTE', ok)"
        ).format(repo=str(REPO), vk=str(self.dir / "vk.key"),
                 st=str(self.dir / "settings.json"), sol=str(self.dir / "nosolc.sol"),
                 abi=str(self.dir / "nosolc.abi"), srs=str(self.dir / "kzg.srs"))
        proc = subprocess.run([sys.executable, "-c", code], env=env, cwd=str(REPO),
                              capture_output=True, text=True, timeout=600)
        self.assertIn("WROTE True", proc.stdout, proc.stdout + proc.stderr)
        self.assertTrue((self.dir / "nosolc.sol").exists())


if __name__ == "__main__":
    unittest.main()
