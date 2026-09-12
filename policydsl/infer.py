"""代理推理证明的**参考实现**（P1-6）——与电路内那份逐位相同。

## 这是什么

P1-6 要落地的是「与 zkAgent 联合证明」：组合义务
``Compose = (推理完整性 ∧ 策略合规)``。真实场景的推理那一半是 zkAgent 的
prover，而 zkAgent 是 SJTU 的 C++ 系统、**源码不可得**（计划 D1）。因此这里用
一个**确定性小模型前向**当 stand-in：结构（输入 → 前向 → 被承诺的输出）与真实
推理证明同构，只是成本量级完全不同（如实记在 ``bench/results/compose.md``）。

本模块是那份电路的 **Python 参考实现**，用途与 ``policydsl/evaluate.py`` 之于
``pop-types::evaluate`` 完全一样：给单测与交叉验证一个**独立于 Rust 的**对照。
两边必须逐位相同 —— 定点整数运算，任何一处顺序、位移、取模不同都会立刻
体现在输出上。

## 与 ``pop-types`` 的对应

===============================  ==========================================
本文件                           ``circuits/types/src/lib.rs``
===============================  ==========================================
``MODEL_SPEC``                   ``INFER_MODEL_SPEC``
``splitmix64``                   ``splitmix64``
``weight``                       ``infer_weight``
``model_hash``                   ``infer_model_hash``
``input_from_response``          ``infer_input``
``forward``                      ``infer_forward``
``input_binding``                ``infer_input_binding``
``run``                          ``run_infer``
===============================  ==========================================

## 模型是什么

* 结构：``16 → 32 (ReLU) → 4`` 的 MLP，全部定点 **Q16**（scale = ``1 << 16``）。
* 权重**不来自输入**：由编译期常量种子经 splitmix64 生成。因此模型**就是程序**
  —— 它被 vkey 承诺，出证方没有「我用的其实是另一张图」的余地
  （对比 P2-9 的 ezkl 委托：那里靠 ``onnx_sha256`` + vk 指纹承诺模型权重，
  这里直接把它编进程序，是更强的形式）。
* 输入**由图内从响应导出**（``input_from_response``），不是证明者自填的向量。
  否则「输出被承诺」只能说明「存在某个输入得到这个输出」，与
  ``pop-types`` 里 P1-5 之前那条自述式 ``tool_calls`` 是同一类毛病。

## 边界（如实标注）

* **它是 stand-in，不是 zkAgent**：这里的「推理」是一个 20 KB 量级的小 MLP，
  证明成本由 zkVM 固定开销主导。真实推理证明的成本量级不同，「组合成本由
  推理证明主导」这一假设**在本机得不到验证**（见 ``bench/results/compose.md``）。
* **模型质量不在讨论范围内**：没有任何数据训练过它，它的输出没有语义意义。
  这一半证明的是「**这张**图在**这条**响应上确实算出**这个**输出」，
  与「这张图好不好」无关 —— 与 L7 的第 ② 条不保证同源。
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Sequence

#: 推理域的域分隔前缀（对应 ``pop_types::INFER_DOMAIN``）。
DOMAIN = b"pop-infer-v1"

#: 定点小数位数（对应 ``INFER_FRAC_BITS``）。
FRAC_BITS = 16
#: 定点 scale = ``1 << FRAC_BITS``。
SCALE = 1 << FRAC_BITS

IN_DIM = 16
HID_DIM = 32
OUT_DIM = 4

#: 模型参数种子（对应 ``INFER_MODEL_SEED``，ASCII ``"PoP_inf"``）。
MODEL_SEED = 0x0050_6F50_5F69_6E66

#: 模型的规范描述串。**必须与 ``pop_types::INFER_MODEL_SPEC`` 逐字符相同** ——
#: 它是 ``model_hash`` 的原像，改一个字就换了模型身份。
MODEL_SPEC = ("pop-proxy-mlp-v1:in=16:hid=32:out=4:q=16:act=relu"
              ":prng=splitmix64:seed=0x506f505f696e66")

_MASK64 = (1 << 64) - 1


def splitmix64(z: int) -> int:
    """splitmix64（对应 Rust 侧同名函数）。全程按 64 位无符号回绕。"""
    z = (z + 0x9E37_79B9_7F4A_7C15) & _MASK64
    z = ((z ^ (z >> 30)) * 0xBF58_476D_1CE4_E5B9) & _MASK64
    z = ((z ^ (z >> 27)) * 0x94D0_49BB_1331_11EB) & _MASK64
    return (z ^ (z >> 31)) & _MASK64


def weight(index: int) -> int:
    """第 ``index`` 个权重（Q16，取值 ``[-4096, 4096)``）。"""
    r = splitmix64((MODEL_SEED + index * 0x9E37_79B9_7F4A_7C15) & _MASK64)
    return (r >> 24) % 8192 - 4096


def model_hash() -> str:
    """模型指纹：``SHA256(domain ‖ "model" ‖ MODEL_SPEC)``。"""
    h = hashlib.sha256()
    h.update(DOMAIN)
    h.update(b"model")
    h.update(MODEL_SPEC.encode("ascii"))
    return h.hexdigest()


def input_from_response(response: str) -> List[int]:
    """由响应确定性导出的模型输入（``IN_DIM`` 个 Q16 值）。"""
    h = hashlib.sha256()
    h.update(DOMAIN)
    h.update(b"input")
    h.update(len(response.encode("utf-8")).to_bytes(4, "big"))
    h.update(response.encode("utf-8"))
    d = h.digest()
    # i16 大端 → 有符号，与 Rust 的 `i16::from_be_bytes(..) as i64` 一致
    return [int.from_bytes(d[2 * k:2 * k + 2], "big", signed=True) for k in range(IN_DIM)]


def forward(x: Sequence[int]) -> List[int]:
    """定点前向：``x → ReLU(x·W₁) → (·W₂)``（对应 ``infer_forward``）。"""
    if len(x) != IN_DIM:
        raise ValueError(f"输入维度必须是 {IN_DIM}，得到 {len(x)}")
    hid: List[int] = []
    for j in range(HID_DIM):
        acc = 0
        for i in range(IN_DIM):
            acc += x[i] * weight(j * IN_DIM + i)
        v = acc >> FRAC_BITS          # Rust 的 `>>` 对非负/负数都是算术右移
        hid.append(0 if v <= 0 else min(v, SCALE))
    wbase = HID_DIM * IN_DIM
    out: List[int] = []
    for k in range(OUT_DIM):
        acc = 0
        for j in range(HID_DIM):
            acc += hid[j] * weight(wbase + k * HID_DIM + j)
        out.append(acc >> FRAC_BITS)
    return out


def input_binding(nonce: bytes, input_values: Sequence[int]) -> str:
    """输入承诺：``SHA256(domain ‖ "input_binding" ‖ len(nonce) ‖ nonce ‖ 各值大端 8 字节)``。"""
    h = hashlib.sha256()
    h.update(DOMAIN)
    h.update(b"input_binding")
    h.update(len(nonce).to_bytes(4, "big"))
    h.update(bytes(nonce))
    for v in input_values:
        h.update(int(v).to_bytes(8, "big", signed=True))
    return h.hexdigest()


def run(response: str, nonce: bytes = b"") -> Dict[str, object]:
    """跑一次推理任务，返回与电路公开值**同形**的字典（对应 ``run_infer``）。"""
    from policydsl.commit import response_binding   # 与策略证明共用同一绑定公式

    x = input_from_response(response)
    return {
        "mode": "infer",
        "domain": DOMAIN.decode("ascii"),
        "model_hash": model_hash(),
        "response_binding": response_binding(nonce, response),
        "input_binding": input_binding(nonce, x),
        "output": forward(x),
    }
