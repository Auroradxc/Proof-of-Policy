"""语义规则的**确定性特征图**（P2-9 的信任边界条件 ②，见 ``docs/plan-p0p1p2.md`` §P2-9）。

本模块是语义规则的「特征侧」真相源。它只做一件事：把一段文本**确定性地**映射成
一个定长向量，且这个映射**没有任何学习参数** —— 全部算术（查表、乘法、求和、
归一化）都在 ONNX 图内完成，因此证明者无法「声明」特征。

## 为什么特征必须是纯确定性的、且必须图内派生

P0-1 的教训是：**凡是证明者能自己填的东西，都不能作为判定依据**。语义规则若写成
「先用大模型算 embedding，再把 embedding 送电路证 head」，那 embedding 就成了
证明者自填的字段 —— 与 P0-1 修掉的漏洞**完全同构**（换一个「永远判安全」的
embedding 即可）。所以本模块的特征只有：

- **固定随机投影**（固定种子生成，常数矩阵，随 ONNX 一起被 sha256 承诺）；
- **字符 n-gram 组合**（一元 / 二元 / 三元），全部由输入的字符 id 决定；
- **L2 归一化**（定点数域内可表达）。

唯一的「学习」部分是 head（``semantic/train.py`` 训练），它的权重同样被
``MODEL.sha256`` 承诺、并被 ezkl 的 vk 唯一确定。

## 特征定义（图内逐步）

设 ``c = encode(T)``（长度 ``MAX_CHARS`` 的字符 id 序列，不足补 0，超出截断）：

```
a_k[i] = A_k[c_i]                                   # 第 k 张常数投影表，k ∈ {1,2,3,4}
f      = Σ_i a_1[i]
       + Σ_i (a_2[i] ⊙ a_3[shift(i,1)])             # 二元（圆周移位）
       + Σ_i (a_2[i] ⊙ a_3[shift(i,1)] ⊙ a_4[shift(i,2)])   # 三元
f     /= sqrt(MAX_CHARS)
f     /= (‖f‖₂ + ε)
score  = head(f)          # Linear(D→32) → ReLU → Linear(32→1)
```

「⊙」是逐元素乘。**这是随机特征（random-feature / tensor-sketch）形式的 n-gram
哈希**：用固定随机矩阵的点积近似「把 n-gram 哈希到 D 个桶再计数」。它比教科书式
的 `hash(ngram) % D` 更适合 zkML —— 后者需要取模与动态索引，而这里只有
查表（one-hot × 常数矩阵）、逐元素乘、求和，全是线性/双线性算术。

**移位的口径**：``shift(i,k)`` 取 ``(i+k) mod MAX_CHARS``（**圆周**移位）。
首尾各最多 2 个位置会「绕回」，即文本末尾的字符会与开头的字符组成一个
跨界的 n-gram。这是刻意的：圆周移位在 ONNX 里只需 ``Concat`` + ``Slice``
（不引入 Pad/动态形状），代价是每段文本多出 2 个伪 n-gram。对判定无实质影响
（固定位置的轻微噪声），但**必须写明**，因为它是一个真实存在的语义偏差。

## 字符表与同形异义

``VOCAB`` 把 ASCII 可打印字符与**常见同形异义字**（西里尔/希腊/全角）都列为
**不同的 id** —— 模型看到的是真实字符，不做任何折叠。这正是本规则相对
``keyword_block`` 的差异点：关键词表被 `wеaponize`（西里尔 е）绕过，而语义规则
在训练中见过这类变异，仍然判有害。确定性的折叠（P2-9b `normalized_keyword_block`）
是**另一条**独立规则，两者互补而非替代。

## 定点语义：为什么 ``input_scale`` 必须是 1（**最容易踩空的一处**）

ezkl 把图编译成定点电路，每个张量带一个 ``scale``（真值 = 存储整数 / ``2^scale``）。
由此有一条**不能用直觉推断**的规则，本机实测确认：

> **索引类算子（``Gather`` / ``OneHot``）吃的是「缩放后的原始整数」，不是去量化后的
> 真值。** 而普通算术算子（``Mul``/``Add``）吃的是去量化后的定点数。

后果：本图的第一步是 ``embedding(idx, A)``（导出为 ``Gather``）。若 ezkl 给输入挑了一个
自动缩放（实测是 ``2^7``），那么 id ``1`` 会被当成 ``128`` 去查 ``[VOCAB_SIZE, DIM]``
的表 —— 表只有 193 行，于是直接 panic：

    AssertionError: self.dims[i] > indices[i]          # Gather 探针，id 3 → 384 越界
    RuntimeError: Expected element to be less than num_classes, but got 8960   # = 70×128，OneHot 探针

更隐蔽的一种失败是**不报错但全错**：若先把 id 除以 ``2^scale`` 再喂进去（一个很自然的
「补偿」直觉），``Cast`` 会先按**去量化后的真值**截断 —— ``1/128 = 0.0078 → 0``，
于是每个位置都退化成 PAD，整段文本变成同一个全零向量，电路**恒输出同一个分数**。
这个 bug 的表现是「有害和无害都判 128」，看上去像模型没训好，实际是量化口径错了。

**正确配置**（实测：浮点参考 ``[9.0, 90.0]`` ↔ 见证 ``[1152, 11520]``，scale 7，
``1152/128 = 9.0`` ✓）：

- ``run_args["input_scale"] = 0``（即 ``2^0 = 1``）—— 让缩放的输入**就是 id 本身**；
- 见证里直接喂**原始 id 的浮点表示**（``input_data: [[float(i) for i in ids]]``）；
- 于是 ``Gather`` 拿到的索引恰好是 id，与 :func:`encode` 的输出逐位相等。

这条配置由 ``policydsl/semantic.py`` 的 :func:`patch_settings` 施加，并在
``scripts/ezkl_prove.py`` 里对「生成设置」的步骤强制执行 —— **不允许出现「忘了打补丁
的设置文件」**：设置文件一旦不带这个补丁，出的证明要么崩、要么恒真，后者尤其危险
（它会静默地让语义规则形同虚设）。``tests/test_semantic.py`` 用一条正例一条反例把它钉住。

## 与输入长度的关系（健全性边界）

图是定长的（``MAX_CHARS``），超长文本**不能**被静默截断 —— 截断等于让
「第 97 个字符之后的有害内容」逃过判定，而证明仍然有效。因此
:func:`policydsl.semantic.require_covering_length_bound` 强制：**含语义规则的策略
必须同时含一条 ``length_bound``，其 ``max <= MAX_CHARS``**，编译期即失败。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import List, Sequence, Tuple

__all__ = [
    "MAX_CHARS", "DIM", "HIDDEN", "USE_TRIGRAM", "VOCAB", "VOCAB_SIZE",
    "FEATURE_VERSION",
    "encode", "projection_matrices", "build_net", "head_state_dict",
    "load_head_state", "export_onnx", "state_dict_fingerprint", "model_sha256",
    "MODEL_DIR", "ONNX_NAME",
]

#: 图上限：文本码点数上限（短则右补 PAD，长则**报错**）。见模块 docstring 的
#: 「健全性边界」。这个值同时是「语义规则能覆盖多长的文本」的上界 ——
#: 图是定长的，超长文本不能静默截断。
#:
#: **为什么是 64 而不是更大**：电路规模实测 ≈ ``0.058 · MAX_CHARS · DIM`` 行
#: （见 ``training_report.json`` 的 ``circuit_rows``），而行数直接决定 ``pk.key``
#: 的体积与出证内存。实测 L=96/DIM=128 时 ``pk.key`` 有 **9.46 GB** ——
#: 本机 12 GB 出不了证。L=64/DIM=64 把行数压到 ~24 万，是本机能真正跑完出证
#: 的大小。要放宽这个上限需要更大的机器（与 P1-7 的 groth16 是同一个约束）。
MAX_CHARS = 64

#: 特征维数。
DIM = 64

#: head 的隐藏层宽度。
HIDDEN = 32

#: 是否启用三元组特征。关掉可省下 **两份** ``[L, DIM]`` 中间张量（一张移位、
#: 一张乘积）及其求和 —— 实测 L=64/DIM=64 时行数从 239,835 降到 131,250（-45%）。
#: 代价是丢掉「三字符片段」这一部分信号。当前取 **False**：在 12 GB 机器上，
#: 这个规模能真正跑完 setup 与出证；要开回来需换更大的机器（同 P1-7 的约束）。
#: 一元 + 二元仍保留，足以覆盖关键词/短语级信号（见 ``training_report.json`` 的
#: 留出集指标 —— 换开关必须重训，因为它改变了特征定义）。
USE_TRIGRAM = False

#: 字符表：id 0 是 PAD（补位），其后是显式列出的字符。
#:
#: 顺序**就是** id 顺序 —— 改动它等于换一套特征，属不兼容变更。
#: 收录原则：① ASCII 可打印全集（覆盖正常英文文本）；② 常见同形异义字，
#: 使模型能区分「真 ASCII」与「长得像的其它字符」（而不是把它们折叠掉）。
VOCAB: str = (
    "\x00"                                     # 0 = PAD
    " !\"#$%&'()*+,-./0123456789:;<=>?@"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
    "abcdefghijklmnopqrstuvwxyz{|}~"
    "\n\t"
    # 同形异义字：西里尔（е о а с р х у і ѕ ј ԁ һ н м т к в）
    "еоасрхуіѕјԁһнмткв"
    # 希腊（ο ν ρ α ε ι κ τ υ χ μ）
    "ονραεικτυχμ"
    # 全角（Ａ-Ｚ ａ-ｚ ０-９ 空格）
    "ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺ"
    "ａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ"
    "０１２３４５６７８９　"
    # 零宽字符（本规则**不**剥离它们 —— 剥离是 P2-9b 的折叠规则干的事）
    "​‌‍﻿"
)

VOCAB_SIZE = len(VOCAB)

#: 字符 → id 的查表（未收录字符落到 PAD）。
_CHAR_ID = {ch: i for i, ch in enumerate(VOCAB)}

#: 模型的落盘目录与文件名。
MODEL_DIR = Path(__file__).resolve().parent
ONNX_NAME = "model.onnx"

#: 特征版本的字符串指纹（进约束、进文档）。定义集一变就必须改它。
FEATURE_VERSION = "pop-semantic-feat-v1"


def _seed_bytes() -> bytes:
    """投影表的种子字节（**常量**，不是随机数 —— 换它等于换特征定义）。"""
    return b"pop-semantic-projection-v1"


def encode(text: str, max_chars: int = MAX_CHARS) -> List[int]:
    """把文本确定性地编码成定长字符 id 序列（**参考实现**）。

    这是全仓库唯一的编码真相源：训练、见证生成、单测、以及验证方
    「拿 T 重算 ids」都调它。图内**没有**这一步 —— 图吃的是已经编码好的 id
    向量（这正是「输入与响应绑定」要核对的对象，见 ``policydsl/semantic.py``）。

    规则：逐码点取 id（未收录 → 0），右补 PAD 到 ``max_chars``，**超出则报错**
    而不是截断 —— 静默截断会让超长文本的尾部逃过判定（见模块 docstring）。
    """
    if len(text) > max_chars:
        raise ValueError(
            f"text has {len(text)} chars > max_chars={max_chars}: 语义规则不允许静默截断"
            "（静默截断会让尾部内容逃过判定）；请给策略补一条 max <= MAX_CHARS 的 length_bound")
    ids = [_CHAR_ID.get(ch, 0) for ch in text]
    ids.extend([0] * (max_chars - len(ids)))
    return ids


def projection_matrices() -> Tuple["object", "object", "object", "object"]:
    """四张常数投影表 ``A1..A4``，形状均为 ``[VOCAB_SIZE, DIM]``（**确定性**）。

    用 ``random.Random(seed).gauss`` 而非 numpy/torch 的 RNG：三者的生成算法
    随版本可能变，而这里要求**逐字节可复现**（否则 ``MODEL.sha256`` 会漂移）。
    ``random.Random`` 的 Mersenne Twister 是 Python 标准库稳定接口。
    """
    import random

    rng = random.Random(_seed_bytes())
    sigma = 0.5

    def _mat() -> List[List[float]]:
        return [[rng.gauss(0.0, sigma) for _ in range(DIM)]
                for _ in range(VOCAB_SIZE)]

    return _mat(), _mat(), _mat(), _mat()


def _random_module():
    """延迟 import torch（本模块被 ``policydsl`` 侧导入时不应要求 torch）。"""
    try:
        import torch
        import torch.nn as nn
    except Exception as exc:  # pragma: no cover - 取决于环境
        raise RuntimeError(
            "语义规则需要 torch（P2-9 的可选依赖）："
            "python3 -m pip install --user -r requirements-ezkl.txt") from exc
    return torch, nn


def build_net(head_state: dict | None = None):
    """构造特征 net（图内特征 + head）。

    ``head_state`` 为 ``None`` 时 head 是随机初始化的（仅用于形状/导出测试）；
    正式模型必须传入 :func:`load_head_state` 读出的训练权重 —— 否则
    ``MODEL.sha256`` 与文档里的分数都会失去意义。
    """
    torch, nn = _random_module()
    a1, a2, a3, a4 = projection_matrices()

    def _t(m):
        return torch.tensor(m, dtype=torch.float32)

    class _FeatureNet(nn.Module):
        """确定性特征 + 小 head。全部维度常量（ezkl 的 tract 前端要求）。"""

        def __init__(self) -> None:
            super().__init__()
            self.register_buffer("A1", _t(a1))
            self.register_buffer("A2", _t(a2))
            self.register_buffer("A3", _t(a3))
            self.register_buffer("A4", _t(a4))
            self.head = nn.Sequential(
                nn.Linear(DIM, HIDDEN), nn.ReLU(), nn.Linear(HIDDEN, 1))

        def features(self, x):
            """[1, MAX_CHARS] id → [1, DIM] 归一化特征（导出时也被复用）。

            **查表用 Gather（``F.embedding``）而不是 ``one_hot(idx) @ A``。** 两者
            数学等价，但代价差三个数量级：Gather 是「每个位置一次查表」（代价 ∝L），
            one-hot×矩阵是「每个位置 × V × D 次乘加」（代价 ∝L·V·D）。实测
            L=96/V=193/D=128 的 one-hot 版本编译出 ~73 万行、``pk.key`` **9.46 GB**
            ——本机 12 GB 出不了证；换成 Gather 后见 ``semantic/training_report.json``
            里的实测数字。

            **不做 clamp**：``x.clamp(...)`` 会导出成 ONNX ``Clip``，而 ezkl 的 tract
            前端对 int64 张量上的 Clip 直接报 ``Failed analyse for node Clip``（实测）。
            id 的取值范围由 :func:`encode` 保证、并由验证方对着 ``encode(T)`` 逐个核对。
            """
            idx = x.to(torch.int64)

            def shift(t, k):
                # 圆周移位（模块 docstring 已写明这是刻意的近似）
                return torch.cat([t[:, k:, :], t[:, :k, :]], dim=1)

            a1s = torch.nn.functional.embedding(idx, self.A1)
            a2s = torch.nn.functional.embedding(idx, self.A2)
            a3s = torch.nn.functional.embedding(idx, self.A3)
            a4s = torch.nn.functional.embedding(idx, self.A4)
            f = a1s.sum(dim=1)
            f = f + (a2s * shift(a3s, 1)).sum(dim=1)
            if USE_TRIGRAM:
                f = f + (a2s * shift(a3s, 1) * shift(a4s, 2)).sum(dim=1)
            f = f / (float(MAX_CHARS) ** 0.5)
            # 手写 L2（Sqrt/Mul/Sum）而不是 torch.linalg.vector_norm：后者导出的
            # ONNX 形状在本栈未经验证，而 Sqrt+ReduceSum 已在 ezkl 前端实测通过。
            norm = (f * f).sum(dim=1, keepdim=True).sqrt() + 1e-6
            return f / norm

        def logits(self, x):
            """sigmoid **之前**的原始分数（训练用：``BCEWithLogitsLoss`` 要它）。"""
            return self.head(self.features(x))

        def forward(self, x):
            # 输出是 **P(有害) ∈ [0,1]**，而不是无界 logit —— 这样约束里的
            # `threshold_bp`（万分点）就是字面意义上的「概率阈值」，
            # 不必再引入一套自定义的分数刻度。Sigmoid 已在 ezkl 前端实测通过。
            return torch.sigmoid(self.logits(x))

    net = _FeatureNet()
    if head_state is not None:
        net.head.load_state_dict({k: torch.tensor(v, dtype=torch.float32)
                                  for k, v in head_state.items()})
    return net


def head_state_dict(net) -> dict:
    """把 head 权重导成可 JSON 化的嵌套列表（``semantic/head.weights.json``）。"""
    return {k: v.detach().cpu().tolist() for k, v in net.head.state_dict().items()}


def load_head_state(path: Path | str | None = None) -> dict:
    """读回 head 权重（缺省 ``semantic/head.weights.json``）。"""
    p = Path(path) if path is not None else MODEL_DIR / "head.weights.json"
    return json.loads(Path(p).read_text(encoding="utf-8"))


def export_onnx(net, path: Path | str, *, opset: int = 17) -> str:
    """把 net 导出成 ONNX，返回**文件字节的 sha256**（即载荷里的 ``onnx_sha256``）。

    两条硬约束（都是本机实测踩出来的，见 ``requirements-ezkl.txt`` 末段）：

    1. **不能带 dynamic_axes** —— ezkl 的 tract 前端遇到符号维度会报
       ``Undetermined symbol in expression``。全部维度必须常量（图本就是定长的）。
    2. **必须 ``dynamo=False``** —— torch ≥2.9 默认走 dynamo 导出器，本栈不兼容。

    导出是**逐字节确定**的：权重来自固定种子的常数表 + 落盘的 head 权重，
    ONNX 不嵌时间戳，同一进程外重复导出得到同一 sha256（``tests/test_semantic.py``
    用**两个独立子进程**钉死这一点 —— 只在同一进程里导两次是测不出问题的）。
    """
    torch, _ = _random_module()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    dummy = torch.zeros(1, MAX_CHARS, dtype=torch.float32)
    # 输入 dtype 是 float32（不是 int64）：ezkl 的量化前端要浮点；id 的整数性由
    # 图内的 `.to(int64)` 保证，且验证方会对着 encode(T) 逐个核对。
    torch.onnx.export(net.eval(), dummy, str(path),
                      input_names=["char_ids"], output_names=["score"],
                      opset_version=opset, dynamo=False)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def state_dict_fingerprint() -> str:
    """四张投影表的指纹（进文档/测试，便于发现「特征定义被悄悄改了」）。"""
    a1, a2, a3, a4 = projection_matrices()
    blob = json.dumps([a1, a2, a3, a4], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def model_sha256() -> str:
    """``semantic/model.onnx`` 的 sha256（未入库时抛出，提示先跑 ``train.py``）。"""
    p = MODEL_DIR / ONNX_NAME
    if not p.exists():
        raise FileNotFoundError(
            f"{p} 不存在 —— 先跑 python3 -m semantic.train 生成模型与 MODEL.sha256")
    return hashlib.sha256(p.read_bytes()).hexdigest()
