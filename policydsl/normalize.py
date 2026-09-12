"""同形异义折叠（P2-9b）—— 关键词规则的**规范化**层。

## 要解决的问题

``keyword_block`` 是**码点子串**判定：响应里出现 ``wеaponize``（第二个字符是
西里尔 е U+0435，不是 ASCII ``e``）时它不命中，而人眼看起来一模一样。攻击者
只要替换一两个字符就能让关键词表失效。这不是实现缺陷，是「比较没做规范化」
这一层缺失 —— 本模块补的就是这一层。

## 折叠规则（``pop-fold-v1``）

对文本做**单遍、从左到右、逐码点**的替换：

1. 码点在 ``map`` 里 → 换成对应的**单个 ASCII 字符**；
2. 码点在 ``drop`` 里 → 删除（零宽字符）；
3. 其它 → 原样保留。

**单遍**是刻意的：不做不动点迭代。于是折叠不可能构成链式放大（``a→b``、``b→c``
不会把 ``a`` 变成 ``c``），`map` 的顺序无关，两层的实现也就能逐字节对齐。

折叠**之后**再做 ASCII 小写化（:func:`ascii_lower`）—— 与 ``keyword_block``
同一套大小写口径，避免 Python 的 ``str.lower()`` 把非 ASCII 字母也小写而电路
侧的 ``ascii_lower`` 不会（那种差异会让链下/链上对同一输入得出不同结论）。

## 表为什么**放在约束里**

折叠表随约束走（``normalized_keyword_block.fold``），而不是两边各硬编码一份：

- 表是 ``policy_hash`` 的一部分，改表 = 换策略，**可审计**：一份策略的规范字节
  里就写着「西里尔 е 折叠成 e」；
- 跨层漂移在结构上不可能 —— 电路不解释「v1 是什么意思」，它只执行带进来的表；
- 未来换一套表（或加码点）不必动电路，只需换 ``version``（未知版本 fail-closed）。

代价是策略 JSON 变长（v1 的表 129 条，其中全角整块 95 条 —— 那一块是整段偏移
生成的，不是手抄），这是刻意的取舍：**看得见的表**胜过两处心照不宣的常量。

## 边界

- 只做**单码点**映射：``ß → ss`` 这类一对多是规范化（NFKC）的活，不在这里；
- 表里出现的码点必须来自仓库既有的「同形异义字」清单
  （``semantic/features.VOCAB`` / ``semantic/dataset.HOMOGLYPH_PAIRS``），
  两者的包含关系由 ``tests/test_normalize.py`` 钉住；
- 本模块**只用标准库**，不依赖 torch/semantic（那是可选的实验依赖）。

## 同形异义 vs 语义规则（P2-9）

两者都拦得住 ``wеaponize``，但性质不同，**不能互相替代**：

- 折叠规则是**符号**判定：命中即违规，可复现、可解释、无需模型；
- 语义规则是**统计**判定：换一个模型/阈值就可能漏。P2-9 用它演示「关键词表被绕过
  而语义规则拦下」（``tests/test_semantic.py``），那是**能力对比**；
- 于是一条策略可以两条都写：符号的兜底 + 统计的泛化。

同一字符串在两处都命中时并不冲突 —— 违规列表按约束顺序各记一条。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Sequence, Set, Tuple

__all__ = [
    "Fold", "FoldError", "FOLD_VERSION", "FOLD_VERSIONS", "DEFAULT_PRESET",
    "PRESET_NAMES", "ascii_lower", "build_v1_spec", "resolve_fold", "fold",
    "canonical_keywords", "MAX_MAP", "MAX_DROP",
]


class FoldError(ValueError):
    """折叠表/声明非法。调用方负责包装成 PolicyError（保持 model 层措辞一致）。"""


#: 当前折叠语义的版本号。**语义**变了才换号，换表不换号（表在约束里）。
FOLD_VERSION = "pop-fold-v1"

#: 电路侧认识的版本白名单 —— 不在其中的版本一律拒绝（fail-closed）。
#: 加新语义时要**同时**改这里与 ``circuits/types/src/lib.rs::FOLD_VERSIONS``。
FOLD_VERSIONS: Tuple[str, ...] = (FOLD_VERSION,)

#: 表大小上限（电路内是线性扫描，必须有界）。
MAX_MAP = 512
MAX_DROP = 64

#: DSL 里 ``"fold": "<预设名>"`` 的可写名字。``"v1"`` 是便利别名，
#: 进约束时会展开成显式表（``version`` 字段才是权威的语义版本）。
PRESET_NAMES = ("v1", FOLD_VERSION)
#: 缺省预设：**用版本号本身**，免得契约里出现一个需要查表才知道含义的短名。
DEFAULT_PRESET = FOLD_VERSION


# --------------------------------------------------------------------------- #
# 同形异义表 —— 与仓库既有清单同源
# --------------------------------------------------------------------------- #

#: 同形字 → ASCII。**就是** ``semantic/dataset.py::HOMOGLYPH_PAIRS`` 的逆
#: （那张表是 ascii → 同形字候选，这里反过来用于折叠），加上 ``features.VOCAB``
#: 里出现、但 dataset 没列的同形字。
#:
#: 只收「几乎分不出差别」的那些：折叠一个其实不像的字符，等于把一种语言的正常
#: 词误判成攻击 —— 规范化表的每一次扩张都要拿这个尺子量一遍。
#:
#: 这张表**故意**比 ``VOCAB`` 大：VOCAB 是「训练时让模型见过哪些字符」，
#: 本表是「哪些字符长得像 ASCII」。两者方向不同 —— 实测有 6 个同形字只出现在
#: ``HOMOGLYPH_PAIRS`` 里而没进 VOCAB（大写西里尔 Ѕ А Е О Т 与小写 п），
#: 也就是模型根本没训过它们：``WЕAPONIZE`` 那种大写变体，统计层很可能是漏的，
#: 而这一层照样折得回来。``tests/test_normalize.py`` 的软检查钉住「每行都有出处」。
_HOMOGLYPHS: Dict[str, str] = {
    # —— 西里尔 ——
    "а": "a",  # а
    "с": "c",  # с
    "е": "e",  # е
    "о": "o",  # о
    "р": "p",  # р
    "х": "x",  # х
    "у": "y",  # у
    "і": "i",  # і
    "ѕ": "s",  # ѕ
    "ј": "j",  # ј
    "һ": "h",  # һ
    "п": "n",  # п
    "т": "t",  # т
    "к": "k",  # к
    "м": "m",  # м
    "в": "b",  # в
    "ԁ": "d",  # ԁ
    "н": "h",  # н（与 һ 同折到 h：只求「归一」，不求还原原字母）
    # 大写：折成 ASCII 大写，再由 ascii_lower 统一到小写
    "А": "A",  # А
    "Е": "E",  # Е
    "О": "O",  # О
    "Ѕ": "S",  # Ѕ
    "Т": "T",  # Т
    # —— 希腊 ——
    "ο": "o",  # ο omicron
    "χ": "x",  # χ chi
    "ν": "v",  # ν nu
    "ρ": "p",  # ρ rho
    "α": "a",  # α alpha
    "ε": "e",  # ε epsilon
    "ι": "i",  # ι iota
    "κ": "k",  # κ kappa
    "τ": "t",  # τ tau
    "υ": "u",  # υ upsilon
    "μ": "u",  # μ mu（视觉上是 u 的另一种写法；折到同一处即可）
}

#: 零宽字符 —— 直接删除。它们**不可见**，删掉不会把正常文本变成另一个词，
#: 却是绕过关键词表最省事的手段（``wea​ponize``）。
_ZERO_WIDTH: Tuple[int, ...] = (
    0x200B,  # ZWSP 零宽空格
    0x200C,  # ZWNJ 零宽不连字
    0x200D,  # ZWJ  零宽连字
    0xFEFF,  # ZWNBSP / BOM
)


def _fullwidth_map() -> Dict[int, str]:
    """全角 ASCII（U+FF01–U+FF5E）与全角空格（U+3000）→ 半角。

    这一段是**整块偏移**（-0xFEE0），所以这里是生成而不是手抄 95 行 ——
    手抄只会抄错。全角字符常常是输入法/复制粘贴带进来的，不是攻击，
    但折叠它们同样没有副作用（正常英文文本里不会出现全角字母）。
    """
    out: Dict[int, str] = {c: chr(c - 0xFEE0) for c in range(0xFF01, 0xFF5F)}
    out[0x3000] = " "
    return out


def build_v1_spec() -> Dict[str, Any]:
    """构造 ``pop-fold-v1`` 的**显式**折叠表（JSON 形状，可直接进约束）。"""
    table: Dict[int, str] = dict(_fullwidth_map())
    for ch, to in _HOMOGLYPHS.items():
        cp = ord(ch)
        if cp in table and table[cp] != to:
            raise FoldError(f"内部矛盾：U+{cp:04X} 同时映射到 {table[cp]!r} 与 {to!r}")
        table[cp] = to
    return {
        "version": FOLD_VERSION,
        "map": [[cp, table[cp]] for cp in sorted(table)],
        "drop": list(_ZERO_WIDTH),
    }


# --------------------------------------------------------------------------- #
# 解析 / 校验
# --------------------------------------------------------------------------- #

def _check_cp(v: Any, what: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool):
        raise FoldError(f"{what} 必须是整数码点，got {v!r}")
    if not (0 <= v <= 0x10FFFF):
        raise FoldError(f"{what} 超出 Unicode 范围：U+{v:04X}" if v >= 0 else f"{what} 为负：{v}")
    if 0xD800 <= v <= 0xDFFF:
        raise FoldError(f"{what} 是代理区码点 U+{v:04X}（不可能是合法 UTF-8 文本的一部分）")
    return v


def _resolve(spec: Any) -> Dict[str, Any]:
    """把声明（预设名 / 显式表 / None）解析成**规范化后的显式表**。

    规范化 = 排序 + 去重检查 + 字段白名单。顺序重要：规范 JSON 会如实保留数组
    顺序，若表以两种顺序出现就会得到两个 ``policy_hash``，同一策略会被判成两份。
    """
    if spec is None:
        spec = DEFAULT_PRESET
    if isinstance(spec, str):
        if spec not in PRESET_NAMES:
            raise FoldError(
                f"未知的折叠预设 {spec!r}（可用：{', '.join(PRESET_NAMES)}）")
        return build_v1_spec()
    if not isinstance(spec, dict):
        raise FoldError(f"fold 必须是预设名或显式表字典，got {type(spec).__name__}")

    unknown = set(spec) - {"version", "map", "drop"}
    if unknown:
        # 严格拒绝：多出来的键意味着写的人以为是另一套语义，猜错=静默换语义
        raise FoldError(f"fold 表里有未知字段 {sorted(unknown)}（只允许 version/map/drop）")

    version = spec.get("version")
    if version not in FOLD_VERSIONS:
        raise FoldError(
            f"未知的折叠语义版本 {version!r}（已知：{', '.join(FOLD_VERSIONS)}）—— "
            f"电路侧同样会拒绝，这里提前报错")

    raw_map = spec.get("map", [])
    raw_drop = spec.get("drop", [])
    if not isinstance(raw_map, (list, tuple)) or not isinstance(raw_drop, (list, tuple)):
        raise FoldError("fold.map / fold.drop 必须是数组")
    if len(raw_map) > MAX_MAP:
        raise FoldError(f"fold.map 过大（{len(raw_map)} > {MAX_MAP}）")
    if len(raw_drop) > MAX_DROP:
        raise FoldError(f"fold.drop 过大（{len(raw_drop)} > {MAX_DROP}）")

    table: Dict[int, str] = {}
    for i, pair in enumerate(raw_map):
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise FoldError(f"fold.map[{i}] 必须是 [码点, 字符] 二元组，got {pair!r}")
        cp = _check_cp(pair[0], f"fold.map[{i}][0]")
        to = pair[1]
        if not isinstance(to, str) or len(to) != 1:
            raise FoldError(f"fold.map[{i}][1] 必须是单个字符，got {to!r}")
        if ord(to) >= 0x80:
            # 单码点 → 单 ASCII：折叠后的文本才是纯 ASCII 主体，跨层比较才无歧义
            raise FoldError(f"fold.map[{i}][1] 必须是 ASCII 字符，got {to!r}")
        if cp in table:
            raise FoldError(f"fold.map 里 U+{cp:04X} 重复出现")
        if cp == ord(to):
            raise FoldError(f"fold.map 里 U+{cp:04X} 映射到自身 —— 空操作，多半是写错了")
        table[cp] = to

    drop: List[int] = []
    for i, cp in enumerate(raw_drop):
        cp = _check_cp(cp, f"fold.drop[{i}]")
        drop.append(cp)
    if len(set(drop)) != len(drop):
        raise FoldError("fold.drop 里有重复码点")
    both = sorted(set(drop) & set(table))
    if both:
        raise FoldError(
            "码点不能既在 map 又在 drop 里：" + " ".join(f"U+{c:04X}" for c in both))

    return {
        "version": version,
        "map": [[cp, table[cp]] for cp in sorted(table)],
        "drop": sorted(drop),
    }


@dataclass(frozen=True)
class Fold:
    """解析并校验过的折叠表：``spec`` 进约束，``apply`` 用于判定。"""

    spec: Dict[str, Any]
    map: Dict[int, str]
    drop: Set[int]

    def apply(self, text: str) -> str:
        """单遍折叠（与 ``circuits/types/src/lib.rs::fold_text`` 逐字符对应）。"""
        m, d = self.map, self.drop
        out: List[str] = []
        for ch in text:
            cp = ord(ch)
            to = m.get(cp)
            if to is not None:
                out.append(to)
            elif cp not in d:
                out.append(ch)
        return "".join(out)


def resolve_fold(spec: Any = None) -> Fold:
    """把 ``fold`` 声明解析成 :class:`Fold`（非法则抛 :class:`FoldError`）。"""
    resolved = _resolve(spec)
    return Fold(
        spec=resolved,
        map={cp: to for cp, to in resolved["map"]},
        drop=set(resolved["drop"]),
    )


def fold(text: str, spec: Any = None) -> str:
    """便捷函数：解析 ``spec`` 并对 ``text`` 折叠一次。"""
    return resolve_fold(spec).apply(text)


# --------------------------------------------------------------------------- #
# 大小写与关键词规范化
# --------------------------------------------------------------------------- #

def ascii_lower(s: str) -> str:
    """仅对 ASCII 大写字母做小写化（与电路内 ``ascii_lower`` 字节级一致）。

    不用 Python 的 ``str.lower()``：它会把非 ASCII 字母也小写（``Е`` → ``е``），
    而电路侧不会 —— 同一条响应在两层得出不同结论是**健全性**问题，不是风格问题。
    """
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def canonical_keywords(params: Dict[str, Any]) -> Tuple[Fold, List[str]]:
    """从规则的 ``params`` 得出（折叠表, **规范化后的关键词表**）。

    规范化 = 逐个「折叠 + ASCII 小写化」后排序去重 —— 与 :func:`policydsl.compile`
    对关键词做的处理是**同一个函数**，这样「链下证据取哪个关键词」与「链上取哪个」
    不会因为顺序不同而分叉。调用方（``evaluate`` / ``commit``）拿到的列表顺序
    就是电路里 ``keywords.iter().find(...)`` 的顺序。
    """
    fold_spec = resolve_fold(params.get("fold", DEFAULT_PRESET))
    words: Iterable[Any] = params["keywords"]
    canon = {ascii_lower(fold_spec.apply(str(w))) for w in words}
    if "" in canon:
        raise FoldError("关键词折叠后为空串 —— 空串是任意文本的子串，该规则会恒真命中")
    return fold_spec, sorted(canon)


def match_keywords(fold_spec: Fold, keywords: Sequence[str], text: str) -> Any:
    """在折叠后的文本里找**第一个**命中的关键词（``None`` = 未命中）。

    关键词按 ``keywords`` 列出的顺序逐个检查，与电路内的迭代顺序一致；
    返回命中的那个关键词本身（= 证据），与 ``keyword_block`` 的口径相同。
    """
    folded = ascii_lower(fold_spec.apply(text))
    for kw in keywords:
        if kw in folded:
            return kw
    return None
