"""一个极简的正则 → NFA 引擎（Proof-of-Policy 的参考层）。

为什么需要它：``pattern_block`` 约束必须被 Python 参考评估器与 SP1（Rust、
no_std）程序**判定结果完全一致**。Python 的 ``re`` 无法在 zkVM 内复现，因此
模式被编译成一个**可序列化的 NFA**，两侧各自解释这份 NFA。本模块就是那个
「唯一的编译器」+ 一个 Pike-VM 模拟器，充当参考语义。

受支持的子集（其它语法一律快速失败）：
  - 字面量、转义的标点、控制转义（``\\n`` ``\\t`` ...）
  - ``.``  除 ``\\n`` 外的任意字符
  - 字符类 ``[...]``，含区间与 ``\\w \\d \\s``、取反 ``[^...]``
  - 类转义 ``\\w \\W \\d \\D \\s \\S``（ASCII 语义，见下）
  - 分组 ``( ... )`` 与分支 ``|``
  - 量词 ``*  +  ?  {m}  {m,}  {m,n}``
  - 不支持（抛 ``RegexSyntaxError``）：锚点 ``^ $``、反向引用、环视、
    懒惰/贪婪区分、``\\b``。

ASCII 语义说明：``\\w \\d \\s`` 这里分别指 ASCII 的
``[A-Za-z0-9_]`` / ``[0-9]`` / ``[ \\t\\n\\r\\f\\v]``。这与 Python 的
``re`` 在 ASCII 输入（目标场景）上一致，但在非 ASCII 字母上不一致；此为
文档化的差异，与阶段一相同。

序列化 NFA ``spec``（即 ConstraintSpec 契约）：

    {"start": int,
     "accept": [int, ...],
     "states": [
        {"eps": [int, ...],
         "edges": [{"to": int, "ranges": [[lo, hi], ...]}, ...]},   # 闭区间
        ...
     ]}
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union

MAX_CP = 0x10FFFF
ANY_EXCEPT_NL = [[0, 9], [11, MAX_CP]]  # "."（re.search 中点号不匹配 \\n）

_WS_RANGES = [[9, 13], [32, 32]]  # \t \n \v \f \r + 空格
_DIGIT_RANGES = [[48, 57]]
_WORD_RANGES = [[48, 57], [65, 90], [95, 95], [97, 122]]


class RegexSyntaxError(ValueError):
    """当模式使用了受支持子集之外的语法时抛出。"""


def _complement(ranges: List[List[int]]) -> List[List[int]]:
    """求给定闭区间集合在 [0, MAX_CP] 内的补集（用于取反字符类）。"""
    out: List[List[int]] = []
    cursor = 0
    for lo, hi in sorted(ranges):
        if lo > cursor:
            out.append([cursor, lo - 1])
        cursor = max(cursor, hi + 1)
    if cursor <= MAX_CP:
        out.append([cursor, MAX_CP])
    return out


def _merge(ranges_list: List[List[List[int]]]) -> List[List[int]]:
    """把多组区间扁平化后排序，并合并重叠/相邻区间。"""
    merged: List[List[int]] = []
    for rs in ranges_list:
        merged.extend(rs)
    merged.sort()
    out: List[List[int]] = []
    for lo, hi in merged:
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return out


# --------------------------------------------------------------------------- #
# AST（抽象语法树）
# --------------------------------------------------------------------------- #

@dataclass
class Lit:
    """字面量/字符类：由一组字符区间表示（可匹配其中任一字符）。"""
    ranges: List[List[int]]


@dataclass
class Concat:
    """连接：顺序匹配多个子表达式。"""
    items: List["Node"]


@dataclass
class Alt:
    """分支：匹配任一子表达式。"""
    options: List["Node"]


@dataclass
class Repeat:
    """重复：子表达式重复 min..max 次（max=None 表示无上界）。"""
    child: "Node"
    min: int
    max: Optional[int]  # None == 无界


Node = Union[Lit, Concat, Alt, Repeat]


def _class_escape(name: str) -> List[List[int]]:
    """把 ``\\d \\w \\s \\D \\W \\S`` 转成对应的字符区间（ASCII 语义）。"""
    if name == "d":
        return _DIGIT_RANGES
    if name == "w":
        return _WORD_RANGES
    if name == "s":
        return _WS_RANGES
    if name == "D":
        return _complement(_DIGIT_RANGES)
    if name == "W":
        return _complement(_WORD_RANGES)
    if name == "S":
        return _complement(_WS_RANGES)
    raise RegexSyntaxError(f"unsupported escape '\\{name}'")


def _parse_char_class(pat: str, i: int):
    """解析一个 ``[...]`` 字符类，起始于 pat[i]=='['。返回 (ranges, i)，
    其中 i 是紧邻 ']' 之后的下标。调用方需已确认 pat[i]=='['。"""
    i += 1  # 跳过 '['
    negate = False
    if i < len(pat) and pat[i] == "^":
        negate = True
        i += 1
    parts: List[List[List[int]]] = []
    while i < len(pat):
        c = pat[i]
        if c == "]" and parts:
            # 遇到 ']' 且已有内容：字符类结束
            i += 1
            ranges = _merge(parts)
            if negate:
                ranges = _complement(ranges)
            return ranges, i
        if c == "\\":
            # 转义：类转义 \d \w 等 / 控制转义 \n \t 等 / 转义任意字符
            if i + 1 >= len(pat):
                raise RegexSyntaxError("trailing backslash in character class")
            nxt = pat[i + 1]
            if nxt in "dDwWsS":
                parts.append(_class_escape(nxt))
                i += 2
            elif nxt in "nrtfv":
                parts.append([[{"n": 10, "r": 13, "t": 9, "f": 12, "v": 11}[nxt]] * 2])
                i += 2
            else:
                parts.append([[ord(nxt), ord(nxt)]])
                i += 2
        elif c == "[":
            raise RegexSyntaxError("nested classes / POSIX classes unsupported")
        else:
            # 普通字符，可能带区间 a-z
            lo = ord(c)
            i += 1
            if i + 1 < len(pat) and pat[i] == "-" and pat[i + 1] != "]":
                hi = ord(pat[i + 1])
                if lo > hi:
                    raise RegexSyntaxError(f"invalid range {c}-{chr(hi)}")
                parts.append([[lo, hi]])
                i += 2
            else:
                parts.append([[lo, lo]])
    raise RegexSyntaxError("unterminated character class")


def _parse_atom(pat: str, i: int) -> Tuple[Node, int]:
    """解析一个「原子」：分组、字符类、点号、转义或单个字面量字符。"""
    if i >= len(pat):
        raise RegexSyntaxError("unexpected end of pattern")
    c = pat[i]
    if c == "(":
        # 分组：递归解析括号内的分支表达式
        node, i = _parse_alt(pat, i + 1)
        if i >= len(pat) or pat[i] != ")":
            raise RegexSyntaxError("unbalanced '('")
        return node, i + 1
    if c == "[":
        ranges, i = _parse_char_class(pat, i)
        return Lit(ranges), i
    if c == ".":
        return Lit(ANY_EXCEPT_NL), i + 1
    if c == "\\":
        if i + 1 >= len(pat):
            raise RegexSyntaxError("trailing backslash")
        nxt = pat[i + 1]
        if nxt in "dDwWsS":
            return Lit(_class_escape(nxt)), i + 2
        if nxt in "nrtfv":
            return Lit([[{"n": 10, "r": 13, "t": 9, "f": 12, "v": 11}[nxt]] * 2]), i + 2
        if nxt.isalnum():
            # \d \w \s 已在上面处理；其余字母数字转义（如 \1 \b \A）不在子集内
            raise RegexSyntaxError(f"unsupported escape '\\{nxt}' at position {i}")
        # 标点的恒等转义：把该字符按字面量处理
        return Lit([[ord(nxt), ord(nxt)]]), i + 2
    if c in "|)*+?{^$":
        # 这些元字符在此处无操作数，属于非法位置
        raise RegexSyntaxError(f"unexpected '{c}' at position {i}")
    return Lit([[ord(c), ord(c)]]), i + 1


def _parse_quantifier(pat: str, i: int) -> Tuple[Tuple[int, Optional[int]], int]:
    """解析量词 * + ? {m} {m,} {m,n}；无显式量词时返回 (1,1)（恰好一次）。"""
    if i >= len(pat):
        return (1, 1), i
    c = pat[i]
    if c == "*":
        return (0, None), i + 1
    if c == "+":
        return (1, None), i + 1
    if c == "?":
        return (0, 1), i + 1
    if c == "{":
        j = pat.find("}", i + 1)
        if j == -1:
            raise RegexSyntaxError("unterminated '{...}'")
        body = pat[i + 1:j]
        if "," in body:
            a, _, b = body.partition(",")
            lo = int(a) if a else 0
            hi: Optional[int] = int(b) if b else None
        else:
            lo = hi = int(body)
        if lo < 0 or (hi is not None and hi < lo):
            raise RegexSyntaxError(f"bad quantifier {{{body}}}")
        return (lo, hi), j + 1
    return (1, 1), i


def _parse_repeat(pat: str, i: int) -> Tuple[Node, int]:
    """解析「原子 + 量词」：先解析原子，再解析其量词。"""
    node, i = _parse_atom(pat, i)
    (lo, hi), i = _parse_quantifier(pat, i)
    if lo == 1 and hi == 1:
        return node, i  # 无实际重复，返回原子本身
    return Repeat(node, lo, hi), i


def _parse_concat(pat: str, i: int) -> Tuple[Node, int]:
    """解析连接（直到遇到 ')' 或 '|'）。"""
    items: List[Node] = []
    while i < len(pat) and pat[i] not in ")|":
        node, i = _parse_repeat(pat, i)
        items.append(node)
    if not items:
        # 空连接 → 匹配空串
        return Lit([]), i
    if len(items) == 1:
        return items[0], i
    return Concat(items), i


def _parse_alt(pat: str, i: int) -> Tuple[Node, int]:
    """解析分支（以 '|' 分隔的多个连接）。"""
    first, i = _parse_concat(pat, i)
    options = [first]
    while i < len(pat) and pat[i] == "|":
        node, i = _parse_concat(pat, i + 1)
        options.append(node)
    if len(options) == 1:
        return options[0], i
    return Alt(options), i


def parse(pattern: str) -> Node:
    """把正则模式解析成 AST；多余尾随字符报错。"""
    node, i = _parse_alt(pattern, 0)
    if i != len(pattern):
        raise RegexSyntaxError(f"unexpected trailing characters at position {i}: "
                               f"'{pattern[i:]}'")
    return node


# --------------------------------------------------------------------------- #
# Thompson NFA 构造 + 可序列化 spec
# --------------------------------------------------------------------------- #

@dataclass
class _State:
    """NFA 状态：ε 转移目标列表 + 字符转移边（目标, 区间集合）。"""
    eps: List[int] = field(default_factory=list)
    edges: List[Tuple[int, List[List[int]]]] = field(default_factory=list)


class _Builder:
    """Thompson 构造器：从 AST 递归构造 NFA 状态图。"""

    def __init__(self) -> None:
        self.states: List[_State] = []

    def new_state(self) -> int:
        """新建一个状态并返回其下标。"""
        self.states.append(_State())
        return len(self.states) - 1

    def build(self, node: Node) -> Tuple[int, int]:  # 返回 (start, end)
        """递归构造，返回该子表达式的 (起始状态, 结束状态)。"""
        if isinstance(node, Lit):
            s, t = self.new_state(), self.new_state()
            if node.ranges:
                self.states[s].edges.append((t, node.ranges))
            else:
                self.states[s].eps.append(t)  # 空语言/空匹配 → ε 直连
            return s, t
        if isinstance(node, Repeat):
            return self._build_repeat(node)
        if isinstance(node, Concat):
            # 连接：把相邻子表达式的 end → next.start 用 ε 连起来
            sub = [self.build(it) for it in node.items]
            for (_, a_end), (b_start, _) in zip(sub, sub[1:]):
                self.states[a_end].eps.append(b_start)
            return sub[0][0], sub[-1][1]
        if isinstance(node, Alt):
            # 分支：新起 s/t，把每个分支并联在 s→...→t 之间
            s, t = self.new_state(), self.new_state()
            for opt in node.options:
                os, oe = self.build(opt)
                self.states[s].eps.append(os)
                self.states[oe].eps.append(t)
            return s, t
        raise RegexSyntaxError(f"unknown AST node {type(node).__name__}")

    def _build_repeat(self, node: Repeat) -> Tuple[int, int]:
        """把 Repeat 展开为「lo 次必选 + (hi-lo) 次可选」或「lo 次必选 + 星号」。
        无上界时用星号做尾部，避免爆炸式展开。"""
        lo, hi = node.min, node.max
        if hi is None:  # 无界尾部
            required = self._concat_count(node.child, lo)
            tail = self._build_star(node.child)
            return self._chain(required + [tail])
        # 有限次数：lo 个必选 + (hi-lo) 个可选
        parts = self._concat_count(node.child, lo)
        parts += [self._build_optional(node.child) for _ in range(hi - lo)]
        return self._chain(parts)

    def _concat_count(self, child: Node, n: int) -> List[Tuple[int, int]]:
        """构造 child 的 n 份副本（各自独立的 NFA 片段）。"""
        return [self.build(child) for _ in range(n)]

    def _build_star(self, child: Node) -> Tuple[int, int]:
        """星号（0 次或多次）：s --ε--> child 和 t；child.end --ε--> child.start 和 t。"""
        cs, ce = self.build(child)
        s, t = self.new_state(), self.new_state()
        self.states[s].eps += [cs, t]
        self.states[ce].eps += [cs, t]
        return s, t

    def _build_optional(self, child: Node) -> Tuple[int, int]:
        """可选（0 次或 1 次）：s --ε--> child 和 t；child.end --ε--> t。"""
        cs, ce = self.build(child)
        s, t = self.new_state(), self.new_state()
        self.states[s].eps += [cs, t]
        self.states[ce].eps.append(t)
        return s, t

    def _chain(self, frags: List[Tuple[int, int]]) -> Tuple[int, int]:
        """把多个 NFA 片段按顺序用 ε 串联。"""
        if not frags:
            return self._build(Lit([]))
        for (_, a_end), (b_start, _) in zip(frags, frags[1:]):
            self.states[a_end].eps.append(b_start)
        return frags[0][0], frags[-1][1]


def compile_pattern(pattern: str) -> dict:
    """把 ``pattern`` 编译成可序列化的 NFA spec 字典（即跨层契约）。"""
    ast = parse(pattern)
    b = _Builder()
    start, end = b.build(ast)
    return {
        "start": start,
        "accept": [end],
        "states": [
            {
                "eps": st.eps,
                "edges": [{"to": to, "ranges": rs} for to, rs in st.edges],
            }
            for st in b.states
        ],
    }


# --------------------------------------------------------------------------- #
# Pike VM：在 spec 上做无锚点的存在性搜索
# --------------------------------------------------------------------------- #

def _closure_table(spec: dict) -> List[frozenset]:
    """预计算每个状态的 ε-闭包（含自身），加速后续匹配。"""
    n = len(spec["states"])
    table: List[frozenset] = []
    for i in range(n):
        seen: set = set()
        stack = [i]
        while stack:
            s = stack.pop()
            if s in seen:
                continue
            seen.add(s)
            for e in spec["states"][s]["eps"]:
                stack.append(e)
        table.append(frozenset(seen))
    return table


def _point_in_ranges(cp: int, ranges: List[List[int]]) -> bool:
    """二分查找：码点 cp 是否落在某条（已排序的）区间内。"""
    lo, hi = 0, len(ranges) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        r = ranges[mid]
        if cp < r[0]:
            hi = mid - 1
        elif cp > r[1]:
            lo = mid + 1
        else:
            return True
    return False


def match_search(spec: dict, text: str) -> bool:
    """若 ``text`` 中存在与编译后 NFA 匹配的子串则返回 True
    （无锚点存在性搜索，对应子集上的 ``re.search``）。

    实现要点：每个字符位置都「重新允许从 start 出发」，
    从而覆盖「匹配不从头开始」的情况。
    """
    closure = _closure_table(spec)
    states = spec["states"]
    accept = frozenset(spec["accept"])

    cur = set(closure[spec["start"]])
    if cur & accept:
        return True  # 匹配空前缀
    for ch in text:
        cp = ord(ch)
        nxt = set()
        for s in cur:
            for e in states[s]["edges"]:
                if _point_in_ranges(cp, e["ranges"]):
                    nxt.update(closure[e["to"]])
        nxt.update(closure[spec["start"]])  # 允许在当前字符位置重新开始
        cur = nxt
        if cur & accept:
            return True
    return False


def format_spec(spec: dict) -> str:
    """把 spec 转成紧凑可读字符串，用于调试/日志。"""
    lines = [f"start={spec['start']} accept={spec['accept']}"]
    for i, st in enumerate(spec["states"]):
        lines.append(f"  {i}: eps={st['eps']} "
                     f"edges={[{'to': e['to'], 'n': len(e['ranges'])} for e in st['edges']]}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# 匹配区间（宿主机侧；用于构造脱敏掩码 / 选择性披露）
# --------------------------------------------------------------------------- #

def _anchored_end(spec: dict, closure: List[frozenset], text: str, start: int) -> Optional[int]:
    """若从 ``start`` 处恰好能开始一次匹配，返回「最长」结束下标（开区间）；
    否则返回 None。锚定在 ``start``（不允许中间重新开始）。

    取最长（类贪婪）结束点是为了与 Python ``re.search`` 在该子集上一致，
    并得到脱敏所需的完整掩码区间。
    """
    states = spec["states"]
    accept = frozenset(spec["accept"])
    cur = set(closure[spec["start"]])
    last_accept: Optional[int] = start if (cur & accept) else None
    for i in range(start, len(text)):
        cp = ord(text[i])
        nxt = set()
        for s in cur:
            for e in states[s]["edges"]:
                if _point_in_ranges(cp, e["ranges"]):
                    nxt.update(closure[e["to"]])
        cur = nxt
        if not cur:
            break
        if cur & accept:
            last_accept = i + 1
    return last_accept


def find_spans(spec: dict, text: str) -> List[Tuple[int, int]]:
    """求每个起点的「最左-每起点」匹配区间，并合并（重叠/相邻合并）。

    确定性算法；参考层用它构造脱敏掩码。
    复杂度 O(n^2 * states)，对短响应在链外可接受。
    """
    closure = _closure_table(spec)
    spans: List[Tuple[int, int]] = []
    for start in range(len(text)):
        end = _anchored_end(spec, closure, text, start)
        if end is not None and end > start:
            spans.append((start, end))
    spans.sort()
    merged: List[Tuple[int, int]] = []
    for lo, hi in spans:
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def mask_indices(specs: List[dict], text: str) -> List[int]:
    """返回被任意给定编译后 spec 匹配覆盖的字符下标（排序）。"""
    covered: set = set()
    for spec in specs:
        for lo, hi in find_spans(spec, text):
            covered.update(range(lo, hi))
    return sorted(covered)


def anchored_full_match(spec: dict, text: str, start: int, end: int) -> bool:
    """``text[start:end]`` 是否「完整」匹配该模式（两端锚定）且至少消耗 1 个字符。

    用于在电路内校验脱敏区间：被掩码的区域必须是真实匹配，而非任意文本。
    """
    if start < 0 or end > len(text) or start >= end:
        return False
    closure = _closure_table(spec)
    states = spec["states"]
    accept = frozenset(spec["accept"])
    cur = set(closure[spec["start"]])
    if cur & accept:
        return False  # 会是空匹配；区间必须消耗 >= 1 个字符
    for i in range(start, end):
        cp = ord(text[i])
        nxt = set()
        for s in cur:
            for e in states[s]["edges"]:
                if _point_in_ranges(cp, e["ranges"]):
                    nxt.update(closure[e["to"]])
        cur = nxt
        if not cur:
            return False
    return bool(cur & accept)


def merge_spans(spans: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """排序并合并重叠/相邻的区间。"""
    merged: List[Tuple[int, int]] = []
    for lo, hi in sorted(spans):
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def match_search_naive(spec: dict, text: str) -> bool:
    """朴素参考匹配器（消融实验用）：在每个起点做锚定尝试。
    语义与 ``match_search``（存在性）一致，但复杂度 O(n^2)。"""
    closure = _closure_table(spec)
    if set(closure[spec["start"]]) & set(spec["accept"]):
        return True
    for start in range(len(text)):
        if _anchored_end(spec, closure, text, start) is not None:
            return True
    return False
