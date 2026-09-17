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

from bisect import bisect_right
from dataclasses import dataclass, field
from functools import lru_cache
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


#: 一条规则的 pattern 会被**反复**编译：``evaluate.check`` 每次判定都重编一遍，
#: 流式路径每采样点再各判一次。实测每次编译 ~22 µs，占 ``check()`` 中位耗时的
#: 约四分之一，而同一个 pattern 编出来的 NFA 逐字节相同 —— 纯重复劳动。
#: 上界取 4096：策略包的 pattern 总数是常数级（7 个包合计不到 40 条），
#: 这个数是为了挡住「有人拿它做逐请求的正则编译」这种用法撑爆内存。
_PATTERN_CACHE_SIZE = 4096


class _CompiledPattern(dict):
    """编译好的 NFA spec：**行为上与普通 dict 完全相同**，只多挂两份记忆表
    （``closure_memo`` 是 ε-闭包表，``trans_memo`` 是匹配用的转移表，见
    :func:`_transition_table`）。二者都是**纯派生量**，不进 dict 内容。

    为什么要子类化：``_closure_table`` 需要一个「跟着 spec 走」的记忆位置，而 spec
    是 dict（不可哈希、不可弱引用）。三条替代路都更差 ——

    * 按 ``id(spec)`` 建全局表，必须**强引用**住 spec 才防得住 id 复用 ⇒ 只增不减；
    * 按内容算哈希键，构键成本与闭包表本身同量级 ⇒ 白忙；
    * 往 dict 里塞一个 ``"_closure"`` 键 ⇒ **改变了规范字节**，而这份 spec 就是
      跨层契约，``policy_hash`` 会跟着变。

    代价是 ``type(spec) is dict`` 变成 False（全仓库没有这种写法，``isinstance``
    不受影响）；``json.dumps`` / ``==`` / 迭代 / 下标都是 dict 语义，逐字节相同。
    这一点由 ``tests/test_nfa_cache.py`` 对着规范文本钉死。
    """

    __slots__ = ("closure_memo", "trans_memo")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.closure_memo: Optional[List[frozenset]] = None
        self.trans_memo: Optional[Tuple] = None


@lru_cache(maxsize=_PATTERN_CACHE_SIZE)
def compile_pattern(pattern: str) -> dict:
    """把 ``pattern`` 编译成可序列化的 NFA spec 字典（即跨层契约）。

    ⚠️ **返回值是共享的、只读的**（带缓存）。同一份 ``pattern`` 只会编译一次，
    之后每次都返回**同一个对象**。所有消费者（``match_search`` / ``find_spans`` /
    ``anchored_full_match`` / ``mask_indices`` / 规范序列化）都只读，这才使得共享
    是安全的 —— 谁要是就地改它，改的就不只是自己手里那份。这条前提由
    ``tests/test_nfa_cache.py::TestCachedSpecIsReadOnly`` 钉住：那组用例把四个
    消费者跑一遍，再与「新鲜编译」的结果比，谁动了缓存当场红。

    ⚠️ 也**不要把它拿去改完当新 spec 用** —— 需要变体就 ``copy.deepcopy``。
    """
    ast = parse(pattern)
    b = _Builder()
    start, end = b.build(ast)
    return _CompiledPattern({
        "start": start,
        "accept": [end],
        "states": [
            {
                "eps": st.eps,
                "edges": [{"to": to, "ranges": rs} for to, rs in st.edges],
            }
            for st in b.states
        ],
    })


# --------------------------------------------------------------------------- #
# Pike VM：在 spec 上做无锚点的存在性搜索
# --------------------------------------------------------------------------- #

def _build_closure_table(spec: dict) -> List[frozenset]:
    """现算每个状态的 ε-闭包（含自身）。**无缓存**的实际计算。"""
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


def _closure_table(spec: dict) -> List[frozenset]:
    """每个状态的 ε-闭包（含自身），加速后续匹配。

    结果缓存在 spec **自己身上**（``_CompiledPattern.closure_memo``）：闭包只取决于
    spec 的结构，而 spec 是编译产物、调用方只读。实测这一步占 ``check()`` 中位耗时
    约 8%（6.9 µs / 83 µs），缓存后降到一次属性读取。

    **普通 dict 不缓存**（手工构造的 spec 照旧每次现算）—— 不为了性能去改动
    对外的行为面；而 ``_CompiledPattern`` 是我们自己造的、只读的，缓存它才安全。
    """
    memo = getattr(spec, "closure_memo", None)
    if memo is not None:
        return memo
    table = _build_closure_table(spec)
    if isinstance(spec, _CompiledPattern):
        spec.closure_memo = table
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


def _transition_table(spec: dict) -> Tuple:
    """匹配用的转移表：每个状态一行，行内每条边一项 ``(starts, ends, 闭包)``。

    ``match_search`` 的最内层是「对 ``cur`` 里每个状态、每条边，问一句
    ``cp`` 落不落在它的区间里」。原先那里直接调 :func:`_point_in_ranges`：一个
    **Python 写的**二分（每次 3–4 轮解释器循环），外加 ``states[s]["edges"]``
    的逐次 dict 查找。两者都在按 (状态, 边, 字符) 计的粒度上跑 —— 实测
    ``pii_redaction_v1`` 的流式路径上，``_point_in_ranges`` 独占总耗时的 42%
    （504 万次调用 / 1.56 s）。

    这里把边**预先解包**成两个平行的已排序数组，查询换成 C 级的
    :func:`bisect.bisect_right`。语义与逐边调 ``_point_in_ranges`` **逐字相同**：
    每条边照旧单独判一次，命中的边把其目标的闭包并进来。

    ⚠️ **不做「把同状态的多条边合并成一张表」那种更省的优化**：那要求边与边、
    区间与区间两两不交，而「当前 8 条 pattern 恰好都不相交」是**巧合，不是契约**
    （本仓的老话：「恰好」不是契约）。这里只做等价变形。

    同理，**区间的排序与两两不交也照旧是前提**（``_point_in_ranges`` 的 docstring
    早就写着「已排序的」）：一条边只要不是「已排序且两两不交」，这一项的
    ``starts`` 就是 ``None``，循环里退回逐条 ``_point_in_ranges`` —— 于是对手工
    构造的 spec，新旧行为**依然**逐字相同（两边都错得一样，而不是一边悄悄"修好"）。

    缓存与 :func:`_closure_table` 同款：只挂在 ``_CompiledPattern`` 上
    （``trans_memo``）；手工构造的普通 dict 每次现算。
    """
    memo = getattr(spec, "trans_memo", None)
    if memo is not None:
        return memo
    closure = _closure_table(spec)
    table: List[Tuple] = []
    for st in spec["states"]:
        rows = []
        for e in st["edges"]:
            rs = e["ranges"]
            if any(rs[i][1] >= rs[i + 1][0] for i in range(len(rs) - 1)):
                rows.append((None, rs, closure[e["to"]]))   # 退回逐条二分
            else:
                rows.append(([r[0] for r in rs], [r[1] for r in rs], closure[e["to"]]))
        table.append(tuple(rows))
    table = tuple(table)
    if isinstance(spec, _CompiledPattern):
        spec.trans_memo = table
    return table


def match_search(spec: dict, text: str) -> bool:
    """若 ``text`` 中存在与编译后 NFA 匹配的子串则返回 True
    （无锚点存在性搜索，对应子集上的 ``re.search``）。

    实现要点：每个字符位置都「重新允许从 start 出发」，
    从而覆盖「匹配不从头开始」的情况。
    """
    closure = _closure_table(spec)
    rows = _transition_table(spec)
    accept = frozenset(spec["accept"])
    start_closure = closure[spec["start"]]

    cur = set(start_closure)
    if not cur.isdisjoint(accept):
        return True  # 匹配空前缀
    for ch in text:
        cp = ord(ch)
        # 「允许在当前字符位置重新开始」这一条用**初始值**表达，而不是算完再并一次：
        # 并集与顺序无关，集合也没有顺序，所以结果逐元素相同 —— 少的是一次
        # 集合合并（每个字符一次，正是热路径）。
        nxt = set(start_closure)
        for s in cur:
            for starts, ends, cl in rows[s]:
                if starts is None:
                    hit = _point_in_ranges(cp, ends)
                else:
                    i = bisect_right(starts, cp) - 1
                    hit = i >= 0 and cp <= ends[i]
                if hit:
                    nxt.update(cl)
        cur = nxt
        if not cur.isdisjoint(accept):
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
