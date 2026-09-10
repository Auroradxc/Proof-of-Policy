"""A minimal regex -> NFA engine (reference layer for Proof-of-Policy).

Why: ``pattern_block`` constraints must be judged *identically* by the Python
reference evaluator and the SP1 (Rust, no_std) program. Python's ``re`` is not
reproducible in the zkVM, so patterns are compiled to a **serializable NFA**
that both sides interpret. This module is the single compiler + a Pike-VM
simulator used as the reference semantics.

Supported subset (fail fast on anything else):
  - literals and escaped punctuation / control escapes (``\\n`` ``\\t`` ...)
  - ``.``  any char except ``\\n``
  - character classes ``[...]`` with ranges and ``\\w \\d \\s``, negation ``[^...]``
  - class escapes ``\\w \\W \\d \\D \\s \\S`` (ASCII semantics, see below)
  - groups ``( ... )`` and alternation ``|``
  - quantifiers ``*  +  ?  {m}  {m,}  {m,n}``
  - NOT supported (raises ``RegexSyntaxError``): anchors ``^ $``, backrefs,
    lookaround, lazy/greedy distinction, ``\\b``.

ASCII semantics note: ``\\w \\d \\s`` here mean ASCII
``[A-Za-z0-9_]`` / ``[0-9]`` / ``[ \\t\\n\\r\\f\\v]``. This matches Python's
``re`` on ASCII input (the intended domain) but not on non-ASCII letters;
documented divergence, same as Phase 1.

Serialized NFA ``spec`` (the ConstraintSpec contract):

    {"start": int,
     "accept": [int, ...],
     "states": [
        {"eps": [int, ...],
         "edges": [{"to": int, "ranges": [[lo, hi], ...]}, ...]},   # inclusive
        ...
     ]}
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union

MAX_CP = 0x10FFFF
ANY_EXCEPT_NL = [[0, 9], [11, MAX_CP]]  # "." (re.search: dot does not match \\n)

_WS_RANGES = [[9, 13], [32, 32]]  # \t \n \v \f \r + space
_DIGIT_RANGES = [[48, 57]]
_WORD_RANGES = [[48, 57], [65, 90], [95, 95], [97, 122]]


class RegexSyntaxError(ValueError):
    """Raised when a pattern uses constructs outside the supported subset."""


def _complement(ranges: List[List[int]]) -> List[List[int]]:
    """Complement of the given inclusive ranges within [0, MAX_CP]."""
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
# AST
# --------------------------------------------------------------------------- #

@dataclass
class Lit:
    ranges: List[List[int]]


@dataclass
class Concat:
    items: List["Node"]


@dataclass
class Alt:
    options: List["Node"]


@dataclass
class Repeat:
    child: "Node"
    min: int
    max: Optional[int]  # None == unbounded


Node = Union[Lit, Concat, Alt, Repeat]


def _class_escape(name: str) -> List[List[int]]:
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
    """Parse a ``[...]`` class starting at pat[i]=='['. Returns (ranges, i) where i
    is index just past ']'. Caller must have confirmed pat[i] == '['."""
    i += 1  # skip '['
    negate = False
    if i < len(pat) and pat[i] == "^":
        negate = True
        i += 1
    parts: List[List[List[int]]] = []
    while i < len(pat):
        c = pat[i]
        if c == "]" and parts:
            i += 1
            ranges = _merge(parts)
            if negate:
                ranges = _complement(ranges)
            return ranges, i
        if c == "\\":
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
    if i >= len(pat):
        raise RegexSyntaxError("unexpected end of pattern")
    c = pat[i]
    if c == "(":
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
            # \d \w \s handled above; anything else alphanumeric (e.g. \1, \b,
            # \A) is not part of the supported subset.
            raise RegexSyntaxError(f"unsupported escape '\\{nxt}' at position {i}")
        # identity escape for punctuation: treat the char literally
        return Lit([[ord(nxt), ord(nxt)]]), i + 2
    if c in "|)*+?{^$":
        raise RegexSyntaxError(f"unexpected '{c}' at position {i}")
    return Lit([[ord(c), ord(c)]]), i + 1


def _parse_quantifier(pat: str, i: int) -> Tuple[Tuple[int, Optional[int]], int]:
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
    node, i = _parse_atom(pat, i)
    (lo, hi), i = _parse_quantifier(pat, i)
    if lo == 1 and hi == 1:
        return node, i
    return Repeat(node, lo, hi), i


def _parse_concat(pat: str, i: int) -> Tuple[Node, int]:
    items: List[Node] = []
    while i < len(pat) and pat[i] not in ")|":
        node, i = _parse_repeat(pat, i)
        items.append(node)
    if not items:
        # empty concat -> matches empty string
        return Lit([]), i
    if len(items) == 1:
        return items[0], i
    return Concat(items), i


def _parse_alt(pat: str, i: int) -> Tuple[Node, int]:
    first, i = _parse_concat(pat, i)
    options = [first]
    while i < len(pat) and pat[i] == "|":
        node, i = _parse_concat(pat, i + 1)
        options.append(node)
    if len(options) == 1:
        return options[0], i
    return Alt(options), i


def parse(pattern: str) -> Node:
    node, i = _parse_alt(pattern, 0)
    if i != len(pattern):
        raise RegexSyntaxError(f"unexpected trailing characters at position {i}: "
                               f"'{pattern[i:]}'")
    return node


# --------------------------------------------------------------------------- #
# Thompson NFA construction + serializable spec
# --------------------------------------------------------------------------- #

@dataclass
class _State:
    eps: List[int] = field(default_factory=list)
    edges: List[Tuple[int, List[List[int]]]] = field(default_factory=list)


class _Builder:
    def __init__(self) -> None:
        self.states: List[_State] = []

    def new_state(self) -> int:
        self.states.append(_State())
        return len(self.states) - 1

    def build(self, node: Node) -> Tuple[int, int]:  # (start, end)
        if isinstance(node, Lit):
            s, t = self.new_state(), self.new_state()
            if node.ranges:
                self.states[s].edges.append((t, node.ranges))
            else:
                self.states[s].eps.append(t)  # empty-language or empty-match
            return s, t
        if isinstance(node, Repeat):
            return self._build_repeat(node)
        if isinstance(node, Concat):
            sub = [self.build(it) for it in node.items]
            for (_, a_end), (b_start, _) in zip(sub, sub[1:]):
                self.states[a_end].eps.append(b_start)
            return sub[0][0], sub[-1][1]
        if isinstance(node, Alt):
            s, t = self.new_state(), self.new_state()
            for opt in node.options:
                os, oe = self.build(opt)
                self.states[s].eps.append(os)
                self.states[oe].eps.append(t)
            return s, t
        raise RegexSyntaxError(f"unknown AST node {type(node).__name__}")

    def _build_repeat(self, node: Repeat) -> Tuple[int, int]:
        lo, hi = node.min, node.max
        if hi is None:  # unbounded tail
            required = self._concat_count(node.child, lo)
            tail = self._build_star(node.child)
            return self._chain(required + [tail])
        # finite
        parts = self._concat_count(node.child, lo)
        parts += [self._build_optional(node.child) for _ in range(hi - lo)]
        return self._chain(parts)

    def _concat_count(self, child: Node, n: int) -> List[Tuple[int, int]]:
        return [self.build(child) for _ in range(n)]

    def _build_star(self, child: Node) -> Tuple[int, int]:
        cs, ce = self.build(child)
        s, t = self.new_state(), self.new_state()
        self.states[s].eps += [cs, t]
        self.states[ce].eps += [cs, t]
        return s, t

    def _build_optional(self, child: Node) -> Tuple[int, int]:
        cs, ce = self.build(child)
        s, t = self.new_state(), self.new_state()
        self.states[s].eps += [cs, t]
        self.states[ce].eps.append(t)
        return s, t

    def _chain(self, frags: List[Tuple[int, int]]) -> Tuple[int, int]:
        if not frags:
            return self._build(Lit([]))
        for (_, a_end), (b_start, _) in zip(frags, frags[1:]):
            self.states[a_end].eps.append(b_start)
        return frags[0][0], frags[-1][1]


def compile_pattern(pattern: str) -> dict:
    """Compile ``pattern`` into a serializable NFA spec dict (the contract)."""
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
# Pike VM: unanchored existence search over the spec
# --------------------------------------------------------------------------- #

def _closure_table(spec: dict) -> List[frozenset]:
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
    """True iff ``text`` contains a substring matching the compiled NFA
    (unanchored existence search, mirroring ``re.search`` on the subset)."""
    closure = _closure_table(spec)
    states = spec["states"]
    accept = frozenset(spec["accept"])

    cur = set(closure[spec["start"]])
    if cur & accept:
        return True  # matches empty prefix
    for ch in text:
        cp = ord(ch)
        nxt = set()
        for s in cur:
            for e in states[s]["edges"]:
                if _point_in_ranges(cp, e["ranges"]):
                    nxt.update(closure[e["to"]])
        nxt.update(closure[spec["start"]])  # allow a fresh start at this position
        cur = nxt
        if cur & accept:
            return True
    return False


def format_spec(spec: dict) -> str:
    """Compact human-readable spec for debugging / logging."""
    lines = [f"start={spec['start']} accept={spec['accept']}"]
    for i, st in enumerate(spec["states"]):
        lines.append(f"  {i}: eps={st['eps']} "
                     f"edges={[{'to': e['to'], 'n': len(e['ranges'])} for e in st['edges']]}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Match spans (host-side; used to build redaction masks / selective disclosure)
# --------------------------------------------------------------------------- #

def _anchored_end(spec: dict, closure: List[frozenset], text: str, start: int) -> Optional[int]:
    """If a match can start exactly at ``start``, return the *longest* end index
    (exclusive); otherwise None. Anchored at ``start`` (no fresh starts).

    Longest (greedy-like) end matches Python's ``re.search`` for the supported
    subset and yields the full masked span for redaction.
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
    """Leftmost-per-start match spans, merged (overlapping/adjacent joined).

    Deterministic; used by the reference layer to build redaction masks.
    O(n^2 * states) — acceptable off-circuit for short responses.
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
    """Sorted char indices covered by any match of the given compiled specs."""
    covered: set = set()
    for spec in specs:
        for lo, hi in find_spans(spec, text):
            covered.update(range(lo, hi))
    return sorted(covered)


def anchored_full_match(spec: dict, text: str, start: int, end: int) -> bool:
    """True iff ``text[start:end]`` *fully* matches the pattern (both ends
    anchored) and consumes at least one char. Used to validate redaction spans
    in-circuit: a masked region must be a genuine match, not arbitrary text."""
    if start < 0 or end > len(text) or start >= end:
        return False
    closure = _closure_table(spec)
    states = spec["states"]
    accept = frozenset(spec["accept"])
    cur = set(closure[spec["start"]])
    if cur & accept:
        return False  # would be an empty match; spans must consume >= 1 char
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
    """Sort and merge overlapping/adjacent spans."""
    merged: List[Tuple[int, int]] = []
    for lo, hi in sorted(spans):
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged
