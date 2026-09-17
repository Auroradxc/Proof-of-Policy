"""跨层**域分隔符**必须逐字节相同（R2）。

域分隔符（domain separator）是「同一个哈希函数在两个不同用途下不互相冒充」这件事
的全部实现：`SHA256("pop-bind-v1" ‖ …)` 与 `SHA256("pop-trace-v1" ‖ …)` 因为前缀
不同，值不会撞上。前缀写错、写少一个字符、两边各写各的 —— 后果不是报错，是
**两侧各自自洽、合起来对不上**：Rust 电路算出 A，Python 参考层算出 B，
而它们都「内部一致」。

**这类漂移最容易被漏掉的地方**：Rust 那一侧只在 `pop-script` 存在时才被跑到，
而单测里那些路径是 `skipUnless(POP_SCRIPT.exists())` —— 缺驱动的机器上全绿。
本文件**不需要 Rust 工具链**：它比对的是**源码里声明的字面量**，所以它进得了
零依赖的那条 CI 通道（`.github/workflows/ci.yml` 的 `tests` job）。

**它能保证什么、不能保证什么**：保证「两份声明写的是同一个串」；不保证「编译
出来的行为」。后者由 `scripts/prove/cross_validate.py`（真跑 Rust）负责 —— 两条
闸门查的是不同层次的东西，都不是对方的替代品。

**为什么用正则读源码而不是 import**：Rust 侧没有可 import 的东西。而且读源码恰好
能覆盖「声明还在不在」这件事 —— 常量被改名或删掉时，正则找不到，测试当场红，
而不是悄悄退化成「没什么可比的，通过」。
"""

import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl.core import normalize  # noqa: E402
from policydsl.evidence import trace  # noqa: E402
from policydsl.privacy import commit  # noqa: E402
from policydsl.proofs import infer, session  # noqa: E402

#: Rust 侧契约类型的唯一出处。域分隔符都在这里声明（`circuits/types/` 一改，
#: 三个 ELF、三个 vkey、已入库的证明工件集体失效 —— 所以它是权威）。
RUST_LIB = REPO / "circuits" / "types" / "src" / "lib.rs"

#: ``pub const NAME: &[u8] = b"…";``
_BYTES_RE = r'pub const {name}\s*:\s*&\[u8\]\s*=\s*b"([^"]*)"\s*;'
#: ``pub const NAME: &str = "…";``
_STR_RE = r'pub const {name}\s*:\s*&str\s*=\s*"([^"]*)"\s*;'
#: ``pub const NAME: &[&str] = &["…", "…"];``
_STRS_RE = r'pub const {name}\s*:\s*&\[&str\]\s*=\s*&\[([^\]]*)\]\s*;'


class _Missing(Exception):
    """源码里找不到那条声明 —— 与「值不一样」是两件事，要分开报。"""


def _source() -> str:
    return RUST_LIB.read_text(encoding="utf-8")


def _search(pattern: str, src: str) -> str:
    m = re.search(pattern, src)
    if m is None:
        raise _Missing(f"`circuits/types/src/lib.rs` 里找不到匹配 {pattern!r} 的声明")
    return m.group(1)


def rust_bytes(const: str, src: str) -> bytes:
    """读 ``pub const <const>: &[u8] = b"…"`` 的字面量（UTF-8 编码回来）。"""
    return _search(_BYTES_RE.format(name=const), src).encode("utf-8")


def rust_str(const: str, src: str) -> str:
    """读 ``pub const <const>: &str = "…"`` 的字面量。"""
    return _search(_STR_RE.format(name=const), src)


def rust_str_list(const: str, src: str) -> list:
    """读 ``pub const <const>: &[&str] = &["…", …]`` 的字面量列表。"""
    body = _search(_STRS_RE.format(name=const), src)
    return re.findall(r'"([^"]*)"', body)


#: ``(Rust 常量名, Python 侧的值, 这份值是什么)`` —— 逐条比对，失败时点名。
#:
#: 每个域前缀都对应一处**真的**哈希：改一处而漏改另一处，两侧就各自自洽地算错。
BYTE_DOMAINS = [
    ("TRACE_DOMAIN", lambda: trace.TRACE_DOMAIN,
     "回执链节点的摘要前缀（P1-5）"),
    ("BIND_DOMAIN", lambda: commit.BIND_DOMAIN,
     "响应绑定的承诺前缀（P0-2）"),
    ("INFER_DOMAIN", lambda: infer.DOMAIN,
     "推理域的域分隔前缀（P1-6；与策略域的 pop-bind-v1 分离）"),
    ("MERKLE_NODE_DOMAIN", lambda: session.MERKLE_NODE_DOMAIN,
     "会话 Merkle 内部节点的摘要前缀（P2-10）"),
]

#: 同一件事的 ``&str`` 形式。两边都声明了，就必须都对齐 —— 只对齐其中一个，
#: 会出现「按字节比的那个对、按字符串比的那个错」这种最难查的形态。
STR_CONSTANTS = [
    ("INFER_DOMAIN_STR", lambda: infer.DOMAIN.decode("utf-8"),
     "INFER_DOMAIN 的 &str 形式（同一个值的两种类型）"),
]

#: 列表形式的版本白名单：Rust 侧用它拒收未知版本，Python 侧用同一个串写进契约。
STR_LISTS = [
    ("FOLD_VERSIONS", lambda: [normalize.FOLD_VERSION],
     "折叠表版本白名单（P2-9b；改它即改 policy_hash）"),
]


class TestCrossLayerConstants(unittest.TestCase):
    """源码级比对：两侧的域分隔符与版本串写的是不是同一个值。"""

    def setUp(self):
        self.src = _source()

    def test_byte_domains_match(self):
        """四个 `&[u8]` 域前缀逐字节相等。"""
        for const, get_py, what in BYTE_DOMAINS:
            with self.subTest(const=const):
                self.assertEqual(
                    get_py(), rust_bytes(const, self.src),
                    f"{const} 在 Rust 与 Python 两侧不是同一个值 —— {what}。"
                    "两侧会各自自洽地算出不同的摘要，而没有任何一处会报错")

    def test_str_constants_match(self):
        """`&str` 形式的常量与 Python 侧对齐（同一件事的另一种类型）。"""
        for const, get_py, what in STR_CONSTANTS:
            with self.subTest(const=const):
                self.assertEqual(get_py(), rust_str(const, self.src),
                                 f"{const} 两侧不一致 —— {what}")

    def test_str_lists_match(self):
        """列表形式的版本白名单逐项相等（顺序也算）。"""
        for const, get_py, what in STR_LISTS:
            with self.subTest(const=const):
                self.assertEqual(get_py(), rust_str_list(const, self.src),
                                 f"{const} 两侧不一致 —— {what}")

    def test_domains_are_distinct(self):
        """这四个前缀两两不同 —— 「域分离」的意思就是它们不相等。

        若哪天有人把两个域合并成同一个前缀，上面逐条比对的断言**可能全部照样通过**
        （只要两边一起改），而域分离本身已经失效了。这一条盯的是它。
        """
        values = [get_py() for _, get_py, _ in BYTE_DOMAINS]
        self.assertEqual(len(values), len(set(values)),
                         f"域前缀出现重复，域分离失效：{values}")

    def test_a_missing_declaration_is_reported_not_ignored(self):
        """**提取器自己也要能失败**：常量被改名/删掉时必须报 `_Missing`。

        没有这一条，`rust_bytes` 找不到声明时若「返回空串」而不是抛错，
        上面三条断言就会拿 `b""` 去比、在改动之后依然全绿。
        """
        with self.assertRaises(_Missing):
            rust_bytes("NO_SUCH_CONST_XYZ", self.src)
        with self.assertRaises(_Missing):
            rust_str_list("NO_SUCH_CONST_XYZ", self.src)
        # 反例对照：同一个提取器在**存在**的声明上正常返回值（证明上一条不是恒真）。
        self.assertEqual(b"pop-trace-v1", rust_bytes("TRACE_DOMAIN", self.src))

    def test_extractor_reads_the_declared_value_not_a_substring(self):
        """提取器认的是**声明**而不是「源码里出现过这个串」。

        合成一份源码喂给它：只有一个 const 声明，但正文里另有一段注释提到别的串。
        必须取到声明里的那个 —— 否则「源码里出现过」就会变成判据，而那是恒真的。
        """
        src = ('// 注释里提到 b"pop-not-this-one"\n'
               'pub const DEMO_DOMAIN: &[u8] = b"pop-demo-v1";\n')
        self.assertEqual(b"pop-demo-v1", rust_bytes("DEMO_DOMAIN", src))


if __name__ == "__main__":
    unittest.main()
