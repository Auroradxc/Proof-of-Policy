"""工件摘要（``sha256_file``）**只有一个口径**，且这个口径没变过。

R5 之前，「对文件字节求 SHA-256」在仓库里写过 **7 份定义 + 1 段内联**：
``proofs/compose.py``、``proofs/multiparty.py``、``runtime/service.py``、
``scripts/prove/issue_cert.py``、``scripts/verify/verify_cert.py``、
``scripts/verify/verify_session.py`` 各一份，加 ``proofs/semantic.py`` 里那份带
缓存的 ``_sha256_of_file``，再加 ``regression_prove.py`` 里 ``driver_fingerprint``
的内联循环。其中 ``service.py`` 那份的 docstring 写的是「与 ``issue_cert.py``
同口径」—— 一句话承认了重复，却没有任何东西保证它**继续**同口径。

**为什么这不是「可读性问题」**：它们摘要的东西（证明工件 ``proof.bin``、公开值
文件、驱动二进制）会进证书的 ``binding.proof_sha256``。出证方算一个值、验证方
另算一个值 —— 两处只要有一处口径变了（换成大写十六进制、多读一行、按文本模式
打开），**两边各自自洽**，证书在第三方手里才验不过。这与 R4 的驱动路径是同一类
事故：抄写得一字不差，所以没有任何基线看得见它。

本文件钉两件事：

1. **口径相同**：分块读（1 MiB）与 ``read_bytes()`` 在块边界两侧给出**同一个**
   摘要 —— 这是「收敛是等效替代」的全部内容，机械证明，不靠读代码；
2. **口径只有一处**：AST 扫全仓，除了申报的例外，谁都不许再定义文件摘要函数，
   也不许再写那段流式读的惯用法。例外逐条申报、条数钉死（对照 R4 的做法）。

``semantic._sha256_of_file`` 与 ``tests/test_regression_prove.py::_sha256`` 是**有意
保留**的两处，理由见各自的申报条目 —— 前者是纯缓存壳（已经委托给唯一出处），
后者是**独立参照**：它验的是生产代码算出来的值，用同一份实现去验就成了自证。
"""

import ast
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl.evidence import cert  # noqa: E402

#: 会被当成「又写了一份文件摘要」的函数名。
DIGEST_HELPER_NAMES = {"sha256_file", "_sha256", "_sha256_of_file", "sha256_of_file",
                       "file_sha256"}

SKIP_DIRS = {".git", "target", "__pycache__", "node_modules", ".venv", "out", ".work"}

#: ── 申报的例外（逐条给理由，条数钉死）──────────────────────────────────────
#:
#: 定义类：名字像文件摘要的那些函数。
DECLARED_HELPER_EXCEPTIONS = {
    # 唯一出处本身。
    "policydsl/evidence/cert.py": ["sha256_file"],
    # **纯缓存壳**：签名里的 mtime_ns/size 是缓存键、不参与计算，函数体只剩
    # 一句 `return sha256_file(path)`。留着它是因为「按 mtime+size 缓存」这个
    # 契约与摘要口径是两件事，而后者已经收走了。
    "policydsl/proofs/semantic.py": ["_sha256_of_file"],
    # **独立参照**，故意不复用生产实现：它验的是 `driver_fingerprint()` 的输出，
    # 用同一份实现去算就成了自己证明自己（本仓对「两处独立算」的用法见
    # test_session.py 与 Rust `pop-types::evaluate` 的对拍）。
    "tests/test_regression_prove.py": ["_sha256"],
}

#: 流式读惯用法（`iter(lambda: fh.read(N), b"")`）的申报例外。
DECLARED_STREAMING_EXCEPTIONS = {
    # 唯一出处本身 —— 收敛后全仓就剩它这一处。
    "policydsl/evidence/cert.py": 1,
    # 见上：测试里的独立参照。
    "tests/test_regression_prove.py": 1,
}

MIN_SCANNED = 100
#: 「真有模块从这个口径取摘要」的下限。
MIN_CALLERS = 8


def _py_files() -> list:
    return [p for p in sorted(Path(REPO).rglob("*.py"))
            if not (SKIP_DIRS & set(p.relative_to(REPO).parts))]


def _streaming_reads(tree: ast.AST) -> int:
    """数出 `iter(lambda: fh.read(N), ...)` 这个惯用法出现几次（按函数归属）。"""
    n = 0
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "iter" and node.args):
            continue
        lam = node.args[0]
        if not isinstance(lam, ast.Lambda):
            continue
        for inner in ast.walk(lam):
            if (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute)
                    and inner.func.attr == "read"):
                n += 1
    return n


def _scan():
    """→ (每个文件里像文件摘要的顶层函数名, 每个文件里的流式读次数)"""
    helpers, streaming = {}, {}
    for p in _py_files():
        rel = str(p.relative_to(REPO))
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"))
        except SyntaxError:
            helpers.setdefault(rel, []).append("<SyntaxError>")
            continue
        names = [n.name for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and n.name in DIGEST_HELPER_NAMES]
        if names:
            helpers[rel] = sorted(names)
        k = _streaming_reads(tree)
        if k:
            streaming[rel] = k
    return helpers, streaming


class TestTheDigestItself(unittest.TestCase):
    """口径本身：分块读 == 一次读尽，且在块的边界两侧都成立。"""

    def _tmp(self, size):
        d = tempfile.TemporaryDirectory()
        p = Path(d.name) / "blob.bin"
        # 内容要随字节变化，否则「只读了第一块」和「读全了」算出来一样
        p.write_bytes(bytes((i * 7 + 3) % 251 for i in range(size)))
        return d, p

    def test_chunked_equals_read_all_bytes_across_the_block_boundary(self):
        """1 MiB 是分块大小，所以边界两侧都要比 —— 差一块或漏一块就只在
        「刚好整除」的那些长度上才看得出来，而那种长度最容易碰巧撞上。"""
        mib = 1 << 20
        for size in (0, 1, mib - 1, mib, mib + 1, 2 * mib + 12345):
            with self.subTest(size=size):
                d, p = self._tmp(size)
                with d:
                    self.assertEqual(cert.sha256_file(p),
                                     hashlib.sha256(p.read_bytes()).hexdigest(),
                                     f"分块读与一次读尽在 {size} 字节上不一致")

    def test_it_is_lowercase_hex(self):
        """小写是契约的一部分：这个值进证书的 binding 字段，改大小写会让
        已入库的证书集体对不上，且两边都「看起来对」。"""
        d, p = self._tmp(64)
        with d:
            got = cert.sha256_file(p)
        self.assertEqual(got, got.lower())
        self.assertRegex(got, r"^[0-9a-f]{64}$")

    def test_it_takes_both_str_and_path(self):
        d, p = self._tmp(32)
        with d:
            self.assertEqual(cert.sha256_file(p), cert.sha256_file(str(p)))

    def test_the_failure_modes_are_unchanged(self):
        """调用方靠异常类型分流（`except OSError` 等），所以收敛不能把
        「文件不存在」变成别的什么。"""
        with self.assertRaises(FileNotFoundError):
            cert.sha256_file(REPO / "no" / "such" / "file.bin")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(IsADirectoryError):
                cert.sha256_file(tmp)


class TestEveryCallerResolvesToOneImplementation(unittest.TestCase):
    """收敛的**等效性**：8 个调用点现在真的是同一个函数对象。"""

    #: (导入用的点分路径, 属性名)。脚本侧要先走 `_bootstrap`。
    CALLERS = [
        ("policydsl.proofs.compose", "sha256_file"),
        ("policydsl.proofs.multiparty", "sha256_file"),
        ("policydsl.runtime.service", "sha256_file"),
        ("scripts.prove.issue_cert", "sha256_file"),
        ("scripts.prove.regression_prove", "sha256_file"),
        ("scripts.verify.verify_cert", "sha256_file"),
        ("scripts.verify.verify_session", "sha256_file"),
    ]

    def test_all_of_them_are_the_same_function_object(self):
        import importlib
        sys.path.insert(0, str(REPO / "scripts"))
        from _bootstrap import bootstrap  # noqa: E402
        bootstrap()  # 与脚本自身走同一条引导（把 5 个脚本组组装进 sys.path）
        for dotted, attr in self.CALLERS:
            with self.subTest(module=dotted):
                mod = importlib.import_module(dotted)
                self.assertIs(getattr(mod, attr), cert.sha256_file,
                              f"{dotted}.{attr} 不是唯一出处那个函数")

    def test_the_kept_cache_wrapper_delegates_and_still_caches(self):
        """`semantic._sha256_of_file` 留下的理由是「缓存」，那就得真的还在缓存，
        且算出来的值与唯一出处一致。"""
        from policydsl.proofs import semantic
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "model.bin"
            p.write_bytes(b"x" * 4096)
            st = p.stat()
            self.assertEqual(semantic._sha256_of_file(str(p), st.st_mtime_ns, st.st_size),
                             cert.sha256_file(p))
            before = semantic._sha256_of_file.cache_info().hits
            semantic._sha256_of_file(str(p), st.st_mtime_ns, st.st_size)
            self.assertEqual(semantic._sha256_of_file.cache_info().hits, before + 1,
                             "同一个 (路径, mtime, size) 第二次没有命中缓存")


class TestOnlyOneImplementation(unittest.TestCase):
    """结构性闸门：除申报的例外外，全仓不许再出现第二份文件摘要。"""

    def test_no_other_module_defines_a_digest_helper(self):
        helpers, _ = _scan()
        self.assertEqual(
            helpers, DECLARED_HELPER_EXCEPTIONS,
            "出现未申报的文件摘要函数（或申报的例外已失效）。新增一律改用 "
            "`from policydsl.evidence.cert import sha256_file`；确有正当理由就把 "
            "名字加进 DECLARED_HELPER_EXCEPTIONS 并写明理由。实测：\n"
            f"{helpers!r}")

    def test_no_other_module_uses_the_streaming_read_idiom(self):
        """名字可以换（`_sha256_of_file` 就换过），但「分块把文件喂给哈希」这个
        惯用法只有一处该有 —— `driver_fingerprint` 当年就是一段**没有名字**的内联
        实现，只扫函数名的话它整条漏掉。"""
        _, streaming = _scan()
        self.assertEqual(
            streaming, DECLARED_STREAMING_EXCEPTIONS,
            "出现未申报的流式读惯用法。实测：\n" + repr(streaming))


class TestTheScanIsNotVacuous(unittest.TestCase):
    """扫不到东西的闸门等于没有闸门。"""

    def test_it_scanned_the_whole_repo(self):
        files = _py_files()
        self.assertGreaterEqual(len(files), MIN_SCANNED, f"只扫到 {len(files)} 个 .py")
        rels = {str(p.relative_to(REPO)) for p in files}
        self.assertIn("policydsl/evidence/cert.py", rels)

    def test_enough_modules_bind_the_name_from_the_authority(self):
        """反向扫描只看「有没有第二处」。再补一个正向下限：确有模块从这里取摘要
        —— 否则把 import 全删光也照样全绿。"""
        n = 0
        for p in _py_files():
            if "from policydsl.evidence.cert import" in p.read_text(encoding="utf-8") \
                    and "sha256_file" in p.read_text(encoding="utf-8"):
                n += 1
        self.assertGreaterEqual(n, MIN_CALLERS, f"只有 {n} 个模块从这里取 sha256_file")

    def test_the_scanner_can_actually_see_a_helper(self):
        """扫描器自身的探针：喂一段**已知**含摘要函数与流式读的源码，它必须报出来。
        （一个认不出东西的扫描器，和没有扫描器在结论上无法区分。）"""
        sample = ast.parse(
            "import hashlib\n"
            "def sha256_file(p):\n"
            "    h = hashlib.sha256()\n"
            "    with open(p, 'rb') as fh:\n"
            "        for blk in iter(lambda: fh.read(1 << 20), b''):\n"
            "            h.update(blk)\n"
            "    return h.hexdigest()\n")
        self.assertEqual([n.name for n in ast.walk(sample)
                          if isinstance(n, ast.FunctionDef)
                          and n.name in DIGEST_HELPER_NAMES], ["sha256_file"])
        self.assertEqual(_streaming_reads(sample), 1)


if __name__ == "__main__":
    unittest.main()
