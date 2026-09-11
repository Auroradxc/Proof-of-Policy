"""交叉验证驱动（``scripts/cross_validate.py``）里**不依赖证明器**的那部分。

真实证明本身很贵（每个向量 ~2 分钟、峰值 RSS ~10.3 GB），所以这里只测「怎么切
向量」「块大小怎么读」这些纯逻辑 —— 它们恰恰是原先踩坑的地方：把 14 个向量交给
**一个** ``pop-script`` 进程，会在第 6~7 个证明处被内核 OOM-kill，前面的证明全白
跑。分块是修复手段，因此「切开后顺序不变、不丢不重」必须被锁住。
"""

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import cross_validate  # noqa: E402


class TestVectorChunking(unittest.TestCase):
    """分块纯函数：每块最多 n 个、顺序不变、不丢不重。"""

    def test_splits_into_contiguous_blocks(self):
        items = list(range(14))
        parts = cross_validate.chunked(items, 4)
        self.assertEqual([len(p) for p in parts], [4, 4, 4, 2])
        # 关键性质：拼回去**逐一相等**（顺序不变、不丢不重）
        self.assertEqual([x for p in parts for x in p], items)

    def test_exact_multiple_and_smaller_than_chunk(self):
        self.assertEqual([len(p) for p in cross_validate.chunked(list(range(8)), 4)], [4, 4])
        self.assertEqual(cross_validate.chunked([1, 2], 4), [[1, 2]])

    def test_zero_means_single_process(self):
        # 大内存机器可以恢复「一个进程跑完」；空输入不能凭空造出一个空块
        self.assertEqual(cross_validate.chunked([1, 2, 3], 0), [[1, 2, 3]])
        self.assertEqual(cross_validate.chunked([], 4), [])

    def test_default_chunk_is_conservative(self):
        # 默认值必须**明显小于**实测会 OOM 的 14：本机在 ~6~7 个证明处被 kill，
        # 默认取 4 留出余量。改大它就意味着重新引入 OOM，故在此固定住。
        self.assertEqual(cross_validate.DEFAULT_CHUNK, 4)
        self.assertLess(cross_validate.DEFAULT_CHUNK, 6)


class TestChunkArgParsing(unittest.TestCase):
    """``--chunk`` 的两种写法都要认，缺省回落到默认值。"""

    def test_both_spellings(self):
        self.assertEqual(cross_validate.parse_chunk(["--chunk", "7"]), 7)
        self.assertEqual(cross_validate.parse_chunk(["--chunk=1"]), 1)

    def test_default_and_ignores_unrelated_args(self):
        self.assertEqual(cross_validate.parse_chunk([]), cross_validate.DEFAULT_CHUNK)
        self.assertEqual(cross_validate.parse_chunk(["--no-prove"]),
                         cross_validate.DEFAULT_CHUNK)


if __name__ == "__main__":
    unittest.main()
