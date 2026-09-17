"""入库的基准结果：``.md`` 必须**恰好**是 ``.json`` 渲染出来的那一份。

理由不是洁癖，是这两个文件的分工：

| | 是什么 | 谁写 |
|---|---|---|
| ``bench/results/*.json`` | **数据**（量到的行 + 量测机器 + 口径）| 跑基准时自动落盘 |
| ``bench/results/*.md`` | **视图**（表 + 由数据现推的结论段）| 同一个 ``dump()`` 顺手渲染 |

视图完全由数据决定 —— 这既是个**承诺**，也是个**可以机械检查**的性质。而它一旦
破了，不会有人发现：``.md`` 是给人读的那一份（论文、文档、issue 里引的都是它），
``.json`` 是给机器读的那一份。谁手工改了 ``.md`` 里的一句话（修个措辞、更新一条
结论），下一次重跑基准就**静默**覆盖回去；反过来，只提交 ``.json`` 忘了 ``.md``，
入库的就是过期的表。

**为什么不用「跑一遍基准对拍」来测**：那要真出证十几分钟，还得撞 `proofs.json`
里那几个**故意留着的 OOM 点**。渲染是纯函数（输入 rows/host，输出字符串），
所以这里直接调渲染函数 —— 零成本、无副作用，而红起来的意思完全一样。

**这里查的不是「数字对不对」**：数字是量出来的，本文件造不出它，也没打算造。
查的是「**入库的这份视图，是不是这份数据渲染的那个**」。

新增一份入库结果时，只要在 :data:`VIEWS` 里加一行，下面几条不变量就都盖上了；
``--render-only`` 是配套的渲染入口（不必重跑基准）。
"""

import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "bench"))     # 与 tests/test_ablation.py 同口径

import bench_proofs as bp  # noqa: E402
import bench_prover_knobs as bk  # noqa: E402

RESULTS = REPO / "bench" / "results"

#: ``(名字, 渲染函数, 重渲染命令)``。渲染函数收整个 JSON dict，返回该份数据的
#: ``.md`` 全文；命令是**渲染**这份数据的那个入口（都不跑证明，也因此**不重采数据**）。
VIEWS = [
    ("proofs",
     lambda d: bp.render_md(d["rows"], d["corpus"], d.get("host")),
     "python3 bench/bench_proofs.py --render-only"),
    ("prover_knobs",
     lambda d: bk.render_md(d["rows"], d.get("host"), d["threshold"],
                            bk.is_complete(d["rows"])),
     "python3 bench/bench_prover_knobs.py --render-only"),
    ("prover_knobs_cliff",
     lambda d: bp.render_md(d["rows"], d["corpus"], d.get("host")),
     "python3 bench/bench_proofs.py --render-only "
     "--out bench/results/prover_knobs_cliff.json"),
]


def load(name: str) -> dict:
    path = RESULTS / f"{name}.json"
    if not path.exists():
        raise AssertionError(
            f"{path} 不在库里 —— 这些是**入库的**结果，不是跑完才有的临时产物。"
            "若是新增的基准，请把它连同渲染出的 .md 一起提交。")
    return json.loads(path.read_text(encoding="utf-8"))


class TestViewsAreRendered(unittest.TestCase):
    """每一份入库结果：``.md`` == 该份 JSON 的渲染结果。"""

    def test_md_is_exactly_the_rendered_json(self):
        for name, render, how in VIEWS:
            with self.subTest(view=name):
                data = load(name)
                want = render(data)
                got = (RESULTS / f"{name}.md").read_text(encoding="utf-8")
                self.assertEqual(
                    got, want,
                    f"{name}.md 与 {name}.json 对不上：要么 .md 被手工改过"
                    "（下次重跑基准会静默覆盖），要么只提交了 .json 没提交 .md。"
                    "修法是从数据重渲染（**不要**手工编辑 .md 去迁就它）：\n"
                    f"    {how}")

    def test_the_renderer_would_notice_a_change(self):
        """上一条不是恒真式：改一行数据，渲染结果必须跟着变。

        没有这一条，``render_md`` 若哪天被改成返回常量、或者 ``rows`` 被忽略，
        上面那条也会照绿 —— 那就成了「空集合上全绿」的又一例。
        """
        for name, render, _ in VIEWS:
            with self.subTest(view=name):
                data = load(name)
                rows = [dict(r) for r in data["rows"]]
                ok = [r for r in rows if r.get("ok")]
                self.assertTrue(ok, f"{name}.json 里没有一个成功的点？那上面那条测不出东西")
                ok[0]["peak_rss_mb"] = ok[0]["peak_rss_mb"] + 1
                changed = dict(data, rows=rows)
                self.assertNotEqual(render(changed), render(data),
                                    "改了一行的内存数字，渲染结果纹丝不动 —— "
                                    "说明渲染没在读数据")


class TestKnobsMatrixIsComplete(unittest.TestCase):
    """``prover_knobs`` 那两份文件特有的两条：**跑完了**、**门槛来自数据**。"""

    def test_the_committed_matrix_ran_to_the_end(self):
        """入库的这份**不是中途落盘的那一份**。

        中途落盘与跑完落到同一个文件名上，而两者只差一个结论段：写「一个都没降」
        的判据是拿基线比非默认配置，可中途那几轮里非默认配置根本没量到 ——
        于是半截数据也能渲染出一句**没有根据**的话。所以「跑完了」这件事本身就是
        一条要钉住的不变量。
        """
        rows = load("prover_knobs")["rows"]
        got = sorted({r.get("config") for r in rows})
        self.assertTrue(
            bk.is_complete(rows),
            f"入库的矩阵缺配置，是中途落盘的那一份：量到的是 {got}，"
            f"而完整矩阵是 {[n for n, _ in bk.CONFIGS]}")

    def test_threshold_comes_from_the_json(self):
        """门槛必须**被记进数据**，不能只活在那个脚本的常量里。

        5% 这条判据是**事先**定死的（计划 §2 的 P2 表），所以它属于口径的一部分：
        读者要看的是「当时按什么判的」。它一旦只存在于代码里，改常量就能悄悄改口径，
        而入库的结果文件看不出区别。
        """
        data = load("prover_knobs")
        self.assertAlmostEqual(data["threshold"], 0.05, places=6,
                               msg="门槛变了。若这是有意的，重新生成结果并说明理由")


class TestCliffProbeIsComparable(unittest.TestCase):
    """悬崖复测那份：**同一个点、两臂对照** —— 只有旋钮不同。

    ⚠️ 这里**不再**比 `cliff.json` 与 `proofs.json` 的语料 `sha256`。**那条断言
    要求的是一件永远不成立的事**：`demo` 语料是 `scripts/examples/out/**` 的 glob，
    那些产物会随举例脚本的重跑而生灭（实测两台批次只差两个文件、两份都是 372 字符），
    而这两份结果文件又**天然是不同时候采的** —— 所以它们必然对不上。
    （2026-09-18 实测：`proofs.json` `8381462c…` / `prover_knobs_cliff.json` `6a1a3431…`。）

    更要紧的是：**「同一个语料」这个条件本来就不该跨文件比。** 它要保证的是**两臂
    之间**可比；而两臂现在是**同一次调用、同一份装载好的语料**里跑出来的（`--arms`），
    这件事由构造保证，比任何断言都硬。跨文件比语料，测的其实是「两天的
    `scripts/examples/out/` 一模一样」—— 那是另一个命题，而且是个假命题。

    所以这里只钉那些**跨语料也成立**、且真正承载结论的结构。
    """

    def test_every_point_was_measured_under_every_arm(self):
        """每个采样点都**在每一个臂下各量了一次** —— 否则就配不成对。

        这是本文件存在的理由：`(200, 3)` 的两行必须能并排读。缺了某个臂的那一行的
        话，「换旋钮把它拉回来了」就只是一句没有对照的独白。
        """
        rows = load("prover_knobs_cliff")["rows"]
        arms = {bp.env_str(r) for r in rows}
        self.assertGreater(len(arms), 1,
                           f"只有 {arms} 一个臂 —— 那它不是 A/B，用不上本文件")
        seen: dict[tuple, set] = {}
        for r in rows:
            seen.setdefault((r["length"], r["rules"]), set()).add(bp.env_str(r))
        for point, got in seen.items():
            self.assertEqual(got, arms,
                             f"采样点 {point} 只在 {sorted(got)} 下量过，不是所有臂 "
                             f"{sorted(arms)} —— 配不成对，读不出「只有旋钮不同」")

    def test_the_probed_points_are_the_ones_that_oom_by_default(self):
        """被复测的点，必须是**默认表里标 ✗ OOM 的那几个**。

        这就是这份文件为什么叫 cliff：它只回答「**已经出不来**的点，换个旋钮还行不行」。
        换成一个默认下本来就过得了的点，量的就不是悬崖，而是冗余。
        """
        cliff = load("prover_knobs_cliff")
        proofs = load("proofs")
        self.assertEqual(cliff.get("proof_mode", "core"), proofs.get("proof_mode", "core"),
                         "证明模式不同 —— 那本身就会大幅改变内存占用")
        rows = {(r["length"], r["rules"]) for r in cliff["rows"]}
        oom = {(r["length"], r["rules"]) for r in proofs["rows"] if not r.get("ok")}
        self.assertTrue(rows & oom,
                        f"复测的采样点 {sorted(rows)} 与默认表里 OOM 的点 {sorted(oom)} "
                        "没有交集 —— 那就不是在回答「同一点换个旋钮行不行」")


if __name__ == "__main__":
    unittest.main()
