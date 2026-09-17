# Real SP1 proofs: wall time, artifact size, peak memory

**量测机器**：24 核 `Intel(R) Core(TM) i7-14650HX`，内存 11.7 GiB （`dxq`，x86_64）。⚠️ 证明耗时随 CPU 走、可行域随内存走，**换机器就是另一张表** —— 所以这张表的每一行都只在这台机器上成立，跨机对照时先对硬件。

语料：`demo`（372 字符，sha256 `6a1a3431efeafa1900a7077d2ac9f4a50dcf23014a1f2128c6f1069cae9806dd…`）。峰值内存由 `/usr/bin/time -v` 量取，**每个点一个独立进程**。

被剔除的 4 段（命中规则，会短路；对「证明耗时」仍是有效点，对「最坏情况成本」不可用）：
- `scripts/examples/out/all/anchor/zk_private/vectors.json/vectors[0]/response` —— kw: ['exploit']；pat2: sk-[A-Za-z0-9]{16,}
- `scripts/examples/out/cert_private/vectors.json/vectors[0]/response` —— pat2: sk-[A-Za-z0-9]{16,}
- `scripts/examples/out/private/vectors.json/vectors[0]/response` —— kw: ['doxxing']；pat: [\w.+-]+@[\w-]+\.[\w.]+
- `scripts/examples/finance_agent_reply.txt` —— pat2: sk-[A-Za-z0-9]{16,}

| length | rules | mode | prover env | time (s) | proof (KiB) | peak RSS (MiB) | verified | passed |
|---:|---:|:--|:--|---:|---:|---:|:--|:--|
| 200 | 3 | core | （默认） | 57.2 | — | — | — | 被 SIGKILL 杀（本机内存不足，OOM） |
| 20000 | 1 | core | （默认） | 62.18 | — | — | — | 被 SIGKILL 杀（本机内存不足，OOM） |
| 200 | 3 | core | NUM_CORE_WORKERS=1 CORE_BUFFER_SIZE=1 | 160.06 | 2730.1 | 10763.8 | yes | True |
| 20000 | 1 | core | NUM_CORE_WORKERS=1 CORE_BUFFER_SIZE=1 | 131.04 | — | — | — | 被 SIGKILL 杀（本机内存不足，OOM） |

## 解读：这份结果自己这几行

**4 行里 1 行成功、3 行被 OOM 杀**（2 个采样点 × 2 个臂）。唯一成功的那一条峰值常驻 10,764 MB。

- `(200, 3)` [core]　⚠️ **两臂结论相反**
    - `（默认）` —— ✗ OOM，死在第 57 s
    - `NUM_CORE_WORKERS=1 CORE_BUFFER_SIZE=1` —— ✓ 160.1 s / 10,764 MB
- `(20000, 1)` [core]
    - `（默认）` —— ✗ OOM，死在第 62 s
    - `NUM_CORE_WORKERS=1 CORE_BUFFER_SIZE=1` —— ✗ OOM，死在第 131 s

⚠️ **这里不写边界结论，而且本文件的价值恰恰在于不能写。** 两臂之间**只有 prover 选项不同**（同一台机器、同一轮、同一份语料），所以同一个点上的两种答案，差别只能归给旋钮。但它**仍然不是边界表**：点集是**挑出来**的悬崖点、不是整张矩阵，成功的那几行还都是在**非默认**选项下量到的。

⇒ 要读边界本身，看 [`proofs.md`](proofs.md)；要读这条边界怎么随旋钮挪，看 [`prover_knobs.md`](prover_knobs.md)；本文件只对上表这几行负责。

## 另见：这张表自己是哪一档

本文件是**同一份语料上的 prover 选项 A/B**，两臂之间只有 `SP1_WORKER_*` 不同 —— 所以同一个点上的两种答案，差别只能归给旋钮，归不给语料，也归不给机器。它回答的是「**那条固定地板压下去之后，哪些点能过**」，不是边界。

⇒ 地板本身压不压得动、压了多少、哪一半在起作用，见 [`prover_knobs.md`](prover_knobs.md)；**默认选项**下的完整采样矩阵与由它推出来的边界，见 [`proofs.md`](proofs.md)。三张表**口径各不相同（默认矩阵 / 默认旋钮实验 / 旋钮 A/B），不要混读**，也不要把本文件的行拿去改默认表。
