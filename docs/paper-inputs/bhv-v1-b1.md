# BHV 论文输入索引（P，2026-11-01）

> 用途：把 `paper/tdsc-paper.tex` §3–§7 里每一个新数字/每张新表指回结果文件或证明底稿。
> 全部路径均在提交 `c78ca67` 上存在；标 **pending** 的项没有结果文件，正文已留
> `\need{BLOCKER ...}`，不得补数。
>
> **2026-11-01 P 最终修订（`bhv/p-final`，基线 `1c1fc60`）更正**：§3/§5 的
> 「X1 云机仍用 pre-NFA-fix binary」已过时。X1c/X1d 云机实测
> binary `7f99fdb1…`、policy vkey `0x003eb14d…`，即 **post-NFA-fix**；
> groth16 已交付并验证（EU AI Act 301.19 s / 30.07 GB / 1,874 B，verify PASS）。
> 论文 §V-C 已改为 90 GiB cgroup 的 16/18 点矩阵；X2/E1/E2/E3 的数字也已落入
> §4–§7。E6（logprobs）与 C2（电路级 coarsening）仍 pending。

## 1. 定理与定义

| 论文位置 | 内容 | 来源 |
|---|---|---|
| §III-B Def. 1 / Prop. 1 | 猜测熵、条件性三难、PV-1/PV-2、带密钥 β | `docs/proofs/theorem-a-b.md` §1–§2 |
| §III-C Thm. 2 / 表 `tab:regimes` | 泄漏剖面、三个 regime | `docs/proofs/theorem-a-b.md` §3；`docs/sp1-zk-audit.md` §2–§4 |
| §III-D Def. 2 / Thm. 3 | D-privacy（固定同一 `T`）、五步混合 | `docs/proofs/theorem-d-g.md` §2–§6 |
| §III-D 带盐构造 | `policy_nonce` 128 bit、规范字节 | `docs/proofs/theorem-d-g.md` §6；`policydsl/privacy/policy_commit.py` |
| §III-E Thm. 4 | 交付绑定 `|S|·c·2^{-f}`、`f=0` | `docs/proofs/theorem-c-e-f.md` §1；`docs/certificate-binding-framework.md` §6 |
| §VII-E Prop. 5 | 组合五条件 | `docs/proofs/theorem-c-e-f.md` §2.1–§2.3 |

## 2. 实验数字

| 论文位置 | 数字 / 表 | 结果文件 | 状态 |
|---|---|---|---|
| §IV-B 表 `tab:policy-infer` | L0 .810/.840/3.445/1.000；L1 .113/.313/.940/.405；L2 .073/.220/.216/.000 | `bench/results/policy_infer.md` | measured |
| §V-B 表 `tab:ablation` | 643,894 / 12,382,720 / 19.2×；… 90.1× | `bench/results/ablation.md` | measured |
| §V-B 表 `tab:dos` | pike n=100 122.2 s / 11,695 MiB；naive n=25 153.2 s / 12,137 MiB；naive n=50 OOM 226.5 s / 13,772 MiB | `bench/results/dos_proof.md` | measured；**pre-NFA-fix binary** |
| §V-C 表 `tab:proofs` | 118.9–172.5 s、2.65–2.66 MiB、10.3 GiB floor、OOM 行 | `bench/results/proofs.md` | measured（`core`）；**pre-NFA-fix binary / old vkey** |
| §V-D 表 `tab:compose` | 四格 (a)–(d)；cell (c) 弱形式 | `bench/results/composition_controls.md` | measured |
| §V-E 表 `tab:gateway` | 0.094 / 0.844 / 10.165 ms；2-of-3 981 B；电路内 blocked | `bench/results/gateway_sig.md` | measured + blocked |
| §V-F 表 `tab:baselines` | 49 格，`[m]`/`[c]` 逐格标注 | `bench/results/baselines.md` | measured/cited |
| §V-G 表 `tab:issuance` | 0.9948 vs 0.0000；99% 检出 m 表 | `bench/results/issuance.md` | measured |
| §V-H | 14 证书、19/19 交叉验证 | `bench/results/compose.md`、`bench/results/verify.md` | measured |

## 3. 仍 pending（正文为 `\need{BLOCKER}`）

| 项 | 缺什么 | blocker |
|---|---|---|
| groth16 / plonk 档、ZK 交叉点 | 任何周期/时间/内存数字 | X1：云机 ≥16 GB；`bench/results/scale-cloud.json` **不存在**。云机 binary 为 **pre-NFA-fix**，其结果必须标该 binary sha256，且不得与新 policy vkey `0x003eb14d…` 同表 |
| 实测猜测熵 `k` | 真实模型多次采样 | X2：真实模型 API/权重 |
| 组合成本、"推理证明主导" | 真实模型规模 | WP4-(2)/WP3 |
| 引文核实 | 作者/页码/出处 | WP8 |
| 作者与资助信息 | 元数据 | 作者 |

## 4. 非数字类来源

| 主题 | 来源 |
|---|---|
| `core` 非 ZK、`opened_values` 明文 | `docs/sp1-zk-audit.md` §2–§3 |
| 策略披露层级是证书层投影，非电路级 | `docs/blockers/C1.md` |
| E-1（`x_U` 强绑定未落地） | `docs/proofs/theorem-c-e-f.md` §2.7；`bench/results/composition_controls.md` |
| G-1 / V1-2 NFA 语义 bug | **已修复**（Core `9ac2d59`）：空字符类解析期 fail-closed（A-G0 成解析器契约）；`a{0}` 等价 ε；Rust naive 空文本 ε 缺口同步修复。记录见 `docs/blockers/Core.md`（main `9ac2d59`，本隔离 worktree 基于 `c78ca67`，合并后可见）与 `docs/blockers/V1.md`（`b20b055`） |
| 电路内 Ed25519 blocked | `docs/blockers/B1.md`；`bench/results/gateway_sig.md` |
| split-view 未实现、只量化检出 | `docs/blockers/B1.md`；`bench/results/issuance.md` |

## 5. NFA 修复后的工件（2026-11-01，Core `9ac2d59`）

| 工件 | 新值 | 旧值（对照） |
|---|---|---|
| `pop-script` sha256 | `7f99fdb11a4a859c45598c384db3b98dd50426210adbc14d6b576c4d15dda49f` | — |
| guest ELF sha256 | `365ad87c435457dc7b8451db62f75cc87b5caebf4f789e9c7b2e0c9f4c908972` | `840d4eeca6560597dccf287acbe5d58007d19b76e3d6c8e0dd94f6012e2d666b` |
| policy vkey | `0x003eb14de80339bddef2b9207ef27469088267888bb9bebb9836b4ee701fd7be` | `0x0091b406dcaf1ea6605439d4f1379835f0824dfb74f909a3d9930fbfbc9c434b` |
| infer vkey | `0x0068573ee6818fa5069f339230c7d900cf548f58ea5a3dac31bf14f370003d32` | — |
| session vkey | `0x00a633b063f8c3cdae4f3e5fa7bbccb39c1237259442ab9963164ffbd46891c7` | — |

来源：`docs/blockers/Core.md`（main `9ac2d59`）。**X1 云机仍是旧 binary**；
本仓库所有已入库的 proving 数字（`tab:proofs`、`tab:dos`）均为 pre-fix，
正文已按此标注。
