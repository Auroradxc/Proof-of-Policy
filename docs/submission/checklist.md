# TDSC 投稿清单（M6）

> **基线**：仓库 `1c1fc60`；论文文件 [`paper/tdsc-paper.tex`](../../paper/tdsc-paper.tex)。  
> **原则**：每项要么有可核对的产物，要么明确写 `OPEN` / `BLOCKED`；不编作者、不编 DOI、
> 不编页数、不把「计划」写成「已完成」。  
> **状态图例**：`[x]` 已就绪 · `[ ]` 待办 · `OPEN` 待确认 · `BLOCKED` 有明确阻塞。

---

## 0. 一句话状态

论文正文与 artifact 文档已更新到最新结果口径，但**投稿包本身尚未定稿**：作者/资助/
COI 仍是占位，PDF 未在本机复编（缺 `algorithmic.sty`），Docker 镜像未构建，
Zenodo DOI 未分配，推荐审稿人未填。**当前不可直接提交。**

---

## 1. PDF / LaTeX 源 / 图

| 项 | 状态 | 说明 / 动作 |
|---|---|---|
| 主文件 | `[x]` | [`paper/tdsc-paper.tex`](../../paper/tdsc-paper.tex)，IEEEtran `[10pt,journal,compsoc]` |
| 编译方式 | `[x]` | 两遍 `pdflatex "\def\SKELQUIET{}\input{tdsc-paper.tex}"`（第二遍收交叉引用） |
| 本机复编 | `[ ]` **OPEN / 环境阻塞** | 本机 TeX Live 2026 缺 `algorithmic.sty`，`pdflatex` 在 `\usepackage{algorithmic}` 处停止；需在 M5 环境补包后复编并记录页数 |
| 页数 | `[ ]` **OPEN** | 已记录稿 **16 页**（[`docs/paper-inputs/audit.md`](../paper-inputs/audit.md)、[`docs/plan-m2-m6.md`](../plan-m2-m6.md)）；填写最新数字后可能变化，**以最终 PDF 为准** |
| 页数上限 | `[x]` 规则已核 | TDSC 常规论文 **12 页双栏**（含参考文献与作者简介），最多 **18 页**；超过 12 页按 MOPC 计费。来源：[IEEE CSDL Author Information](https://www.computer.org/csdl/journals/tq/write-for-us/15068) |
| 超长费 | `[ ]` **OPEN** | 若 16 页投稿，超出 12 页 4 页；历史文档记 **$200/页**（约 $800），18 页约 $1,200。**2026 年费率必须在 live author guide 复核**，不要直接引用旧 PDF |
| 图 | `[x]` | 当前正文无 `\includegraphics`，无可分离图源；若 M5 加图，补 PDF/EPS 源与授权 |
| 表 | `[x]` | 全部为 LaTeX `tabular`，无外部图源 |
| 参考文献 | `[x]` 形式 / `[ ]` 内容 | 正文内联 `thebibliography`；当前 **20 个 `\cite{}`**，9 个 `\need{}`、0 个 `\fixme{}`；引文核实在 M5-02 |
| PDF 元数据 | `[ ]` | 标题/作者/关键词需与最终稿一致；嵌入字体；无红色标记 |
| 文件命名 | `[ ]` | 建议 `PoP-TDSC-<version>.pdf` + `PoP-TDSC-source.zip`；按投稿系统要求命名 |

**提交前必须**：

```bash
grep -c '\\need{' paper/tdsc-paper.tex     # 目标 0；若保留，每条有 blocker 且不进 PDF
grep -c '\\fixme{' paper/tdsc-paper.tex    # 目标 0
# 两遍编译，确认 0 error / 0 undefined ref / 页数
```

> 当前 `\need` 里至少包含作者元数据与 X1 条件性标题；这些不能带进 PDF。论文正文的
> 清理是 M5 的职责，M6 不修改 `paper/`。

---

## 2. 作者 / 资助 / 利益冲突

| 项 | 状态 | 说明 |
|---|---|---|
| 作者姓名、顺序、单位 | `[ ]` **OPEN** | `\author{Author Name(s)}` 仍是占位；需全作者确认顺序与拼写 |
| 通讯作者与邮箱 | `[ ]` | 投稿系统与 PDF 脚注一致 |
| ORCID | `[ ]` | 至少通讯作者；Zenodo creators 也要填 |
| 资助声明 | `[ ]` `\<FUNDING\>` | 基金号/项目名；无资助则写 “No external funding” |
| 致谢 | `[ ]` | 不含匿名审稿人姓名；云机/模型提供方按实际写 |
| 利益冲突 | `[ ]` `\<CONFLICT OF INTEREST\>` | 包括与 zkAgent、Proof-of-Guardrail、云厂商、模型厂商的关系；无则明确写 “None” |
| 作者贡献 | `[ ]` | 若期刊要求 CRediT / 贡献声明 |
| AI 工具使用声明 | `[ ]` **OPEN** | 按 IEEE 投稿时的生成式 AI 政策填写；不得把 AI 列为作者 |
| 版权/许可 | `[ ]` | 仓库目前**没有 LICENSE 文件**；Zenodo 的 `license` 仍是占位，上传前必须加 |
| 第三方材料许可 | `[ ]` | XSTest 数据集、Qwen/Mistral 模型、DeepSeek API 条款；确认可再分发的结果字段 |

---

## 3. 推荐 / 回避审稿人

| 项 | 状态 | 说明 |
|---|---|---|
| 推荐审稿人 3–5 名 | `[ ]` **OPEN** | 需姓名、单位、邮箱、研究方向、与本文的关系；优先 ZK/LLM 安全/可复现系统 |
| 回避审稿人 | `[ ]` | 有直接合作/竞争关系者；按投稿系统上限填写 |
| 利益核对 | `[ ]` | 推荐人不得与作者同机构、近 3 年合作者或利益相关 |
| 编辑建议 | `[ ]` | 可建议 AE 方向（安全系统 / 隐私 / 形式化），但不要点名施压 |

> 不要编造审稿人邮箱；找不到合适人选时留 `OPEN`，不要用占位邮箱提交。

---

## 4. 论文内部一致性（M5 交接）

| 项 | 状态 | 说明 |
|---|---|---|
| 标题与交付档一致 | `[ ]` **OPEN** | 当前标题保留 “Zero-Knowledge”，但正文仍写 X1 blocker；最新证据已有 `groth16`（wrapper-only、非后量子）。M5 必须二选一：保留标题并写清 wrapper-only + 3×10k OOM，或改 “Succinct” |
| 摘要数字 | `[ ]` | 摘要仍用 A1 的 0.810→0.073；E2 的新数字（L2 0.382 / 真实 0.112 / L2 可链接）需在 M5 决定是否替换/并列 |
| §5 证明表 | `[ ]` | 当前 Table 6 是 pre-NFA-fix、24 核/12 GB 的旧点；最新 `scale-cloud` / `eu_ai_act_proof` / `scale-6x*` 未进正文 |
| `k` 的 N 截断 | `[ ]` | 若正文报 `k`，必须同时写 N=50/20 的截断上限与「不能证明高熵」；不能把 5.644 bit 写成上界 |
| E2 L2 链接性 | `[ ]` | 若正文报 L2 隐私，必须加入「确定性证据承诺可跨样本链接」与新数字，不能只写 count-only |
| A11 demote | `[ ]` | 语义模型不得被写成可用 guardrail；准备引用 `semantic_feasibility.md` 的负结果 |
| E-1 弱形式 | `[ ]` | 组合仍只证 `derive(T_U)`；不得在 rebuttal/摘要升格为 `x_U` 强绑定 |
| 测试计数 | `[ ]` | 论文/附录与仓库 `reproduce.md` 的 801/783 漂移需结清；artifact 镜像口径是 42，宿主脚本 17 |
| 负对照保留 | `[ ]` | 四格 composition、OOM 行、L2 零效用、issuance 0.0000 不得为页数删除 |

---

## 5. Artifact 与可复现

| 项 | 状态 | 说明 |
|---|---|---|
| 一键复现脚本 | `[x]` | [`scripts/ops/reproduce_artifact.sh`](../../scripts/ops/reproduce_artifact.sh)；M6 实测 `RESULT: PASS`（13 证书、17 tests） |
| 默认 CMD | `[x]` | 42 项测试在宿主机等价通过 |
| Dockerfile / `.dockerignore` | `[x]` | 结构、338 文件上下文、敏感项 0 已复查 |
| Docker build / run | `[ ]` **BLOCKED** | engine 不可用；见 [`docs/blockers/M6.md`](../blockers/M6.md)。**投稿材料不得写镜像已实测或给镜像大小** |
| Artifact README | `[x]` | [`docs/artifact/README.md`](../artifact/README.md) 已加入 X1c/X1d/X1e/X1f/E1/E2/E3/A11 入口与边界 |
| Zenodo 元数据 | `[x]` 模板 / `[ ]` 发布 | [`docs/artifact/zenodo.json`](../artifact/zenodo.json)：版本/关键词/related identifiers/checksums 占位已更新；**无虚构 DOI** |
| 结果 checksums | `[ ]` **发布时** | 用 `sha256sum` 回填 `release_checksums`，不要现在编造 |
| DOI | `[ ]` **OPEN** | 录用/发布后由 Zenodo 分配；cover letter 与 checklist 不填假 DOI |
| Artifact badge | `[ ]` | TDSC 可选；若申请，需提供可用/可复现证据。当前 Docker 阻塞，只能按宿主机路径申请 |
| 数据可用性声明 | `[ ]` | 写清：结果文件在仓库；XSTest 为公开数据集；模型权重不随仓库分发；API key/私有数据不入库 |
| 硬件/版本/种子 | `[x]` 结果文件内 | `scale-cloud` / `eu_ai_act_proof` / `k_entropy_*` 等含 host、binary、vkey、commit；E2 含种子 20261101 |
| 口径表（不混表） | `[ ]` | 投稿前给审稿人一张「host / binary / vkey / proof_mode / pre-post-NFA」对照表；pre-fix 与 post-fix 不得并列 |

---

## 6. 伦理 / 数据 / 安全

| 项 | 状态 | 说明 |
|---|---|---|
| 人体受试者 | `[x]` | 无；不需要 IRB |
| 个人数据 | `[x]` | 未收集；真实响应来自公开模型生成，未见个人数据 |
| 模型输出≠合规真值 | `[x]` | E3/结果文档已写明；论文与 cover letter 保持同一口径 |
| API key / 私钥 | `[x]` | 未入库/未入镜像；`.dockerignore` 排除 `.pop-keys`、`*.key`、`*.pem`、`.env*` |
| 云机密码 | `[x]` | 未写入仓库；按 A4/M6 blocker 口径 |
| 双用途/滥用 | `[ ]` | 论文 limitations 已谈「provider 可拒绝签发」「策略质量不由密码学回答」；投稿系统若要求，补一段 |
| 数据许可 | `[ ]` `OPEN` | XSTest 与模型许可证需在 README/附录注明；确认结果文件可再分发 |

---

## 7. 投稿系统与信件

| 项 | 状态 | 说明 |
|---|---|---|
| 投稿系统账号 | `[ ]` | 确认 TDSC 当前使用 IEEE Author Portal / ScholarOne，并核对 ORCID 绑定 |
| 审稿模式 | `[ ]` **OPEN** | 确认当前是单盲/双盲；若是双盲，PDF 与源文件需去作者信息、致谢、自引措辞 |
| Cover letter | `[x]` 草稿 | [`cover-letter.md`](cover-letter.md)；待填日期/作者/单位/邮箱/资助/COI |
| 摘要 / 关键词 | `[ ]` | 与 PDF 一致；关键词覆盖 ZK、LLM agent、policy compliance、privacy、accountability |
| 推荐审稿人 | `[ ]` | 见 §3 |
| 补充材料 | `[ ]` | 若放附录/补充，给 DOI 或稳定链接；不要放「不可获取」的材料 |
| 提交前邮件模板 | `[ ]` | 给编辑的短邮件：标题、贡献三句、artifact 链接、无 COI |

---

## 8. 提交前最后一遍（可执行）

```bash
# 1) 论文标记与页数（M5 环境）
grep -c '\\need{' paper/tdsc-paper.tex
grep -c '\\fixme{' paper/tdsc-paper.tex
cd paper && pdflatex "\def\SKELQUIET{}\input{tdsc-paper.tex}" && \
             pdflatex "\def\SKELQUIET{}\input{tdsc-paper.tex}"

# 2) 文档链接闸门
cd .. && python3 -m unittest tests.test_doc_links -v

# 3) 宿主 artifact（不出证）
bash scripts/ops/reproduce_artifact.sh --no-build

# 4) 结果文件与正文数字对表（至少）
#    scale-cloud / eu_ai_act_proof / scale-6x{2000,3000,4000,4500,5000}
#    k_entropy_largeN / k_entropy_crossmodel
#    policy_corpus_infer / agent_e2e_deepseek / semantic_feasibility
```

**放行条件**：

- [ ] PDF 可编译、0 error / 0 undefined ref、页数与 MOPC 已拍板；
- [ ] 作者/资助/COI/推荐审稿人填实；
- [ ] 标题与 `groth16` 交付档一致（否则改 “Succinct”）；
- [ ] 所有 `\need{}` 清除或移出 PDF；
- [ ] artifact README/Zenodo 与最终 commit 一致，DOI 只回填真实值；
- [ ] Docker 阻塞如实披露，或解除后回填镜像大小；
- [ ] `tests.test_doc_links` 通过。
