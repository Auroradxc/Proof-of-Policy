# 引文核实审计（WP8 / A5）

> **日期**：2026-11-01
> **范围**：`paper/tdsc-paper.tex` 的 11 条 `\bibitem`，以及全部与引文相关的 `\need{}`。
> **方法**：逐条打开出版方 / IACR ePrint / arXiv / Crossref / DBLP / 官方文档页面，核对作者、标题、会议或期刊、年份、页码、DOI。
> **边界**：本轮只改 `\bibitem`（必要时同步 `\cite{}` key，本轮无需改 key），不改摘要与 §1–§9 的论证、数字、断言；`\need{}` 文本一律保留（`\SKELQUIET` 构建下为空）。

## 0. 结论摘要

| 项 | 数量 |
|---|---|
| `\bibitem` 总数 | 11 |
| 已核实（有可打开来源） | 11 |
| 其中原本是占位/错误条目、需实质补全或改正 | 5（`zkattach`、`pco`、`hiddencred`、`xacmlpriv`、`vdr`） |
| 仅补页码 / DOI / venue 细节并核对无误 | 6 |
| 仍 `unverified` 的 `\bibitem` | **0** |
| 引文相关 `\need{}` | 5（行 193、1058、1667、1698、2155） |
| 正文点名但未入 bibliography 的工作 | 15 项：13 项有可打开来源，2 项仍无法确认（`Zaguk`、`Lean-Agent`） |

**关键纠正**（均已写入 bibliography）：

1. `hiddencred` 原稿写 “D. Balfanz and J. Schweitzer, 2002 manuscript”，**作者与出处均错**。正确条目是 J. E. Holt, R. W. Bradshaw, K. E. Seamons, H. Orman, *Hidden Credentials*, WPES 2003, pp. 1–8。
2. `zkattach` 与 `pco` 原稿只有 “Author list to be verified” / 副标题。已补全真实标题与作者。
3. `vdr` 原稿只有 DOI 与 “authors and year to be verified”。正确条目是 Chabanne, Hugel, Keuffer, *Verifiable Document Redacting*, ESORICS 2017, LNCS 10492, pp. 334–351。**不是 IACR ePrint 2024/813**；该编号是 Kiraz/Larraia/Vaughan, *How to Redact the Bitcoin Backbone Protocol*。
4. `xacmlpriv` 原稿是描述性占位，无作者/会议/页码。本轮把它落到一条可核实、与正文 “privacy-preserving access control over XACML policies” 最贴近的论文；**原意是否就是这一篇，仍需作者确认**（见 §1 该行“剩余风险”）。

---

## 1. 参考文献逐条（`\bibitem`）

| key | 论文中的用途 | 来源链接 | verified | 修正内容 | 剩余风险 |
|---|---|---|---|---|---|
| `hollowllm` | §1 / §6 攻击与负面结果；effort gap | [arXiv:2607.28884](https://arxiv.org/abs/2607.28884)、[IEEE CSDL](https://store.computer.org/csdl/proceedings-article/sp/2026/606500e339/2hBEtZrxaeI)、[DOI](https://doi.org/10.1109/SP63933.2026.00258) | ✅ | 核对作者 C. Gong / B. Liu / M. Li、标题、S&P 2026、pp. 4339–4355、DOI；补 arXiv 号；venue 写全 | 无 |
| `zkattach` | §1 / §4 / §6：source-integrity gap | [arXiv:2608.30083](https://arxiv.org/abs/2608.30083) | ✅ | 原为 “Author list to be verified. ‘zk-attach’”。改为真实标题 *Zero-Knowledge Predicate Proofs Between AI Agents: A Measured, Cross-Protocol Gateway and the Source-Integrity Gap* 与作者 A. S. Gopalakrishna（2026-08-30）；注明 `zk-attach/v0` 是论文的系统贡献 | 正文仍用系统名 “zk-attach”，与论文标题不同名；已在条目内加括注桥接 |
| `zkgen` | §6 表 1：policy→circuit | [DOI](https://doi.org/10.1109/ICBC59979.2024.10634440)、[Crossref](https://api.crossref.org/works/10.1109/ICBC59979.2024.10634440) | ✅ | 核对作者 J. Lauinger / J. Ernstberger / S. Steinhorst、标题、ICBC 2024、pp. 620–624、DOI；venue 写全 | 无 |
| `pco` | §6 表 1：agent/LLM compliance | [IACR ePrint 2026/994](https://eprint.iacr.org/2026/994) | ✅ | 原为 “Author list to be verified. ‘Verification via proof-carrying output’”。改为作者 H. Avni / S. Dolev / A. Yagudaev / M. Yung 与完整标题 *Super-intelligence Survival Guide: Verification via Proof-Carrying Output* | 正文用缩写 “PCO”，条目内已给完整标题 |
| `zkagent` | §6：与 zkAgent 的正交对比、表 2 | [IACR ePrint 2026/199](https://eprint.iacr.org/2026/199) | ✅ | 核对作者 L. Wang / H. Lou / C. Li / Y. Yu / Y. Hu、标题；补 “IACR Cryptology ePrint Archive, Report 2026/199” | 无 |
| `hiddencred` | §4.6 prior art：policy hiding 家族 | [ACM DL](https://dl.acm.org/doi/abs/10.1145/1005140.1005142)、[DBLP](https://dblp.org/rec/conf/wpes/HoltBSO03.html) | ✅ | **原稿作者与出处错误**（D. Balfanz / J. Schweitzer, 2002 manuscript）。改为 J. E. Holt, R. W. Bradshaw, K. E. Seamons, H. Orman，WPES 2003，pp. 1–8，DOI 10.1145/1005140.1005142 | 无 |
| `handshake` | §4.6 prior art：secret handshakes | [DOI](https://doi.org/10.1109/SECPRI.2003.1199336)、[DBLP](https://dblp.org/rec/conf/sp/BalfanzDSSSW03.html) | ✅ | 核对六位作者与标题；补 pp. 180–196 与 DOI；venue 写全 | 无 |
| `xacmlpriv` | §4.6 prior art：XACML 隐私 | [DOI](https://doi.org/10.1109/CIT.2010.199)、[Crossref](https://api.crossref.org/works/10.1109/CIT.2010.199) | ✅ | 原为描述性占位，无作者/会议/页码。落到 C. A. Ardagna, S. De Capitani di Vimercati, G. Neven, S. Paraboschi, F.-S. Preiss, P. Samarati, M. Verdicchio, *Enabling Privacy-Preserving Credential-Based Access Control with XACML and SAML*, CIT 2010, pp. 1090–1095 | ⚠️ **映射风险**：原占位没有唯一标识，无法证明作者原意就是这一篇。备选 M. Harbach et al., *Towards Privacy-Preserving Access Control with Hidden Policies, Hidden Credentials and Hidden Decisions*, PST 2012, pp. 17–24, DOI 10.1109/PST.2012.6297915（更贴“hidden policies”，但不含 XACML 字样）。作者需二选一确认 |
| `sw05` | §4.6 prior art：fuzzy IBE / attribute hiding | [DOI](https://doi.org/10.1007/11426639_27)、[Crossref](https://api.crossref.org/works/10.1007/11426639_27) | ✅ | 核对 A. Sahai / B. Waters 与标题；补 EUROCRYPT 2005、LNCS 3494、pp. 457–473、DOI | 无 |
| `ksw08` | §4.6 prior art：predicate encryption | [DOI](https://doi.org/10.1007/978-3-540-78967-3_9)、[Crossref](https://api.crossref.org/works/10.1007/978-3-540-78967-3_9) | ✅ | 核对 J. Katz / A. Sahai / B. Waters 与标题；补 EUROCRYPT 2008、pp. 146–162、DOI | LNCS 卷号（4965）未在 Crossref 记录中返回，为避免未核实数字，条目未写卷号 |
| `vdr` | §1 / §6：redaction 积木、`mask_covered` 的 bit selector | [DOI](https://doi.org/10.1007/978-3-319-66402-6_20)、[Crossref](https://api.crossref.org/works/10.1007/978-3-319-66402-6_20)、[Springer book](https://link.springer.com/book/10.1007/978-3-319-66402-6) | ✅ | 原只有 DOI + “authors and year to be verified”。改为 H. Chabanne / R. Hugel / J. Keuffer，ESORICS 2017，LNCS 10492，pp. 334–351，2017 | 无。**再次确认不得写成 IACR ePrint 2024/813** |

---

## 2. 引文相关的 `\need{}`

| 位置 | 内容 | 本轮结论 | 依据 / 备注 |
|---|---|---|---|
| `paper/tdsc-paper.tex:193` | 正文点名的 Proof-of-Guardrail / Agentrust,cMCP,cA2A / Lean-Agent / zk-regex V2 / ZK Email / WITNESS / `@brivora/verify` / DeepProve / EU AI Act Art. 12/13 未给 `\cite{}` | **部分可解，本轮不入 bibliography** | 13 项已找到可打开来源（见 §3）；`Zaguk`、`Lean-Agent` 无法唯一确认。按本轮“只改 bibliography / 引用 key”的边界，不向正文新增 `\cite{}`、不新增未使用的 `\bibitem`。该 `\need` 保留 |
| `paper/tdsc-paper.tex:1058` | 五条 prior-art 引文（`hiddencred`、`handshake`、`xacmlpriv`、`sw05`、`ksw08`）待打开核实 | **已解** | 五条均已逐条核实，见 §1。`(P-PP)` 的链上 registry vs 签名 manifest 仍是作者决策，与本条引文核实无关；`\need` 保留 |
| `paper/tdsc-paper.tex:1667` | 除 Hollow-LLM / zkGen / zkAgent / PCO 外，其余参考文献须打开核实 | **已解** | 11 条全部核实，见 §1。`\need` 保留 |
| `paper/tdsc-paper.tex:1698` | SP1 官方安全模型是否明说 “individual STARK proofs do not currently satisfy zero-knowledge” | **已核实** | [SP1 Security Model § “Groth16, PLONK, and the Zero-Knowledgeness of SP1”](https://docs.succinct.xyz/docs/sp1/security/security-model#groth16-plonk-and-the-zero-knowledgeness-of-sp1)：原文为 “our implementations of Groth16 and PLONK are zero-knowledge” 与 “individual STARK proofs in SP1 do not currently satisfy the zero-knowledge property”。正文断言成立。因是网页文档，未新增 `\bibitem`；建议后续把精确 URL + 小节锚点写进脚注后再撤 `\need` |
| `paper/tdsc-paper.tex:2155` | 文末 “以下条目仍是占位、作者/venue/页码未核实” | **已解（文本保留）** | 11 条均已核实并改写。该 `\need` 在 `\SKELQUIET` 构建下不排版；若用非静默构建，这段文字已过时，建议下一轮编辑时删除或改写。按本轮边界未改 `\need` 文本 |

> 说明：`\need{}` 在 `\def\SKELQUIET{}` 构建下被定义为空宏（`paper/tdsc-paper.tex:71-73`），因此上述已过时的 blocker 文字不会进入本轮 PDF；它们仍是作者侧待清理项，不是正文主张。

---

## 3. 正文点名但未入 bibliography 的工作

这些名字出现在 §1、§6 表 1 或 `\need{193}` 中，但没有 `\bibitem`。本轮只核实、不新增引用。

| 名称 | 论文中的位置 / 用途 | 来源链接 | verified | 备注 |
|---|---|---|---|---|
| zk-regex V2 | §1 积木；§6 提及 NFA 契约 | [IACR ePrint 2026/1284](https://eprint.iacr.org/2026/1284)、[zk.regex v2 blog](https://zk.email/blog/zk-regex-v2)、[GitHub](https://github.com/zkemail/zk-regex) | ✅ | ePrint 2026/1284：*Zero-Knowledge Proofs of Generalized Regular Expression Matching for Anonymized Email Verification*，作者 S. Londhe, A. Gupta, S. Suegami, Y. Shahi, R. Figueiredo, P. Hassanizadeh, S. Ebrahimi |
| ZK Email | §1 积木 | [zk.email](https://zk.email/)、[docs](https://docs.zk.email/zk-regex) | ✅（项目） | 无单篇 “ZK Email” 论文；引用时应引项目文档或上条 ePrint（ZK Email 团队出品），不要编造论文条目 |
| Proof-of-Guardrail | §1 相关工作 / `\need{193}` | [arXiv:2603.05786](https://arxiv.org/abs/2603.05786) | ✅ | X. Jin, M. Duan, Q. Lin, A. Chan, Z. Chen, J. Du, X. Ren, *Proof-of-Guardrail in AI Agents and What (Not) to Trust from It*, AI4GOOD Workshop @ ICML 2026；TEE attestation，不是 ZK |
| NiyamAI | §6 表 1：agent/LLM compliance | [arXiv:2608.07167](https://arxiv.org/abs/2608.07167) | ✅ | A. Katkar, O. Karkele, K. Mandhane, M. More, Y. Kashid, *NiyamAI - An Intent-Bound AI Agent with Cryptographically Verifiable Guardrails using Zero-Knowledge Proofs*，2026 |
| Zaguk | §6 表 1：agent/LLM compliance | — | ❌ **unverified** | 多轮检索未找到任何名为 “Zaguk” 的 AI-agent / 合规项目或论文；疑似拼写有误（可能指 zkAGI / zCloak AI，但无法确认）。**不得凭此名写 bibitem**；建议作者核对原名后替换 |
| Agentrust / cMCP / cA2A | §1 相关工作 / `\need{193}` | [agentrust-io.com](https://agentrust-io.com/)、[cMCP (Zenodo)](https://www.zenodo.org/records/23001694)、[cA2A 文档](https://github.com/agentrust-io/ca2a/blob/main/docs/concepts.md) | ✅（项目/规范） | cMCP 是 TEE 内的 confidential MCP gateway；cA2A 是 A2A 的 trust profile；均非同行评审论文 |
| Lean-Agent | §1 相关工作 / `\need{193}` | [arXiv:2610.00885](https://arxiv.org/abs/2610.00885)、[lean-agent-protocol](https://github.com/arkanemystic/lean-agent-protocol) | ⚠️ **ambiguous** | 至少三个不同项目同名/近名（FORALL-LEAN-AGENT、Numina-Lean-Agent、lean-agent-protocol），无法唯一确定正文所指；按 unverified 处理 |
| WITNESS | §1、§6 表 1：非 ZK / 两原语对照 | [Devpost](https://devpost.com/software/witness-31tp9c) | ✅（项目） | 两原语 `NumericThreshold` / `KeywordAbsence`、绑定 Midnight、**Apache 2.0 / public from day one**；无同行评审论文 |
| `@brivora/verify` | §1、§6 表 1：非 ZK 基线 | [npm](https://www.npmjs.com/package/@brivora/verify)、[docs](https://brivora.dev/verify/overview/) | ✅（项目） | PQC 签名 Merkle proof（ML-DSA-65 + Ed25519），**不是 ZK**；与正文 “not zero-knowledge” 一致 |
| DeepProve | §1、§6 表 1：model computation | [IACR ePrint 2026/1112](https://eprint.iacr.org/2026/1112)、[docs](https://docs.lagrange.dev/deepprove/overview) | ✅ | N. Gailly et al., *DeepProve: Verifiable End-to-End Large Language Model Inference*, ePrint 2026/1112 |
| zkGPT | §6 表 1：model computation | [IACR ePrint 2025/1184](https://eprint.iacr.org/2025/1184) | ✅ | W. Qu, Y. Sun, X. Liu, T. Lu, Y. Guo, K. Chen, J. Zhang；USENIX Security 2025 |
| Circuitree | §6 表 1：policy→circuit | [DOI](https://doi.org/10.1109/ACCESS.2022.3153366)、[DBLP](https://dblp.org/rec/journals/access/GoddenSDVSB22.html) | ✅ | T. Godden, R. De Smet, C. Debruyne, T. Vandervelden, K. Steenhaut, A. Braeken, *Circuitree: A Datalog Reasoner in Zero-Knowledge*, IEEE Access 10:21384–21396, 2022 |
| Prezta | §6 表 1：policy→circuit | [arXiv:2607.11466](https://arxiv.org/abs/2607.11466) | ✅ | Z. Wei, O. M. Ameer, N. Borisov, Y. Zhang, *Prezta: Provable Remote Execution of Zero-Trust Authorization using SNARKs*, 2026（USENIX Security 2026 artifact） |
| VAOL | §6 表 1：非 ZK 行业基线 | [GitHub](https://github.com/ogulcanaydogan/Verifiable-AI-Output-Ledger) | ✅（项目） | Verifiable AI Output Ledger：DSSE 签名 + RFC 6962 Merkle + OPA；不是 ZK |
| EU AI Act Art. 12/13 | §1 相关工作 / `\need{193}` | [Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) | ✅ | Art. 12 record-keeping（日志能力/可追溯性）；Art. 13 transparency（面向 deployer 的说明与日志机制说明）。引用官方 EUR-Lex，不引二手解读 |

---

## 4. 复现与验收

```bash
cd paper
pdflatex "\def\SKELQUIET{}\input{tdsc-paper.tex}"
pdflatex "\def\SKELQUIET{}\input{tdsc-paper.tex}"
python3 -m unittest tests.test_doc_links -v
```

- 编译后页数：16 页（≤ 18 页上限）。
- 编译错误：0；未定义引用：0。
- `tests.test_doc_links`：通过。

## 5. 仍未闭合 / 需作者决策

1. **`xacmlpriv` 的原意**：当前落到 Ardagna et al. 2010（XACML 字面匹配），备选 Harbach et al. 2012（hidden policies 语义匹配）。请作者二选一。
2. **`Zaguk`**：无任何可核实来源，疑为拼写错误；核实前不得写入 bibliography。
3. **`Lean-Agent`**：至少三个同名/近名项目，正文所指不明。
4. **已过时的 WP8 `\need{}`**（行 1667、1698、2155，以及行 193/1058 的“待核实”措辞）：本轮按边界未改正文；下一轮编辑应清理或改写成“已核实 + 来源”。
5. **正文点名未给 `\cite{}` 的 13 项**：来源已核，但本轮不新增引用；若要在 §1/§6 正式引用，需另开一次“加引用”改动（会动正文行）。
