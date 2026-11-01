# 理论收口给论文 owner（P）的 §3/§7 更新说明（A1）

> **状态**：A1 理论收口，2026-11-01。**本文件不改 `paper/tdsc-paper.tex`**；
> P 是论文唯一 owner。下面每条给出：论文位置、当前文字的问题、建议替换文字
> 或要点、是否需要 P 重新编译及页数影响。
>
> **权威来源**（A1 已同步）：
> - [`../certificate-binding-framework.md`](../certificate-binding-framework.md)
>   §3 D5/D9/D10、§4 定理 A、§5 定理 B、§6 定理 C、§7 定理 D、§8 定理 E、§9 定理 F；
> - [`../proofs/theorem-a-b.md`](../proofs/theorem-a-b.md)；
> - [`../proofs/theorem-c-e-f.md`](../proofs/theorem-c-e-f.md)；
> - [`../proofs/theorem-d-g.md`](../proofs/theorem-d-g.md)。
>
> **当前论文版本核对基线**：`paper/tdsc-paper.tex`（本 worktree 的 `28f0625`）。
> 论文 §3 已经吸收了此前的多数修正（guess-tight、PV-2、固定 `T`、`G_rep`/`G_del`
> 分离），下面是**仍然存在或可以再收紧**的点。P 可逐条采纳，不必全部重写。

---

## 0. 优先级与页数总览

| 优先级 | 条目 | 论文位置 | 是否需重编译 | 页数影响 |
|---|---|---|---|---|
| P0（正确性） | A-1 定理 A 的“需要”改“上界认证” | §3.2 `thm:t1` | 是 | 0（改词） |
| P0（正确性） | C-1 显式命名 `G_rep`/`G_del` | §3.5 `thm:t3` | 是 | +0~2 行 |
| P0（正确性） | E-1 组合命题补齐五个反例/条件 | §9 `thm:composition` | 是 | +3~5 行 |
| P0（正确性） | F-1 抽样审计三前提显式化 | §9 `sec:disc-coverage` | 是 | +2~4 行 |
| P1（完整性） | A-2 `n` 公开/保密分列 | §3.2 末尾 | 是 | +4~6 行或 1 个小表 |
| P1（完整性） | B-1 regime 表补 `n` 两行 | §3.3 `tab:regimes` | 是 | +2 行（表内） |
| P1（完整性） | D-1 D-privacy 游戏与优势 | §3.4 `def:dpriv` 前后 | 是 | +3~4 行 |
| P1（完整性） | D-2 枚举精确指数脚注 | §3.4 salted 段 | 是 | +1 脚注 |
| P2（一致性） | G-1 NFA 正确性放入附录 | 附录 A（Proofs） | 是 | +0.3~0.5 页 |
| P2（措辞） | E-2 `x` 不是熵 | §9 composition 段 | 是 | 0（改词） |

> **总页数**：若全采纳，预计 **+0.5~1 页**；其中 G-1 是唯一可能明显增加篇幅的
> 条目。P 若页数紧，可只做 P0 + A-2/B-1/D-2 的字句级修改（几乎不增页）。

---

## 1. 定理 A（§3.2 `sec:tradeoff`，`thm:t1`）

### A-1 把“需要”改成“由上界认证”的充分条件

- **论文位置**：§3.2，`\begin{proposition}[Conditional trilemma]`（`thm:t1`），
  第 (1) 条末句 “Hiding with advantage $\varepsilon$ therefore needs
  $k_X\ge\log q+\log(1/\varepsilon)$.”（约 `tdsc-paper.tex:493-495`）。
- **当前问题**：A.1 是**上界**；上界超过 `ε` 不自动等于“存在成功率为 `ε` 的攻击”。
  论文写 “needs” 会被读成必要条件，而 §3.2 的 Remark
  `rem:trilemma-scope` 又承认偏斜分布下不成立——两处口径不一致。
- **建议替换**：
  > “Hiding with advantage $\varepsilon$ is \emph{certified} by the bound when
  > $k_X\ge\log q+\log(1/\varepsilon)$; for a skewed distribution this is a
  > sufficient condition, not a matching attack.”
- **页数影响**：0（改 2 行词）。

### A-2 `n` 公开 / `n` 保密两制式

- **论文位置**：§3.2 末尾（`cor:reexec` 与 `rem:designated` 之后），或 §3.5 开头。
- **当前问题**：`thm:t1` 的 `β(X)` 没有区分 `n` 是否在 `L_pub`；读者会把
  `q·2^{-k_T}` 套到“`n` 保密”的 API 上。安全模型 T1 只覆盖 `n` 公开；
  `n` 保密时界变成 `(1+q·2^{-f})·2^{-k_T}`，且 PV-2 丢失。
- **建议加入**（3–4 行，无需新表）：
  > “When the challenge $n$ is public, one evaluation of $\beta$ tests one
  > candidate $T$, giving $q\cdot2^{-k_T}$. When $n$ is secret (a designated
  > verifier), an evaluation must guess both $n$ and $T$, giving
  > $(1+q\cdot2^{-f})\cdot2^{-k_T}$ with $f=|n|$; the price is PV-2, since a
  > third party cannot recompute $b$.”
- **页数影响**：+4~6 行（约 0.1 栏）。

### A-3 三难是 Proposition + Remark（论文已基本做到，建议加一句）

- **论文位置**：§3.2 `rem:trilemma-scope`。
- **当前问题**：标题 “Conditional trilemma” 与 Remark 已说明是分类，但第 (3) 条
  仍用 “cannot satisfy ... simultaneously”，可被读成不可能性定理。
- **建议**：在第 (3) 条首句加 “\emph{Within the scheme class defined above}”，
  并在 Remark 首句明写 “Proposition~\ref{thm:t1}(3) is a proposition plus a
  remark, not an impossibility theorem.”
- **页数影响**：0（改词）。

### A-4 带密钥 β 的措辞（论文已修，确认无需再动）

- **论文位置**：§3.2 `thm:t1` 第 (2) 条（`tdsc-paper.tex:496-502`）。
- **状态**：论文已经写成 “The correct reading is \emph{not} ‘hiding survives
  even when $k_X=0$’ ... What the keyed form buys is hiding when
  $k_X<\log q+\log(1/\varepsilon)$.”，与 A1 口径一致。**无需修改。**
- **动作**：仅确认框架 §4.1(2) 与此一致（已同步）。

---

## 2. 定理 B（§3.3 `sec:leak`，`thm:leak` + `tab:regimes`）

### B-1 regime 表补 `n` 公开 / 保密两行

- **论文位置**：§3.3 `Table~\ref{tab:regimes}`（约 `tdsc-paper.tex:616-646`）。
- **当前问题**：表只列 proof tier 三个 regime + public-value 反例 + salted policy；
  没有 `n` 的两种可见性。定理 A 的 `n` 保密界与 PV-2 代价在表里不可见。
- **建议新增两行**（沿用表的列）：
  ```
  n public   & any & ≈2^{-k_T} & q·2^{-k_T} & PV-2 ✓ \\
  n secret   & any & ≈2^{-k_T} & (1+q·2^{-f})·2^{-k_T} & PV-2 ✗ (designated verifier) \\
  ```
  表注补一句：“`n` rows are request-side visibility, not proof tiers.”
- **页数影响**：+2 行（表内），可能触发表格浮动位置微调，约 +0~0.1 页。

### B-2 定理 B 陈述：保留 `q·2^{-k}+negl`，不写 `q·2^{-λ}`

- **论文位置**：§3.3 `thm:leak` 与 Appendix A 的证明。
- **当前问题**：论文 `thm:leak` 已写 `q·Guess+negl`，**没有** `q·2^{-λ}`，正确。
  但 Appendix A 若仍提旧 T1-H 的 `q·2^{-λ}`，需确认它只作为“另一种获胜条件”
  出现，不进入定理陈述。
- **建议**：在 Appendix A 的 `thm:leak` 证明末尾加一句：
  > “The term $q\cdot2^{-\lambda}$ from the earlier T1-H formulation is not part
  > of this game: it belongs to a consistency-win variant and only survives when
  > $q$ is non-polynomial.”
- **页数影响**：+1~2 行。

### B-3 `q` 是求值次数、不是时间

- **论文位置**：§3.2 `thm:t1` 第 (1) 条末句已有 “The integer $q$ counts
  evaluations of $\beta$, not time”。§3.3 `thm:leak` 未重复。
- **建议**：`thm:leak` 陈述后加半句 “again, $q$ counts evaluations of $\beta$”。
- **页数影响**：0（半行）。

---

## 3. 定理 C（§3.5 `sec:t3`，`thm:t3`）

### C-1 显式命名 `G_rep` 与 `G_del`

- **论文位置**：§3.5 `thm:t3`（`tdsc-paper.tex:741-774`）。
- **当前问题**：定理已经写了 “divergence advantage” 与 “replay-only probability”，
  但没有给两个游戏命名；读者容易把 `|S|·c·2^{-f}` 当作 `G_del` 的逐点界。
  A1 的收口是：`|S|·c·2^{-f}` 界的是 **`G_rep`（重放接受）**；在 D2 下
  `G_del` 的 divergence 只有 `negl`；`f=0` 的“1”属于 `G_rep`/非绑定 `B`。
- **建议替换/加句**：
  > “Call the acceptance-only game $G_{\mathrm{rep}}$ and the divergent-delivery
  > game $G_{\mathrm{del}}$. The bound $|S|\cdot c\cdot2^{-f}$ is the
  > $G_{\mathrm{rep}}$ acceptance bound. Under D2, divergence in
  > $G_{\mathrm{del}}$ is only $\mathrm{negl}(\lambda)$; the $f=0$ probability
  > $1$ is a statement about $G_{\mathrm{rep}}$ (or about a non-binding $B$),
  > not about $G_{\mathrm{del}}$ under D2.”
- **页数影响**：+3~4 行（约 0.1 栏）。
- **备注**：论文当前 `thm:t3` 的 proof 已实质包含这两条（“A certificate minted
  after $r$ ... costs negl” 与 “replay probability is 1”），所以这是**命名与
  读法**的收紧，不是新结果。

### C-2 紧致性分两层（若论文正文有“达到该界”措辞）

- **论文位置**：§3.5 定理后的解释段，或 Appendix A。
- **当前问题**：若写 “the receiver-nonce protocol attains the bound” 而不说哪个
  游戏，审稿人会问“达到的是接受还是 divergence”。
- **建议**：写成 “the receiver-nonce protocol attains the bound in
  $G_{\mathrm{rep}}$; in $G_{\mathrm{del}}$ under D2 the divergence advantage is
  strictly smaller ($\mathrm{negl}$).”
- **页数影响**：0~1 行。

### C-3 分离命题的模型限定

- **论文位置**：§3.5 `rem:taxonomy` 与 `thm:t3` 后半。
- **当前问题**：论文已有 “classification, not exhaustiveness” 的 Remark，但
  “`f=0` 下不存在公开可验证 + 防重放 + 无接收方参与”这一分离的**模型**
  （stateless 公开验证、无外部机制）没有在 §3.5 明写；A1 的 `prop:C-Sep`
  只在 proof 文件里。
- **建议**：在 `f=0` 句后加 “under stateless public verification and no external
  mechanism (no revocation table, trusted clock, or hardware).”
- **页数影响**：+1 行。

---

## 4. 定理 D（§3.4 `sec:policy-side`，`def:dpriv` + `thm:dpriv`）

### D-1 完整 D-privacy 游戏与优势

- **论文位置**：§3.4 `\begin{definition}[D-privacy]`（`tdsc-paper.tex:687-694`）。
- **当前问题**：定义已固定同一条 `T`（很好），但没有写出挑战者/对手/挑战/猜测
  与优势公式；审稿人无法直接核对“不可区分”的量化口径。
- **建议**：在定义后加 2–3 行游戏骨架：
  > “Formally, the challenger samples $b\leftarrow\{0,1\}$ and returns
  > $\mathsf{View}_b$; the adversary outputs $b'$, and
  > $\mathsf{Adv}_{CS,D}=|2\Pr[b'=b]-1|$.”
- **页数影响**：+2~3 行。

### D-2 枚举指数：只保留定性 + 精确式脚注

- **论文位置**：§3.4 salted construction 段（`tdsc-paper.tex:710-725`）。
- **当前问题**：论文已经**没有**写 `|Π_c|/2^{λ+128}`（很好），但只说 “the work
  is multiplied by $2^{128}$, and the qualitative statement is all we claim”。
  建议把精确式放进脚注，避免读者自行补一个错误指数。
- **建议脚注**：
  > “With $q_s$ salt guesses per candidate, recovery is at most
  > $q_s/2^{128}+|\Pi_c|q_s/2^{\lambda}$; exhausting the salt space gives an
  > aggregate false-positive term $|\Pi_c|/2^{\lambda-128}$. The salt does not
  > lengthen the $\lambda$-bit hash output, so $|\Pi_c|/2^{\lambda+128}$ is not
  > the right exponent.”
- **页数影响**：+1 脚注（约 3 行）。

### D-3 两个通道（公开值 vs 证明工件）

- **论文位置**：§3.4 “What the salt does not close” 段（`tdsc-paper.tex:727-736`）
  与 §7.1 `tab:wp4`。
- **当前问题**：论文已分开写 C1/C2 失败，口径正确。唯一可收紧的是：§7.1 的
  `tab:wp4` 第 4/6 行（`PrivateViolation`、`delegated`）与 §3.4 的 C1 失败
  是**同一条**；建议交叉引用一下，避免读者以为是两条独立债。
- **建议**：§3.4 的 C1 句末加 “(Table~\ref{tab:wp4}, rows 4 and 6)”；
  §7.1 表注加 “rows 4 and 6 are the C1 failures of \S\ref{sec:policy-side}.”
- **页数影响**：0（交叉引用）。

---

## 5. 定理 E（§9 `sec:disc-composition`，`thm:composition`）

### E-1 五个条件与五个反例对齐

- **论文位置**：§9 `\begin{proposition}[Composition: five necessary conditions]`
  （`tdsc-paper.tex:1860-1872`）。
- **当前问题**：命题列了 C1–C5，但末句只点名 “dropping C2, C4, C5” 三个反例；
  C1（两半健全）与 C3（同一 `T`）的必要性没有点名。A1 的证明底稿为五条各给了
  一个反例。
- **建议替换末句**：
  > “Each condition is necessary: dropping C1 admits a forged half that the
  > conjunction cannot detect; dropping C2 admits two nonces; dropping C3 admits
  > two distinct $T$ values with the same $n$; dropping C4 admits a derived
  > input; dropping C5 admits an undecided delegated rule.”
- **页数影响**：+2~3 行。

### E-2 `x` 不是 `f` 位熵

- **论文位置**：§9 composition 段 “it is exactly $f>0$ in Theorem~\ref{thm:t3},
  with the user-submitted $x$ playing the role of the $f$ fresh bits”
  （`tdsc-paper.tex:1852-1854`）。
- **当前问题**：这句是类比，容易被读成“`x` 提供 `f` 比特熵”。`x_U` 是**承诺量**
  （相关性），不是熵源；用户输入可以低熵甚至公开。
- **建议替换**：
  > “... is the same structural role as $f>0$ in Theorem~\ref{thm:t3}: a value the
  > adversary cannot choose after seeing the challenge. The analogy is about
  > commitment, not entropy---$x_U$ need not be uniform or secret.”
- **页数影响**：0（改 2 行词）。

### E-3 vkey 分离

- **论文位置**：§9 composition 的 “resulting contract is short” 句
  （`tdsc-paper.tex:1856-1858`）。
- **当前问题**：论文的 short contract 只写 “expose $T$ + bind $x$”；A1 的
  `verify_composite` 还要求 `vkey_policy≠vkey_inference` 与 expected vkey。
  这是“哪一半是哪一半”的可判定性条件，不是逻辑必要条件，但缺了会被替换攻击。
- **建议**：short contract 后加 “and the two halves use distinct, pinned
  verification keys.”
- **页数影响**：+1 行。

### E-4 当前实现只证弱形式（论文已写，确认）

- **论文位置**：§9 “First, the inference half must be bound to the
  \emph{submitted} input...” 段（`tdsc-paper.tex:1875-1883`）。
- **状态**：论文已经明确写 “The current verifier binds it to
  $\mathsf{derive}(T_U)$ instead, so it certifies only the weak form ... until
  then the strong form is not claimed.” 与 A1 的 E-1 一致。**无需修改。**
- **动作**：P 只需确认该段与 §3.4 的 `x` 类比不冲突（见 E-2）。

---

## 6. 定理 F（§9 `sec:disc-coverage`）

### F-1 三前提显式化：F-1 / F-3 / F-4

- **论文位置**：§9 `sec:disc-coverage`（`tdsc-paper.tex:1813-1837`）。
- **当前问题**：论文已有 “must append a digest binding the \emph{delivered}
  artifact before delivery, and the log is append-only and publicly readable with
  inclusion proofs” 与 “sample frame, not sampling luck”。但三件事混在一段，
  没有点名：F-1 外部义务、F-3 日志条目绑定 `T`、F-4 抽样框是交付。
- **建议**：把 “Conditional sufficiency” 句拆成三条短句，或在段末加：
  > “Three premises travel with the result: (F-1) the append-before-deliver
  > obligation is external to cryptography; (F-3) the log entry must bind the
  > delivered $T$ (or a receipt), not only $H(\mathrm{cert})$; (F-4) the audit
  > sample frame is delivered artifacts, not log entries.”
- **页数影响**：+3~4 行。

### F-2 检出概率的模型限定

- **论文位置**：§9 `sec:disc-coverage` 的 “Detection” 句。
- **当前问题**：论文给了 $0.9948$ 的实验数，但没有写 $1-(1-p)^m$ 的独立性、
  命中即检出、检出≠阻止。A1 的 F3 要求写清。
- **建议**：加一句 “The $1-(1-p)^m$ form assumes independent sampling and
  detection-on-hit; it quantifies detection, not prevention.”
- **页数影响**：+1 行。

### F-3 baseline 只作成本可行性

- **论文位置**：§9 coverage 或 §8 evaluation 的日志段。
- **当前问题**：论文已有 “log prototype implements only checkpoints, not
  consistency proofs or gossip”，与 F-2 一致；baseline 的 648B/761B 是否被
  读成安全性证据，取决于上下文。
- **建议**：在 baseline 数字旁加 “feasibility only; not evidence that a public
  transparency log is deployed.”
- **页数影响**：0（半行）。

---

## 7. 定理 G（NFA 编译器正确性；论文无现成小节）

### G-1 放入 Appendix A（Proofs）或 §3 的一个 Proposition

- **论文位置**：当前 `paper/tdsc-paper.tex` **没有**定理 G 的独立陈述；
  NFA 契约在 `paper/proof-of-policy.md` §4.2（非 TDSC 正文）。
- **当前问题**：若论文要主张“策略编译器/匹配器正确”，需要一个明确的
  Proposition，并写清语法子集与解析器契约；否则这部分只能算实现细节。
- **建议**（放 Appendix A，0.3–0.5 页）：
  > **Proposition G.** For the supported regex subset $P$ (empty character
  > classes are rejected at parse time, fail-closed), the Thompson construction
  > preserves the language, the Pike VM implements unanchored substring search,
  > and the Python reference and Rust circuit matchers agree on the same
  > compiled NFA spec. The last claim is an algorithm-level bisimulation plus
  > differential-fuzz evidence, not a line-by-line formal verification.
- **必须同时写**：
  - A-G0 现在是**解析器契约**（空类 `[^\d\D]` 等在编译期拒绝），不是定理假设；
  - V1-2 `a{0}` 已修成 `ε`；Rust `nfa_match_naive` 空文本 `ε` 缺口已修；
  - A-G1–A-G5：ASCII、ranges 有序/不交、Unicode 标量、索引、同一策略；
  - E12/P2-03 差分模糊是证据，不是全称证明。
- **页数影响**：+0.3~0.5 页（可压缩到 6–8 行 + 一个小表）。
- **P 的决策**：若页数紧，可只放一个 3 行 Proposition + 指向
  `docs/proofs/theorem-d-g.md` 的脚注；不建议把整个证明搬进正文。

---

## 8. 论文当前已经正确、无需改动的点（避免 P 重复劳动）

| 点 | 论文位置 | 状态 |
|---|---|---|
| guess-tight 假设与 `β=id/encode` 反例 | §3.2 `thm:t1` + `rem:betanec` | 已正确 |
| PV-1 / PV-2 区分，三难用 PV-2 | §3.2 “Two strengths of public verifiability” | 已正确 |
| 带密钥 `β` 不写“`k=0` 也能隐藏” | §3.2 `thm:t1`(2) | 已正确 |
| 三难是分类不是不可能性 | §3.2 `rem:trilemma-scope` | 已正确 |
| `q` 是求值次数、不是时间 | §3.2 `thm:t1`(1) | 已正确 |
| 定理 B 主陈述用 `q·Guess+negl` | §3.3 `thm:leak` | 已正确 |
| 定理 B 字面版平凡性 | §3.3 解释段 | 已正确 |
| D-privacy 固定同一条 `T` | §3.4 “The artifact must be fixed” | 已正确 |
| 不写 `|Π_c|/2^{λ+128}` | §3.4 salted 段 | 已正确（建议加精确式脚注，见 D-2） |
| 定理 C 的 replay vs divergence 分离 | §3.5 `thm:t3` | 实质正确（建议命名 `G_rep`/`G_del`，见 C-1） |
| 组合的弱形式 `derive(T_U)` | §9 composition | 已正确 |
| 签发“检测而非阻止” | §9 coverage | 已正确 |
| 两个泄露通道 | §7.1 `tab:wp4` | 已正确 |
| P-PP 与三方模型 | §7.3 | 已正确 |

---

## 9. 给 P 的最小行动清单

若只做**正确性必需**（不增页）：

1. A-1：`thm:t1`(1) 的 “needs” → “is certified by”。
2. C-1：`thm:t3` 加 `G_rep`/`G_del` 命名（可放 proof 首句）。
3. E-1：`thm:composition` 末句点名五条反例。
4. F-1：`sec:disc-coverage` 段末加 F-1/F-3/F-4 三前提。
5. A-3：`thm:t1`(3) 首句加 “Within the scheme class defined above”。

若还能加 **0.5 页**：

6. A-2：`n` 公开/保密两句。
7. B-1：`tab:regimes` 两行。
8. D-2：枚举精确式脚注。
9. E-2：`x` 不是熵的措辞。
10. G-1：Appendix A 的 Proposition G（可只写 3 行 + 脚注）。

---

## 10. 需要作者决策的项（A1 不能替 P 定）

1. **定理 G 是否进正文**：进则需 +0.3~0.5 页；不进则论文不主张 NFA 编译器
   正确性，只在实现文档里写。A1 倾向“进附录、3 行 Proposition”。
2. **D-privacy 游戏展开到什么程度**：定义 + 2 行优势公式足够，还是把完整
   challenger 伪代码放附录？A1 建议正文 2 行、附录完整。
3. **`n` 保密制式是否在正文单列**：若论文主打“接收方 nonce”（`f>0`），
   `n` 保密（验证者 nonce）是过渡形态，可只在脚注提；若审稿人可能混淆，
   建议正文一句 + 表一行。
4. **枚举精确式的脚注 vs 正文**：正文可能触发“为什么不是 `2^{λ+128}`”的追问；
   A1 建议脚注，保持正文的定性结论。
5. **页码/模板限制**：本文件只给内容，不承诺排版；P 需按 IEEEtran 双栏实际
   页数取舍。

---

## 11. 复核清单（P 改完后）

- [ ] 三份 proof 与框架的陈述逐字一致（尤其 `q·2^{-k}+negl`、PV-2、固定 `T`）。
- [ ] `thm:t3` 中 `|S|·c·2^{-f}` 的主语是 `G_rep`。
- [ ] `thm:composition` 的五条反例都在正文或附录出现。
- [ ] `sec:disc-coverage` 的 F-1/F-3/F-4 三前提都在。
- [ ] `tab:regimes` 有 `n` 公开/保密两行（若采纳 B-1）。
- [ ] 全角/半角、LaTeX 转义（`\|`、`\allowbreak`）无回归。
- [ ] 重新编译后页数与 `\need{...}` 标记一致。
