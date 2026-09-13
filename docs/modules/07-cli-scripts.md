# 07 · CLI 与脚本

> 覆盖 `policydsl/__main__.py` 与 `scripts/` 下的全部脚本（15 个 Python 入口 + 7 个 shell）。
> 这一板块回答：**每个脚本负责哪一段，什么时候该用哪个。**
> 完整的复现顺序见 [`../reproduce.md`](../reproduce.md)；这里讲的是**脚本内部在做什么**。

---

## 1. 脚本地图

| 脚本 | 一句话 | 需要 Rust 二进制？ | 需要 SP1 证明？ | 典型耗时 |
|---|---|---|---|---|
| **`demo_all.sh`** | **总入口**：把下面各条支路依次跑一遍 + 汇总成 `REPORT.md` | 视支路 | 视支路（`--prove`） | fast 约 20 秒 / `--prove` 约 26–27 分钟（本机实测） |
| `policydsl/__main__.py` | 编译策略 / 参考判定 | 否 | 否 | 毫秒 |
| `prove_policy.py` | 单条响应 → 真实证明 + golden 比对 | `pop-script` | 是（可 `--no-prove`） | ~70 s |
| `cross_validate.py` | 19 条向量 × (host + prove) 与 golden 对拍 | `pop-script` | 是（可 `--no-prove`） | host 秒级；prove 约 2 分钟/条（默认分 4 块，每块峰值 ~10 GB） |
| `private_demo.py` | 私有模式全链路实验（Leak/Binding/Evidence/证明） | `pop-script` | 是（可 `--no-prove`） | ~70 s |
| `gen_key.py` | 生成/查看 Ed25519 出证密钥对（打印 keyid + 公钥） | 否 | 否 | 毫秒 |
| `issue_cert.py` | 签发证书 + 锚定（可选上链） | `pop-script` | 是（可 `--no-prove`） | ~70 s |
| `proof_service.py` | **证明服务**（第二步）：HTTP 两段接口 —— 宿主判定入证 + 出证队列 | `pop-script` | 是（`--host-check` 否） | check 毫秒级；attest ~2.5 分钟/作业（队列 1） |
| `verify_cert.py` | **第三方**独立验证单张证书 | `pop-script` / `pop-verify` | 验证已有证明 | ~20 s |
| `demo_e2e.py` | 一键真实会话（LangChain + MCP + zk + **公私对比** + 锚定） | `pop-script` | 可 `--no-prove` / `--no-contrast` / `--model`（真模型） | host 秒级；出证 **~2.5 分钟**（1 份证明 —— 对比那 2 张默认只做宿主校验） |
| `verify_session.py` | **第三方**独立验证整个会话包 | 同上 | 验证已有证明 | 秒级 |
| `ezkl_prove.py` | 语义规则（`semantic_bound`）的 ezkl 出证/验证/自检 | 否（需 ezkl+torch） | 否（ezkl 自己的证明） | setup ~48 s / prove ~77 s |
| `compose_proof.py` | **组合证明**（P1-6）：策略半 + 推理半各出一份 → 合成 → 联合验证 | `pop-script` | 是（可 `--no-prove` / `--reuse-proofs`） | 两次出证，各 ~2 分钟 |
| `prove_session.py` | **会话聚合证明**（P2-10）：一个 run 的流式证书 → 一次证明 + 独立验证 | `pop-script` | 是（可 `--no-prove`） | 出证 ~2.5 分钟（3 张证书） |
| `prove_multiparty.py` | **多证明者**（P2-11）：三个角色各证一段策略切片 → 证书 + 两条验收判据的现场造假演示 | `pop-script` | 是（可 `--no-prove`） | 出证 ~2 分钟 × 非空切片数（示例包 2 段） |
| `deploy_anchor.py` | 部署 `Anchor.sol`（字节码来自入库 artifact） | 否 | 否 | 秒级 |
| `make_shots.py` | 从会话产物生成截图/HTML/SVG | 否 | 否 | 秒级 |
| `anchor_e2e.sh` | 起 anvil → 部署 → demo → `--rpc` 核对 + 反例 | 可选 | 可 `--prove` | ~10 s / **3:10**（带真证明，2026-09-12 本机实测） |
| `make_audit_proof.sh` | 生成 compressed 审计 fixture | `pop-script` | 是（需 ≥16 GB） | 若干分钟 |
| `install_ezkl.sh` | 装 ezkl 栈（`ezkl==23.0.5 / onnx / torch`）到独立 venv，装前核版本、装后冒烟 `ezkl_prove.py info` | 否 | 否 | 取决于网络 |
| `install_frameworks.sh` | 装 langchain/langgraph/mcp 到独立 venv | 否 | 否 | 取决于网络 |
| `retry_install_frameworks.sh` | 上述网络的镜像回退版 | 否 | 否 | 同上 |
| `retry_install_foundry.sh` | 装 foundry（anvil/cast/forge） | 否 | 否 | 取决于网络 |

> **不知道从哪下手就跑 `demo_all.sh`** —— 它自己不出证、不重新实现任何逻辑，只是按依赖
> 顺序调用下表里的驱动，并如实记下「哪条跑了 / 哪条为什么跳过 / 耗时与峰值内存」。
> 完整说明见 §3。

补充：`scripts/vectors.json`、`results.json`、`results_check.json`、`results_prove.json`、
`scripts/examples/out/` 都是**运行产物**（部分入库、部分 gitignored）。

---

## 2. 各脚本的输入 / 输出 / 判定标准

### 2.1 `prove_policy.py` —— 最小的一件事

```bash
SP1_PROVER=cpu python3 scripts/prove_policy.py \
  --pack policy_packs/eu_ai_act_v1.json \
  --response scripts/examples/eu_agent_reply.txt \
  [--out-dir DIR] [--no-prove] [--expect pass|violate]
```

流程：`load_policy` → `check`（golden）→ `compile_policy` → `spec_canonical_text` →
写 `vectors.json`（`spec_canonical` 字段）→ `pop-script --check`（host）→ `pop-script`（prove）
→ 逐项与 golden 比 `passed` + 违规规则集合。

- `--expect pass|violate` 是**健全性护栏**：先验 golden 是否符合预期，不符合直接退出码 2
  （防止「测试通过」其实是因为响应早就变了）。
- 退出码：`0` PASS；`1` 比对失败；`2` 前置条件/环境错误。

### 2.2 `cross_validate.py` —— I1 的总闸门

19 条向量，覆盖各规则各至少一条 pass + 一条 violate：

| 向量 | 规则类型 |
|---|---|
| `clean_pass` / `keyword_hit` / `length_too_long` | keyword / length |
| `email_hit` / `email_clean` / `secret_hit` / `secret_clean` | pattern（PII） |
| `format_ok` / `format_bad` | format_check |
| `tool_arg_hit` / `tool_arg_clean` | tool_arg_guard |
| `budget_over` / `budget_ok` / `token_over` | budget_bound（calls / tokens） |
| `norm_homoglyph` / `norm_zero_width` / `norm_fullwidth` / `norm_ascii` / `norm_clean` | normalized_keyword_block（P2-9b：三种绕过 + ASCII 正例 + 干净对照） |

比对方式：Python 的 `(rule.name, kind)` 集合 vs Rust 输出的 `(rule, kind)` 集合，加上 `passed`。
期望输出 `RESULT: host 19/19  prove 19/19  PASS`；带 `--no-prove` 时末行是
`RESULT: host 19/19  prove SKIPPED (--no-prove)  PASS` —— **`--no-prove` 下这条 prove 字段不是出证结论**，
早期版本会照抄 host 计数，读起来像「19 条证明都过了」，已改掉。

**真实证明默认分块跑**（`--chunk N`，缺省 4）：SP1 core 证明的峰值 RSS 本就 ~10.3 GB，
且每证完一个还会缓慢累加 —— 本机实测把（当时的）14 个向量交给**一个** `pop-script` 进程，会在第
6 / 第 7 个证明处被内核 OOM-kill（峰值 10.65 / 10.82 GB，`SIGKILL 9`），而逐个单独出证都是好的。
分块只做**进程隔离**：每块是原向量的连续子序列，结果按原序合并，下游比对逻辑完全不知道分块存在。
`--chunk 0` 恢复单进程（需 ≥16 GB）。分块逻辑本身有 `tests/test_cross_validate.py` 守住
（切开后拼回去逐一相等）。

> 这个脚本是**改判定逻辑后必须跑的第一件事**。它把「两侧不一致」变成一次红灯，而不是等到
> 复现论文数字时才发现。

### 2.3 `private_demo.py` —— 私有模式的六个实验

构造一个含 keyword + length + email 正则三条规则的用例，并**故意**让响应同时命中关键词与邮箱。
它跑六个实验，每个都有独立的 PASS/FAIL 行：

| 实验 | 检查什么 |
|---|---|
| `check` | 电路内 `--check` 的私有输出与 golden **逐字段**一致（响应承诺 / 证据承诺 / 脱敏） |
| `negative` | 伪造见证区间 → `mask_covered=false`（证明这个性质不是恒真） |
| `leak` | 公开输出里**没有**响应/证据明文；承诺是 64 位十六进制且 ≠ 原响应 |
| `binding` | 承诺确定性、不同输入不同承诺、伪造脱敏被拒 |
| `challenge`（第二行） | P0-2 绑定：`(T′, nonce)` 能打开绑定、换 `T′` 拒、换 nonce 拒、空 nonce 域分离 |
| `opening` | 证据开示自洽 + 承诺与证明输出一致 + 篡改被拒 |
| `prove` | 同一任务真实证明后复查（`--no-prove` 跳过） |

### 2.4 `issue_cert.py` —— 签发 + 锚定

```bash
python3 scripts/issue_cert.py --pack P --response R --out-dir D \
    [--mode public|private] [--proof-mode core|compressed|groth16|plonk] \
    [--nonce auto|none|<hex>] [--key 私钥.pem] \
    [--no-prove] [--no-semantic] [--ledger L] [--rpc URL --contract 0x…] [--private-key KEY]
```

`--nonce` 默认 `auto`：现场 `challenge.new_nonce()` 出一个 32 字节随机挑战值，
并把它写进向量（电路据此算 `response_binding`）与证书 `challenge` 块。
`none` 表示空挑战（只绑定「空 nonce」，退化为旧行为）；也可以传一个十六进制串
去**复现**某次会话。出证后会打印 `nonce` 与 `resp_binding` 两行，便于核对。

产物：`vectors.json`、`results.json`、`proof.bin`（+ `.meta.json`/边车）、
`cert.json`（信封）、`payload.json`（明文载荷，便于阅读）、`key.json`（出证方**公钥**）、
`anchor.json`（锚定条目）。

关键实现点：

- 私有模式下自动计算 `mask` / `redacted` / `spans` 并塞进向量（`--mode private`）。
- `run_pop` **强制 `SP1_PROVER=cpu`**（避免继承环境里非法的 `native`）。
- `outcome` 直接从 `results.json` 剥掉 `name`/`mode` 得到（**不重算**），保证证书里的结论 ==
  电路承诺的结论。
- 锚定走 `anchor.backend_from_env(...)`：没给 `--rpc/--contract` 就写文件账本。
- **签名（P0-3）**：`keys.signer_from_env(--key)` 取 Ed25519 私钥（缺省 `$POP_SIGNING_KEY`，
  都没有就在 `.pop-keys/signing.key` **生成一把新的**，0600、已 gitignore）。公钥写进
  `<out-dir>/key.json` —— 验证方只需要它。
- **语义规则的陪伴证明（P2-9）**：电路公开值里的 `delegated` 非空时，自动调
  `scripts/ezkl_prove.py prove` 出一份 ezkl 陪伴证明（**~77 s / 峰值 ~9 GiB**，
  见 `08` §3.5），并把每个约定约束的指纹写进证书的 `semantic.companions[]`。
  同一份证明被所有规则共用（v1 只有**一个**模型 —— 证明的内容是"`encode(T)` 经这张
  图算出的分数"，方向与阈值只是对同一个分数的不同比较）。
  `--no-semantic` 只跳过这一步，**不负责让证书变得能过** —— 跳过后 `delegated` 非空
  而 `companions` 缺失，`verify_cert.py` 会据此判 FAIL（fail closed）。
  出证方在写证书**之前**会被打印出每条语义规则的分数与满足情况：`passed: True`
  只覆盖电路判得了的约束，不该被读成"合规"。

### 2.5 `verify_cert.py` —— 第三方验证单张证书

```bash
python3 scripts/verify_cert.py --cert C --pack P --ledger L [--proof proof.bin] \
    [--response T.txt] [--nonce HEX] [--keyring key.json|pub.hex|pub.pem] \
    [--receipts receipts.json [--gateway-key gw.pub.hex]] \
    [--semantic-dir semantic/artifacts] [--semantic-skip-ezkl] \
    [--rpc URL --contract 0x…]
```

检查项（逐行 PASS/FAIL）：

| 检查 | 内容 |
|---|---|
| `signature` | DSSE 信封签名（**Ed25519**，用 `--keyring` 给的公钥；缺省读证书同目录 `key.json`）。P0-3 之前的 `demo-hmac-sha256` 信封会被**结构性拒绝** |
| `policy_hash` | **重新编译**策略包并比对（不是从证书里读） |
| `response_binding` | P0-2：证书 `challenge` 块 / `outcome` 内嵌 / 证明公开值 / **由送达的 `--response` 现场重算** 四者比对（≥2 来源才算过） |
| `trace_binding` | P1-5：证书 `outcome` 内嵌 / 证明公开值 / **由 `--receipts` 给的网关侧回执链现场重算** 的 `trace_root` 三者比对。链长不必塞进公开值 —— 验证方本来就持有网关发给它的回执 |
| `receipt_chain`（可选） | P1-5：对 `--receipts` 的链**逐条 Ed25519 验签**（链下那一关）。只给 `--receipts` 不给 `--gateway-key` 时如实记「未给 --gateway-key，回执签名未验」，**不假装验过** |
| `trace_seal` | P1-5b：载荷**顶层** `trace_seal`（网关在会话末端签的 `{count, trace_root}`）——验签 + `seal.trace_root == outcome.trace_root` +（有 `--receipts` 时）`len(chain) == seal.count` 与链尾摘要。**这一卡拦的是截尾**：`trace_binding` 比的是两份检材，二者可以同时是那条被截断的链。**只给 `--receipts` 而没给 `--gateway-key` 时**核不了签名、也分不开「出证方没承诺」与「没给我看」，故如实记 `PASS + 「截尾不可排除」(skipped)`；**给了 `--gateway-key` 却没有 `trace_seal`** 的证书判 FAIL（既然知道这段会话有网关，就该有它的末端承诺） |
| `semantic[<rule>]`（P2-9） | 语义规则的**陪伴证明**：`system` 一致 → 证书声明的 `{vk_sha256, onnx_sha256, threshold_bp, direction}` 与**电路公开值**逐字段相等 → 证明文件字节哈希 == 证书承诺的 `proof_sha256` → 本地 `vk.ezkl` 哈希 == 约束承诺的 `model_vkey` + 设置口径合规 + ezkl 验证器通过 → 公开实例的输入部分 == **由送达的 `--response` 现场重算的 `encode(T′)`** → 分数满足阈值。**缺 `--semantic-dir` 或 `--response` 一律 FAIL**（没有 T′ 就核不了绑定，这几条规则根本没被 SP1 判过，不能默认通过）；证书多带陪伴证明而公开值 `delegated` 为空也判 FAIL。`--semantic-skip-ezkl` 跳过 ezkl 验证器那一步（用于离线预检），此时该行会**如实注明"证明有效性未核"** |
| `anchor` | 账本链完整 + 摘要存在于账本 |
| `anchor_on_chain`（可选） | 链上 `anchoredAt` 读回，且与本地 meta 的 `chain_ts` 一致 |
| `proof_mode` | P0-4：证书自称的 `binding.proof_mode` 与**工件自报的模式**（边车 `*.verify.json` / `*.meta.json` / 验证器输出）比对，多来源必须指向同一档。没有工件的证书只能标 `unproven` —— 自称 `core` 却拿不出证明即判 FAIL；P0-4 之前的旧证书（无此字段）**如实跳过**，不倒过来判它失败 |
| `vkey_label` | **`vkey_hash` 标注的诚实性** —— 与 `proof_mode` 同构的第二条不变量（见 §2.11 的说明）。`binding.vkey_hash` 的语义是「哪块电路判定了它」；宿主判定的证书没有电路参与，只能标 `unproven`。未附工件却声明 vkey = 过度声明，附了工件却标 `unproven` = 低报，两者都 FAIL；缺字段的旧证书如实跳过 |
| `proof_verify` / `proof_outcome` / `proof_vkey` / `proof_sha256` | 证明有效 + 承诺的 outcome/vkey/工件哈希都匹配 |
| `verify_only` / `public_values` / `vkey_hash` | 走快路径时的对应三项（**注意与 `vkey_label` 是两回事**：这几项比的是「证明的 vkey == 证书声称的 vkey」，而 `vkey_label` 问的是「证书声称的 vkey 本身可不可能为真」） |

签名失败会**提前返回**（`print_fail`），因为后面所有检查都建立在「载荷可信」之上。
拿不到公钥时同样提前返回并提示用 `--keyring` 指明（**不会**静默降级为「跳过签名」）。

`--keyring` 接受 `key.json`、`*.pub.hex`、`*.pub.pem` 或一段公钥十六进制。
**验证方全程只需要公钥** —— 拿不到私钥，也就伪造不出签名。
路径拼错会当场报「找不到公钥文件：…」并**连同路径一起打印**（而不是把它当公钥
文本解析、回一句「不是合法十六进制」把真因盖掉）。

`--response` 是**你手上真正收到的那条 T′**。给了它，验证器就现场重算
`commit.response_binding(nonce, T′)` 并和解出来的绑定比 —— 这是整套流程里
唯一一处「证明的 T」与「送达的 T′」被真正对上的地方（P0-2 要解决的正是这个）。
不给也能跑：此时只做证书内部两个来源的自洽比对，报告里**不会**声称已核对送达内容。
`--nonce` 是给演示重放用的覆盖项（比如故意拿另一个 nonce 去重算，看它被拒）。

`--receipts` 是**你（验证方）手上那条工具回执链**（网关发给你的 JSON 数组），
与 `--response` 完全对称：给了它，验证方就现场重算链尾摘要并与证书/公开值比对，
于是「这张证明绑的是**我手上这条轨迹**」被真正验证 —— 而不再是「出证方自己前后自洽」。
`--gateway-key` 再往前一步，对整条链**逐条验签**（网关公钥，形式同 `--keyring`）。
两者**不可互相替代**：摘要比对回答「送检的链与证明绑的是不是同一条」，验签回答
「这条链是不是网关签的」。

电路内只校验链的**结构**（`seq` 连续、`prev` 咬合），所以改动**链尾**那条回执的
内容不破坏结构；当送检的链与证书正是**同一份被改过的链**时，摘要照样对得上 ——
此时 `trace_binding` 会 PASS 而 `receipt_chain` 判 FAIL。这正是「一致性 ≠ 来源」
的实例，也是为什么两道关都要跑。刻意留出的这个边界被写成了显式用例
（`tests/test_trace.py::TestTraceInCircuit::test_in_circuit_blind_to_last_element_forgery`
与 `TestVerifyCertTraceBinding::test_forged_last_element_caught_by_gateway_key`），
详见 [`security-model.md`](../security-model.md) §5。

`--semantic-dir` 指向存放 `vk.ezkl` / `settings.json` / `kzg.srs` / 陪伴证明的目录。
**策略含语义规则时必给** —— 那些规则没有被 SP1 证明判定，缺了材料就无从判断，
按 fail closed 判 FAIL（而不是"跳过"）。更要紧的是 `--response`：陪伴证明的公开实例里
有 `encode(T)`，验证方拿 T′ 重算才能把证明绑到**送达的**响应上（信任边界 ③）。

#### `RESULT` 与 `合规` 是两行，不要只看第一行

验证结束时会打印两行：

```
RESULT: PASS | FAIL      ← 这张证书**是不是真的**（签名/绑定/证明都对得上）
合规: PASS | FAIL | 未核  ← 证书说的是不是「策略满足了」
```

一张**如实记录违规**的证书同样是**真**证书（`RESULT: PASS` 而 `passed=false`），
仓库里 `--expect violate` 的演示就依赖这一点，所以二者不能合并。
而 `outcome.passed` **只覆盖 SP1 判得了的约束** —— 被委托出去的语义规则不在其中。
少了 `合规` 那行，一张 `passed=true` 而语义规则没过的证书会被读成合规，
而那正是本项目的头号失败形态（P0-1）。现场输出见
[`../design-semantic-rules.md`](../design-semantic-rules.md) §7。

### 2.6 `ezkl_prove.py` —— 语义规则的 ezkl 出证（P2-9）

```bash
python3 scripts/ezkl_prove.py setup      # gen_settings → compile → gen_srs → setup（每策略一次）
python3 scripts/ezkl_prove.py prove      --response T.txt
python3 scripts/ezkl_prove.py verify
python3 scripts/ezkl_prove.py selftest   # 四条文本端到端自检（含同形异义反例）
python3 scripts/ezkl_prove.py info       # 产物尺寸与口径
```

**`setup` 与 `prove` 必须分进程跑** —— 出证峰值 ~8.7 GiB、setup ~4.8 GiB，
两段叠加会在 12 GB 机器上 OOM。这不是建议，是实测出来的硬约束（`08` §3.5）。

两个最容易踩空的口径，都写在脚本 docstring 里：

1. **`run_args.input_scale` 必须为 0**（= 1）。ezkl 里**消费下标**的算子
   （`Gather`/`OneHot`）拿的是**缩放后**的值，而算术算子拿**解量化后**的值。
   用常见的 `input_scale=7` 会让 `Cast` 把 `id/128` 截断成 0 —— 全序列变 PAD、
   模型输出一个**常数**，而**证明照样验证通过**：症状看起来像"训练失败"。
   `patch_settings` 强制这个值，`check_settings` 在验证方侧再核一遍。
2. **响应超过 `MAX_CHARS` 时 `prove` 报错退出**，而不是截断 —— 静默截断会让尾部
   内容逃过判定。策略必须自带一条 `max <= MAX_CHARS` 的 `length_bound`
   （编译期强制，见 `policydsl/compile.py::require_covering_length_bound`）。

### 2.7 `compose_proof.py` —— 组合证明（P1-6）

```bash
SP1_PROVER=cpu python3 scripts/compose_proof.py \
  --pack policy_packs/eu_ai_act_v1.json \
  --response scripts/examples/eu_agent_reply.txt \
  [--out-dir scripts/examples/out/compose] [--nonce auto|none|<hex>] \
  [--proof-mode core|compressed|groth16|plonk] [--no-prove] [--reuse-proofs]
```

组合义务 `Compose = (推理完整性 ∧ 策略合规)`：**两份证明** ——
策略半用 `--job policy`（`pop-program`），推理半用 `--job infer`（`pop-infer`）——
再合成一张 `composite.json` 并当场独立验证一遍。收尾打印两行，口径与
`verify_cert.py` 相同：

```
RESULT: PASS | FAIL           ← 这张**组合证书**是不是真的
组合义务(Compose): PASS | FAIL ← 策略那一半是不是**确实合规**
```

四个容易踩空的点：

1. **两半必须分进程跑**。一个进程里连出两份证明会在第二份的 `setup` 阶段被
   OOM killer 终止（各 ~10.2–10.5 GiB 峰值，12 GB 机器；实测见
   `bench/results/compose.md`）。脚本本身就是两次 `pop-script`。
2. **`--reuse-proofs` 沿用已有的两份证明，只重跑合成 + 验证** —— 改
   `policydsl/compose.py` 后不必再花 4 分钟出证。它不重新校验证明是否对应本次
   `--response`，但尾部验证会现场重算 `response_binding`，对不上即 FAIL。
3. **`nonce` 出证时落在 `out-dir/nonce.hex`**。绑定里含 nonce，所以
   `--reuse-proofs` 必须沿用同一个 —— 脚本会自动读回；读不到就报错退出，
   **不会**默默换一个（换了必然 FAIL）。
4. **`--no-prove` 不产组合证书**。它只跑宿主校验（两端判定逻辑对齐 + Rust↔Python
   参考实现逐位一致），并**如实打印**「未产出组合证书」—— 组合证书的输入是两份
   **证明**，宿主校验替代不了。

**推理半是代理**（`policydsl/infer.py`，16→32→4 定点 MLP），不是 zkAgent ——
见 [`../../bench/results/compose.md`](../../bench/results/compose.md) 与 L6.2。

### 2.8 `prove_session.py` —— 会话聚合证明（P2-10）

```bash
python3 scripts/prove_session.py \
  --session scripts/examples/out/e2e/session.json \
  [--run N] [--nonce-hex <hex>] [--keyring <公钥>] \
  [--proof-out <f>] [--proof-mode core|compressed|groth16|plonk] [--no-prove]
```

把 `session.json` 里**同一个 run 的流式证书**按序取出（`--run` 选第几个；
不选则全部），证「①同一策略 ②链无缝无缺口 ③覆盖完整轨迹」三条义务，
用 Merkle 根把 N 张证书摘要聚合成**一次**证明。每个 run 打印三行：

```
  merkle_root / policy_hash / trace_root  ← Python 参考实现现场重算
  [ ok ] parity  Python == Rust（9 个公开字段逐一相等）  ← 与 pop-script --check --job session 对拍
  [ ok ] verify  …                                        ← 真证明的独立验证（--no-prove 时跳过）
```

五个容易踩空的点：

1. **`--no-prove` 不做任何证明**，只跑「Python ↔ Rust 同聚合」对拍 —— 输出里会
   明确写「**不要把上面的重算当成已出证**」。别把对拍结果读成出证结论。
2. **只出证，不验签**。不给 `--keyring` 时验证环节会如实注明「seal 签名未验」；
   「这条链网关真的签过」要另外给 `--keyring`（或跑 `verify_session.py --gateway-key`）。
3. **一次证明只覆盖一个 run，且只覆盖链上证书**。一个 run 的权威 `on_llm_end`
   证书没有 `streaming.chain`，按内容被判在 run 之外（`policydsl/session.py::runs_of`）——
   这是**设计如此**，不是漏了：它在链外的另一套核对里（`verify_session.py`）。
4. **`--nonce-hex` 是重放新鲜度的旋钮**。缺省随机取 16 字节并打印；`session_binding`
   含 nonce，所以验证必须用同一个 —— 脚本内部自己传，跑一次就够了。
5. **没有 seal 的证书集会被拒**（义务 ③），这是**如实拒绝**：拿旧版 `demo_e2e`
   在盘留下的 `scripts/examples/out/*/session.json` 去出会话证明就会撞上这一条
   （那些 bundle 生成于「每张流式证书都附 `gateway.seal()`」落地之前）。
   用当前代码重跑 `demo_e2e.py` 得到的证书集每张都带 seal。

### 2.9 `prove_multiparty.py` —— 多证明者（P2-11）

```bash
python3 scripts/prove_multiparty.py \
  --pack policy_packs/multiparty_demo_v1.json \
  --response scripts/examples/eu_agent_reply.txt \
  [--out-dir <d>] [--role-keys <私钥目录>] [--nonce-hex <hex>] \
  [--receipts receipts.json] [--proof-mode core|compressed|groth16|plonk] [--no-prove]
```

按**规则类**把一条策略切成三段（模型方 / 工具网关 / 部署方，切割依据见
`policydsl/multiparty.py::KIND_OWNER`），各角色用**自己的键**对**自己那段**出证并签名，
合成 `multiparty.json` + `multiparty.keyring.json`（只有公钥）。脚本末尾会拿真工件
**现场造两个假**，把计划 §P2-11 的两条验收判据跑一遍：

```
--- 验收 ①：去掉一个角色的签名 ---        → 三个角色各试一次，都必须被拒
--- 验收 ②：单角色切片被换（用该角色自己的键重签）---  → 必须被拒
RESULT: PASS   ← 三段出证/签名/验证全过 **且** 两条判据都按预期被拒
```

四个容易踩空的点：

1. **`--no-prove` 不产生证书**（不是「证书没有证明」——那种证书根本组不出来，`build` 会
   fail closed）。这一档只做「切完之后 Python 参考实现与 Rust 宿主校验算的还一不一样」的
   对拍，输出里**明说**「这不是证明、没有产生证书」。别把它读成出证结论。
2. **缺省用一次性密钥**，打印时**如实标注**：它们不进任何证据链，重跑一次就再也验不了旧证书。
   要可复现就用 `--role-keys DIR`（落盘私钥 0600，gitignored）。
3. **角色密钥必须两两不同**（`verify_multiparty` 第 2 步）。共用一把键会让「这一段是谁证的」
   无从判定，脚本不拦你生成，但验证会拒。
4. **三方合谋改 `plan` 是挡不住的** —— 三把键一起改、一起重签，签名层完全自洽。只有拿
   `policy_pack` 现场重编译并比对 `plan` 才拦得住（`verify_multiparty(..., policy=…)`）。
   这条边界在 `tests/test_multiparty.py::test_colluding_roles_rewritten_plan_needs_the_pack`
   里被钉成「不带策略包时**会通过**」。

### 2.10 `demo_e2e.py` —— 一键真实会话

五段，除**生成那一段缺省用离线桩**外，其余都用**真实**组件（`--no-prove` 只跳过
SP1 证明）。生成那段要真模型得显式给 `--model`：

```bash
python3 scripts/demo_e2e.py --model openai:gpt-4o-mini        # 裸名按 openai 处理
OPENAI_BASE_URL=http://127.0.0.1:8000/v1 python3 scripts/demo_e2e.py --model openai:<m>
python3 scripts/demo_e2e.py --model anthropic:claude-sonnet-5 # 需 ANTHROPIC_API_KEY
```

**缺省不传真模型**，因为 CI 与 `demo_all.sh` 不该依赖网络与 key。规格由
`policydsl/llm.py` 解析：未知 provider、空模型名、缺 key 都在**构造时**报错并
说清是哪一个环境变量（`OPENAI_API_KEY` / `ANTHROPIC_API_KEY`），**绝不静默退回
桩** —— 静默退回会让一份「真模型演示」的产物其实来自写死的字符串，而且没人看
得出来。终端那行 `llm model : …` 就是这件事的如实交代，它**永远**打印。

0. **一次会话只有一条轨迹**：先建**唯一**那把 `trace.ToolGateway()`，注入下面的
   工具守护与内容 handler。此前两处各自缺省构造 ⇒ 内容链与工具链的 `trace_root`
   指向两条不同的链（#99 修的缝）。次序是**先工具、后生成** —— 真实 agent 就是
   「先调工具拿材料，再写答复」，而且这样内容证书的 `trace_seal` 覆盖的正是
   **会话终态**那条链（seal 是签发那一刻的末端承诺，晚签才盖得全）；
1. **MCP 工具路径**：真实 `stdio_client` 起 `tests/mcp_echo_server.py`，
   调用 `search_kb`（干净）、`dump_config`（秘密结果）、带 `token` 参数的调用（**飞行前拦截**）。
   **工具清单问服务器要**（`await guard.discover_tools(session)`，即 MCP 的 `tools/list`），
   不写死 —— 打出来的 `mcp tools : N discovered from server (…)` 就是服务器当场报的名单；
   脚本还会核对 `search_kb`/`dump_config` 确实在里面，缺了就把名字记进
   `summary.mcp_tools_missing`（写死的名字在服务器改名之后不会报错，只会静默地跑成另一次调用）；
2. **LLM 流式路径**：流式两次 —— 一次干净、一次中途泄露 `sk-…` 触发**真早停**
   （`hard_stop=True`，流被 `EarlyStop` 掐断，离线桩上实测在 5/38 字符处，
   密钥**没有**到达调用方）与链式证书。缺省用 `GenericFakeChatModel` 的离线桩；
   `--model` 则换成真实模型，提示词随之改为「问一句正常问题」与「把这一行原样
   回显」（主动请模型踩线，好让 `no_secret` 有条规则可命中）。
   **触发与否是数据相关的**：真模型不照做是**正常结果**而非失败，`aborted` 实测
   值如实落盘 —— 任何「模型一定会违规」的断言都是在赌 provider 的服从性。
   真模型下 `full_len` 是 `null`（不是「暂时未知」而是**不可知** —— 量全长就得先
   让它写完，那等于取消这次早停），改报 `canary_len`（请它回显的那行有多长）；
3. **zk 路径**：对一条响应真实出证（`zk_path`）——**走完整挑战流程**：客户端先出
   `nonce = challenge.new_nonce()`，把它喂进向量与证书 `challenge` 块（`--nonce` 可覆盖），
   出证后再用「送达的 T′」离线核对绑定（`challenge_experiment`：`T′` 能开、
   篡改后的 `T′` 打不开、换 nonce 打不开），vkey 哈希、证明哈希与**证明模式**
   （`proof_mode`，取 pop-script 写的 `.meta.json`；`--no-prove` 时为 `unproven`）
   一起绑进证书；
4. **公私模式对比**（`mode_contrast`，`--no-contrast` 可跳过）：拿**同一条响应、
   同一个 nonce**分别走 `public` 与 `private` 两次 `zk_path`（输出到 `zk_public/` 与
   `zk_private/`），再把两份 `outcome` **现读**成一张并排表 —— 表里每一格都来自证书
   本身，不是手写的说明文字，所以策略一改这张表跟着变：

   ```text
   验证方能看到           公开模式                                                   私有模式
   结论 passed            False                                                      False
   策略指纹 policy_hash   ffb2722e19d886c6…                                          ffb2722e19d886c6…
   命中了哪几条规则       no_bad_topics no_secret                                    no_bad_topics no_secret
   每条规则的证据         no_bad_topics「exploit」, no_secret「sk-[A-Za-z0-9]{16,}」 no_bad_topics 04da09655d48e492…, no_secret 71a60a1657d3fe25…
   响应本身的承诺         —（该模式不承诺 T）                                        28df5e47336a061b…
   脱敏见证               —                                                          mask_count=29 mask_covered=True
   ```

   要点：两行的 `policy_hash` 与 `passed` **必须相同**（同一个 T、同一条策略 ——
   这是对比成立的前提，脚本自己断言）；差别只在**验证方看得见什么** —— 公开模式把
   命中的那个词**逐字**写进证书（`no_bad_topics「exploit」`），私有模式只给
   `evidence_commitment`，外加 `response_commitment` 与脱敏见证。随后再演示私有模式
   真正的出口：**证据选择性开示**（`commit.evidence_bundle` 自洽、与证书里的承诺
   **逐条相符**、篡改一件被拒）—— 公开模式没有这一步，因为证据本来就是明文。
   这两张证书也进 `session.json`（`kind` 同为 `"zk"`），所以 `verify_session.py`
   会顺带一起验，对比演示**不额外开一条验证旁路**；
5. **锚定**：每张证书的 `cert_digest` 入账本；给了 `--rpc/--contract` 就**同时上链**
   （成功后回写 `meta.on_chain`）。

> ⚠️ **第 4 步默认只做宿主校验，两张证书都标 `unproven`** —— 这不是为了省时间，
> 是**证不了**：用本 demo 的 `agent_content_v1`（3 条规则、含 `pattern_block`）出证，
> **公开模式能过、私有模式不能**。本机 11.9 GB 上实测被内核 OOM-kill，
> `anon-rss` **10.391 GiB**，而本机可用天花板约 **10.385 GiB**
> （对照：`private_demo.py` 那条更小的策略峰值 10.383 GiB **能过**）。
> 私有模式的**真证明**由支路② `private_demo.py` 承担。
> ≥16 GB 的机器可以加 `--contrast-prove` 让对比也出真证明。
> `--no-contrast` 则整步跳过。
>
> 混合会话（1 张真证明 + 2 张宿主校验）在 `verify_session.py` 里是**分别计数的**：
> `zk_proof` 那一行会印成 `SP1 proof verified (pop-script) + unproven (host-check only)×2`，
> 不会因为最后一条是 unproven 就把验过的证明说没了。

每张证书都用 Ed25519 签名：demo 缺省生成一把**临时**密钥（`--key` 可换成落盘私钥），
公钥写进 `session.json` 的 `signers` 字段并打印（`signer : ed25519:…` + `public_hex=…`）。
私钥不落盘、也不进会话包 —— 第三方拿到的是**只能验、不能签**的公钥。

产出 `session.json`（含 `signers` 公钥记录、`certificates` 列表、`summary`
（多一项 `challenge_bound`、`zk_proof_mode`、`mode_contrast`、`tool_trace`、
工具清单 `mcp_tools`/`mcp_tools_missing` 与早停实测 `early_stop`）、
顶层的 `challenge` 记录、以及有链时的 `chain` 坐标），

> `summary.tool_trace`（P1-5）= `{receipts, trace_root, gateway_keyid, gateway_public_hex, seal}`：
> 链长、链尾摘要、工具网关公钥与**会话末端承诺**（`seal`，P1-5b）。前四项都是**公开坐标** ——
> 验证方拿网关侧收到的回执重算最后一条的 `SHA256`，即可核对「这份证明绑的是哪条链」，
> 与 `challenge` 之于响应完全对称；`seal` 更进一步回答「这条链**到此为止**」，因此是
> 「链尾有没有被整条删掉」的唯一依据（见 [`../security-model.md`](../security-model.md) §5.3）。
末尾提示用 `verify_session.py` 验证。**上文各处引用的「13 张证书」就是这一次运行的产出**
（`stream=4 llm=1 tool-args=3 tool-result=2 zk=3`）。

> **为什么 `llm` 只有 1 张**：两次流式运行里，干净那次正常收尾 → 一张权威的 `llm` 证书；
> 违规那次被**真早停**掐断（`hard_stop=True`），生成没有正常结束 → 那次**没有**权威证书，
> 只留下流式链上的 3 张：前两个判定沿（首次判定、判定翻转）各一张部分证书 + 一张
> `streaming.stop` 的停止证书（带 `reason: violation` 与链头指针）。
> 「被掐断的生成没有最终结论证书」是**如实**的 —— 它的结论就是那张停止证书。
> 早停实测随会话一起落盘：`summary.early_stop`（`aborted` / `delivered_len` /
> `full_len`（真模型下为 `null`，见上）/ `canary_len` / `leak_delivered` /
> `clean_aborted` / `clean_len` / `model` / `model_spec`）。
> `leak_delivered` 是那条硬指标，它必须是 `false`。

### 2.11 `verify_session.py` —— 第三方验证整个会话

```bash
python3 scripts/verify_session.py --session S [--keyring 公钥] \
    [--rpc URL --contract 0x…] [--no-chain]
```

检查项：`keyring`（**P0-3 前置**：拿不到公钥就直接 FAIL，不静默跳过）/ `ledger_chain` /
`certificates_signature` / `certificates_policy_hash` / `certificates_response_binding` /
`certificates_proof_mode` / `certificates_vkey_label` / `certificates_anchored` /
`stream_chains` / `zk_proof`（+ 可选 `chain_anchored`）。

细节：

- 公钥来源优先级：`--keyring` → `session.json` 的 `signers` 字段 → 同目录 `key.json`。
  一条 `signers` 记录同时带 `keyid` 与 `public_hex`，装载时会**校验两者一致**
  （否则「按 keyid 选密钥」就失效了）。

- `policy_hash` 用 `spec_cache` 缓存，同一策略包只编译一次。
- 流式链按 `chain.index == 0` **切分成多个 run**（一次会话可能有多次流式生成），逐个 `verify_chain`。
- zk 证明：有边车且模式允许 → `pop-verify` 快路径；否则 → `pop-script --verify`（core）。
- **`chain_anchored` 的交叉核对**是本脚本最有价值的一段（见 [`04`](04-anchoring-audit.md) §4）：
  逐证书读链上 `anchoredAt`，并与本地账本 `meta.on_chain` 的 `chain_ts`/`block` 三方对上。
- 未附证明的证书（`proof_sha256 is None`）会被正确地判为 `unproven (host-check only)`，不算失败。
- `certificates_proof_mode` 是个**双条件**检查：标了某档模式就必须真有工件
  （`proof_sha256` 非空），附了工件就不许标 `unproven`；缺字段的旧证书单独计数
  （`N cert(s) labeled, M predate the field`）。`zk_proof` 那一步还会再拿
  **工件自报的模式**核对一次（多来源必须一致）。
- `certificates_vkey_label` 是**同构的第二条**（`verify_cert.py` 对应 `vkey_label` 卡）。
  `binding.vkey_hash` 的语义是「**哪块电路**判定了它」—— 指向 `pop-program` /
  `pop-infer` / `pop-session` 三块 guest ELF 各自派生的验证密钥。而宿主判定的三类
  证书（stream/llm/tool）**没有电路参与**，没有验证密钥可指，唯一诚实的取值就是
  `unproven`。判据同样双向：未附工件却声明 vkey = **过度声明**；附了工件却标
  `unproven` = **低报**，两者都 FAIL。
  > **这条卡是补上的**：在此之前 `vkey_hash` **一条不变量都没有** —— 上面几张卡
  > 只比对「证书 vs 证明」，从不问这个值**本身**是否可能是真的。于是
  > `demo_e2e.py` 里写过的魔法值 `"demo"` 可以**全绿通过验证**：一个有内容、
  > 却没有任何东西能证伪的字段。现在它会被当场判 FAIL
  > （`tests/test_policy_binding.py::TestVkeyLabelHonestyRejected` 用 `"demo"`
  > 本身作为反例锁住）。

### 2.12 `deploy_anchor.py` / `make_shots.py`

- `deploy_anchor.py`：`--rpc`（默认 `http://127.0.0.1:8545`）、`--private-key`（默认 `anchor.ANVIL_KEY`）、
  `--out`（默认 `.anchor_deploy.json`，gitignored）。**不需要 solc/forge**，字节码来自
  `contracts/Anchor.json`。末尾打印 `export POP_ANCHOR_RPC=… / POP_ANCHOR_CONTRACT=…`。
- `make_shots.py`：`--run-demo` 会先跑 demo 再生成 `docs/demo/session_report.html`、
  `session_report.svg`、`session_summary.png`、`verify_result.png`。

---

### 2.13 `gen_key.py` —— 出证方密钥对（P0-3）

```bash
python3 scripts/gen_key.py [--out-dir D] [--path P] [--name demo] [--force]
python3 scripts/gen_key.py --show                     # 读已有私钥、只打印公钥，不写盘
python3 scripts/gen_key.py --pubkey keys/demo.pub.hex # 只有公钥时算 keyid
```

产出 `<name>.key`（PKCS#8 PEM，`0600`，**已存在则拒绝覆盖**，要轮换请先删除或用 `--force`）、
`<name>.pub.hex`、`<name>.pub.pem`，并打印 `keyid`（`ed25519:<sha256(原始公钥)>`）、
公钥 hex 与 PEM。

验证方只需要 `--pubkey` 那一路（**永远不读私钥**）：

```bash
python3 scripts/verify_cert.py --cert c.json --pack p.json --ledger l.jsonl \
    --keyring keys/demo.pub.hex
```

私钥路径的解析顺序：`--path` > `$POP_SIGNING_KEY` > `.pop-keys/signing.key`（已 gitignore）。
设 `$POP_SIGNING_KEY_PASSPHRASE` 则私钥以口令加密落盘；不设则为明文 PKCS#8，依赖文件权限。

---

### 2.14 `proof_service.py` —— 证明服务（第二步）

```bash
python3 scripts/proof_service.py --host-check      # 演示/边缘：作业几秒，证书标 unproven
SP1_PROVER=cpu python3 scripts/proof_service.py    # 真证明：~2.5 分钟/作业，峰值 ~10.2 GiB
python3 scripts/proof_service.py --rpc http://127.0.0.1:8545 --contract 0x… \
  --auth-file /etc/pop/tokens --require-auth       # 生产的样子：同时上链 + 鉴权
```

给了 `--rpc` 与 `--contract` 就**同时**把证书摘要登记进链上 `Anchor` 合约
（**两个必须同时给**，只给一个**拒绝启动** —— 静默退回文件账本的那种错没有症状：
证书照样签得出来、账本照样自洽，等到有人去链上查那份摘要才发现从来没有过）。
`/v1/health` 多出 `anchor_backend` 与 `chain{healthy, detail, age}`；链已知断时
`/v1/check` 与 `/v1/attest` 都返 `503`，且在**收下作业之前**就拒（免得用 ~2.5 分钟
+ ~10.2 GiB 去回答一个启动时就有答案的问题）。

库在 `policydsl/service.py`（+ `policydsl/auth.py`），本脚本只做 HTTP（**纯标准库
`http.server`**，零新依赖）。**默认只绑 `127.0.0.1:8787`**；没配 token 时**默认无
鉴权**（`/v1/health` 的 `auth.mode` 会如实写 `none`），配上 `--auth-token` /
`--auth-file` / `$POP_SERVICE_TOKEN` 之后**作业只对提交它的那把 token 可见**。
运维细节、排查表、已知边界见 [`docs/runbook-proof-service.md`](../runbook-proof-service.md)。

两段接口（理由：宿主判定毫秒级、SP1 证明 ~2.5 分钟，差 4 个数量级）：

| 方法 | 路径 | 干什么 |
|---|---|---|
| `POST` | `/v1/check` | 宿主判定（Python 参考评估器）+ **unproven** 证书，**毫秒级、不占队列** |
| `POST` | `/v1/attest` | 入队，返 `202` + `job_id` + `queue_position` |
| `GET` | `/v1/attest/{job}` | `queued` / `proving` / `done` / `failed`。**服务重启后仍答得出来**（记录在 `<out-dir>/jobs/<job_id>/job.json`，产物是权威、记录是索引） |
| `GET` | `/v1/health` | 并发上限 / 队列深度 / 计数（运维看的） |
| `GET` | `/v1/policies` | 已注册策略（含 `serviceable` 标注） |

```bash
curl -s localhost:8787/v1/check -H 'Content-Type: application/json' \
  -d '{"policy_id":"agent-content-v1","response":"Leak sk-abcdefghijklmnopqrstuvwxyz now"}'
# → 200，passed=false，proof_mode="unproven"，含 challenge nonce 与 verify_hint（可直接粘贴）

curl -s -X POST localhost:8787/v1/attest -H 'Content-Type: application/json' \
  -d '{"policy_id":"agent-content-v1","response":"...","nonce":"<上一步回的那个>"}'
# → 202 {job_id, state:"queued", queue_position}
```

请求体可带 `receipts`（工具网关签发的回执，P1-5）：给了才判得了工具类规则，
并且会落盘成 `receipts.json`，让 `verify_cert.py --receipts` 那条有第二个来源可比。

**状态码的取法**：

| 码 | 什么时候 | 为什么是这个码 |
|---|---|---|
| `401` | 没带 / 带错 `Authorization: Bearer …`（仅在配了 token 时） | 带 `WWW-Authenticate`；且**区分「格式错」与「token 错」**，否则 401 会把人引去怀疑 token 本身 |
| `429` | 队列满（`concurrency + max_queue`，缺省 9） | 该做的是**退避重试**；`503` 会被读成「服务坏了」，而队列满恰恰说明服务是好的，只是不想把活儿收下之后 OOM |
| `429` | 某把 token 超出配额（`--rate`/`--burst`） | 两种 429 **语境不同**：队列满要等或换机器，配额满要降速。按 **token** 分桶而不是按 IP（一个 NAT 出口后面是一整个机房） |
| `404` | 策略 / 作业不存在，**或作业不是你的** | 后一种报 404 而不是 403：403 等于确认「这个 id 存在」，那就成了探测别家 job_id 的预言机。两种情况措辞**逐字相同** |
| `400` | 缺字段 / 策略含语义规则（见下） | 报错里说清楚是哪一条、怎么办 |
| `413` | 请求体超 1 MiB（**不读正文**就回） | `http.server` 会把声明的字节全读进内存 |
| `503` | 链上账本不可用（给了 `--rpc`/`--contract` 而链不通） | 不是 `500`：`500` 是「这个服务坏了，别重试」，`503` 是「依赖暂时不可用，待会儿再来」。报错明说「**没有签发证书**」，免得调用方去找一个不存在的产物 |

**一处刻意的能力边界**：含语义规则（`semantic_bound`）的策略**当场拒**（400）。
陪伴证明只存在于 `issue_cert.py` 那条命令行路径，服务发一张 `delegated` 非空却没有
`companion` 的证书只会「看起来验过了」。`GET /v1/policies` 里如实标
`serviceable: false`，不等到调用时才说。

**队列位是「预留-归还」的**：被拒的请求（未知策略 / 不可出证 / 参数错）**不占位**，
作业无论成功失败都归还位 —— 否则一次参数错误会永久吃掉一个队列位，服务越跑越满
且没有任何日志解释为什么。

**失败要翻成人话**（`service.failure_reason`）：真证明在本机最常见的样子是
`pop-script` 被 OOM killer 杀掉，而 `CalledProcessError` 的原样输出是**一屏临时路径**
加 `<Signals.SIGKILL: 9>`，唯独没说原因。信号类失败因此被翻成「多半是内存不足 +
~10.15 GiB 地板 + `dmesg | grep -i 'killed process'` 的核实法」，其他信号如实说
信号号、不甩锅给内存。这条是**被真事逼出来的**：`POP_TEST_PROOF=1` 那条验收用例
2026-09-13 在本机（11.7 GiB）与别的进程并跑时被 OOM 杀在 9.7 GiB 常驻 —— **腾空后
重跑通过**（171.1 s）。也就是说这台机器装得下这一次证明，但**没有余量**：`MemAvailable`
中途一度只剩 0.15 GiB。

## 3. Shell 脚本

### `demo_all.sh` —— 全链路总入口

```bash
bash scripts/demo_all.sh              # fast：走宿主校验（--no-prove），约 20 秒
bash scripts/demo_all.sh --prove      # 出真证明，每条支路数分钟、峰值 ~10 GB，本机实测 26–27 分钟
bash scripts/demo_all.sh --out-dir D  # 产物与报告落 D（默认 scripts/examples/out/all）
bash scripts/demo_all.sh --list       # 只列支路，不跑
```

**它存在的理由**：本项目的端到端能力分散在 8 条支路上，`demo_e2e.py` 只覆盖其中
「公开模式主干」一条，但第一次读仓库的人跑完它很容易以为链路已经全覆盖了。

依次跑这 8 条（顺序即依赖顺序）：

| # | key | 支路 | 驱动 |
|---|---|---|---|
| ① | `policy` | 公开模式主干（**含公私对比**，见 §2.10 第 4 步） | `demo_e2e.py` |
| ② | `private` | 私有模式六实验（① 里的对比只覆盖「同一条 T 两种模式」；这一条挖得更深：泄漏/绑定/证据/证明） | `private_demo.py` |
| ③ | `semantic` | 语义规则（P2-9） | `ezkl_prove.py selftest` |
| ④ | `compose` | 组合证明（P1-6） | `compose_proof.py` |
| ⑤ | `session` | 会话聚合（P2-10） | `prove_session.py` |
| ⑥ | `multiparty` | 多证明者（P2-11） | `prove_multiparty.py` |
| ⑦ | `anchor` | 链上锚定（P7-c） | `anchor_e2e.sh` |
| ⑧ | `verify` | 第三方独立验证 | `verify_session.py` |

**结果三态，必须分开读**：`PASS` / `FAIL`（该步真的失败了，退出码 1）/ `SKIP`
（缺依赖 —— 未装 ezkl、缺 `semantic/artifacts/`、未装 foundry、或上游 `session.json`
没产出，**不代表功能不存在**）。⑤⑧ 依赖 ① 的产物，① 失败时会级联成 SKIP 并写明原因。

耗时与峰值用 `/usr/bin/time -f %M` 量；没有 `/usr/bin/time` 时退化成 `date`，此时报告里
峰值列显示 `-` 而不是编一个数。产物：`REPORT.md` + `logs/<key>.log`。

报告末尾**现推**三条最容易被误读的结论（从合约 ABI、demo 源码、安全模型原文里读，
所以不会随文档更新漂移）：① 链上只锚定证书摘要，没有 `anchorWithProof`；
② 流式路径的「LLM」**缺省**是 `GenericFakeChatModel`（`--model` 可换真模型，终端会
如实打出当前用的是哪个）；③ 组合证明里的「推理」是 stand-in。
细节见 [`../../README.md`](../../README.md) 的「8 条端到端支路」。

> ⚠️ **fast 模式下的 `PASS` 不是「已出证」** —— 各驱动在 `--no-prove` 下只做
> Python ↔ Rust 宿主对拍。要真证明必须加 `--prove`。

### `anchor_e2e.sh` —— 端到端链上锚定（推荐入口）

```bash
bash scripts/anchor_e2e.sh                 # 不生成证明，~10s
SP1_PROVER=cpu bash scripts/anchor_e2e.sh --prove    # 附真实 Core 证明，本机实测 3:10 / 峰值 10.2 GiB
RPC=http://… bash scripts/anchor_e2e.sh    # 复用已有节点
bash scripts/anchor_e2e.sh --keep          # 结束后不关 anvil
```

步骤：① 找 foundry → ② 没节点就起 anvil（端口 `PORT`，默认 8545）→ ③ `deploy_anchor.py`
→ ④ `demo_e2e.py`（每张证书上链）→ ⑤ `verify_session.py --rpc` 独立核对
→ ⑥ **反例对照**：一个未登记的摘要必须读回 `0`。

结束后 `trap cleanup EXIT` 负责关掉自己起的 anvil（`--keep` 则保留）。
退出码：`0` 全 PASS，`1` 任一步失败。

### `make_audit_proof.sh` —— compressed 审计 fixture

生成一份**极小**策略（2 条规则 + 一句无命中的短响应）的 **compressed** 证明，
连同 `.bytes`/`.pv`/`.vkh`/`.meta.json`/`.verify.json` 一起放进 `circuits/testdata/audit_proof/`，
并把边车里的路径**重写成相对名**（避免把本机绝对路径带进仓库）。

有了 fixture，`tests/test_verifier_only.py` 的 2 个用例会自动启用（否则 skip）。
**本机 12 GB 内存下 compressed 会 OOM**，需 ≥16 GB 机器。

### 四个安装脚本

| 脚本 | 说明 |
|---|---|
| `install_ezkl.sh` | 创建独立 venv 装 **ezkl 栈**（`ezkl==23.0.5 / onnx==1.22.0 / torch==2.14.0`）。幂等（已装同版本则跳过）；`--check` 只检不装；**装前核版本**（版本错了会让陪伴证明与策略固化的 `onnx_sha256`/`model_vkey` 对不上）；装后冒烟 `ezkl_prove.py info`（`KeyError: 'settings_version'` 就是那时候撞出来的）；网络不通**快速失败**（退出码 2）而不是挂死；锁文件防并发。离线走 `--save-wheels` / `--offline` 两条路 —— 但 **wheelhouse 本身不入库**（torch 一个轮子几百 MB～2 GB，纯二进制、可由 pip 重下，`wheelhouse/` 已 gitignore） |
| `install_frameworks.sh` | 创建独立 venv 装 langchain / langgraph / mcp；索引按镜像顺序尝试，失败不致命 |
| `retry_install_frameworks.sh` | 网络受限版：按字节数探测镜像可用性后重试，带 `--trusted-host` |
| `retry_install_foundry.sh` | 装 foundry；官方 `foundryup` 常超时，实际走 `gh-proxy.com` 拉发行包 |

> 本机网络约束（github/crates.io 直连被限流）与具体镜像配置见
> [`../reproduce.md`](../reproduce.md) §0。**git 的镜像 `insteadOf` 必须保持仓库局部，不要设成全局。**

---

## 4. 常见组合

| 想做什么 | 命令 |
|---|---|
| 快速验证一套改动没破坏一致性 | `python3 -m unittest discover tests` + `cross_validate.py --no-prove` |
| 只看结论、不出证 | 给任意脚本加 `--no-prove`（走 `pop-script --check`） |
| 第三方复核一张证书 | `verify_cert.py --cert … --pack … --ledger … --keyring <公钥> [--proof …]` |
| 复核整个会话 | `verify_session.py --session session.json [--keyring <公钥>]`（公钥通常已在 `signers` 里） |
| **核对送达的 T′ 就是被证明的 T** | 上一条再加 `--response T′.txt`（P0-2，见 §2.5） |
| **核对被证明的轨迹就是我手上这条链** | 上一条再加 `--receipts receipts.json [--gateway-key gw.pub.hex]`（P1-5，见 §2.5） |
| **核对链有没有被截尾** | 上一条的 `--gateway-key` 是必要条件：seal 的签名与「会话末端承诺」都要它才立得住（P1-5b，见 `verify_cert.py` 的 3d 与安全模型 §5.3） |
| **一次看全 8 条支路** | `bash scripts/demo_all.sh`（真出证加 `--prove`；汇总在 `REPORT.md`） |
| 全链路最小复现 | `bash scripts/anchor_e2e.sh` |
| 生成论文/文档用的截图 | `python3 scripts/make_shots.py --run-demo` |

---

## 5. 约定与注意

1. **路径解析统一用 `REPO = Path(__file__).resolve().parent.parent`**，因此仓库改名/搬家不影响脚本
   （仓库曾从 `方向二` 改名为 `Proof-of-Policy`）。
2. **二进制路径固定**：`circuits/target/release/pop-script` 与 `pop-verify` —— 没构建时脚本会给出
   `cd circuits && cargo build --release -p pop-script` 的提示。
3. **`SP1_PROVER=cpu` 是硬要求**；`issue_cert.run_pop` 直接 `env=dict(os.environ, SP1_PROVER="cpu")`
   覆盖，`anchor_e2e.sh` 在调用处显式带上。
4. **退出码语义**：`0` PASS / `1` 比对或验证失败 / `2` 前置条件不满足（缺二进制、`--expect` 不符等）。
5. **产物目录约定**：`scripts/examples/out/<场景>/`；账本默认
   `scripts/examples/out/ledger.jsonl`。
6. **CI 只跑不需要 Rust 与网络的部分**（见 `.github/workflows/ci.yml`）：
   Python 测试套件 + 锚定测试（离线 fake-RPC）+ 一条「文档里没有陈旧绝对路径」的检查。

---

## 6. 测试对应

| 测试 | 覆盖的脚本 |
|---|---|
| `tests/test_verifier_only.py` | `verify_cert.py` / `verify_session.py` 的快路径判定 |
| `tests/test_demo_e2e.py` | `demo_e2e.py` 的会话产物结构 |
| `tests/test_binding.py::TestChallengedCertificateEndToEnd` | `issue_cert.py --nonce` → `verify_cert.py --response` 的完整闭环（含失败分支） |
| `tests/test_trace.py::TestVerifyCertTraceBinding` | P1-5 的第三方核对闭环：`verify_cert.py --receipts [--gateway-key]` 的 `trace_binding` / `receipt_chain` / `trace_seal`（含换链 / 重排 / 伪造链尾 / 截尾三路 / 缺公钥五个分支） |
| `tests/test_anchor_chain.py::TestAnvilEndToEnd` | `deploy_anchor.py` 的部署与读回 |
| （间接）`tests/test_rules_incircuit.py` | `cross_validate.py` 所用路径的单元版 |

---

## 7. 扩展指引

- **加一个新的验证维度**（如「策略包是否被多张证书一致引用」）：在 `verify_session.py` 的
  `results` 列表里追加一项 `(name, ok, detail)` 即可 —— 打印与退出码会自动跟上。
- **加一个新后端**：`anchor.backend_from_env` 认识新配置项后，`issue_cert.py` / `demo_e2e.py`
  **无需改动**（它们只调 `backend.anchor(...)`）。
- **把脚本接到 CI**：优先选 `--no-prove` 路径 + 离线 fake，避免在 CI 里跑证明或依赖网络。

---

**相关**：一键锚定的原理 → [`04-anchoring-audit.md`](04-anchoring-audit.md)；
完整复现步骤与环境要求 → [`../reproduce.md`](../reproduce.md)。
