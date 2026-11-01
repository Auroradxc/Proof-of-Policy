# 跨系统 / TEE 基线（P1-12）

**量测机器（本脚本）**：24 核 `Intel(R) Core(TM) i7-14650HX`，内存 14.6 GiB（`dxq`，x86_64）；Python 3.10.12。

> 每格都标 **measured** 或 **cited**。`cited` 一律给来源；没有取到的数字写 `—`，不猜。七列的证明义务不同，**不要**把这张表读成单一排行榜。

| 维度 | PoP | signed-Merkle | trusted-server / TEE (sim) | zkAgent | NiyamAI | Zaguk | PCO |
|---|---|---|---|---|---|---|---|
| **信任根** | vkey + 密码学假设（A1/A2）；无硬件信任、无「信网关」 `[m]` | Ed25519 网关钥；信「持钥的网关」 `[m]` | 服务器（或 TEE 硬件 attestation）；本模拟只测签名，不含硬件 `[m]` | zkVM 证明 + provider 的模型/工具执行承诺 `[c]` | zk-SNARK + SHA-256 Intent Contract + 神经 Judge `[c]` | ezkl zk-SNARK + SHA-256 输出承诺 `[c]` | 命名权威发布的谓词 + 独立 validator + 只追加账本 `[c]` |
| **延迟（出证 + 验证）** | 出证 118.89–172.50 s；纯验证 89.84 ms `[m]` | 签名 0.132 ms + 追加 2.131 ms；公开核验 0.322 ms；重跑核验 0.772 ms `[m]` | 服务端判定+签 0.139 ms；客户端验签 0.102 ms `[m]` | Shout: 194.40 s / 0.42 s；LogUp: ~1069 s / 0.038 s `[c]` | 1.7 s / 次获批动作；验证 51 ms `[c]` | 未报告可比数字（证明生成是主成本） `[c]` | — |
| **证明/证书大小** | 2.65–2.66 MiB（证明） `[m]` | 648 B 证书 + 761 B 包含证明 `[m]` | 648 B 证书；TEE 模拟 attestation 520 B `[m]` | Shout ~96 MiB；LogUp 3.1 MiB `[c]` | 18.6 KB `[c]` | 未取到具体数值（原文称随编码长度稳定） `[c]` | — |
| **响应隐私** | 有（私有模式：只给 response_commitment / response_binding） `[m]` | 无（验证者需 T 明文重跑；本仓库基线实测路径） `[m]` | 对验证者无（T 交给服务器）；TEE 可对服务器隐藏，本模拟不测 `[m]` | 承诺式（证明推理与工具轨迹，不公开明文） `[c]` | 未在摘要中单独报告隐私指标 `[c]` | 有（验证者不见输出前缀原文） `[c]` | 有（binding + hiding；证明在审计时披露） `[c]` |
| **策略隐私** | 有（策略进电路作私有见证；需 P-PP 才可问责） `[m]` | 无（验证者需 π 明文重跑） `[m]` | 无（服务器知道 π；验证者不需要） `[m]` | 不适用（无策略 π 这一义务） `[c]` | Intent Contract 以 SHA-256 承诺；证明不公开模型参数 `[c]` | 有（证明不公开过滤器参数） `[c]` | 部分（谓词由命名权威发布；验证者需规范） `[c]` |
| **验证者需要 T 明文？** | 否（私有模式下只给承诺） `[m]` | 是（不重跑 J(π,T) 无法确认 passed） `[m]` | 否（验证者只验签；服务器需要） `[m]` | 否（证明覆盖推理与工具轨迹） `[c]` | 未明确（摘要只称验证无需模型参数） `[c]` | 否（只给 SHA-256 输出承诺） `[c]` | 否（证明覆盖 (x,y) 满足谓词；输入真实性不在范围内） `[c]` |
| **验证者需要 π 明文？** | 否（只需 policy_hash 与 vkey；P-PP 除外） `[m]` | 是（重跑需要同一份策略） `[m]` | 否（验证者只验签；服务器需要） `[m]` | 不适用（无 π） `[c]` | 未明确（Intent Contract 以 SHA-256 承诺；摘要未说验证者是否需规范） `[c]` | 否（证明不公开过滤器参数） `[c]` | 部分（谓词由权威发布；验证者需规范或承诺） `[c]` |

`[m]` = measured（本仓库/本次运行实测）；`[c]` = cited（外部文献）。

## 本仓库实测的三臂

- **PoP**：出证 118.89–172.50 s，证明 2.65–2.66 MiB，峰值 RSS 10.3 GiB，纯验证 89.84 ms。来源：`bench/results/proofs.json, bench/results/verify.json`；那批数字的量测机是 24 核 / 11.7 GiB。
- **signed-Merkle**：签名 0.132 ms，追加 2.131 ms，公开核验 0.322 ms，重跑核验 0.772 ms，证书 648 B，包含证明 761 B。来源：`bench/results/baseline.json`。
- **trusted-server / TEE（模拟）**：服务端判定+签 0.139 ms，客户端验签 0.102 ms，证书 648 B；TEE 模拟 attestation 签名 0.040 ms / 520 B。**硬件 attestation 未测**，模拟件只量「度量 + 签名」这一步。

## 信任取舍（不是速度排名）

- **PoP**：验证者不需要 `T`/`π` 明文，也不信某台机器；代价是出证秒级到分钟级、证明 MiB 级，且 `core` 模式的零知识与策略问责仍需外部前提（`docs/sp1-zk-audit.md`、`docs/security-model.md` §4.6 的 P-PP）。
- **signed-Merkle**：亚毫秒，但验证者必须拿 `T` 与 `π` 明文重跑；换句话说，它把「验证」变成了「你有本事自己再算一遍」。
- **trusted-server / TEE**：验证者最省事（只验签），但把正确性押在服务器或硬件上；TEE 能移走「信运营方」，移不走「信厂商/固件」，且本表**没有**量硬件。
- **zkAgent**：证的是模型推理 + 工具轨迹，与 PoP 的「策略合规」正交，成本由推理证明主导。
- **NiyamAI / Zaguk / PCO**：与 PoP 的机制相邻，但义务/信任根不同；NiyamAI 守工具调用，Zaguk 守输出前缀的 PII 过滤，PCO 是证明携带输出 + 账本 + 监管。

## 来源（cited）

| 系统 | 来源 | 用于 |
|---|---|---|
| zkAgent | Lizheng Wang et al., zkAgent: Verifiable LLM Agent Execution via One-Shot Transcript Proofs, IACR ePrint 2026/199 — https://eprint.iacr.org/2026/199 | prove/verify time, proof size |
| NiyamAI | Aditya Katkar et al., NiyamAI - An Intent-Bound AI Agent with Cryptographically Verifiable Guardrails using Zero-Knowledge Proofs, arXiv:2608.07167 (2026-08) — https://arxiv.org/abs/2608.07167 | 1.7 s/action, 51 ms verify, 18.6 KB proof |
| Zaguk | Zaguk, JNIC 2026 proceedings (INCIBE), JNIC26-Acta-red.pdf — https://www.incibe.es/sites/default/files/eventos/JNIC/JNIC26-Acta-red.pdf | mechanism/qualitative only; exact numbers not extracted |
| PCO | Hillel Avni, Shlomi Dolev, Avraam Yagudaev, Moti Yung, Super-intelligence Survival Guide: Verification via Proof-Carrying Output, IACR ePrint 2026/994 — https://eprint.iacr.org/2026/994 | mechanism/trust model; no performance numbers reported |

> **诚实边界**：本文件不含任何本次新跑的 SP1 证明；PoP 列的数字来自已入库的 `proofs.json`/`verify.json`，量测机与本次脚本所在机器可能不同，已在上面分别标注。Zaguk 与 PCO 的原文在本次环境中未能取到完整性能表，因此这两列只写机制/定性，**不填数字**。

