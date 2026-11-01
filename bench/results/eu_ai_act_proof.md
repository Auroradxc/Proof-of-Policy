# 真实 EU AI Act 策略出证（X1d）

**口径**：host `autodl-container-14574f97ce-6e5bc639`（cgroup 16 核 / 92160 MB；宿主 128 核 / 754 GiB 仅记录）；
binary `7f99fdb1…`（sha256 `7f99fdb11a4a859c45598c384db3b98dd50426210adbc14d6b576c4d15dda49f`）；policy vkey `0x003eb14de80339bddef2b9207ef27469088267888bb9bebb9836b4ee701fd7be`；
commit `cf7bb54e06f2524885de0e335d7ff1a4250ddaeb`（binary 构建基线 `e45178b`，**post-NFA-fix**）；
单进程串行（`flock /tmp/pop-proof.lock`）；groth16 缓存
`/root/autodl-tmp/sp1-cache/groth16`（官方 v6.1.0，手工播种）。

**策略**：`eu_ai_act_v1`（3 条规则：`banned_high_risk_topics` keyword_block、
`disclosure_length` length_bound、`no_pii_email` pattern_block），
policy_hash `5b5fd101…`。

**响应**：`scripts/examples/eu_agent_reply.txt`（167 字符，
sha256 `3036f3a2…`）。**模式**：`public` —— 响应作为出证方输入进入
`vectors.json`，交付的证书/公开值只有承诺。

| tier | status | 墙钟 | 峰值 RSS | `proof.bin` | `cert.json` | hiding | verified | verify_cert |
|---|---|---:|---:|---:|---:|---|---|---|
| core | ok | 48.82 s | 12382.7 MB | 2,793,531 B | 1,846 B | none | ✅ | PASS |
| groth16 | ok | 301.19 s | 30073.9 MB | 1,874 B | 1,850 B | wrapper-only | ✅ | PASS |

## 读数

- **core**：48.82 s / 12.4 GB / 2.79 MB 证明；**groth16**：301.19 s / 30.1 GB /
  1,874 B 证明。groth16 的墙钟与内存大头在 STARK + 外层 MSM，与 X1c 的
  `agent_content_v1`（297–344 s / 29.7–35.1 GB）同量级。
- 两档都用 `scripts/verify/verify_cert.py --proof --response` 独立验过：
  `RESULT: PASS`，包括 **response_binding 由送达的 T′ 现场重算**
  （core `1654219c…`、groth16 `b3ee6a3e…`；两次 nonce 不同，故绑定不同）。
- `passed=True`、`violations=[]`：示例回复满足三条规则。
- **隐藏性**：core `hiding=none`（STARK trace 开值可见）；groth16
  `wrapper-only`（包装器层面隐藏见证，非后量子）。
- 证书交付物不含响应明文（见 `privacy_surface_real` 的响应子串探针），
  但 `response_commitment = sha256(T)` 是公开可重算的猜测-验证 oracle，设计如此。

原始工件在云机 `/root/autodl-tmp/x1d-work/eu-{core,groth16}/`（未入库）；
本文件与 `eu_ai_act_proof.json` 是回传的可审计摘要。
