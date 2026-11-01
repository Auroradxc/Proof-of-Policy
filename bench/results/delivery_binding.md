# 交付绑定基准（f=0 / verifier-only / end-user）

**生成时间**：`2026-11-01T07:08:28Z` ｜ **每场景 trial 数**：200
**代码**：`bench/bench_delivery.py`（标准库 + Ed25519，无证明器）

## 结果

| 场景 | issuer | f (bits) | 诚实交付接受率 | divergent 接受率 | 重放接受率 |
|---|---|---:|---:|---:|---:|
| f=0 (empty nonce) | verifier | 0 | 1.00 | 1.00 | 1.00 |
| verifier-only (fresh V nonce) | verifier | 256 | 1.00 | 1.00 | 0.00 |
| end-user (fresh U nonce) | end-user | 256 | 1.00 | 0.00 | 0.00 |

**判据**

- ✅ `f0_replay_succeeds`
- ✅ `verifier_only_divergent_succeeds`
- ✅ `end_user_divergent_fails`
- ✅ `end_user_honest_succeeds`

**总判定：PASS**

## 怎么读

- **f=0**：nonce 为空，重放的是同一张证书 + 同一条 T，所以重放接受率为 1；
  这不是实现缺陷，是「没有新鲜性」的定义性后果。
- **verifier-only**：V 的 nonce 让 V 能核对 T_V；但 U 手上没有 nonce，证书里
  也没有 end-user 绑定，U 只能验签 —— **divergent delivery 仍被接受**。
  这正是 §4.6.3 验证者能力表里「终端用户只能绑到自己收到的那串」的缺口。
- **end-user**：U 出 nonce，证书 challenge 块带 `issuer=end-user` 与
  `end_user_binding`（新域 `pop-bind-enduser-v1`）。U 用 `(nonce, T′)` 重算：
  诚实交付通过，换货被拒。
- **重放**：f>0 时旧证书绑的是旧 nonce；新会话换 nonce 后旧证书对不上。
  若允许复用 nonce 且不记录已用 nonce，重放仍会通过 —— 这就是
  `NonceStore` 存在的理由。

## 边界

- 只测**证书 challenge 块**的交付绑定；电路公开值仍是 verifier 域
  `pop-bind-v1`（不改电路 / vkey）。见 `docs/blockers/C1.md`。
- 判据是**场景级**的接受/拒绝率（离散），不是统计优势估计；trial 数只用于
  排除偶发实现错误。

## 复现

```bash
python3 bench/bench_delivery.py --out-dir bench/results
```
