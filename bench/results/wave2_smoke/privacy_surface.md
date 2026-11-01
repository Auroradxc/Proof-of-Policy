# 隐私面探针（P0-07 / Wave 2 X1）

**生成时间**：2026-11-01T07:13:54Z  **pack**：`/home/dong/Proof-of-Policy/03_代码仓库/zk-policy/policy_packs/agent_content_v1.json`  
**canary**：`POP_PRIVACY_CANARY_7f3a9c`  **响应哈希**：`ca2b53418cfc6e76…`

| tier | status | hiding | proof 文件 | canary 在文本 | canary 在证明 | 响应在任一文件 |
|---|---|---|---:|---|---|---|
| unproven | ok | n/a | 0 | 0 | 0 | 0 |

## 怎么读

- **canary 在证明里 > 0** = 该档**确定泄露** `T` 的明文；`core`/`compressed` 的 trace 开值本来就明文可见。
- **canary 在文本/证明里 = 0** 只说明这一组探针没找到，**不是**零知识证明；`groth16/plonk` 才在包装器层面隐藏见证。
- `response_commitment` 是公开、可离线重算的 `T` 的函数 —— 它本来就是猜测-验证 oracle；真正的攻击是**重执行**（E2）。
- `re_execution.status=skipped` 是诚实的：本脚本不跑模型；`bench_k_entropy.py` 负责测 `k`。

## 复现

```bash
python3 bench/bench_privacy_surface.py --tiers unproven --no-prove --out-dir bench/results
# 云机：
SP1_PROVER=cpu python3 bench/bench_privacy_surface.py --tiers core,groth16
```
