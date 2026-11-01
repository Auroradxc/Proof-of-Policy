# Wave 2 数据集

本目录由 `scripts/datasets/prepare_wave2.py` 生成；**不要手改 JSONL**。

## XSTest

- 来源：local
- 许可证：CC-BY-4.0
- 计数：450（safe 250 / unsafe 200）
- 文件：`prompts_xstest.jsonl`、`prompts_smoke.jsonl`
- 论文：Röttger et al., "XSTest: A Test Suite for Identifying Exaggerated Safety
  Behaviours in Large Language Models", NAACL 2024 (arXiv:2308.01263)

## τ-bench（可选）

- 未准备。用 `--taubench <tasks.json>` 或 `--download-taubench`。

- 上游：sierra-research/tau2-bench，`data/tau2/domains/airline/tasks.json`
- 注意：原始 `tau-bench` 的 tasks 已过时，Sierra 建议用 τ²/τ³。

## Enron（可选）

- 只登记路径与 sha256；解析用 `scripts/datasets/enron2pack.py`。
- 数据大、许可需自查；本仓库不随包分发。

## 用法

```bash
# 采样 + 实测 k
python3 bench/bench_k_entropy.py \
    --prompts scripts/examples/datasets/wave2/prompts_smoke.jsonl \
    --backend stub --n-samples 20 --temperatures 0,0.7 --out-dir bench/results

# 真实模型（OpenAI 兼容端点）
export OPENAI_API_KEY=...
python3 bench/bench_k_entropy.py \
    --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl \
    --backend openai:gpt-4o-mini --max-prompts 50 --n-samples 20 \
    --temperatures 0,0.7 --out-dir bench/results

# 端到端（响应级策略检查 + 可选证书）
python3 bench/bench_real_llm_e2e.py --samples bench/results/k_samples.jsonl \
    --policy policy_packs/safety_xstest_v1.json --out-dir bench/results --no-prove
```
