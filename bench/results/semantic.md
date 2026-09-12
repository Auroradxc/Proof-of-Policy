# 语义规则（ezkl / halo2）出证代价

模型 `semantic/model.onnx` sha256 `5931f59c6d2fedfb…`，MAX_CHARS=64，DIM=64，VOCAB=193。
图规模 **num_rows = 131270**。

| 阶段 | 耗时 | 体积 / 峰值常驻 | 频次 |
|---|---:|---|---|
| setup（gen_settings+compile+gen_srs+setup） | 48.2 s | 峰值 4.76 GiB | 每策略一次 |
| prove（每条响应） | 76.6 s（3 次中位） | 峰值 8.72 GiB，proof 40 KiB | 每条响应 |
| verify（每条响应） | 1.0 s | — | 每条响应 |

## 产物体积

| 文件 | 体积 | 入库 |
|---|---:|---|
| `settings.json` | 4 KiB | 是 |
| `model.compiled` | 1.2 MiB | 是 |
| `vk.ezkl` | 802 KiB | 是 |
| `proof.json` | 40 KiB | 否（每条响应一份，随证书归档） |
| `MANIFEST.json` | 1 KiB | 是 |
| `pk.ezkl` | 2.92 GiB | 否（可重算） |
| `kzg.srs` | 32.0 MiB | 否（可重算） |

> **峰值内存**是这条链路的硬约束：出证峰值 ~9 GiB，在 12 GB 机器上很紧。
> 因此 `setup` 与 `prove` 必须**分进程**跑（否则两段峰值叠加）。
> 放宽 `MAX_CHARS`/`DIM` 会线性抬高行数与峰值（见 `semantic/features.py`）。
