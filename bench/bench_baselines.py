#!/usr/bin/env python3
"""P1-12 跨系统 / TEE 基线：把「同一张绑定表的七行」放在一起看。

本脚本不提出新机制，只做两件事：

1. **量本仓库能量的两臂**：PoP（从已入库的 ``bench/results/proofs.json`` /
   ``verify.json`` 读，**不重跑 SP1**）与 signed-Merkle（从 ``baseline.json`` 读）；
   再加一条**新测的 trusted-server 臂**（运营方跑 ``J(π,T)`` 并签结果，验证方只验签）。
2. **抄本仓库能抄的两类外部系统**：zkAgent / NiyamAI / Zaguk / PCO。每一格都标
   ``measured`` 或 ``cited``；``cited`` 必须带来源；**没有数字就写 null，不编**。

Seven columns（任务指定的对照集）:

* **PoP**：本仓库 ZK 证明；
* **signed-Merkle**：本仓库 WP9 非 ZK 基线；
* **trusted-server / TEE（模拟）**：本脚本新测的「信服务器」臂。TEE 只模拟
  **签名 + 度量**这一步，硬件 attestation 的延迟与安全**没有**测，也不声称；
* **zkAgent**（IACR ePrint 2026/199，cited）；
* **NiyamAI**（arXiv 2608.07167，cited）；
* **Zaguk**（JNIC'26，cited；本环境只能取到定性描述）；
* **PCO**（IACR ePrint 2026/994，cited；无可比性能数字）。

Rows（任务指定的七个维度）: 信任根 / 延迟 / 证明或证书大小 / 响应隐私 /
策略隐私 / 验证者是否需要 ``T`` 明文 / 验证者是否需要 ``π`` 明文。

> **读法**：七列不是同一条曲线上的七个点。它们的**证明义务**不同（PoP/Zaguk
> 证输出过策略；zkAgent 证模型与工具轨迹；PCO 证输出满足谓词并上账本；
> signed-Merkle 只证「谁说过」；trusted-server 什么都不证，只让你信服务器）。
> 因此表里没有「谁最快」的结论，只有「谁要你信什么、付多少」。

结果写到 ``bench/results/baselines.json`` 与同目录 ``.md``（``.md`` 是 JSON 的纯渲染，
``--render-only`` 可重新生成）。

用法：
  python3 bench/bench_baselines.py
  python3 bench/bench_baselines.py --reps 500
  python3 bench/bench_baselines.py --render-only
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "bench"))

import bench_proofs as bp  # noqa: E402
from policydsl import Policy, Rule, check  # noqa: E402
from policydsl.core.compile import compile_policy  # noqa: E402
from policydsl.evidence import cert  # noqa: E402
from policydsl.privacy import challenge, commit  # noqa: E402

RESULTS = REPO / "bench" / "results"
DEFAULT_PACK = REPO / "policy_packs" / "eu_ai_act_v1.json"
DEFAULT_REPS = 300

DEFAULT_RESPONSE = (
    "The assistant summarised the quarterly report in plain language "
    "and did not disclose any personal data."
)

SYSTEMS = ["PoP", "signed-Merkle", "trusted-server / TEE (sim)", "zkAgent",
           "NiyamAI", "Zaguk", "PCO"]

DIMENSIONS = ["信任根", "延迟（出证 + 验证）", "证明/证书大小", "响应隐私",
              "策略隐私", "验证者需要 T 明文？", "验证者需要 π 明文？"]


# --------------------------------------------------------------------------- #
# 本地已有量测：从入库 JSON 读，不重跑
# --------------------------------------------------------------------------- #

def load_json(name: str) -> dict | list:
    path = RESULTS / f"{name}.json"
    if not path.exists():
        raise SystemExit(f"缺少入库结果 {path} —— 先跑对应的 bench，本脚本不重跑 SP1。")
    return json.loads(path.read_text(encoding="utf-8"))


def pop_cell() -> dict:
    """PoP 的 measured 摘要：证明时间范围、证明大小、纯验证时间、峰值内存。"""
    proofs = load_json("proofs")
    ok_rows = [r for r in proofs["rows"] if r.get("ok")]
    if not ok_rows:
        raise SystemExit("proofs.json 里没有任何成功的行")
    seconds = [r["seconds"] for r in ok_rows]
    sizes = [r["proof_bytes"] for r in ok_rows]
    mem = [r["peak_rss_mb"] for r in ok_rows]
    verify = load_json("verify")
    verify_ms = verify[0]["verify_median_ms"]
    return {
        "prove_s_min": min(seconds),
        "prove_s_max": max(seconds),
        "proof_bytes_min": min(sizes),
        "proof_bytes_max": max(sizes),
        "peak_rss_mb_max": max(mem),
        "verify_ms": verify_ms,
        "host": proofs.get("host"),
        "source": ["bench/results/proofs.json", "bench/results/verify.json"],
        "status": "measured",
    }


def merkle_cell() -> dict:
    """signed-Merkle 的 measured 摘要（WP9 基线）。"""
    d = load_json("baseline")
    metrics = {m["metric"]: m for m in d["metrics"]}
    return {
        "sign_ms": metrics["签名 `cert.sign_payload`（Ed25519 + DSSE 信封）"]["median"],
        "append_ms": metrics["Merkle 追加（追加一叶 + 重算根）"]["median"],
        "verify_public_ms": metrics["公开核验（验签 + 验包含）"]["median"],
        "verify_reexec_ms": metrics["重跑核验（验签 + 验包含 + `J(π,T)`）"]["median"],
        "cert_bytes": metrics["证书大小"]["median"],
        "inclusion_bytes": metrics["包含证明大小"]["median"],
        "host": d.get("host"),
        "source": ["bench/results/baseline.json"],
        "status": "measured",
    }


# --------------------------------------------------------------------------- #
# 新测：trusted-server / TEE 模拟臂
# --------------------------------------------------------------------------- #

def load_policy(path: Path) -> Policy:
    data = json.loads(path.read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r["name"], params=r.get("params", {}))
             for r in data["rules"]]
    return Policy(data["id"], data.get("version", "0.1.0"), rules=rules)


def measure_trusted_server(reps: int) -> dict:
    """运营方跑判定并签结果；验证方只验签。

    这是**信任服务器**的基线：验证方不重跑 ``J(π,T)``，因此它拿到的 ``passed``
    只在「服务器诚实」时成立。TEE 版本把「信服务器」换成「信硬件 attestation」，
    但本机**没有** TEE，所以这里只模拟「度量 + 签名」这一步：
    ``measurement = SHA256(程序/策略标识)`` 被签进信封；验证方验签。
    **不声称**模拟件具备 TEE 的安全性或性能。
    """
    policy = load_policy(DEFAULT_PACK)
    spec = compile_policy(policy)
    verdict = check(policy, DEFAULT_RESPONSE)
    body = {
        "policy_hash": spec["sha256"],
        "response_commitment": commit.commitment(DEFAULT_RESPONSE),
        "nonce": challenge.new_nonce().hex(),
        "passed": bool(verdict.passed),
        "ts": cert.utc_now(),
    }
    signer = cert.Ed25519Signer.generate()
    keyring = {signer.keyid: signer.public_key}

    server_t: list[float] = []
    verify_t: list[float] = []
    env = None
    for _ in range(reps):
        t0 = time.perf_counter()
        # 服务端：判定 + 签结果
        check(policy, DEFAULT_RESPONSE)
        env = cert.sign_payload(body, signer)
        server_t.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ok, _ = cert.verify_envelope(env, keyring)
        verify_t.append(time.perf_counter() - t0)
        if not ok:
            raise SystemExit("trusted-server 信封验签失败")

    # TEE 模拟：把「度量值」签进一个 attestation 信封。只有签名成本是实测的。
    tee_t: list[float] = []
    tee_env = None
    measurement = cert.sha256_hex(b"pop-program-v1|" + spec["sha256"].encode())
    for _ in range(reps):
        t0 = time.perf_counter()
        tee_env = cert.sign_payload({"measurement": measurement,
                                     "policy_hash": spec["sha256"],
                                     "ts": cert.utc_now()}, signer)
        tee_t.append(time.perf_counter() - t0)
        ok, _ = cert.verify_envelope(tee_env, keyring)
        if not ok:
            raise SystemExit("TEE 模拟 attestation 验签失败")

    return {
        "server_eval_and_sign_median_ms": round(statistics.median(server_t) * 1000, 3),
        "verify_median_ms": round(statistics.median(verify_t) * 1000, 3),
        "cert_bytes": len(cert.canonical(env)),
        "tee_sim_sign_median_ms": round(statistics.median(tee_t) * 1000, 3),
        "tee_sim_bytes": len(cert.canonical(tee_env)),
        "reps": reps,
        "status": "measured",
        "tee_hardware_measured": False,
        "source": ["本次运行（trusted-server 臂）"],
    }


# --------------------------------------------------------------------------- #
# 对照单元格
# --------------------------------------------------------------------------- #

def cell(value, status: str, source: str) -> dict:
    return {"value": value, "status": status, "source": source}


def build_cells(pop: dict, merkle: dict, server: dict) -> dict:
    """构造 ``{dimension: {system: cell}}``，每一格都带 measured/cited。"""
    M, C = "measured", "cited"
    zk_src = "IACR ePrint 2026/199；本仓库 bench/comparison_zkagent.md §1"
    niyam_src = "arXiv:2608.07167（abstract，2026-08）"
    zaguk_src = ("JNIC'26 proceedings: https://www.incibe.es/sites/default/files/"
                 "eventos/JNIC/JNIC26-Acta-red.pdf（本环境只取到定性描述）")
    pco_src = "IACR ePrint 2026/994（abstract）"
    pop_src = "bench/results/proofs.json + verify.json（本仓库实测）"
    merkle_src = "bench/results/baseline.json（本仓库实测）"
    server_src = "本次运行（bench/bench_baselines.py 的 trusted-server 臂）"

    return {
        "信任根": {
            "PoP": cell("vkey + 密码学假设（A1/A2）；无硬件信任、无「信网关」", M, pop_src),
            "signed-Merkle": cell("Ed25519 网关钥；信「持钥的网关」", M, merkle_src),
            "trusted-server / TEE (sim)": cell("服务器（或 TEE 硬件 attestation）；本模拟只测签名，不含硬件", M, server_src),
            "zkAgent": cell("zkVM 证明 + provider 的模型/工具执行承诺", C, zk_src),
            "NiyamAI": cell("zk-SNARK + SHA-256 Intent Contract + 神经 Judge", C, niyam_src),
            "Zaguk": cell("ezkl zk-SNARK + SHA-256 输出承诺", C, zaguk_src),
            "PCO": cell("命名权威发布的谓词 + 独立 validator + 只追加账本", C, pco_src),
        },
        "延迟（出证 + 验证）": {
            "PoP": cell(f"出证 {pop['prove_s_min']:.2f}–{pop['prove_s_max']:.2f} s；"
                        f"纯验证 {pop['verify_ms']:.2f} ms", M, pop_src),
            "signed-Merkle": cell(f"签名 {merkle['sign_ms']:.3f} ms + 追加 {merkle['append_ms']:.3f} ms；"
                                  f"公开核验 {merkle['verify_public_ms']:.3f} ms；"
                                  f"重跑核验 {merkle['verify_reexec_ms']:.3f} ms", M, merkle_src),
            "trusted-server / TEE (sim)": cell(f"服务端判定+签 {server['server_eval_and_sign_median_ms']:.3f} ms；"
                                               f"客户端验签 {server['verify_median_ms']:.3f} ms", M, server_src),
            "zkAgent": cell("Shout: 194.40 s / 0.42 s；LogUp: ~1069 s / 0.038 s", C, zk_src),
            "NiyamAI": cell("1.7 s / 次获批动作；验证 51 ms", C, niyam_src),
            "Zaguk": cell("未报告可比数字（证明生成是主成本）", C, zaguk_src),
            "PCO": cell(None, C, pco_src),
        },
        "证明/证书大小": {
            "PoP": cell(f"{pop['proof_bytes_min']/1024/1024:.2f}–{pop['proof_bytes_max']/1024/1024:.2f} MiB（证明）", M, pop_src),
            "signed-Merkle": cell(f"{merkle['cert_bytes']} B 证书 + {merkle['inclusion_bytes']} B 包含证明", M, merkle_src),
            "trusted-server / TEE (sim)": cell(f"{server['cert_bytes']} B 证书；TEE 模拟 attestation {server['tee_sim_bytes']} B", M, server_src),
            "zkAgent": cell("Shout ~96 MiB；LogUp 3.1 MiB", C, zk_src),
            "NiyamAI": cell("18.6 KB", C, niyam_src),
            "Zaguk": cell("未取到具体数值（原文称随编码长度稳定）", C, zaguk_src),
            "PCO": cell(None, C, pco_src),
        },
        "响应隐私": {
            "PoP": cell("有（私有模式：只给 response_commitment / response_binding）", M, pop_src),
            "signed-Merkle": cell("无（验证者需 T 明文重跑；本仓库基线实测路径）", M, merkle_src),
            "trusted-server / TEE (sim)": cell("对验证者无（T 交给服务器）；TEE 可对服务器隐藏，本模拟不测", M, server_src),
            "zkAgent": cell("承诺式（证明推理与工具轨迹，不公开明文）", C, zk_src),
            "NiyamAI": cell("未在摘要中单独报告隐私指标", C, niyam_src),
            "Zaguk": cell("有（验证者不见输出前缀原文）", C, zaguk_src),
            "PCO": cell("有（binding + hiding；证明在审计时披露）", C, pco_src),
        },
        "策略隐私": {
            "PoP": cell("有（策略进电路作私有见证；需 P-PP 才可问责）", M, pop_src),
            "signed-Merkle": cell("无（验证者需 π 明文重跑）", M, merkle_src),
            "trusted-server / TEE (sim)": cell("无（服务器知道 π；验证者不需要）", M, server_src),
            "zkAgent": cell("不适用（无策略 π 这一义务）", C, zk_src),
            "NiyamAI": cell("Intent Contract 以 SHA-256 承诺；证明不公开模型参数", C, niyam_src),
            "Zaguk": cell("有（证明不公开过滤器参数）", C, zaguk_src),
            "PCO": cell("部分（谓词由命名权威发布；验证者需规范）", C, pco_src),
        },
        "验证者需要 T 明文？": {
            "PoP": cell("否（私有模式下只给承诺）", M, pop_src),
            "signed-Merkle": cell("是（不重跑 J(π,T) 无法确认 passed）", M, merkle_src),
            "trusted-server / TEE (sim)": cell("否（验证者只验签；服务器需要）", M, server_src),
            "zkAgent": cell("否（证明覆盖推理与工具轨迹）", C, zk_src),
            "NiyamAI": cell("未明确（摘要只称验证无需模型参数）", C, niyam_src),
            "Zaguk": cell("否（只给 SHA-256 输出承诺）", C, zaguk_src),
            "PCO": cell("否（证明覆盖 (x,y) 满足谓词；输入真实性不在范围内）", C, pco_src),
        },
        "验证者需要 π 明文？": {
            "PoP": cell("否（只需 policy_hash 与 vkey；P-PP 除外）", M, pop_src),
            "signed-Merkle": cell("是（重跑需要同一份策略）", M, merkle_src),
            "trusted-server / TEE (sim)": cell("否（验证者只验签；服务器需要）", M, server_src),
            "zkAgent": cell("不适用（无 π）", C, zk_src),
            "NiyamAI": cell("未明确（Intent Contract 以 SHA-256 承诺；摘要未说验证者是否需规范）", C, niyam_src),
            "Zaguk": cell("否（证明不公开过滤器参数）", C, zaguk_src),
            "PCO": cell("部分（谓词由权威发布；验证者需规范或承诺）", C, pco_src),
        },
    }


def citations() -> list[dict]:
    return [
        {"system": "zkAgent", "source": "Lizheng Wang et al., zkAgent: Verifiable LLM Agent Execution via One-Shot Transcript Proofs, IACR ePrint 2026/199",
         "url": "https://eprint.iacr.org/2026/199", "used_for": "prove/verify time, proof size"},
        {"system": "NiyamAI", "source": "Aditya Katkar et al., NiyamAI - An Intent-Bound AI Agent with Cryptographically Verifiable Guardrails using Zero-Knowledge Proofs, arXiv:2608.07167 (2026-08)",
         "url": "https://arxiv.org/abs/2608.07167", "used_for": "1.7 s/action, 51 ms verify, 18.6 KB proof"},
        {"system": "Zaguk", "source": "Zaguk, JNIC 2026 proceedings (INCIBE), JNIC26-Acta-red.pdf",
         "url": "https://www.incibe.es/sites/default/files/eventos/JNIC/JNIC26-Acta-red.pdf", "used_for": "mechanism/qualitative only; exact numbers not extracted"},
        {"system": "PCO", "source": "Hillel Avni, Shlomi Dolev, Avraam Yagudaev, Moti Yung, Super-intelligence Survival Guide: Verification via Proof-Carrying Output, IACR ePrint 2026/994",
         "url": "https://eprint.iacr.org/2026/994", "used_for": "mechanism/trust model; no performance numbers reported"},
    ]


# --------------------------------------------------------------------------- #
# 渲染
# --------------------------------------------------------------------------- #

def render_md(data: dict) -> str:
    h = data.get("host") or {}
    md = ["# 跨系统 / TEE 基线（P1-12）", "",
          f"**量测机器（本脚本）**：{h.get('cpu_count')} 核 "
          f"`{h.get('cpu_model') or '未知型号'}`，内存 {(h.get('mem_total_mb') or 0)/1024:.1f} GiB"
          f"（`{h.get('hostname')}`，{h.get('platform')}）；Python {h.get('python')}。", "",
          "> 每格都标 **measured** 或 **cited**。`cited` 一律给来源；没有取到的数字写 `—`，"
          "不猜。七列的证明义务不同，**不要**把这张表读成单一排行榜。", "",
          "| 维度 | " + " | ".join(SYSTEMS) + " |",
          "|---|" + "---|" * len(SYSTEMS)]
    for dim in DIMENSIONS:
        vals = []
        for sysname in SYSTEMS:
            c = data["cells"][dim][sysname]
            v = c["value"]
            if v is None:
                vals.append("—")
            else:
                tag = "m" if c["status"] == "measured" else "c"
                vals.append(f"{v} `[{tag}]`")
        md.append(f"| **{dim}** | " + " | ".join(vals) + " |")
    md += ["", "`[m]` = measured（本仓库/本次运行实测）；`[c]` = cited（外部文献）。", "",
           "## 本仓库实测的三臂", "",
           f"- **PoP**：出证 {data['pop']['prove_s_min']:.2f}–{data['pop']['prove_s_max']:.2f} s，"
           f"证明 {data['pop']['proof_bytes_min']/1024/1024:.2f}–{data['pop']['proof_bytes_max']/1024/1024:.2f} MiB，"
           f"峰值 RSS {data['pop']['peak_rss_mb_max']/1024:.1f} GiB，纯验证 {data['pop']['verify_ms']:.2f} ms。"
           f"来源：`{', '.join(data['pop']['source'])}`；那批数字的量测机是 "
           f"{data['pop']['host'].get('cpu_count')} 核 / "
           f"{(data['pop']['host'].get('mem_total_mb') or 0)/1024:.1f} GiB。",
           f"- **signed-Merkle**：签名 {data['merkle']['sign_ms']:.3f} ms，追加 "
           f"{data['merkle']['append_ms']:.3f} ms，公开核验 {data['merkle']['verify_public_ms']:.3f} ms，"
           f"重跑核验 {data['merkle']['verify_reexec_ms']:.3f} ms，证书 {data['merkle']['cert_bytes']} B，"
           f"包含证明 {data['merkle']['inclusion_bytes']} B。来源：`{', '.join(data['merkle']['source'])}`。",
           f"- **trusted-server / TEE（模拟）**：服务端判定+签 "
           f"{data['server']['server_eval_and_sign_median_ms']:.3f} ms，客户端验签 "
           f"{data['server']['verify_median_ms']:.3f} ms，证书 {data['server']['cert_bytes']} B；"
           f"TEE 模拟 attestation 签名 {data['server']['tee_sim_sign_median_ms']:.3f} ms / "
           f"{data['server']['tee_sim_bytes']} B。**硬件 attestation 未测**，"
           "模拟件只量「度量 + 签名」这一步。", "",
           "## 信任取舍（不是速度排名）", "",
           "- **PoP**：验证者不需要 `T`/`π` 明文，也不信某台机器；代价是出证秒级到分钟级、"
           "证明 MiB 级，且 `core` 模式的零知识与策略问责仍需外部前提（`docs/sp1-zk-audit.md`、"
           "`docs/security-model.md` §4.6 的 P-PP）。",
           "- **signed-Merkle**：亚毫秒，但验证者必须拿 `T` 与 `π` 明文重跑；换句话说，"
           "它把「验证」变成了「你有本事自己再算一遍」。",
           "- **trusted-server / TEE**：验证者最省事（只验签），但把正确性押在服务器或硬件上；"
           "TEE 能移走「信运营方」，移不走「信厂商/固件」，且本表**没有**量硬件。",
           "- **zkAgent**：证的是模型推理 + 工具轨迹，与 PoP 的「策略合规」正交，成本由推理证明主导。",
           "- **NiyamAI / Zaguk / PCO**：与 PoP 的机制相邻，但义务/信任根不同；"
           "NiyamAI 守工具调用，Zaguk 守输出前缀的 PII 过滤，PCO 是证明携带输出 + 账本 + 监管。", "",
           "## 来源（cited）", "",
           "| 系统 | 来源 | 用于 |", "|---|---|---|"]
    for c in data["citations"]:
        md.append(f"| {c['system']} | {c['source']} — {c['url']} | {c['used_for']} |")
    md += ["", "> **诚实边界**：本文件不含任何本次新跑的 SP1 证明；PoP 列的数字来自已入库的 "
           "`proofs.json`/`verify.json`，量测机与本次脚本所在机器可能不同，已在上面分别标注。"
           "Zaguk 与 PCO 的原文在本次环境中未能取到完整性能表，因此这两列只写机制/定性，"
           "**不填数字**。", ""]
    return "\n".join(md) + "\n"


def dump(out_path: Path, data: dict) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    out_path.with_suffix(".md").write_text(render_md(data), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=DEFAULT_REPS,
                    help=f"trusted-server 臂的重复次数（默认 {DEFAULT_REPS}）")
    ap.add_argument("--out", type=Path,
                    default=REPO / "bench" / "results" / "baselines.json")
    ap.add_argument("--render-only", action="store_true")
    args = ap.parse_args()

    if args.render_only:
        data = json.loads(args.out.read_text(encoding="utf-8"))
        args.out.with_suffix(".md").write_text(render_md(data), encoding="utf-8")
        print(f"→ {args.out.with_suffix('.md')}（由 {args.out} 重新渲染，未重采数据）")
        return 0

    h = bp.host_info()
    host = {**h, "python": platform.python_version(), "os": platform.platform()}
    print(f"host={host['hostname']}  {host['cpu_count']} 核  "
          f"{host['mem_total_mb']/1024:.1f} GiB  Python {host['python']}")

    pop = pop_cell()
    merkle = merkle_cell()
    print(f"PoP（入库）: {pop['prove_s_min']:.2f}–{pop['prove_s_max']:.2f} s, "
          f"verify {pop['verify_ms']:.2f} ms")
    print(f"signed-Merkle（入库）: sign {merkle['sign_ms']:.3f} ms, "
          f"public verify {merkle['verify_public_ms']:.3f} ms")

    print(f"trusted-server 臂：n={args.reps} …")
    server = measure_trusted_server(args.reps)
    print(f"  server eval+sign {server['server_eval_and_sign_median_ms']:.3f} ms, "
          f"verify {server['verify_median_ms']:.3f} ms, cert {server['cert_bytes']} B")

    data = {
        "arm": "cross-system-baselines",
        "host": host,
        "reps": args.reps,
        "systems": SYSTEMS,
        "dimensions": DIMENSIONS,
        "pop": pop,
        "merkle": merkle,
        "server": server,
        "cells": build_cells(pop, merkle, server),
        "citations": citations(),
        "notes": [
            "每格标 measured/cited；cited 必须带来源。",
            "PoP/signed-Merkle 数字来自入库 JSON，未在本次运行重跑。",
            "TEE 只模拟度量+签名，硬件 attestation 未测。",
        ],
    }
    dump(args.out, data)
    print(f"\nwrote {args.out} and {args.out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
