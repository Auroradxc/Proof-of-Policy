#!/usr/bin/env python3
"""P1-10 网关验签成本：**签在哪里**，就信在哪里。

本脚本只回答一个成本问题，不改变任何既有语义：

* **(a) 链下（宿主）Ed25519 验签** —— 现状。回执由 :class:`policydsl.evidence.trace.ToolGateway`
  签发，验证方用 :func:`policydsl.evidence.trace.verify_chain` 在链下逐条验签。
  量 1 / 10 / 100 条回执的签发、验签、单条字节数。
* **(b) SP1 电路内验签** —— **本机不可做，记为 blocker，不给数字**。
  ``circuits/`` 按设计**不含** Ed25519 验签（见 ``circuits/types/src/lib.rs`` 的
  ``ToolReceipt`` 注释与 ``docs/security-model.md`` §5.3）：``sig`` 字段刻意不进电路，
  验签是链下网关公钥的职责。要量电路内成本，必须新增一个 guest crate（越出 B1 的
  文件所有权），且需要 ``flock /tmp/pop-proof.lock`` 才能跑小规模证明。两者都不满足，
  所以这一列写 ``blocked``，**不填任何周期数/时间/内存**。详细原因与解除条件见
  ``docs/blockers/B1.md``。
* **(c) 2-of-3 阈值网关（宿主侧原型）** —— 只做**多签拼接**（multi-signature），
  不是紧凑阈值签名：三把钥各签同一段规范字节，验证方要求至少 2 个**不同** keyid 的
  有效签名。量签名、合并、验签、证书大小，并与 1-of-1 单签对照。

**本实验不改变现有 ToolSeal 语义**。``ToolSeal`` 仍是网关在会话末端签发的
``{count, trace_root, ts, keyid, sig}``；阈值原型是**另一条候选路径**的宿主侧成本探针，
不接入 ``trace.py``、不改证书格式、不改验证脚本。阈值化若将来落地，需要单独的设计与
安全模型（尤其是「2 把钥同时泄露」与「3 个网关对同一条链的视图一致性」两件事）。

结果写到 ``bench/results/gateway_sig.json`` 与同目录 ``.md``（``.md`` 是 JSON 的纯渲染，
``--render-only`` 可重新生成）。

用法：
  python3 bench/bench_gateway_sig.py
  python3 bench/bench_gateway_sig.py --reps 500
  python3 bench/bench_gateway_sig.py --render-only
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

import bench_proofs as bp  # noqa: E402  量测机器记录只此一处
from policydsl.evidence import cert, trace  # noqa: E402

DEFAULT_REPS = 300
COUNTS = (1, 10, 100)

#: 电路内验签的 blocker 标识。**没有数字**不是疏忽，是结论：本机/本仓库当前
#: 没有可执行的电路内 Ed25519 验签工件（见模块 docstring 与 docs/blockers/B1.md）。
CIRCUIT_BLOCKER = "B1-circuit-ed25519"

#: Blocked 行的统一占位。渲染时原样输出，避免调用方把它读成 0。
BLOCKED = "blocked"


# --------------------------------------------------------------------------- #
# (a) 链下宿主 Ed25519
# --------------------------------------------------------------------------- #

def measure_host(gateway: trace.ToolGateway, keyring: dict, reps: int) -> dict:
    """量 1/10/100 条回执的签发与验签。

    每个样本都**重新签发**（签发会推进链），验签用同一份链。这样「签发 N 条」
    与「验证 N 条」是两条独立的时间序列，不会被对方的缓存/预热混进来。
    """
    rows: list[dict] = []
    for n in COUNTS:
        sign_t: list[float] = []
        verify_t: list[float] = []
        for _ in range(reps):
            gateway.reset()
            t0 = time.perf_counter()
            for i in range(n):
                gateway.issue("search_kb", {"query": f"q{i}", "k": i},
                              result=f"result-{i}", ts="2026-11-01T00:00:00Z")
            sign_t.append(time.perf_counter() - t0)

            receipts = gateway.receipts
            t0 = time.perf_counter()
            ok, why = trace.verify_chain(receipts, keyring)
            verify_t.append(time.perf_counter() - t0)
            if not ok:
                raise SystemExit(f"链下验签在 n={n} 时失败：{why}")

        receipts = gateway.receipts
        per_receipt = sum(len(trace.canonical_receipt_bytes(r)) for r in receipts) / n
        rows.append({
            "receipts": n,
            "sign_median_ms": median_ms(sign_t),
            "verify_median_ms": median_ms(verify_t),
            "sign_per_receipt_ms": round(median_ms(sign_t) / n, 4),
            "verify_per_receipt_ms": round(median_ms(verify_t) / n, 4),
            "receipt_bytes": round(per_receipt, 1),
            "n": reps,
            "status": "measured",
        })

    # ToolSeal：会话末端的网关承诺（P1-5b）。它是**链下 + 证书**那一层，
    # 本表把它单列，免得把「回执验签」与「截尾承诺」混成一个数。
    gateway.reset()
    for i in range(10):
        gateway.issue("search_kb", {"query": f"q{i}"}, result=f"r{i}",
                      ts="2026-11-01T00:00:00Z")
    seal_t: list[float] = []
    seal_verify_t: list[float] = []
    seal = None
    for _ in range(reps):
        t0 = time.perf_counter()
        seal = gateway.seal()
        seal_t.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ok, why = trace.verify_seal(seal, gateway.keyring(), gateway.receipts)
        seal_verify_t.append(time.perf_counter() - t0)
        if not ok:
            raise SystemExit(f"ToolSeal 验签失败：{why}")

    seal_bytes = len(json.dumps(trace.seal_to_json(seal), separators=(",", ":")).encode())
    return {
        "rows": rows,
        "seal": {
            "sign_median_ms": median_ms(seal_t),
            "verify_median_ms": median_ms(seal_verify_t),
            "bytes": seal_bytes,
            "n": reps,
            "status": "measured",
            "note": "ToolSeal 语义未改：仍是 {count, trace_root, ts, keyid, sig}",
        },
    }


# --------------------------------------------------------------------------- #
# (b) SP1 电路内：blocked
# --------------------------------------------------------------------------- #

def circuit_status() -> dict:
    """电路内验签的**状态**，不是一个数字。

    为什么 blocked（三条缺一不可，且两条是硬边界）：

    1. ``circuits/`` 的 ``ToolReceipt`` 视图**刻意去掉** ``sig``，电路只验链结构；
       电路内没有 Ed25519 验签这段代码。
    2. 要量它必须新增 guest crate / 修改电路 —— 越出 B1 允许改动的文件清单。
    3. 本机 14.6 GiB 且当前没有 ``/tmp/pop-proof.lock``；SP1 core 证明的固定内存
       地板约 10.15 GiB，按约定不得与其它 agent 并发跑。
    """
    return {
        "status": BLOCKED,
        "blocker": CIRCUIT_BLOCKER,
        "blocker_doc": "docs/blockers/B1.md",
        "reason": ("circuits/ 按设计不含 Ed25519 验签（sig 不进电路）；新增 guest crate "
                   "越出 B1 文件所有权；且本机无 /tmp/pop-proof.lock。"),
        "cycles": None,
        "prove_time_s": None,
        "peak_mem_mb": None,
        "cannot_conclude": ["电路内验签的周期数", "电路内验签的证明时间",
                            "电路内验签的峰值内存"],
    }


# --------------------------------------------------------------------------- #
# (c) 2-of-3 多签网关（宿主侧原型）
# --------------------------------------------------------------------------- #

def threshold_certificate(body: dict, signers: list[cert.Ed25519Signer]) -> dict:
    """三把钥各签同一段规范字节，返回 ``{payload, signatures}``。

    这是**多签拼接**，不是紧凑阈值签名：证书大小随签名数线性增长。验证方必须
    检查「至少 t 个**不同** keyid」。这里不引入 DKG / 聚合签名，因为那会改变
    信任假设（需要一次性的分布式密钥生成），不适合作为「只测宿主侧成本」的原型。
    """
    data = cert.canonical(body)
    return {
        "payload": body,
        "signatures": [{"keyid": s.keyid, "sig": s.sign(data).hex()} for s in signers],
    }


def verify_threshold(env: dict, keyring: dict, t: int = 2) -> tuple[bool, str]:
    """至少 ``t`` 个**不同** keyid 的有效签名。"""
    body = env.get("payload") or {}
    data = cert.canonical(body)
    good: set[str] = set()
    for item in env.get("signatures") or []:
        keyid = item.get("keyid")
        verifier = keyring.get(keyid)
        if verifier is None or keyid in good:
            continue
        try:
            sig = bytes.fromhex(item.get("sig") or "")
        except ValueError:
            continue
        try:
            if bool(cert._ed25519_verify(verifier, data, sig)
                    if isinstance(verifier, cert.Ed25519PublicKey)
                    else verifier.verify(data, sig)):
                good.add(keyid)
        except Exception:
            continue
    if len(good) < t:
        return False, f"有效且互异的签名 {len(good)} 个 < 阈值 {t}"
    return True, f"{len(good)} 个互异有效签名 ≥ {t}"


def measure_threshold(signers: list[cert.Ed25519Signer], reps: int) -> dict:
    """量 2-of-3 的签名、合并、验签与证书大小，并给出 1-of-1 对照。"""
    body = {
        "policy_hash": "5b5fd101580e9233" + "0" * 48,
        "response_commitment": "309c3b150c4031d4" + "0" * 48,
        "nonce": "dfbbed6d6b7e23ca" + "0" * 48,
        "passed": True,
        "ts": "2026-11-01T00:00:00Z",
    }
    keyring = {s.keyid: s.public_key for s in signers}

    # 1-of-1 单签对照（与现有签名路径同一段规范字节）
    single = cert.Ed25519Signer.generate()
    single_ref = {single.keyid: single.public_key}
    single_sign_t: list[float] = []
    single_verify_t: list[float] = []
    single_env = None
    for _ in range(reps):
        t0 = time.perf_counter()
        single_env = cert.sign_payload(body, single)
        single_sign_t.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ok, _ = cert.verify_envelope(single_env, single_ref)
        single_verify_t.append(time.perf_counter() - t0)
        if not ok:
            raise SystemExit("1-of-1 单签验签失败")

    # 2-of-3：逐把签名、合并、验签
    sign_t: list[float] = []
    combine_t: list[float] = []
    verify_t: list[float] = []
    env = None
    for _ in range(reps):
        data = cert.canonical(body)
        t0 = time.perf_counter()
        sigs = [{"keyid": s.keyid, "sig": s.sign(data).hex()} for s in signers]
        sign_t.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        env = {"payload": body, "signatures": sigs}
        combine_t.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ok, why = verify_threshold(env, keyring, 2)
        verify_t.append(time.perf_counter() - t0)
        if not ok:
            raise SystemExit(f"2-of-3 验签失败：{why}")

    three = threshold_certificate(body, signers)
    two = {"payload": body, "signatures": three["signatures"][:2]}
    ok2, why2 = verify_threshold(two, keyring, 2)
    if not ok2:
        raise SystemExit(f"任意 2 个签名应通过：{why2}")
    one = {"payload": body, "signatures": three["signatures"][:1]}
    ok1, _ = verify_threshold(one, keyring, 2)
    if ok1:
        raise SystemExit("只有 1 个签名却通过了 2-of-3 —— 阈值检查失效")

    # 负对照：换一个 keyid 冒充第二个签名者，不能凑数
    duplicate = {
        "payload": body,
        "signatures": [three["signatures"][0],
                       {"keyid": three["signatures"][0]["keyid"],
                        "sig": three["signatures"][1]["sig"]}],
    }
    okdup, _ = verify_threshold(duplicate, keyring, 2)
    if okdup:
        raise SystemExit("同一个 keyid 的两条签名被算成两个 —— 互异检查失效")

    def size(env_: dict) -> int:
        return len(json.dumps(env_, separators=(",", ":")).encode())

    return {
        "body_bytes": len(cert.canonical(body)),
        "single": {
            "sign_median_ms": median_ms(single_sign_t),
            "verify_median_ms": median_ms(single_verify_t),
            "cert_bytes": size(single_env),
            "threshold": "1-of-1",
            "n": reps,
            "status": "measured",
        },
        "threshold_2of3": {
            "sign_all_median_ms": median_ms(sign_t),
            "sign_per_share_ms": round(median_ms(sign_t) / 3, 4),
            "combine_median_ms": median_ms(combine_t),
            "verify_median_ms": median_ms(verify_t),
            "cert_bytes_3sigs": size(three),
            "cert_bytes_2sigs": size(two),
            "n": reps,
            "status": "measured",
            "scheme": "2-of-3 multi-signature (concatenated Ed25519), NOT a compact threshold signature",
        },
        "checks": [
            {"check": "任意 2 个互异签名 ⇒ 通过", "ok": ok2},
            {"check": "只有 1 个签名 ⇒ 拒绝", "ok": not ok1},
            {"check": "同一 keyid 的两条签名 ⇒ 不算两个", "ok": not okdup},
        ],
    }


# --------------------------------------------------------------------------- #
# 渲染
# --------------------------------------------------------------------------- #

def median_ms(values: list[float]) -> float:
    """秒列表 → 毫秒中位数（1 µs 分辨率）。"""
    return round(statistics.median(values) * 1000, 3)


def render_md(data: dict) -> str:
    """把结果 dict 渲染成 Markdown。必须是 ``data`` 的纯函数。"""
    h = data.get("host") or {}
    md = ["# 网关验签成本：链下 / 电路内 / 2-of-3（P1-10）", "",
          f"**量测机器**：{h.get('cpu_count')} 核 `{h.get('cpu_model') or '未知型号'}`，"
          f"内存 {(h.get('mem_total_mb') or 0)/1024:.1f} GiB"
          f"（`{h.get('hostname')}`，{h.get('platform')}）；"
          f"Python {h.get('python')}；`{h.get('os')}`。", "",
          "> **本实验不改变现有 ToolSeal 语义。** `ToolSeal` 仍是网关在会话末端签发的 "
          "`{count, trace_root, ts, keyid, sig}`；阈值列是**宿主侧候选路径的成本探针**，"
          "没有接入 `trace.py`、没有改证书格式、没有改验证脚本。", "",
          "## (a) 链下宿主 Ed25519（现状，measured）", "",
          "| 回执数 | 签发中位数 (ms) | 验签中位数 (ms) | 签发/条 (ms) | 验签/条 (ms) | 单条字节 | n |",
          "|---:|---:|---:|---:|---:|---:|---:|"]
    for r in data["host_verify"]["rows"]:
        md.append(f"| {r['receipts']} | {r['sign_median_ms']:.3f} | {r['verify_median_ms']:.3f} | "
                  f"{r['sign_per_receipt_ms']:.4f} | {r['verify_per_receipt_ms']:.4f} | "
                  f"{r['receipt_bytes']:.1f} | {r['n']} |")
    s = data["host_verify"]["seal"]
    md += ["",
           f"`ToolSeal`（10 条回执的会话末端）：签发 {s['sign_median_ms']:.3f} ms，"
           f"验签 {s['verify_median_ms']:.3f} ms，{s['bytes']} B（n={s['n']}）。"
           f"这一行是**链下 + 证书**那一层，单独列出，避免与逐条回执验签混读。", ""]

    c = data["circuit"]
    md += ["## (b) SP1 电路内验签（blocked，未量）", "",
           f"**状态：`{c['status']}`**（blocker `{c['blocker']}`，见 `{c['blocker_doc']}`）。", "",
           f"- 原因：{c['reason']}",
           "- 因此本表**不给出**周期数、证明时间、峰值内存；这三格是 `null`，不是 0。",
           "- 不得把「链下验签的成本」当作「电路内验签的成本」；两者的信任含义与工作量级都不同。", ""]

    t = data["threshold_2of3"]
    one = data["single"]
    md += ["## (c) 2-of-3 多签网关（宿主侧原型，measured）", "",
           f"方案：**多签拼接**（concatenated Ed25519），阈值 2/3；"
           f"不是紧凑阈值签名，证书大小随签名数线性增长。规范载荷 {data['body_bytes']} B。", "",
           "| 配置 | 签名 (ms) | 合并 (ms) | 验签 (ms) | 证书 (B) | n |",
           "|---|---:|---:|---:|---:|---:|",
           f"| 1-of-1 单签 | {one['sign_median_ms']:.3f} | — | {one['verify_median_ms']:.3f} | "
           f"{one['cert_bytes']} | {one['n']} |",
           f"| 2-of-3 多签（3 个签名） | {t['sign_all_median_ms']:.3f} | "
           f"{t['combine_median_ms']:.3f} | {t['verify_median_ms']:.3f} | "
           f"{t['cert_bytes_3sigs']} | {t['n']} |",
           "",
           f"2-of-3 每把钥签名 {t['sign_per_share_ms']:.4f} ms；只带 2 个签名的证书 "
           f"{t['cert_bytes_2sigs']} B。", "",
           "| 机器校验的阈值语义 | 结果 |", "|---|---|"]
    for row in data["checks"]:
        md.append(f"| {row['check']} | {'✅' if row['ok'] else '❌'} |")

    md += ["", "## 成本与信任取舍", "",
           "| 位置 | 成本（本表） | 验证方必须信谁 | 失败模式 | 状态 |",
           "|---|---|---|---|---|",
           f"| (a) 链下 Ed25519 | 见上表（1 条验签约 "
           f"{data['host_verify']['rows'][0]['verify_per_receipt_ms']:.4f} ms） | **网关**（持钥方） | "
           "网关作恶可签与真实执行不符的回执；密钥泄露即可伪造 | measured |",
           "| (b) 电路内验签 | **未量** | 理论上只剩 vkey / 电路 | 成本（周期/内存）未知；"
           "且需改电路与签名格式 | blocked |",
           f"| (c) 2-of-3 多签 | 签名 ×3、验签 {t['verify_median_ms']:.3f} ms、证书 "
           f"{t['cert_bytes_3sigs']} B | **2 个网关**（而非 1 个） | 单点信任降为「任意 2 把钥」；"
           "三网关对同一条链的视图一致性需另证 | measured |", "",
           "**读法**：链下验签最便宜，但把信任压在**一把网关钥**上；电路内验签若可行会把"
           "「信网关」换成「信电路」，代价是更大的证明成本，而本机**没有**这个数；"
           "2-of-3 不降低单次验签的密码学成本，只降低**单点信任**——它把「1 把钥泄露即失守」"
           "改成「2 把钥同时失守」，代价是 3 倍签名、约 3 倍证书体积，以及新的"
           "「多网关视图不一致」问题。三列不是同一条曲线上的三个点，是三种信任结构。", "",
           "### 与 ToolSeal 的关系（不变）", "",
           "`ToolSeal` 回答的是「这条链到此为止」，它由**网关签名**；阈值原型回答的是"
           "「要不要把网关从 1 个变成 3 个里取 2 个」。二者正交：阈值化**不会**自动消除"
           "§5.3 的截尾缺口，因为 2 个网关仍可一起为截断链签 seal。若将来采用阈值网关，"
           "必须单独论证「多网关对链尾的共识」，本实验不提供该论证。", ""]
    return "\n".join(md) + "\n"


def dump(out_path: Path, data: dict) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    out_path.with_suffix(".md").write_text(render_md(data), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=DEFAULT_REPS,
                    help=f"每个时间数的重复次数（默认 {DEFAULT_REPS}）")
    ap.add_argument("--out", type=Path,
                    default=REPO / "bench" / "results" / "gateway_sig.json")
    ap.add_argument("--render-only", action="store_true",
                    help="不重采数据：只把已有的 --out JSON 重新渲染成 .md")
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

    gateway = trace.ToolGateway(signer=cert.Ed25519Signer.generate())
    keyring = gateway.keyring()

    print(f"(a) 链下 Ed25519：1/10/100 条回执，n={args.reps} …")
    host_data = measure_host(gateway, keyring, args.reps)
    for r in host_data["rows"]:
        print(f"  n={r['receipts']:>3}  sign {r['sign_median_ms']:>7.3f} ms  "
              f"verify {r['verify_median_ms']:>7.3f} ms")

    print("(b) SP1 电路内验签：blocked（见 docs/blockers/B1.md）")
    circuit = circuit_status()

    print(f"(c) 2-of-3 多签网关，n={args.reps} …")
    signers = [cert.Ed25519Signer.generate() for _ in range(3)]
    threshold = measure_threshold(signers, args.reps)
    for row in threshold["checks"]:
        print(f"  [{'PASS' if row['ok'] else 'FAIL'}] {row['check']}")
    if not all(row["ok"] for row in threshold["checks"]):
        raise SystemExit("阈值语义的机器校验没有全绿 —— 本臂结论不成立")

    data = {
        "arm": "gateway-signature-cost",
        "host": host,
        "reps": args.reps,
        "counts": list(COUNTS),
        "host_verify": host_data,
        "circuit": circuit,
        **threshold,
        "toolseal_semantics_unchanged": True,
        "notes": [
            "链下与阈值列是 measured；电路内列是 blocked，无数字。",
            "2-of-3 是 multi-signature 拼接，不是紧凑阈值签名；证书大小线性增长。",
            "本实验不改变 ToolSeal 语义，也不接入 trace.py。",
        ],
    }
    dump(args.out, data)
    print(f"\nwrote {args.out} and {args.out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
