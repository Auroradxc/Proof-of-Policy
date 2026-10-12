#!/usr/bin/env python3
"""WP9 非 ZK 基线臂：**签名 Merkle 日志**（brivora / VAOL 风格）。

这一臂量的不是「我们比它快」—— 而是把「透明模式下 ZK 冗余」这句话变成**有刻度的
设计结论**（见 ``docs/tdsc-plan.md`` §WP9.1）。核验链是：

    验签（Ed25519 网关钥） → 验日志包含（Merkle 证明） → **重跑 ``J(π,T)`` 才能确认
    ``passed`` 为真**

最后一步**必须同时持有 ``π`` 与 ``T`` 的明文**。这不是实现缺陷，是签名范式的结构性
后果：签名只担保「某个持钥者说了这句话」，担保不了「这句话是真的」，所以「真」只能靠
**验证者自己重算**。ZK 换来的恰恰是把这一步从验证者手里拿走。

因此本脚本有两条**都被真实测过**的验证路径：

* :func:`verify_public_only` —— 只用公开数据（信封 + 公钥 + 日志根 + 包含证明）。
  它能验签、能验包含，但 ``passed`` 恒为 ``None``、``honest`` 恒为 ``False``；
* :func:`verify_by_reexecution` —— 额外要求 ``π`` 与 ``T`` 的明文，重跑参考评估器，
  并把「签名者说的话」与「重跑的结果」逐位对齐。

**不对称本身是被机器校验的**（``asymmetry`` 字段，全绿才算跑完）：公开路径下
:func:`require_honest` 必须抛错；给了明文才允许说「诚实核验过」；一份**签名有效但内容
为假**的证书（同一把钥、同一条日志）在公开路径下照样全绿，只有重跑才抓得住。

复用仓库里**真实**的件，不另写语义：

* 判定：:func:`policydsl.check`（链外参考评估器，与电路内判定同源）；
* 承诺 / 绑定：``policydsl.privacy.commit``（``response_commitment`` /
  ``response_binding``，与 Rust 侧逐字节一致）；
* 签名 / 信封：``policydsl.evidence.cert``（``Ed25519Signer``、``sign_payload``、
  ``verify_envelope`` —— 与网关签发工具回执用的是同一套）；
* Merkle：``policydsl.proofs.session``（``MERKLE_NODE_DOMAIN`` / ``merkle_root`` /
  ``merkle_proof`` / ``verify_merkle_proof``，全仓唯一的 Merkle 实现）；
* 挑战：``policydsl.privacy.challenge``（一次性 nonce）。

不出证、不碰 SP1，所以是**秒级**的；每个数取 ``--reps`` 次重复的中位数。

结果写到 ``bench/results/baseline.json`` 与同目录的 ``.md``（``.md`` 是该 JSON 的
纯渲染，``--render-only`` 可重新生成）。

用法：
  python3 bench/bench_baseline.py
  python3 bench/bench_baseline.py --reps 2000 --log-size 4096
  python3 bench/bench_baseline.py --render-only     # 由已有 JSON 重渲染 .md
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
sys.path.insert(0, str(REPO / "bench"))     # 与 tests/test_ablation.py 同口径

import bench_proofs as bp  # noqa: E402  量测机器记录只此一处（与 proofs 表同口径）
from policydsl import Policy, Rule, check  # noqa: E402
from policydsl.core.compile import compile_policy  # noqa: E402
from policydsl.evidence import cert  # noqa: E402
from policydsl.privacy import challenge, commit  # noqa: E402
from policydsl.proofs import session  # noqa: E402

DEFAULT_PACK = REPO / "policy_packs" / "eu_ai_act_v1.json"

#: 默认响应：合规（``passed=True``）—— 本臂要展示的正是「一个**为真的**结论在签名
#: 范式下仍然无法被公开核验」，所以默认响应必须过判定（见 :func:`main` 的断言）。
DEFAULT_RESPONSE = (
    "The assistant summarised the quarterly report in plain language "
    "and did not disclose any personal data."
)

#: 默认重复次数。本臂的量级在亚毫秒，取几百次才能给出稳定的中位数。
DEFAULT_REPS = 500

#: 追加时日志里已有的叶子数（= 包含证明的深度由它决定）。1024 ⇒ 10 层兄弟。
DEFAULT_LOG_SIZE = 1024

#: ZK 侧成本列**故意**只留指引、**不留任何数字** —— 那些数要用 WP1 那台云机重跑才
#: 拿得到（见 ``bench/results/proofs.md``；本机的边界在那里，不在本文件里）。
#: 这里连引一个已发布的内存数字都不做，免得「本文件不含任何 ZK/SP1 数字」这句话
#: 自己就不成立。
ZK_COST_REF = "见 WP1 / `bench/results/proofs.md`（ZK 成本待 WP1 的云机重跑后补）"


class BaselineError(RuntimeError):
    """签名 Merkle 基线**不能**回答/不该被这么用 —— 抛出来而不是悄悄返回 False。

    这里刻意用异常而不是 ``return False``：本臂要钉住的是「公开数据**验不了** ``passed``」
    这件结构性事实。若降级成 False，调用方很容易把它读成「验过了、结论是假」，
    而事实是「根本没验、也验不了」。
    """


# --------------------------------------------------------------------------- #
# 仅追加的 Merkle 日志
# --------------------------------------------------------------------------- #

class MerkleLog:
    """仅追加的 Merkle 日志：叶子 = 证书摘要，根 = 现有全部叶子的 Merkle 根。

    Merkle 原语**全部来自** :mod:`policydsl.proofs.session`（``MERKLE_NODE_DOMAIN``
    与 Rust 侧逐字节一致），本类只负责「追加 + 取根 + 出包含证明」。

    ``append`` 每次重算整棵树（``Θ(n)``）—— 这是参考实现的口径。真做增量式
    （RFC 6962 风格的 frontier）可以把摊销降到 ``Θ(log n)``，本臂**没有**实现，
    所以 ``.md`` 里的「Merkle 追加」一栏要按「重算根」来读，别当成增量追加的价。
    """

    def __init__(self, leaves: list[str] | None = None):
        self.leaves: list[str] = list(leaves or [])

    def append(self, digest: str) -> str:
        """追加一片叶子并返回新根。"""
        self.leaves.append(digest)
        return session.merkle_root(self.leaves)

    def root(self) -> str:
        return session.merkle_root(self.leaves)

    def prove(self, index: int) -> list[tuple[str, str]]:
        """``index`` 那片叶子的包含证明（``[(side, 兄弟摘要), …]``）。"""
        return session.merkle_proof(self.leaves, index)

    def __len__(self) -> int:
        return len(self.leaves)


def filler_digest(i: int) -> str:
    """日志填充叶：**确定性**的假证书摘要（只为把树撑到 ``log_size`` 深）。

    用真哈希而不是随机串，是为了让「同一组参数重跑得到同一个根」—— 数字可比。
    """
    return commit.commitment(f"baseline-filler-{i}")


# --------------------------------------------------------------------------- #
# 证书：签什么、怎么签
# --------------------------------------------------------------------------- #

def build_certificate(signer: cert.Ed25519Signer, policy_hash: str, response: str,
                      nonce: bytes, passed: bool, ts: str) -> tuple[dict, str]:
    """签一张证书：返回 ``(DSSE 信封, 证书摘要)``。

    签名体**就是**规格里那五个字段（WP9 原文）::

        {policy_hash, response_commitment, nonce, passed, ts}

    ``response_commitment`` 取 :func:`policydsl.privacy.commit.commitment`（= 对
    ``T`` 的 UTF-8 字节求 SHA-256），``nonce`` 是一次性挑战的十六进制 —— 两者都是
    ZK 路径用的**同一个**函数算出来的，这里只是 import 进来用，不另写哈希。

    信封与签名走 :func:`policydsl.evidence.cert.sign_payload`（类 DSSE：
    ``payloadType`` + base64 载荷 + ``keyid`` 带方案前缀的签名），与网关签发工具回执
    是同一条路径 —— 于是验证方用 :func:`cert.verify_envelope` 就能核，不必为本臂
    另造一套验签逻辑。
    """
    body = {
        "policy_hash": policy_hash,
        "response_commitment": commit.commitment(response),
        "nonce": nonce.hex(),
        "passed": bool(passed),
        "ts": ts,
    }
    return cert.sign_payload(body, signer), cert.cert_digest(body)


# --------------------------------------------------------------------------- #
# 两条验证路径
# --------------------------------------------------------------------------- #

def verify_public_only(env: dict, keyring: cert.Keyring, root: str,
                       inclusion: list) -> dict:
    """**只用公开数据**核验证书：验签 + 验日志包含。

    ``passed`` **恒为 ``None``**、``honest`` **恒为 ``False``** —— 公开数据里没有
    任何东西能说明签名者写的 ``passed`` 是真是假。这不是「实现偷懒」：签名只把
    「谁说了这句话」绑到字节上，不把「这句话是真的」绑到任何东西上，所以这一步
    结构性地做不了。

    ``inclusion`` 是 ``[(side, 兄弟摘要), …]``（JSON 里是两元列表，这里先归一成元组）。
    """
    sig_ok, body = cert.verify_envelope(env, keyring)
    if not sig_ok:
        return {"signature_ok": False, "inclusion_ok": False, "cert_digest": None,
                "claimed_passed": None, "passed": None, "honest": False,
                "reason": "信封签名验不过（keyid 不在 ring 里，或载荷被改过）"}
    leaf = cert.cert_digest(body)
    inc_ok = session.verify_merkle_proof(leaf, [tuple(x) for x in inclusion], root)
    return {
        "signature_ok": True,
        "inclusion_ok": inc_ok,
        "cert_digest": leaf,
        "claimed_passed": body.get("passed"),   # 签名者**声称**的值，不是被核验过的值
        "passed": None,                         # ← 关键：公开路径回答不了这个问题
        "honest": False,
        "reason": ("签名 + 日志包含只担保『持钥者说了这句话』；要确认 passed 为真，"
                   "必须重跑 J(π,T)，而那需要 π 与 T 的明文"),
    }


def require_honest(result: dict) -> bool:
    """把一个「诚实的核验结论」里的 ``passed`` 取出来；不诚实就**炸掉**。

    存在的理由：本臂最容易犯的错，是把 :func:`verify_public_only` 的结果当成核验
    结论去用。有了这个入口，「拿公开数据当诚实核验」这件事在代码里就是一条异常，
    而不是一句注释。
    """
    if not result.get("honest"):
        raise BaselineError(
            "这不是一次诚实的核验：公开数据只能验签与验包含，"
            "确认 passed 必须重跑 J(π,T)（需 π 与 T 的明文）。"
            "请改用 verify_by_reexecution(policy, response, ...)。")
    return result["passed"]


def verify_by_reexecution(policy: Policy | None, response: str | None, env: dict,
                          keyring: cert.Keyring, root: str, inclusion: list) -> dict:
    """**重跑 ``J(π,T)``** 才算核验完 —— 这是签名范式下唯一能确认真值的一步。

    ``π`` 与 ``T`` 缺一不可；缺任何一个都直接抛 :class:`BaselineError`（fail loud），
    绝不退化成「那就只验签好了」——那正是本臂要指出的错误用法。

    四步，一步都不能少：

    1. 公开数据那一关（验签 + 验包含）必须先过；
    2. 送达的 ``T`` 必须能打开签名体里的 ``response_commitment``（换货即在此被抓）；
    3. ``policy_hash`` 必须与**手上这份 π** 编译出的哈希一致（策略被换即在此被抓）；
    4. 重跑参考评估器，结果必须与签名者写的 ``passed`` **逐位一致**；不一致说明
       签名者说了假话（签名有效，内容为假）。
    """
    if policy is None or response is None:
        raise BaselineError(
            "重跑 J(π,T) 需要 π 与 T 的**明文**，二者缺一不可。"
            "这正是签名 Merkle 基线相对 ZK 的结构性缺口："
            "验证者必须同时看到策略与响应，才能自己重算那个『真』。")

    pub = verify_public_only(env, keyring, root, inclusion)
    if not (pub["signature_ok"] and pub["inclusion_ok"]):
        raise BaselineError(f"公开数据那一关就没过：{pub['reason']}")

    _, body = cert.verify_envelope(env, keyring)
    # 2) T 必须能打开 response_commitment
    if body.get("response_commitment") != commit.commitment(response):
        raise BaselineError("送达的 T 打不开证书里的 response_commitment —— 被换过货")
    # 3) 手上的 π 必须就是签名时那份
    spec = compile_policy(policy)
    if body.get("policy_hash") != spec["sha256"]:
        raise BaselineError("手上的 π 与证书里的 policy_hash 对不上 —— 策略被换过")
    # 4) 重跑
    res = check(policy, response)
    if bool(body.get("passed")) != bool(res.passed):
        raise BaselineError(
            f"签名称 passed={body.get('passed')}，重跑 J(π,T) 得 passed={res.passed} —— "
            "签名有效，但签名者说了假话")
    return {
        "honest": True,
        "passed": bool(res.passed),
        "claimed_passed": body.get("passed"),
        "violations": [f"{v.rule}:{v.kind}" for v in res.violations],
        "reason": "验签 + 验包含 + 重跑 J(π,T)（π 与 T 均明文）",
    }


# --------------------------------------------------------------------------- #
# 机器校验的「不对称」
# --------------------------------------------------------------------------- #

def check_asymmetry(signer: cert.Ed25519Signer, keyring: cert.Keyring, policy: Policy,
                    policy_hash: str, response: str, nonce: bytes, ts: str,
                    fillers: list[str]) -> tuple[list[dict], dict]:
    """把本臂的结论**跑成断言**，返回 ``(可渲染的行, 供 JSON 存的明细)``。

    五条，缺一条就说明「不对称」是纸上的：

    1. 公开路径验得过签名与包含 —— 它**不是**废的；
    2. 公开路径的 ``passed`` 是 ``None`` / ``honest`` 是 ``False``；
    3. 拿公开结果当诚实核验 → :func:`require_honest` 必须抛;
    4. 抽掉 ``π`` 或 ``T`` → :func:`verify_by_reexecution` 必须抛;
    5. **反例**：同一把钥签一份 ``passed=False`` 的证书（真值其实是 ``True`` 的响应），
       公开路径照样全绿 —— 只有重跑才抓得住。这条是本臂最该被记住的一行。

    返回值里的每一行都是 ``{check, ok, note}``，``ok`` 全为 True 才算跑完。
    """
    ts_true = ts
    env, digest = build_certificate(signer, policy_hash, response, nonce, True, ts_true)
    log = MerkleLog(fillers)
    root = log.append(digest)
    idx = len(log) - 1
    proof = log.prove(idx)

    rows: list[dict] = []

    pub = verify_public_only(env, keyring, root, proof)
    rows.append({"check": "公开路径验签 + 验包含都通过",
                 "ok": bool(pub["signature_ok"] and pub["inclusion_ok"]),
                 "note": "公开数据不是废的：签名与日志包含都由它核"})
    rows.append({"check": "公开路径回答不了 passed（None / honest=False）",
                 "ok": pub["passed"] is None and pub["honest"] is False,
                 "note": "签名不担保内容为真，只担保『谁说了』"})

    raised = False
    try:
        require_honest(pub)
    except BaselineError:
        raised = True
    rows.append({"check": "拿公开结果当诚实核验 ⇒ 抛 BaselineError",
                 "ok": raised, "note": "require_honest() 把这个误用变成异常"})

    missing_ok = True
    for miss in (("π", None, response), ("T", policy, None)):
        try:
            verify_by_reexecution(miss[1], miss[2], env, keyring, root, proof)
            missing_ok = False
        except BaselineError:
            pass
    rows.append({"check": "缺 π 或 T ⇒ 重跑路径拒绝（fail loud）",
                 "ok": missing_ok, "note": "不静默降级成『只验签』"})

    # 反例：同一把钥、同一条日志，签一份**假**声明
    env_lie, digest_lie = build_certificate(signer, policy_hash, response, nonce,
                                            False, ts_true)
    log_lie = MerkleLog(fillers)
    root_lie = log_lie.append(digest_lie)
    proof_lie = log_lie.prove(len(log_lie) - 1)
    pub_lie = verify_public_only(env_lie, keyring, root_lie, proof_lie)
    lie_caught = False
    try:
        verify_by_reexecution(policy, response, env_lie, keyring, root_lie, proof_lie)
    except BaselineError:
        lie_caught = True
    rows.append({"check": "签名有效但内容为假 ⇒ 公开路径全绿、重跑才抓住",
                 "ok": bool(pub_lie["signature_ok"] and pub_lie["inclusion_ok"] and lie_caught),
                 "note": "公开路径看到的是一份『合格』证书；真值只有重跑 J(π,T) 才知道"})

    honest = verify_by_reexecution(policy, response, env, keyring, root, proof)
    rows.append({"check": "给了 π 与 T ⇒ 重跑确认 passed=True",
                 "ok": bool(honest["honest"] and honest["passed"] is True),
                 "note": "这一步是 ZK 从验证者手里**拿走**的那一步"})

    detail = {
        "public_ok": bool(pub["signature_ok"] and pub["inclusion_ok"]),
        "public_passed": pub["passed"],
        "public_honest": pub["honest"],
        "require_honest_raised": raised,
        "missing_plaintext_rejected": missing_ok,
        "false_claim_passed_public": bool(pub_lie["signature_ok"] and pub_lie["inclusion_ok"]),
        "false_claim_caught_by_reexecution": lie_caught,
        "reexecution_honest": honest["honest"],
        "reexecution_passed": honest["passed"],
        "all_checks_ok": all(r["ok"] for r in rows),
    }
    return rows, detail


# --------------------------------------------------------------------------- #
# 渲染（纯函数：只读 data，产出 .md 全文）
# --------------------------------------------------------------------------- #

def render_md(data: dict) -> str:
    """把结果 dict 渲染成 Markdown。**必须**是 ``data`` 的纯函数 —— 见
    ``tests/test_bench_views.py`` 对「视图 == 数据的渲染」这条不变量的一贯口径。"""
    h = data.get("host") or {}
    r = data["response"]
    md = ["# 非 ZK 基线：签名 Merkle 日志（WP9）", "",
          f"**量测机器**：{h.get('cpu_count')} 核 "
          f"`{h.get('cpu_model') or '未知型号'}`，"
          f"内存 {(h.get('mem_total_mb') or 0)/1024:.1f} GiB"
          f"（`{h.get('hostname')}`，{h.get('platform')}）；"
          f"Python {h.get('python')}；`{h.get('os')}`。",
          "本臂**不出证、不碰 SP1**（纯 Python），所以是秒级的；"
          "同一组参数换台机器重跑，数字会略微不同但量级不变。", ""]

    md += [f"策略包 `{data['pack']['path']}`（`{data['pack']['id']}` "
           f"{data['pack']['version']}，policy_hash `{data['pack']['policy_hash'][:16]}…`）；"
           f"响应 {r['chars']} 字符（`response_commitment` `{r['commitment'][:16]}…`，"
           f"`response_binding` `{r['binding'][:16]}…`）；"
           f"一次性挑战 nonce `{data['nonce'][:16]}…`。", "",
           f"每个时间数取 **n = {data['reps']}** 次重复的**中位数**；"
           f"日志规模 {data['log_size']} 片叶子（含本次这张证书），"
           f"根 `{data['log_root'][:16]}…`，包含证明针对第 {data['leaf_index']} 片叶子。", "",
           "| 指标 | 中位数 | 单位 | n |", "|---|---:|---|---:|"]
    for m in data["metrics"]:
        med = m["median"]
        shown = f"{med:,}" if isinstance(med, int) else f"{med:,.3f}"
        md.append(f"| {m['metric']} | {shown} | {m['unit']} | {m['n']} |")

    inc, cinfo = data["inclusion_proof"], data["certificate"]
    md += ["",
           f"证书大小 {cinfo['bytes']:,} B（DSSE 信封 JSON，`keyid` "
           f"`{cinfo['keyid'][:20]}…`，证书摘要 `{cinfo['cert_digest'][:16]}…`）；"
           f"包含证明 {inc['bytes']:,} B / {inc['siblings']} 个兄弟节点。", "",
           "## 不对称：签名担保不了「真」", "",
           "签名 Merkle 日志的核验链是「验签 → 验日志包含 → **重跑 `J(π,T)`**」。"
           "前两步只需要公开数据；**第三步需要 `π` 与 `T` 的明文**，这不是实现缺陷，"
           "是签名范式的结构性后果 —— 签名只把「谁说了这句话」绑到字节上，不把"
           "「这句话是真的」绑到任何东西上。下面每一条都是**跑出来的断言**（全绿才算跑完）：", "",
           "| 机器校验的断言 | 结果 | 说明 |", "|---|---|---|"]
    for row in data["asymmetry"]:
        md.append(f"| {row['check']} | {'✅' if row['ok'] else '❌'} | {row['note']} |")
    md += ["", "最后一行值得单独读：**同一把钥签一份内容为假的证书，公开路径照样全绿**"
           "—— 因为它看到的是一份签名有效、包含有效的『合格』证书；真值只有重跑 `J(π,T)` "
           "才知道。ZK 换来的恰恰是把这一步从验证者手里拿走。", ""]

    md += ["## 属性对照", "",
           "| property | signed-Merkle baseline | PoP (ZK) |", "|---|---|---|"]
    for p in data["properties"]:
        md.append(f"| {p['property']} | {p['baseline']} | {p['pop']} |")
    md += ["",
           f"> **ZK 侧成本一律不在此表**：{ZK_COST_REF}。本文件**不含任何 ZK/SP1 数字** —— "
           "交叉点数据在 WP1 落地前缺一半（`docs/tdsc-plan.md` §WP9.1 的诚实边界）。", ""]
    return "\n".join(md) + "\n"


def dump(out_path: Path, data: dict) -> None:
    """把结果写进 ``.json``，并由它渲染 ``.md``（两者必须同源）。"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    out_path.with_suffix(".md").write_text(render_md(data), encoding="utf-8")


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #

def load_policy(path: Path) -> Policy:
    """从 ``policy_packs/`` 读一个真策略包并构造 ``Policy``（与 tests 的最小加载器同形）。"""
    data = json.loads(path.read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r["name"], params=r.get("params", {}))
             for r in data["rules"]]
    return Policy(data["id"], data.get("version", "0.1.0"), rules=rules)


def median_ms(values: list[float]) -> float:
    """秒列表 → 毫秒中位数，保留 3 位小数（= 1 µs 分辨率；亚毫秒量级够用，
    且与渲染处的 ``:,.3f`` 同一口径，免得表里与属性行两个写法）。"""
    return round(statistics.median(values) * 1000, 3)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", type=Path, default=DEFAULT_PACK,
                    help="策略包 JSON（默认 EU AI Act 包）")
    ap.add_argument("--response", type=str, default=DEFAULT_RESPONSE,
                    help="被证明的那条响应 T（默认是一条合规响应）")
    ap.add_argument("--reps", type=int, default=DEFAULT_REPS,
                    help=f"每个时间数的重复次数（默认 {DEFAULT_REPS}）")
    ap.add_argument("--log-size", type=int, default=DEFAULT_LOG_SIZE,
                    help=f"追加时日志里已有的叶子数（默认 {DEFAULT_LOG_SIZE}）")
    ap.add_argument("--out", type=Path, default=REPO / "bench" / "results" / "baseline.json")
    ap.add_argument("--render-only", action="store_true",
                    help="不重采数据：只把已有的 --out JSON 重新渲染成 .md")
    args = ap.parse_args()

    if args.render_only:
        data = json.loads(args.out.read_text(encoding="utf-8"))
        args.out.with_suffix(".md").write_text(render_md(data), encoding="utf-8")
        print(f"→ {args.out.with_suffix('.md')}（由 {args.out} 重新渲染，未重采数据）")
        return 0

    policy = load_policy(args.pack)
    spec = compile_policy(policy)
    policy_hash = spec["sha256"]
    response = args.response
    verdict = check(policy, response)
    if not verdict.passed:
        raise SystemExit(
            "这条响应在本策略下**不合规**，本臂量的是「一个**为真的**结论在签名范式下"
            f"也验不了」——请换一条合规响应。违规：{[f'{v.rule}:{v.kind}' for v in verdict.violations]}")

    signer = cert.Ed25519Signer.generate()
    keyring = cert.keyring(signer.public_key)
    nonce = challenge.new_nonce()
    ts = cert.utc_now()

    h = bp.host_info()
    host = {**h, "python": platform.python_version(), "os": platform.platform()}
    print(f"host={host['hostname']}  {host['cpu_count']} 核  "
          f"{host['mem_total_mb']/1024:.1f} GiB  Python {host['python']}")
    print(f"policy={policy.id}  policy_hash={policy_hash[:16]}…  "
          f"响应 {len(response)} 字符  passed={verdict.passed}")

    fillers = [filler_digest(i) for i in range(max(0, args.log_size - 1))]
    env, digest = build_certificate(signer, policy_hash, response, nonce, True, ts)
    log = MerkleLog(fillers)
    root = log.append(digest)
    leaf_index = len(log) - 1
    inclusion = log.prove(leaf_index)

    # ---- 量测 ----
    sign_t: list[float] = []
    append_t: list[float] = []
    public_t: list[float] = []
    reexec_t: list[float] = []
    for _ in range(args.reps):
        t0 = time.perf_counter()
        cert.sign_payload({"policy_hash": policy_hash,
                           "response_commitment": commit.commitment(response),
                           "nonce": nonce.hex(), "passed": True, "ts": ts}, signer)
        sign_t.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        MerkleLog(fillers).append(digest)      # 追加 = 重算整棵树的根（见 MerkleLog）
        append_t.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        verify_public_only(env, keyring, root, inclusion)
        public_t.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        verify_by_reexecution(policy, response, env, keyring, root, inclusion)
        reexec_t.append(time.perf_counter() - t0)

    cert_bytes = len(cert.canonical(env))
    inc_bytes = len(json.dumps([list(x) for x in inclusion], separators=(",", ":")).encode())
    print(f"sign {median_ms(sign_t)} ms · merkle append {median_ms(append_t)} ms · "
          f"public verify {median_ms(public_t)} ms · reexec verify {median_ms(reexec_t)} ms "
          f"(n={args.reps})")
    print(f"cert {cert_bytes} B · inclusion proof {inc_bytes} B "
          f"({len(inclusion)} siblings)")

    asym_rows, asym_detail = check_asymmetry(signer, keyring, policy, policy_hash,
                                             response, nonce, ts, fillers)
    for row in asym_rows:
        print(f"  [{'PASS' if row['ok'] else 'FAIL'}] {row['check']}")
    if not asym_detail["all_checks_ok"]:
        raise SystemExit("不对称的机器校验没有全绿 —— 本臂的结论不成立，别入库这份结果")

    data = {
        "arm": "signed-merkle-baseline",
        "host": host,
        "pack": {"path": str(args.pack.relative_to(REPO)) if str(args.pack).startswith(str(REPO)) else str(args.pack),
                 "id": policy.id, "version": policy.version, "policy_hash": policy_hash},
        "response": {"chars": len(response), "commitment": commit.commitment(response),
                     "binding": commit.response_binding(nonce, response),
                     "passed": bool(verdict.passed)},
        "nonce": nonce.hex(),
        "ts": ts,
        "reps": args.reps,
        "log_size": len(log),
        "leaf_index": leaf_index,
        "log_root": root,
        "certificate": {"bytes": cert_bytes, "keyid": cert.envelope_keyid(env),
                        "cert_digest": digest},
        "inclusion_proof": {"siblings": len(inclusion), "bytes": inc_bytes},
        "metrics": [
            {"metric": "签名 `cert.sign_payload`（Ed25519 + DSSE 信封）",
             "median": median_ms(sign_t), "unit": "ms", "n": args.reps},
            {"metric": "Merkle 追加（追加一叶 + 重算根）",
             "median": median_ms(append_t), "unit": "ms", "n": args.reps},
            {"metric": "公开核验（验签 + 验包含）",
             "median": median_ms(public_t), "unit": "ms", "n": args.reps},
            {"metric": "重跑核验（验签 + 验包含 + `J(π,T)`）",
             "median": median_ms(reexec_t), "unit": "ms", "n": args.reps},
            {"metric": "证书大小", "median": cert_bytes, "unit": "B", "n": 1},
            {"metric": "包含证明大小", "median": inc_bytes, "unit": "B", "n": 1},
        ],
        "asymmetry": asym_rows,
        "asymmetry_detail": asym_detail,
        "properties": [
            {"property": "trust root（信任根基）",
             "baseline": "Ed25519 网关密钥 —— 信任落在**持钥的网关**上（密钥泄了就没有不可否认性）",
             "pop": "密码学 / 无硬件信任：只需 vkey，无需信任某台机器或某把钥不泄"},
            {"property": "验证者需要 `T` 明文？",
             "baseline": "**需要** —— 不重跑 `J(π,T)` 就无法确认 `passed`（本表量到的那条路）",
             "pop": "不需要 —— 判定在电路内，响应可只以承诺出现"},
            {"property": "验证者需要 `π` 明文？",
             "baseline": "**需要** —— 重跑要用同一份策略；签名要求签名者公开判定依据",
             "pop": "不需要 —— 只需 `policy_hash` 与 vkey"},
            {"property": "响应隐私",
             "baseline": "无 —— `T` 要交到验证者手里",
             "pop": "有（私有模式：证书里只有 `response_commitment` / `response_binding`）"},
            {"property": "策略隐私",
             "baseline": "无 —— 策略保密下签名范式直接失效（验证者无从重算）",
             "pop": "有 —— 策略进电路作私有见证"},
            {"property": "不可否认性",
             "baseline": "**相同** —— Ed25519 与 ZK 路径同源，这条基线**不更弱**（诚实的一行）",
             "pop": "**相同** —— 同样是 Ed25519 签名 / vkey 绑定，本行不为 ZK 记分"},
            {"property": "成本",
             "baseline": f"本表实测：签名 {median_ms(sign_t):,.3f} ms · "
                         f"公开核验 {median_ms(public_t):,.3f} ms · "
                         f"重跑核验 {median_ms(reexec_t):,.3f} ms · "
                         f"证书 {cert_bytes:,} B · 证明 {inc_bytes:,} B（n={args.reps}）",
             "pop": f"**n/a — {ZK_COST_REF}**"},
        ],
    }
    dump(args.out, data)
    print(f"\nwrote {args.out} and {args.out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
