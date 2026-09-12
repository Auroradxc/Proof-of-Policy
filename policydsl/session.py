"""跨证书策略一致性（P2-10）—— 把**一组证书**聚合成**一次**证明。

## 问题

一张证书说的是「**这条**响应满足策略 π」。可一次真实会话会签出**很多**张证书：
流式前缀证书、每次工具调用后的证书、LLM 结束时的权威证书。于是验证方手上是一
**叠**证书，而它们共同讲的故事（「同一个策略下、从会话开头到结尾、一张不缺」）
**没有任何一张证书说得出来**。审查者只能自己写脚本去核 —— 那是自述式的核对，
不是被证明的结论。

## 三条义务

本模块（与电路内 `pop_types::run_session` 逐字节对应）把三件事变成一次聚合证明：

1. **同一策略** —— 整组证书的 `policy_hash` 全同；
2. **无缝拼接** —— `streaming.chain = {index, prev}` 逐张连续（`prev` = 上一张的
   载荷摘要，首张为 `"genesis"`），与 :func:`policydsl.langchain_adapter.verify_chain`
   同一判据；
3. **覆盖完整轨迹** —— 链尾那张证书携带网关签的会话末端承诺（`trace_seal`，
   P1-5b），其 `(count, trace_root)` 进公开值。

## 承诺怎么拴到「真证书」上（本模块的关键）

叶子 = 每张证书的 ``cert_digest``（= ``SHA256(cert.canonical(payload))``）。
电路内对**证明者交来的载荷文本**求这个哈希，于是 Merkle 根承诺的就是
**一组具体的证书**；验证方拿**手上的证书文件**重算同一个根再比对：

* 换成别的证书 → 叶子变 → 根变 → 对不上；
* **挖掉一张** → 叶子数变 → 根变 → 对不上（**这是本域相对
  :func:`verify_chain` 多出来的那一层**：`verify_chain` 判不出尾部的缺失 ——
  `index = 0..k` 截断后仍然是「连续」的，这正是 P1-5b 的截尾问题在会话层的形态）；
* 重排 → `chain.index`/`prev` 在电路内就断（出不了证明），且根也会变。

## 边界（如实标注）

* 电路**不验网关签名**（zkVM 内没有网关公钥）。它证明的是「这组证书里链尾那张
  携带的 `(count, trace_root)` 是这些值」，验证方再用
  :func:`policydsl.trace.verify_seal` 拿网关公钥核签名、拿真回执链核
  `count`/`trace_root`。`verify_session_proof` 给了 ``keyring`` 与 ``receipts``
  时会把这一步跑掉，**没给时会如实说明「签名未验」**，不会让调用方以为跑全了。
* **只覆盖一个 run，且只覆盖链上的证书**。一个 session 里可能有多条互不相干的
  流式链（不同 ``run_id``），它们在 `chain.index == 0` 处各自重新开始；本模块对
  **一个 run** 成立，跨 run 请用 :func:`runs_of` 切开后逐个证。而链上只有**流式
  前缀证书** —— ``on_llm_end`` 那张**权威证书**没有 ``streaming`` 块，不在链上，
  因而不在任何 run 里（:func:`runs_of` 会跳过它）。它自己的合规结论由它自己的
  证书 + ``verify_cert.py`` 负责；本模块**不**声称覆盖它。
* 「完整」指的是**证书覆盖到的轨迹**。一次根本没签证书的工具调用不会被发现 ——
  那要靠 `ToolSeal.count` 与真回执链在链下的比对（同 P1-5b 的口径）。
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from policydsl import cert
from policydsl import verifier as V
from policydsl.commit import response_binding

REPO = Path(__file__).resolve().parent.parent
POP_SCRIPT = V.POP_SCRIPT
POP_VERIFY = V.POP_VERIFY

#: Merkle 内部节点的域分隔前缀（**必须与 Rust `MERKLE_NODE_DOMAIN` 逐字节相同**）。
MERKLE_NODE_DOMAIN = b"pop-session-node-v1"

#: 流的域标签（进 outcome 的 `domain` 字段，用于域绑定检查）。
DOMAIN = "session"

#: 链首的 `prev` 哨兵值。
GENESIS = "genesis"

#: 会话向量的格式版本。
SESSION_VERSION = "v1"


class SessionError(ValueError):
    """一组证书不满足三条义务中的某一条（或输入形状不对）。"""


# --------------------------------------------------------------------------- #
# Merkle：与 Rust `pop_types::merkle_root` 逐字节对应
# --------------------------------------------------------------------------- #

def _hex32(digest: str, what: str = "摘要") -> bytes:
    """十六进制摘要 → 32 字节；形状不对即抛错（fail closed）。"""
    try:
        raw = bytes.fromhex(digest)
    except (TypeError, ValueError) as exc:
        raise SessionError(f"{what}不是合法十六进制：{digest!r}") from exc
    if len(raw) != 32:
        raise SessionError(f"{what}不是 32 字节：{len(raw)} 字节（{digest!r}）")
    return raw


def merkle_levels(digests: Sequence[str]) -> List[List[str]]:
    """自底向上逐层展开（第一层是叶子，最后一层只有一个节点 = 根）。"""
    if not digests:
        raise SessionError("Merkle 树至少需要一片叶子（空集的『一致性』是恒真的）")
    level = [d for d in digests]
    for d in level:
        _hex32(d, "叶子")
    levels = [list(level)]
    while len(level) > 1:
        nxt: List[str] = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(
                MERKLE_NODE_DOMAIN + _hex32(level[i]) + _hex32(level[i + 1])
            ).hexdigest())
        if len(level) % 2:
            # 奇数个：末位**提升**，不复制。复制会让 [a,b,c] 与 [a,b,c,c] 同根，
            # 于是「挖掉一张尾证书」有了一条伪造路径（与 Rust 侧同一约定）。
            nxt.append(level[-1])
        level = nxt
        levels.append(list(level))
    return levels


def merkle_root(digests: Sequence[str]) -> str:
    """一组证书摘要 → Merkle 根（十六进制）。"""
    return merkle_levels(digests)[-1][0]


def merkle_proof(digests: Sequence[str], index: int) -> List[Tuple[str, str]]:
    """``index`` 那片叶子的包含证明，返回 ``[(side, 兄弟摘要), …]``（自底向上）。

    有了它，持**一张**证书的一方可以拿聚合证明里的根做包含证明，而不必交出
    整组证书 —— 根是全组承诺的，单证书的包含证明因此也能独立核对。
    """
    if not 0 <= index < len(digests):
        raise SessionError(f"叶子下标越界：{index}（共 {len(digests)} 片）")
    levels = merkle_levels(digests)
    path: List[Tuple[str, str]] = []
    i = index
    for depth in range(len(levels) - 1):
        level = levels[depth]
        if i % 2 == 0:
            # 自己是左孩子：兄弟在右。**末位提升**的情形没有兄弟节点。
            if i + 1 < len(level):
                path.append(("right", level[i + 1]))
        else:
            path.append(("left", level[i - 1]))
        i //= 2
    return path


def verify_merkle_proof(leaf: str, proof: Sequence[Tuple[str, str]], root: str) -> bool:
    """用包含证明从一片叶子重算根，与 ``root`` 比对。"""
    cur = _hex32(leaf, "叶子")
    try:
        for side, sibling in proof:
            sib = _hex32(sibling, "兄弟摘要")
            if side == "left":
                cur = hashlib.sha256(MERKLE_NODE_DOMAIN + sib + cur).digest()
            elif side == "right":
                cur = hashlib.sha256(MERKLE_NODE_DOMAIN + cur + sib).digest()
            else:
                raise SessionError(f"包含证明的方向只能是 left/right，得到 {side!r}")
    except SessionError:
        return False
    return cur.hex() == root


# --------------------------------------------------------------------------- #
# 证书 → 叶子 / 视图
# --------------------------------------------------------------------------- #

def cert_text(envelope: Dict[str, Any]) -> str:
    """一张证书信封 → 其载荷的**规范 JSON 文本**。

    这就是交给电路的那份文本：电路对它求 SHA-256 得到的正是
    :func:`policydsl.cert.cert_digest`，因此「电路里被聚合的那组证书」与
    「验证方手上这组证书文件」是同一个东西的两种表示。
    """
    payload = cert.envelope_payload(envelope)
    return cert.canonical(payload).decode("utf-8")


def cert_leaf(envelope: Dict[str, Any]) -> str:
    """一张证书的叶子值（= 载荷摘要 = 账本里的锚定值）。"""
    return cert.cert_digest(cert.envelope_payload(envelope))


def _payload(envelope: Dict[str, Any]) -> Dict[str, Any]:
    return cert.envelope_payload(envelope)


def runs_of(envelopes: Sequence[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    """按 ``streaming.chain.index == 0`` 把证书切成一条条 run。

    与 ``scripts/verify_session.py`` 的分组口径一致：一个 session 包里可能有多条
    互不相干的流式链，本模块的证明只对**一条 run** 成立。

    **只收「链上」的证书**（载荷里真有 ``streaming.chain`` 的那种）。真实会话包里
    还有**不在链上**的证书 —— ``on_llm_end`` 那张权威证书就没有 ``streaming`` 块，
    因为流式链是「前缀快照」的序列。把它扫进 run 只会让它撞上义务②而整组不可证，
    而它本来也不属于那条链。``verify_session.py`` 用 ``kind == "stream"`` 过滤，
    这里是同一个判据的**内容版**（看载荷里有没有链，而不是看调用方贴的标签）。
    """
    groups: List[List[Dict[str, Any]]] = []
    current: List[Dict[str, Any]] = []
    for env in envelopes:
        chain = (_payload(env).get("streaming") or {}).get("chain")
        if not isinstance(chain, dict):
            continue                     # 不在链上：不属于任何 run
        if chain.get("index") == 0 and current:
            groups.append(current)
            current = []
        current.append(env)
    if current:
        groups.append(current)
    return groups


# --------------------------------------------------------------------------- #
# 参考实现：镜像 Rust `pop_types::run_session`
# --------------------------------------------------------------------------- #

def run_session(certs: Sequence[str], nonce: bytes = b"") -> Dict[str, Any]:
    """三条义务的**参考实现**（纯 Python），返回与电路同形的 outcome 字典。

    与 ``pop-types::run_session`` 的关系，和 ``policydsl/evaluate.py`` 与
    ``pop-types::evaluate`` 的关系一样：两端独立算，``pop-script --check``
    逐字段对拍。任何一条义务不满足即抛 :class:`SessionError`（对应电路里的
    ``assert!`` —— 那边是出不了证明）。
    """
    if not certs:
        raise SessionError("会话证明至少需要一张证书")

    leaves: List[str] = []
    policy_hash: Optional[str] = None
    seal_keyid: Optional[str] = None
    last_seal: Optional[Dict[str, Any]] = None
    prev = GENESIS

    for i, text in enumerate(certs):
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        try:
            payload = json.loads(text)
        except (TypeError, ValueError) as exc:
            raise SessionError(
                f"第 {i} 张证书的载荷不是合法 JSON（本域的输入必须是 "
                f"cert.canonical(payload) 的文本）：{exc}") from exc
        if not isinstance(payload, dict):
            raise SessionError(f"第 {i} 张证书的载荷不是 JSON 对象")

        # ---- ① 同一策略 ----
        ph = payload.get("policy_hash")
        if not isinstance(ph, str) or not ph:
            raise SessionError(f"第 {i} 张证书载荷缺 policy_hash")
        if policy_hash is None:
            policy_hash = ph
        elif ph != policy_hash:
            raise SessionError(
                f"第 {i} 张证书的策略哈希与第 0 张不同（{policy_hash} vs {ph}）——"
                "这组证书不是同一个策略下签发的")

        # ---- ② 流式链无缝拼接 ----
        chain = (payload.get("streaming") or {}).get("chain")
        if not isinstance(chain, dict):
            raise SessionError(
                f"第 {i} 张证书缺 streaming.chain（它不是流式链上的一环，"
                "本域无从判『无缺口』）")
        if chain.get("index") != i:
            raise SessionError(
                f"第 {i} 张证书的 chain.index 是 {chain.get('index')!r}，应为 {i}"
                "（链有缺口或中间缺了证书）")
        if chain.get("prev") != prev:
            raise SessionError(
                f"第 {i} 张证书的 chain.prev 与上一张的载荷摘要不符"
                "（链被重排或中间被换过）")

        # ---- ③ 会话末端承诺 ----
        seal = payload.get("trace_seal")
        if not isinstance(seal, dict):
            raise SessionError(
                f"第 {i} 张证书缺 trace_seal（会话末端未被网关承诺 ⟹ "
                "无法排除链尾被删）")
        keyid = str(seal.get("keyid", ""))
        if seal_keyid is None:
            seal_keyid = keyid
        elif keyid != seal_keyid:
            raise SessionError(
                f"第 {i} 张证书的 seal 来自另一个网关（{seal_keyid} vs {keyid}）"
                "——这组证书不是同一条会话")
        last_seal = seal

        prev = digest
        leaves.append(digest)

    root = merkle_root(leaves)
    assert last_seal is not None  # 空集已在入口拒绝
    return {
        "mode": "session",
        "domain": DOMAIN,
        "policy_hash": policy_hash,
        "cert_count": len(certs),
        "merkle_root": root,
        "session_binding": response_binding(nonce, root),
        "trace_root": str(last_seal.get("trace_root", "")),
        "sealed_count": int(last_seal.get("count", 0)),
        "seal_keyid": seal_keyid or "",
    }


def session_vectors(envelopes: Sequence[Dict[str, Any]], nonce: bytes = b"",
                    name: str = "session") -> Dict[str, Any]:
    """一组证书 → 会话域的向量（``pop-script --job session`` 的输入形状）。"""
    return {"name": name, "certs": [cert_text(e) for e in envelopes],
            "nonce": list(nonce)}


# --------------------------------------------------------------------------- #
# 出证方
# --------------------------------------------------------------------------- #

def prove_session(envelopes: Sequence[Dict[str, Any]], *,
                  nonce: bytes = b"",
                  proof_out: Optional[Path] = None,
                  proof_mode: str = "core",
                  pop_script: Path = POP_SCRIPT) -> Dict[str, Any]:
    """对一组证书出一次聚合证明，返回验证器输出的字典（含 ``outcome``）。

    ``proof_out`` 给定时把证明与边车存到那里（供第三方独立验证）。
    """
    with tempfile.TemporaryDirectory(prefix="pop-session-") as tmp:
        vp = Path(tmp) / "vectors.json"
        op = Path(tmp) / "results.json"
        vp.write_text(json.dumps({"vectors": [session_vectors(envelopes, nonce)]},
                                 ensure_ascii=False), encoding="utf-8")
        cmd = [str(pop_script), "--job", "session", "--proof-mode", proof_mode,
               "--vectors", str(vp), "--out", str(op)]
        if proof_out is not None:
            cmd += ["--proof-out", str(proof_out)]
        proc = V.run_cmd(cmd, {"SP1_PROVER": "cpu"})
        if proc.returncode != 0:
            raise SessionError(f"会话证明失败："
                               f"{proc.stderr.strip() or proc.stdout.strip()}")
        results = json.loads(op.read_text(encoding="utf-8"))
    if len(results) != 1:
        raise SessionError(f"期望 1 条结果，得到 {len(results)} 条")
    return {"outcome": results[0], "proof_file": proof_out}


# --------------------------------------------------------------------------- #
# 验证方
# --------------------------------------------------------------------------- #

def verify_session_proof(outcome: Dict[str, Any], *,
                         envelopes: Sequence[Dict[str, Any]],
                         nonce: bytes = b"",
                         proof: Optional[Path] = None,
                         keyring: Any = None,
                         receipts: Optional[Sequence[Any]] = None,
                         policy_pack: Optional[Path] = None,
                         policy: Any = None) -> Tuple[bool, str, bool]:
    """核一次会话聚合证明。返回 ``(ok, detail, satisfied)``。

    ``ok`` = 「这次聚合是真的」：证明有效（给 ``proof`` 时做密码学验证）、
    承诺的 Merkle 根 == 由**交付的这批证书**重算的根、且三条义务的公开结论
    与这批证书逐字段相符。``satisfied`` = 「这批证书覆盖的轨迹确实合规」——
    与 ``verify_composite`` 一样分开：一张如实记录了违规的聚合证明**同样是真**的。

    ``keyring``/``receipts`` 给定时，额外用 :func:`policydsl.trace.verify_seal`
    核会话末端承诺（那是 ③ 的另一半，链下做）；**没给时会如实注明未验签名**。
    """
    notes: List[str] = []
    if not envelopes:
        return False, "交付的证书集为空", False

    # ---- 交付的证书：叶子、根、三条义务的现场重算 ----
    try:
        leaves = [cert_leaf(e) for e in envelopes]
        root = merkle_root(leaves)
        recomputed = run_session([cert_text(e) for e in envelopes], nonce)
    except SessionError as exc:
        return False, f"交付的证书集不满足会话义务：{exc}", False

    if outcome.get("mode") != "session":
        return False, f"这份证明的 mode 是 {outcome.get('mode')!r}，应为 'session'", False
    if outcome.get("domain") != DOMAIN:
        return False, (f"这份证明的 domain 是 {outcome.get('domain')!r}，"
                       f"应为 {DOMAIN!r}"), False

    if outcome.get("merkle_root") != root:
        return False, (
            "承诺的 Merkle 根与交付的证书集对不上 —— 被证明的那组证书不是这一批"
            "（换了一张 / **挖掉了一张** / 顺序不同，都会走到这里）："
            f"证明称 {V.short_hash(str(outcome.get('merkle_root') or ''))}，"
            f"现场重算 {V.short_hash(root)}"), False
    notes.append(f"Merkle 根与交付的 {len(envelopes)} 张证书相符")

    for field in ("policy_hash", "cert_count", "session_binding",
                  "trace_root", "sealed_count", "seal_keyid"):
        if outcome.get(field) != recomputed[field]:
            return False, (f"承诺的 {field} 与交付的证书集现场重算结果不符："
                           f"证明称 {outcome.get(field)!r}，现场重算 "
                           f"{recomputed[field]!r}"), False
    notes.append("policy_hash / cert_count / trace_root / sealed_count 均与证书集相符")

    # ---- 密码学验证（可选） ----
    if proof is not None:
        try:
            v = V.verify_proof_file(Path(proof), "session")
        except ValueError as exc:
            return False, f"会话证明未通过密码学验证：{exc}", False
        if not v.get("verified"):
            return False, "会话证明未通过密码学验证", False
        # 只剥 `name`（那是驱动程序按需追加的展示元信息，不参与承诺）；
        # **`mode`/`domain` 必须留下** —— 它们正是本域要判的东西。
        committed = {k: val for k, val in (v.get("outcome") or {}).items() if k != "name"}
        if committed != {k: val for k, val in outcome.items() if k != "name"}:
            return False, ("证明公开值解出的 outcome 与交付的 outcome 不一致 —— "
                           "转述的不是证明说的"), False
        notes.append("证明通过密码学验证，公开值与 outcome 逐字段一致")
    else:
        notes.append("**证明有效性未核**（未给 proof）")

    # ---- ③ 的另一半：会话末端承诺（链下） ----
    if policy_pack is not None or policy is not None:
        from policydsl.compile import compile_policy
        pol = policy if policy is not None else _load_policy(policy_pack)
        want = compile_policy(pol)["sha256"]
        if outcome.get("policy_hash") != want:
            return False, ("承诺的 policy_hash 与现场重编译的策略不符 —— "
                           "被聚合的不是这个策略"), False
        notes.append("policy_hash 与现场重编译相符")

    seal = _last_seal(envelopes)
    if seal is None:
        return False, "链尾证书没有 trace_seal", False
    from policydsl import trace as T
    ok_seal, why = T.verify_seal(seal, keyring=keyring, receipts=receipts)
    if not ok_seal:
        return False, f"会话末端承诺核对失败：{why}", False
    notes.append(why)
    if (int(seal.count) != int(outcome.get("sealed_count", -1))
            or seal.trace_root != outcome.get("trace_root")):
        return False, ("链尾证书的 trace_seal 与证明承诺的 (sealed_count, trace_root) "
                       "不一致 —— 链尾被换过"), False

    # ---- 合规结论：与 compose 层同一条保守口径 ----
    # 只要有一张证书的结论不是「通过」，这批证书覆盖的轨迹就**没有被满足**。
    # 取不到 `passed` 记 False（fail closed）：一张读不出结论的证书不能算合规。
    # 注意这与 `ok` 无关 —— 一张如实记录违规的聚合证明同样是**真**的。
    bad = [i for i, e in enumerate(envelopes)
           if not (_payload(e).get("outcome") or {}).get("passed", False)]
    satisfied = not bad
    if bad:
        notes.append(f"交付的证书里有 {len(bad)} 张 passed 非 true（第 {bad[:3]} 张…）"
                     " —— 聚合证明为**真**，但所覆盖的轨迹**不合规**")
    else:
        notes.append(f"覆盖的 {len(envelopes)} 张证书均为合规结论")

    return True, "; ".join(notes), satisfied


def _last_seal(envelopes: Sequence[Dict[str, Any]]):
    """交付证书集里**链尾那张**（`chain.index` 最大）的 `ToolSeal`。"""
    from policydsl.trace import ToolSeal
    best, best_index = None, -1
    for e in envelopes:
        payload = _payload(e)
        chain = (payload.get("streaming") or {}).get("chain") or {}
        idx = chain.get("index")
        if isinstance(idx, int) and idx > best_index:
            seal = payload.get("trace_seal")
            if isinstance(seal, dict):
                best, best_index = ToolSeal.from_dict(seal), idx
    return best


def _load_policy(path: Path):
    """从 JSON 载入策略包（与 ``compose._load_policy`` 同口径，避免循环导入）。"""
    from policydsl.model import Policy, Rule
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r.get("name", f"r{i}"), params=r.get("params", {}))
             for i, r in enumerate(d["rules"])]
    return Policy(d["id"], d.get("version", "0.1.0"), rules=rules)


def pop_check(envelopes: Sequence[Dict[str, Any]], nonce: bytes = b"",
              pop_script: Path = POP_SCRIPT) -> Dict[str, Any]:
    """把一组证书喂给 Rust 的宿主校验（``--check --job session``），返回 outcome。

    与 :func:`run_session` 是两条独立实现（Python / Rust），供逐字段对拍 ——
    「两端算的是同一个聚合」这条性质由 ``tests/test_session.py`` 的第一层守住。
    """
    with tempfile.TemporaryDirectory(prefix="pop-session-check-") as tmp:
        vp = Path(tmp) / "vectors.json"
        op = Path(tmp) / "results.json"
        vp.write_text(json.dumps({"vectors": [session_vectors(envelopes, nonce)]},
                                 ensure_ascii=False), encoding="utf-8")
        proc = V.run_cmd([str(pop_script), "--check", "--job", "session",
                          "--vectors", str(vp), "--out", str(op)])
        if proc.returncode != 0:
            raise SessionError(f"pop-script --check --job session 失败："
                               f"{proc.stderr.strip() or proc.stdout.strip()}")
        return json.loads(op.read_text(encoding="utf-8"))[0]


__all__ = [
    "SessionError", "MERKLE_NODE_DOMAIN", "DOMAIN", "GENESIS", "SESSION_VERSION",
    "merkle_root", "merkle_levels", "merkle_proof", "verify_merkle_proof",
    "cert_text", "cert_leaf", "runs_of", "run_session", "session_vectors",
    "prove_session", "verify_session_proof", "pop_check",
]
