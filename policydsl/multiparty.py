"""多证明者：策略切片 + 角色签名（P2-11）—— 三个角色各证一段，缺谁都不成立。

## 问题

``pop-program`` 证明的是「响应 ``T`` 满足策略 ``π``」。到 P2-10 为止，``π`` 一直是
**一个**证明者的义务：谁出证，谁就要对整条策略负责。真实部署里这条义务是**分裂**的：

* 响应文本本身的性质（有没有出现禁用词、长度是否越界、格式对不对）—— 归**模型方**，
  因为 ``T`` 是它产出的；
* 工具调用的性质（有没有带禁用字段、调用次数有没有超预算）—— 归**工具网关**，
  因为只有它持有 P1-5 的回执链，判定依据在它手里；
* 学出来的那部分（「有害概率 ≤ 阈值」）—— 归**部署方**，模型与阈值在它手里。

一份「谁都能出、出了也不用说清是谁」的证明，恰好把这三段责任混成一段。本模块把它
们**分开**：三个角色各持一把键、各证自己那一段（切片），产出一张
:class:`MultipartyCertificate`。

## 切片怎么分（:func:`shard`）

按**规则类**分，判据是「谁能拿到这条规则的判定依据」：

| 角色 | 规则类 |
|---|---|
| 模型方 ``model`` | `keyword_block` / `normalized_keyword_block` / `pattern_block` / `format_check` / `length_bound` |
| 工具网关 ``gateway`` | `tool_arg_guard` / `budget_bound` |
| 部署方 ``deployer`` | `semantic_bound` |

未知规则类**不猜**：:func:`role_of_kind` 直接抛错。新加一类规则必须显式指定谁为它
负责，否则它会静默地落进一个「没人证」的位置 —— 那正是本模块要消灭的形态。

切片**互斥，且并集为整条策略**。这是本模块的核心不变式，验证方会现场重算。
没有自己那类规则的角色的切片是**空切片**：它**仍然要签名**（「这一段我不负责」必须
是显式的，不能表现为「这个角色在证书里不存在」——那就分不清是有意还是被删了）。

## 「聚合证明」是什么、不是什么（如实标注）

计划里的措辞是「N 签名 + 聚合证明」。本实现里的**聚合**是：

* 每个非空切片各一份 SP1 证明（**同一个** ``pop-program``、同一个 vkey —— 切片在
  电路眼里就是一条普通策略，因此本设计**不需要新 guest、不作废任何已有证明**）；
* 一份把 N 份证明拴在一起的证书：共同的 ``policy_hash``（**整条**策略）、共同的
  ``response_binding``（同一条 ``T``）、共同的 ``trace_root``（同一条回执链）、
  一份 ``plan``（谁证哪几段）及其摘要，以及**每个角色对自己那一份 part 的 Ed25519
  签名**（签名覆盖 part 的每一个字段，含它承诺的切片哈希与那条 ``T``）。

它**不是**一个递归聚合证明（把 N 份证明折成一份、验证成本 O(1)）—— 那需要一个新的
guest 与一个新的 vkey，本仓库没有接线。所以这里的验证成本是 **O(N) 份证明**，别把它
读成「一份证明搞定了所有人」。

## 验证方跑什么（:func:`verify_multiparty`）

1. **形状**：``parts`` 恰好是三个角色各一份（重复或缺失都拒）；``plan`` 覆盖三个角色；
2. **角色键分离**：三份信封的 keyid **两两不同** —— 同一把键扮演两个角色时，
   「这一份是谁证的」无从判断，多证明者当场退化成单证明者；
3. **签名**：给了 ``keyring`` 就逐份验签，并要求「签名覆盖的载荷 == part 的字段」
   （改了 part 而没重签，在这里就被拦住）；**没给 keyring 时如实注明未核签名**；
4. **切片划分**：part 自述的 ``rules``/``slice_sha256`` 必须与 ``plan`` 一致、plan 摘要
   必须现场重算相符、并集**互斥**；给了策略包/策略对象时再**现场重编译** ——
   整条策略哈希、三个切片的哈希与规则列表都要逐字段对上（**单角色切片被换**
   正是这一步拦的）。不给策略包时如实注明：只能核自洽，不能核「整条策略就是你手上
   那个包」；
5. **证明**：空切片必须**没有**证明（带了就拒）；非空切片必须有证明，且文件哈希、
   密码学验证、公开值与 part 记录、``policy_hash == 该切片的哈希``（**证明的是这一段**）、
   ``mode == "public"`` 全部成立；各切片证明必须来自**同一个** vkey，给了
   ``expected_vkey`` 还要与它相等；
6. **同一条 T / 同一条轨迹**：证书声明、各切片公开值、各 part 自述、以及由送达的
   ``T′`` 与 nonce 现场重算的值，全部相等；各切片的 ``trace_root`` 也必须相等
   （见下面「回执链」）；
7. **合规结论**：所有非空切片的 ``passed`` 且 ``delegated`` 为空。

第 7 条与 ``compose.py`` 的第 8 条同一条口径：``delegated`` 非空（部署方那段通常
含 ``semantic_bound``）意味着**有规则没被这份证书判定**，合规结论要由验证方合取
陪伴证明后才给出 —— 多证明者层**不替它下结论**。

``ok``（这份多证明者证书是**真的**）与 ``satisfied``（整条策略确实被**满足**）必须
分开读，理由与 ``verify_composite`` / ``verify_session_proof`` 完全相同：一张如实
记录了违规的多证明者证书同样是**真**证书。

## 回执链（P1-5）要**给所有**切片

``build_multiparty`` 把同一条回执链发给每个切片。理由不是省事，而是：``trace_root``
是「这三段判的是**同一条**轨迹」唯一可机检的形式 —— 网关那段用回执判
``tool_arg_guard``/``budget_bound``，其余两段虽然不用它判定，但照样承诺同一个
``trace_root``。验证方因此可以要求三者相等（第 6 条）。哪一段看到了**另一条**链，
就是三段各判各的，「三段合起来等于整条策略」这句话就没有依据了。

## 边界（如实标注）

* 本模块**不产生**语义规则的陪伴证明。部署方那段的 SP1 证明会把 ``semantic_bound``
  记进 ``delegated``，而**不判定**它（那是 L7 的委托路径，归 ``ezkl_prove.py`` 那条线）。
  多证明者证书因此只说「这一段被**委托**出去了、且由部署方签过字」；
* 要把多证明者证书接进组合层（``verify_composite``）需要把 N 份切片证明折成**一个**
  policy part —— 组合层要求单个证明文件，本模块没有做这件事，如实记为未接线；
* 三个角色是**责任划分**，不是三道独立信任边界：它们共享同一个 ``pop-program``
  （同一个 vkey）。要「不同角色用不同电路」得各出 vkey，本模块不主张做到了那件事。
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from policydsl import cert as C
from policydsl import commit as CMT
from policydsl import verifier as V
from policydsl.compile import (compile_policy, compile_slice_policy,
                               require_covering_length_bound)
from policydsl.model import Policy
from policydsl.serialize import build_vectors, vector_entry

REPO = Path(__file__).resolve().parent.parent
POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"
POP_VERIFY = REPO / "circuits" / "target" / "release" / "pop-verify"

#: multiparty.json 的格式版本。
MULTIPARTY_VERSION = "v1"

#: 三个角色。顺序固定：``plan``/``parts`` 的遍历、诊断信息的顺序都由它决定。
ROLE_MODEL = "model"
ROLE_GATEWAY = "gateway"
ROLE_DEPLOYER = "deployer"
ROLES: Tuple[str, ...] = (ROLE_MODEL, ROLE_GATEWAY, ROLE_DEPLOYER)

#: 角色 → 中文名（诊断信息用；证书里存的是英文 id）。
ROLE_LABELS: Dict[str, str] = {
    ROLE_MODEL: "模型方/model",
    ROLE_GATEWAY: "工具网关/gateway",
    ROLE_DEPLOYER: "部署方/deployer",
}

#: 规则类 → 归属角色。判据：**谁能拿到这条规则的判定依据**（见模块头）。
KIND_OWNER: Dict[str, str] = {
    "keyword_block": ROLE_MODEL,
    "normalized_keyword_block": ROLE_MODEL,
    "pattern_block": ROLE_MODEL,
    "format_check": ROLE_MODEL,
    "length_bound": ROLE_MODEL,
    "tool_arg_guard": ROLE_GATEWAY,
    "budget_bound": ROLE_GATEWAY,
    "semantic_bound": ROLE_DEPLOYER,
}

#: 角色 → 它负责的规则类（由 :data:`KIND_OWNER` 派生，不手抄第二份）。
KINDS_BY_ROLE: Dict[str, Tuple[str, ...]] = {
    role: tuple(k for k, r in KIND_OWNER.items() if r == role) for role in ROLES
}

#: 多证明者的义务陈述（进证书，供人读）。
OBLIGATION = "⋀(每个角色对其切片 π_r 的证明 ∧ 该角色键对 π_r 的签名) ∧ (⋃π_r = π)"


class MultipartyError(ValueError):
    """多证明者证书在构造或验证上不成立（缺角色、切片对不上、绑定不符等）。"""


def label(role: str) -> str:
    """角色的可读名（诊断信息里到处在用，集中一处避免措辞漂移）。"""
    return ROLE_LABELS.get(role, f"{role}/?")


# --------------------------------------------------------------------------- #
# 切片：整条策略 → 角色 → 子策略
# --------------------------------------------------------------------------- #

def role_of_kind(kind: str) -> str:
    """规则类 → 归属角色。**未知类不猜**：直接抛错（见模块头）。"""
    try:
        return KIND_OWNER[kind]
    except KeyError:
        raise MultipartyError(
            f"未知规则类 {kind!r}：分片不猜归属 —— 新加一类规则必须在 "
            f"policydsl/multiparty.py 的 KIND_OWNER 里显式指定哪个角色为它的判定"
            f"依据负责，否则它会静默地落到一个「没人证」的位置上。"
            f"已知：{sorted(KIND_OWNER)}") from None


def shard(policy: Policy) -> Dict[str, Policy]:
    """把整条策略按规则类切成三个角色的切片（**互斥且并集为整条策略**）。

    返回值恒含全部三个角色：没有自己那类规则的角色的切片是**空策略**。

    **定长前提在整条策略上检查一次**：``require_covering_length_bound`` 陈述的是
    「任意合法输入都能被完整判定」，而 ``length_bound`` 归模型方那段切片 ——
    在部署方那段上再查一次会把每个含语义规则的策略结构性地变成无法分片
    （见 :func:`policydsl.compile.compile_slice_policy`）。
    """
    policy.validate()
    require_covering_length_bound(policy)      # 整条策略层面的不变式
    names = [r.name for r in policy.rules]
    dups = sorted({n for n in names if names.count(n) > 1})
    if dups:
        raise MultipartyError(
            f"规则名必须唯一：plan 用规则名标识「谁证了哪一段」，重名会让这句话 "
            f"产生歧义。重名规则：{dups}")
    buckets: Dict[str, List[Any]] = {role: [] for role in ROLES}
    for rule in policy.rules:
        buckets[role_of_kind(rule.kind)].append(rule)
    return {
        role: Policy(policy.id, policy.version, policy.description,
                     list(buckets[role]), policy.semantic)
        for role in ROLES
    }


def slice_specs(policy: Policy) -> Dict[str, Dict[str, Any]]:
    """角色 → 该角色切片的 ``ConstraintSpec``（**切割后现场编译**，没缓存）。"""
    return {role: compile_slice_policy(sub) for role, sub in shard(policy).items()}


def slice_rules(spec: Dict[str, Any]) -> List[str]:
    """切片覆盖的规则名（按约束顺序 = 策略包里的顺序）。"""
    return [c["name"] for c in spec["constraints"]]


def plan_of(policy: Policy) -> Dict[str, Dict[str, Any]]:
    """角色 → ``{"rules": [...], "slice_sha256": ...}``。

    **验证方现场重算的就是这个函数** —— 出证方与验证方共用同一份，不存在
    「两边各切一次、切法不一致」的可能。
    """
    return {role: {"rules": slice_rules(spec), "slice_sha256": spec["sha256"]}
            for role, spec in slice_specs(policy).items()}


def plan_digest(plan: Dict[str, Any]) -> str:
    """计划摘要：把「谁证哪几段」压成一个值，进每个角色的签名载荷。"""
    return hashlib.sha256(C.canonical(plan)).hexdigest()


def sha256_file(path: Path) -> str:
    """对文件字节求 SHA-256（小写十六进制）。"""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _signer_keyid(signer: Any) -> str:
    """取签名器的 keyid；取不到就报错（**不猜**：三个角色是不是同一把键要靠它判）。"""
    kid = getattr(signer, "keyid", None)
    if not kid:
        raise MultipartyError(
            f"签名器 {signer!r} 没有 keyid —— 无法判断三个角色用的是不是不同的键，"
            "而「键分离」正是本层成立的前提")
    return str(kid)


def _committed_outcome(proof_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """取验证结果里的 outcome，**只剥 `name`**（与 ``compose._outcome_of`` 同口径）。

    刻意不用 ``verifier.outcome_without_meta``：那个函数连 ``mode`` 一起剥掉，
    而 ``mode``（public/private）正是本层要判的字段之一。
    """
    outcome = proof_result.get("outcome")
    if not isinstance(outcome, dict):
        return None
    return {k: v for k, v in outcome.items() if k != "name"}


def _meta_vkey(proof: Path) -> Optional[str]:
    """从 ``<proof>.meta.json`` 读自报的 vkey 哈希（只用于非密码学的一致性检查）。"""
    try:
        m = json.loads(Path(f"{proof}.meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    v = m.get("vkey_hash")
    return v if isinstance(v, str) and v else None


def _load_policy(path: Path) -> Policy:
    """从 JSON 载入策略包（与 ``compose._load_policy`` 同口径，避免循环导入）。"""
    from policydsl.model import Rule
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r.get("name", f"r{i}"), params=r.get("params", {}))
             for i, r in enumerate(d["rules"])]
    return Policy(d["id"], d.get("version", "0.1.0"), rules=rules)


# --------------------------------------------------------------------------- #
# 证书结构
# --------------------------------------------------------------------------- #

@dataclass
class SlicePart:
    """一个角色的一「段」：证明（可为空）+ 它对这一段的自述 + 它的签名。

    ``policy_hash`` / ``response_binding`` / ``plan_digest`` 三个**共同上下文**字段
    刻意复制进每一份 part：签名覆盖的是 :meth:`claim` —— 也就是「我认可这条整策略、
    认可这份划分、认可这条 T，并对我这一段负责」这句话的**全部**内容。少了它们，
    角色签的就只是「有这么一段」，而不是「这一段属于**这条**策略、**这条**响应」。
    """

    role: str
    rules: List[str] = field(default_factory=list)
    slice_sha256: str = ""
    proof_file: Optional[str] = None
    proof_sha256: Optional[str] = None
    vkey_hash: Optional[str] = None
    proof_mode: Optional[str] = None
    outcome: Dict[str, Any] = field(default_factory=dict)
    policy_hash: str = ""
    response_binding: str = ""
    plan_digest: str = ""
    envelope: Dict[str, Any] = field(default_factory=dict)

    @property
    def empty(self) -> bool:
        """空切片 = 这个角色没有需要判定的规则（仍要签名）。"""
        return not self.rules

    def claim(self) -> Dict[str, Any]:
        """签名覆盖的载荷 = part 的**全部**字段（不含 ``envelope`` 本身）。"""
        return {
            "role": self.role,
            "rules": list(self.rules),
            "slice_sha256": self.slice_sha256,
            "proof_file": self.proof_file,
            "proof_sha256": self.proof_sha256,
            "vkey_hash": self.vkey_hash,
            "proof_mode": self.proof_mode,
            "outcome": self.outcome,
            "policy_hash": self.policy_hash,
            "response_binding": self.response_binding,
            "plan_digest": self.plan_digest,
        }

    def to_json(self) -> Dict[str, Any]:
        return {**self.claim(), "envelope": self.envelope}

    @staticmethod
    def from_json(d: Dict[str, Any]) -> "SlicePart":
        return SlicePart(
            role=d["role"],
            rules=list(d.get("rules") or []),
            slice_sha256=d.get("slice_sha256") or "",
            proof_file=d.get("proof_file"),
            proof_sha256=d.get("proof_sha256"),
            vkey_hash=d.get("vkey_hash"),
            proof_mode=d.get("proof_mode"),
            outcome=d.get("outcome") or {},
            policy_hash=d.get("policy_hash") or "",
            response_binding=d.get("response_binding") or "",
            plan_digest=d.get("plan_digest") or "",
            envelope=d.get("envelope") or {},
        )


@dataclass
class MultipartyCertificate:
    """N 份切片证明 + 每个角色对其切片的签名 + 一份共同的切片计划。

    刻意**不**冻结（与 ``CompositeCertificate`` 同一个理由）：测试与工具常要拿
    「一份已验证的证书改一个字段」来构造反例。
    """

    nonce: bytes
    response_binding: str
    policy_hash: str
    plan: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    parts: List[SlicePart] = field(default_factory=list)
    #: 声明出来的计划摘要。**它必须与现场重算的 ``plan_digest(plan)`` 相等**，
    #: 且每个 part 的签名覆盖的那个值也要等于它 —— 两处一起才把「谁证哪几段」
    #: 钉住（只核一边的话，改掉另一边仍然自洽）。
    plan_digest: str = ""
    obligation: str = OBLIGATION
    version: str = MULTIPARTY_VERSION

    def part(self, role: str) -> Optional[SlicePart]:
        """按角色取 part；没有则 None（**不做默认值**：缺失必须被看见）。"""
        for p in self.parts:
            if p.role == role:
                return p
        return None

    @property
    def proved_parts(self) -> List[SlicePart]:
        """非空切片（= 真的出了证明的那几段）。"""
        return [p for p in self.parts if not p.empty]

    def to_json(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "kind": "multiparty",
            "obligation": self.obligation,
            "role_separation": {
                "roles": list(ROLES),
                "note": "三个角色各持一把**不同**的键：同一把键扮演两个角色时，"
                        "『这一份是谁证的』无从判断，多证明者当场退化成单证明者。",
            },
            "nonce_hex": self.nonce.hex(),
            "response_binding": self.response_binding,
            "policy_hash": self.policy_hash,
            "plan_digest": self.plan_digest,
            "plan": self.plan,
            "parts": [p.to_json() for p in self.parts],
        }

    @staticmethod
    def from_json(d: Dict[str, Any]) -> "MultipartyCertificate":
        return MultipartyCertificate(
            nonce=bytes.fromhex(d.get("nonce_hex") or ""),
            response_binding=d.get("response_binding") or "",
            policy_hash=d.get("policy_hash") or "",
            plan=d.get("plan") or {},
            plan_digest=d.get("plan_digest") or "",
            parts=[SlicePart.from_json(p) for p in d.get("parts") or []],
            obligation=d.get("obligation") or OBLIGATION,
            version=d.get("version") or MULTIPARTY_VERSION,
        )


# --------------------------------------------------------------------------- #
# 出证方：每个角色自己的那一段
# --------------------------------------------------------------------------- #

def slice_vectors(policy: Policy, response: str, *,
                  receipts: Optional[Sequence[Any]] = None,
                  nonce: bytes = b"") -> Dict[str, Any]:
    """一个角色切片 → 一条 vectors 条目（``--job policy`` 的输入形状）。

    出证与宿主校验共用这一份：两条路若各拼一次向量，迟早会有一条拼错字段而
    静默退化成「没带 receipts」之类。
    """
    spec = compile_slice_policy(policy)
    extra: Dict[str, Any] = {"name": policy.id, "nonce": list(nonce)}
    if receipts:
        extra["receipts"] = receipts
    return vector_entry(spec, response, **extra)


def _run_slice_vectors(entry: Dict[str, Any], *, check_mode: bool, proof_out: Optional[Path],
                       proof_mode: str, pop_script: Path) -> Dict[str, Any]:
    """跑一次 ``pop-script``（``--check`` 或出证），返回那一条结果的 outcome。"""
    with tempfile.TemporaryDirectory(prefix="pop-multiparty-") as tmp:
        vp = Path(tmp) / "vectors.json"
        op = Path(tmp) / "results.json"
        vp.write_text(json.dumps(build_vectors([entry]), ensure_ascii=False),
                      encoding="utf-8")
        cmd = [str(pop_script), "--job", "policy"]
        if check_mode:
            cmd.append("--check")
        else:
            cmd += ["--proof-mode", proof_mode]
        cmd += ["--vectors", str(vp), "--out", str(op)]
        if proof_out is not None:
            cmd += ["--proof-out", str(proof_out)]
        proc = V.run_cmd(cmd, {"SP1_PROVER": "cpu"})
        if proc.returncode != 0:
            raise MultipartyError(
                f"切片{'宿主校验' if check_mode else '证明'}失败"
                f"（policy_id={entry.get('name')!r}）："
                f"{proc.stderr.strip() or proc.stdout.strip()}")
        results = json.loads(op.read_text(encoding="utf-8"))
    if len(results) != 1:
        raise MultipartyError(f"期望 1 条结果，得到 {len(results)} 条")
    return {k: v for k, v in results[0].items() if k != "name"}


def prove_slice(policy: Policy, response: str, *, receipts: Optional[Sequence[Any]] = None,
                nonce: bytes = b"", proof_out: Optional[Path] = None,
                proof_mode: str = "core",
                pop_script: Path = POP_SCRIPT) -> Dict[str, Any]:
    """对**一个角色切片的策略**出一次证明，返回 ``{"outcome", "proof_file", "spec"}``。

    走的是 ``scripts/prove_policy.py`` 公开模式的**同一条路**（同一个
    ``--job policy``、同一个 guest、同一种向量形状）：切片在电路眼里就是一条普通
    策略。这正是本设计不需要新 guest / 新 vkey、已有证明不作废的原因。

    ``receipts`` 应当把**全量**回执链传给每个切片（见模块头「回执链」）。
    """
    spec = compile_slice_policy(policy)
    entry = slice_vectors(policy, response, receipts=receipts, nonce=nonce)
    outcome = _run_slice_vectors(entry, check_mode=False, proof_out=proof_out,
                                 proof_mode=proof_mode, pop_script=pop_script)
    return {"outcome": outcome, "proof_file": proof_out, "spec": spec}


def check_slice(policy: Policy, response: str, *, receipts: Optional[Sequence[Any]] = None,
                nonce: bytes = b"", pop_script: Path = POP_SCRIPT) -> Dict[str, Any]:
    """对**一个角色切片**跑 Rust 宿主校验（``--check``，秒级、不出证明）。

    与 Python 侧的参考评估是两条独立实现，可逐字段对拍 —— 「切完之后两端算的
    还是同一个判定」这条性质由 ``tests/test_multiparty.py`` 的第一层守住。
    """
    return _run_slice_vectors(slice_vectors(policy, response, receipts=receipts,
                                            nonce=nonce),
                              check_mode=True, proof_out=None, proof_mode="core",
                              pop_script=pop_script)


def part_from_proof(proof: Path, *, role: str, spec: Dict[str, Any],
                    pop_verify: Path = POP_VERIFY, pop_script: Path = POP_SCRIPT,
                    relative_to: Optional[Path] = None) -> SlicePart:
    """验证一份切片证明并构造对应角色的 part。

    **当场核「证明的是这一段」**：证明公开值里的 ``policy_hash`` 必须等于
    ``spec``（该角色切片的规范哈希）。少了这一步，一个角色可以拿「恒通过的空
    切片」的证明来冒充自己那一段 —— 切片划分在证书里写得漂漂亮亮，证明却属于
    别的东西。

    验证失败**不降级**：抛 :class:`MultipartyError`。
    """
    proof = Path(proof)
    v = V.verify_proof_file(proof, "policy", pop_verify=pop_verify, pop_script=pop_script)
    if not v.get("verified"):
        raise MultipartyError(f"{label(role)}：切片证明未通过验证（{proof}）")
    outcome = _committed_outcome(v) or {}
    if outcome.get("policy_hash") != spec["sha256"]:
        raise MultipartyError(
            f"{label(role)}：这份证明确实的不是该角色的切片 —— 证明称 "
            f"policy_hash={V.short_hash(str(outcome.get('policy_hash') or ''))}，"
            f"而该切片的哈希是 {V.short_hash(spec['sha256'])}")
    rel: Any = proof
    if relative_to is not None:
        try:
            rel = proof.resolve().relative_to(Path(relative_to).resolve())
        except ValueError:
            rel = proof
    return SlicePart(
        role=role,
        rules=slice_rules(spec),
        slice_sha256=spec["sha256"],
        proof_file=str(rel),
        proof_sha256=sha256_file(proof),
        vkey_hash=str(v.get("vkey_hash") or ""),
        proof_mode=str(v.get("proof_mode") or ""),
        outcome=outcome,
    )


def empty_part(role: str, spec: Dict[str, Any]) -> SlicePart:
    """空切片 part：没有可证明的东西，**但签名不能少**（见模块头）。"""
    return SlicePart(role=role, rules=[], slice_sha256=spec["sha256"])


def sign_part(part: SlicePart, signer: Any) -> SlicePart:
    """用该角色的键对 :meth:`SlicePart.claim` 签名（就地填 ``envelope``）。"""
    part.envelope = C.sign_payload(part.claim(), signer)
    return part


def assemble(policy: Policy, parts: Sequence[SlicePart], *,
             signers: Dict[str, Any], nonce: bytes = b"") -> MultipartyCertificate:
    """给「已造好的三个角色的 part」补上共同上下文并逐角色签名，合成证书。

    与 :func:`build_multiparty` 的分工：后者负责从**证明文件**造 part（并当场验证
    证明证的是这一段），本函数负责**校验划分 + 绑定 + 签名**，不碰证明文件。
    测试与工具要构造反例（换一段、去掉一个签名、换一条 T）时用这个，不必真的出证 ——
    但这**不是**一条更松的路径：两个函数收尾都走这里，检查只有一份。

    fail-closed 的几处：

    * 角色不全（重复/缺失）→ 抛错；
    * part 自述的 ``rules``/``slice_sha256`` 与 ``plan_of(policy)`` 不符 → 抛错
      （**单角色切片被换**在出证侧就已经拦一次；验证侧还会独立再拦一次）；
    * ``signers`` 缺任一角色、或三个 keyid 有重复 → 抛错（键分离是前提）；
    * 三段切片全空 → 抛错（那是「什么都没证明」，正是 P0-1 的形态）；
    * 各切片的 ``response_binding`` 不一致或缺失 → 抛错（各判各的 T 没有意义）；
    * 各切片的 ``trace_root`` 不一致 → 抛错（三段判的不是同一条轨迹）。
    """
    roles = [p.role for p in parts]
    if sorted(roles) != sorted(ROLES):
        raise MultipartyError(
            f"parts 必须恰好是三个角色各一份，得到 {roles!r} —— 缺角色不是能事后补的")
    specs = slice_specs(policy)                 # 内含 shard 的全部不变式检查
    want_plan = {role: {"rules": slice_rules(specs[role]),
                        "slice_sha256": specs[role]["sha256"]} for role in ROLES}
    for p in parts:
        if p.rules != want_plan[p.role]["rules"] or p.slice_sha256 != want_plan[p.role]["slice_sha256"]:
            raise MultipartyError(
                f"{label(p.role)} 的 part 与现场切分不符 —— part 自述 "
                f"{p.rules!r}/{V.short_hash(p.slice_sha256)}，现场切分 "
                f"{want_plan[p.role]['rules']!r}/{V.short_hash(want_plan[p.role]['slice_sha256'])}")

    missing = [r for r in ROLES if r not in signers]
    if missing:
        raise MultipartyError(
            f"缺角色的键：{[label(r) for r in missing]} —— 三个角色各持一把键，"
            "缺一个就组不出多证明者证书")
    kids = {r: _signer_keyid(signers[r]) for r in ROLES}
    if len(set(kids.values())) != len(ROLES):
        clash = sorted({k for k in kids.values() if list(kids.values()).count(k) > 1})
        raise MultipartyError(
            f"角色键分离失败：{ {label(r): k for r, k in kids.items()} } —— 同一把键"
            f"扮演两个角色时（{clash}），『这一份是谁证的』无从判断，多证明者当场"
            "退化成单证明者")

    binds = {p.role: p.outcome.get("response_binding") for p in parts if not p.empty}
    if not binds:
        raise MultipartyError(
            "三段切片全空：这份证书没有证明任何东西（P0-1 的形态：空策略恒通过）")
    uniq = set(binds.values())
    if len(uniq) != 1 or not next(iter(uniq)):
        raise MultipartyError(
            f"各切片的 response_binding 不一致（或缺失）—— 它们判的不是同一条响应，"
            f"不能合成：{ {label(r): v for r, v in binds.items()} }")
    roots = {p.role: p.outcome.get("trace_root") for p in parts if not p.empty}
    if len(set(roots.values())) != 1:
        raise MultipartyError(
            f"各切片承诺的 trace_root 不一致 —— 三段判的不是同一条轨迹（回执链必须"
            f"把**全量**发给每个切片，见模块头）：{ {label(r): v for r, v in roots.items()} }")

    full_hash = compile_policy(policy)["sha256"]     # 整条策略的哈希（不是切片哈希）
    pd = plan_digest(want_plan)
    binding = next(iter(uniq))
    for p in parts:
        p.policy_hash = full_hash
        p.response_binding = binding
        p.plan_digest = pd
        sign_part(p, signers[p.role])
    return MultipartyCertificate(nonce=nonce, response_binding=binding,
                                 policy_hash=full_hash, plan=want_plan,
                                 plan_digest=pd, parts=list(parts))


def build_multiparty(policy: Policy, response: str, *,
                     signers: Dict[str, Any],
                     receipts: Optional[Sequence[Any]] = None,
                     proofs: Optional[Dict[str, Path]] = None,
                     nonce: bytes = b"",
                     prove: bool = False,
                     proof_dir: Optional[Path] = None,
                     proof_mode: str = "core",
                     relative_to: Optional[Path] = None,
                     pop_verify: Path = POP_VERIFY,
                     pop_script: Path = POP_SCRIPT) -> MultipartyCertificate:
    """把三个角色的切片证明 + 签名合成为一张多证明者证书。

    两份输入，对应真实部署里的两种交替方式：

    * ``proofs``：**各角色自己出好证再把文件交过来**（更接近现实：模型方、网关、
      部署方各自跑自己的证明器）；
    * ``prove=True``：由本进程代跑（demo / 测试用），证明落到 ``proof_dir``。

    收尾的划分/绑定/签名检查全在 :func:`assemble`（只有一份）。
    """
    specs = slice_specs(policy)                 # 内含 shard 的全部不变式检查

    parts: List[SlicePart] = []
    for role in ROLES:
        spec = specs[role]
        if not slice_rules(spec):
            parts.append(empty_part(role, spec))
            continue
        pf = (proofs or {}).get(role)
        if pf is None:
            if not prove:
                raise MultipartyError(
                    f"{label(role)} 的切片有 {len(slice_rules(spec))} 条规则，但没有"
                    f"证明文件（proofs[{role!r}]）—— 没证过的切片不能进证书")
            out_dir = Path(proof_dir or (REPO / "scripts" / "examples" / "out" / "multiparty"))
            out_dir.mkdir(parents=True, exist_ok=True)
            pf = out_dir / f"{role}.proof"
            prove_slice(shard(policy)[role], response, receipts=receipts, nonce=nonce,
                        proof_out=pf, proof_mode=proof_mode, pop_script=pop_script)
        parts.append(part_from_proof(pf, role=role, spec=spec, pop_verify=pop_verify,
                                     pop_script=pop_script, relative_to=relative_to))
    return assemble(policy, parts, signers=signers, nonce=nonce)


def write_multiparty(cert: MultipartyCertificate, out_path: Path) -> Path:
    """把多证明者证书写到 ``out_path``（父目录须已存在）。"""
    out_path = Path(out_path)
    out_path.write_text(json.dumps(cert.to_json(), ensure_ascii=False, indent=2),
                        encoding="utf-8")
    return out_path


def read_multiparty(path: Path) -> MultipartyCertificate:
    """从文件读回多证明者证书。"""
    return MultipartyCertificate.from_json(
        json.loads(Path(path).read_text(encoding="utf-8")))


# --------------------------------------------------------------------------- #
# 验证方
# --------------------------------------------------------------------------- #

def verify_multiparty(cert: MultipartyCertificate, *, response: str,
                      base: Optional[Path] = None,
                      keyring: Any = None,
                      policy: Optional[Policy] = None,
                      policy_pack: Optional[Path] = None,
                      expected_vkey: Optional[str] = None,
                      verify_proofs: bool = True,
                      pop_verify: Path = POP_VERIFY,
                      pop_script: Path = POP_SCRIPT) -> Tuple[bool, str, bool]:
    """核一张多证明者证书。返回 ``(ok, detail, satisfied)``。

    ``ok`` = 「这张多证明者证书是真的」：三个角色各一份**有效签名**（键两两不同）、
    切片划分与现场重算相符、每份切片证明都有效且证的是**它自己那一段**、三段绑的
    是同一条 ``T`` 与同一条轨迹。
    ``satisfied`` = 「整条策略确实被满足」—— 与 ``verify_composite`` /
    ``verify_session_proof`` 一样**分开读**：一张如实记录了违规的多证明者证书同样
    是真的。

    ``verify_proofs=False`` 跳过密码学验证（只跑划分与绑定检查），用于离线预检与
    快测 —— 此时 detail 会**如实注明**「证明有效性未核」，不会让调用方误以为跑全了。
    """
    base = Path(base) if base is not None else Path(".")
    notes: List[str] = []
    ok = True
    satisfied = True

    # ---- 1. 形状：三个角色各一份 ----
    roles = [p.role for p in cert.parts]
    if sorted(roles) != sorted(ROLES):
        dups = sorted({r for r in roles if roles.count(r) > 1})
        why = f"（重复：{dups}）" if dups else "（缺角色）"
        return False, (f"parts 必须恰好是三个角色各一份，得到 {roles!r} {why}"
                       " —— 被省略的那一段正是没人证的那一段"), False
    if sorted(cert.plan.keys()) != sorted(ROLES):
        return False, (f"plan 必须覆盖 {sorted(ROLES)}，得到 {sorted(cert.plan)}"), False

    # ---- 2. 角色键分离 + 3. 签名 ----
    kids: Dict[str, str] = {}
    for p in cert.parts:
        kid = C.envelope_keyid(p.envelope) if isinstance(p.envelope, dict) else None
        if not kid:
            return False, (f"{label(p.role)}：**没有签名**（信封缺失或没有 signatures）"
                           " —— 三个角色各持一把键、各签一份；缺一份就等于有一段是"
                           "没人负责的"), False
        kids[p.role] = kid
    if len(set(kids.values())) != len(ROLES):
        clash = sorted({k for k in kids.values() if list(kids.values()).count(k) > 1})
        return False, (f"角色键分离失败：{ {label(r): V.short_hash(k) for r, k in kids.items()} }"
                       f" —— 同一把键（{clash}）扮演两个角色时，「这一份是谁证的」"
                       "无从判断，多证明者退化成单证明者"), False

    if keyring is not None:
        for p in cert.parts:
            ok_sig, payload = C.verify_envelope(p.envelope, keyring)
            if not ok_sig:
                return False, (f"{label(p.role)}：签名未通过验证（键 "
                               f"{V.short_hash(kids[p.role])} 不在 keyring 里，"
                               "或签名不符）"), False
            if payload != p.claim():
                return False, (f"{label(p.role)}：签名覆盖的载荷与 part 的字段**不一致**"
                               " —— 签名转述的不是 part 说的（改了 part 而没重签，"
                               "就会走到这里）"), False
        notes.append("三份签名均通过验证，且与各自 part 的字段逐字段一致")
    else:
        for p in cert.parts:
            try:
                payload = C.envelope_payload(p.envelope)
            except (KeyError, TypeError, ValueError):
                return False, f"{label(p.role)}：信封载荷解不开（不是合法 base64/JSON）", False
            if payload != p.claim():
                return False, (f"{label(p.role)}：签名覆盖的载荷与 part 的字段**不一致**"
                               " —— 签名转述的不是 part 说的"), False
        notes.append("**未提供 keyring**：只核了「签名载荷 == part 字段」的自洽，"
                     "没核密码学签名 —— 给不出公钥就判断不了签名是真是假")

    # ---- 4. 切片划分（part 自述 / plan / 现场重算） ----
    for p in cert.parts:
        want = cert.plan.get(p.role) or {}
        if list(p.rules) != list(want.get("rules") or []):
            return False, (f"{label(p.role)}：part 自述的 rules 与 plan 不一致 —— "
                           f"part={p.rules!r} plan={want.get('rules')!r}"), False
        if p.slice_sha256 != want.get("slice_sha256"):
            return False, (f"{label(p.role)}：part 自述的切片哈希与 plan 不一致 —— "
                           f"part={V.short_hash(p.slice_sha256)} "
                           f"plan={V.short_hash(str(want.get('slice_sha256') or ''))}"), False
    if plan_digest(cert.plan) != cert.plan_digest:
        return False, ("plan 摘要与现场重算不符 —— plan 被改过（换掉某一段切片的第一步"
                       "就是把 plan 也改掉）"), False
    for p in cert.parts:
        if p.plan_digest != cert.plan_digest:
            return False, (f"{label(p.role)}：签名覆盖的 plan 摘要与证书声明的不是同一个"
                           f" —— 它签的是**另一份划分**"), False

    owner: Dict[str, str] = {}
    for role in ROLES:
        for name in cert.plan[role].get("rules") or []:
            if name in owner:
                return False, (f"规则 {name!r} 同时出现在 {label(owner[name])} 与 "
                               f"{label(role)} 的切片里 —— 切片必须**互斥**"
                               "（重叠 = 这一段到底谁负责说不清）"), False
            owner[name] = role
    if not owner:
        return False, "三段切片全空 —— 这份证书没有证明任何东西（P0-1 的形态）", False

    if policy is not None or policy_pack is not None:
        try:
            pol = policy if policy is not None else _load_policy(Path(policy_pack))
            full = compile_policy(pol)
            want_plan = plan_of(pol)
        except Exception as exc:
            return False, f"策略重编译失败：{exc}", False
        if cert.policy_hash != full["sha256"]:
            return False, ("证书声明的 policy_hash 与现场重编译的**整条策略**不符 —— "
                           f"被切片的不是这个策略包：证书称 "
                           f"{V.short_hash(cert.policy_hash)}，现场重算 "
                           f"{V.short_hash(full['sha256'])}"), False
        if want_plan != cert.plan:
            diff = {label(r): {"现场重算": want_plan.get(r), "证书声明": cert.plan.get(r)}
                    for r in ROLES if want_plan.get(r) != cert.plan.get(r)}
            return False, ("声明的切片划分与现场重算不符（**单角色的策略切片被换**"
                           f"正是本检查要拦的）：{diff}"), False
        notes.append("policy_hash 与三个切片的划分均与现场重编译相符")
    else:
        notes.append("**未提供策略包**：只能核切片划分的自洽（互斥、并集非空、plan 摘要"
                     "与各 part 自述一致），不能核『整条策略就是你手上那个包』")

    # ---- 5. 证明 ----
    vkeys = set()
    proved = 0
    for p in cert.parts:
        if p.empty:
            if p.proof_file or p.outcome:
                return False, (f"{label(p.role)}：空切片（没有规则）却带着证明/公开值"
                               f"（{p.proof_file!r}）—— 空切片只该有签名"), False
            continue
        proved += 1
        if not p.proof_file:
            return False, (f"{label(p.role)}：切片有 {len(p.rules)} 条规则却**没有证明"
                           "文件** —— 没证过的切片不能算数"), False
        f = (base / p.proof_file) if not Path(p.proof_file).is_absolute() else Path(p.proof_file)
        if not f.exists():
            return False, f"{label(p.role)}：证明文件不存在：{f}", False
        got = sha256_file(f)
        if got != p.proof_sha256:
            return False, (f"{label(p.role)}：证明文件哈希不符 —— part 承诺 "
                           f"{V.short_hash(str(p.proof_sha256 or ''))}，实际 "
                           f"{V.short_hash(got)}（**换证明**正是本检查要拦的攻击）"), False
        if verify_proofs:
            try:
                v = V.verify_proof_file(f, "policy", pop_verify=pop_verify,
                                        pop_script=pop_script)
            except ValueError as exc:
                return False, f"{label(p.role)}：{exc}", False
            if not v.get("verified"):
                return False, f"{label(p.role)}：切片证明未通过密码学验证", False
            if _committed_outcome(v) != (p.outcome or None):
                return False, (f"{label(p.role)}：证明公开值解出的 outcome 与 part 记录的"
                               "**不一致** —— 转述的不是证明说的"), False
            if str(v.get("vkey_hash") or "") != p.vkey_hash:
                return False, (f"{label(p.role)}：vkey 哈希不符 —— part 声明 "
                               f"{V.short_hash(str(p.vkey_hash or ''))}，证明来自 "
                               f"{V.short_hash(str(v.get('vkey_hash') or ''))}"), False
        else:
            m = _meta_vkey(f)
            if m and m != p.vkey_hash:
                return False, (f"{label(p.role)}：边车自报 vkey {V.short_hash(m)} 与 part "
                               f"声明的 {V.short_hash(str(p.vkey_hash or ''))} 不符"), False
        # 「证明的是**这一段**」核的是 part 内部两个声明之间的关系（公开值承诺的
        # policy_hash vs 它自己声明的切片哈希），不需要密码学 —— 因此放在公共路径上，
        # verify_proofs=False 的离线预检同样拦得住。
        if p.outcome.get("policy_hash") != p.slice_sha256:
            return False, (f"{label(p.role)}：证明承诺的 policy_hash 与 part 声明的切片"
                           "哈希不符 —— 被证明的不是这一段切片（拿别段/空段的证明来"
                           "冒充，就是这里失败）"), False
        if p.outcome.get("mode") != "public":
            return False, (f"{label(p.role)}：切片证明的 mode 是 "
                           f"{p.outcome.get('mode')!r}，应为 'public'"
                           "（合规结论要求语义规则也能被判定）"), False
        vkeys.add(str(p.vkey_hash or ""))

    if len(vkeys) > 1:
        return False, ("各切片证明用的不是同一个程序（vkey："
                       f"{sorted(V.short_hash(v) for v in vkeys)}）—— 切片必须由"
                       "同一个 pop-program 判定，否则『切片』只是名字上的"), False
    if expected_vkey is not None and vkeys and next(iter(vkeys)) != expected_vkey:
        return False, (f"切片证明的 vkey 不是期望的那一个 —— 期望 "
                       f"{V.short_hash(expected_vkey)}，得到 "
                       f"{V.short_hash(next(iter(vkeys)))}"), False
    if expected_vkey is None:
        notes.append("**未提供期望 vkey**：只能核『三段用的是同一个程序』，"
                     "不能核『它是你信任的那个程序』")
    if verify_proofs:
        notes.append(f"{proved} 份切片证明通过密码学验证，且各证各的那一段")
    else:
        notes.append("**证明有效性未核**（verify_proofs=False）")

    # ---- 6. 同一条 T / 同一条轨迹 ----
    try:
        recomputed = CMT.response_binding(cert.nonce, response)
    except Exception as exc:  # pragma: no cover - 只可能是 nonce 类型不对
        return False, f"无法由送达响应重算 response_binding：{exc}", False
    sources: List[Tuple[str, Optional[str]]] = [("certificate", cert.response_binding)]
    for p in cert.parts:
        if p.empty:
            continue
        sources.append((f"{p.role}.claim", p.response_binding))
        sources.append((f"{p.role}.outcome", p.outcome.get("response_binding")))
    sources.append(("response", recomputed))
    ok_b, detail_b = V.check_response_binding(sources)
    if not ok_b:
        return False, (f"各段判的不是同一条送达响应（或绑定缺失）：{detail_b}"), False
    notes.append("response_binding 多方一致（含由 T′ 现场重算）")

    roots = {p.role: p.outcome.get("trace_root") for p in cert.parts if not p.empty}
    if len(set(roots.values())) != 1:
        return False, ("各切片承诺的 trace_root 不一致 —— 三段判的不是同一条轨迹"
                       f"：{ {label(r): v for r, v in roots.items()} }"), False
    notes.append(f"trace_root 三段一致（{V.short_hash(str(next(iter(roots.values()))))}）")

    # ---- 7. 合规结论：与 compose 层同一条保守口径 ----
    failed = [label(p.role) for p in cert.parts if not p.empty and not p.outcome.get("passed")]
    delegated = [(label(p.role), p.outcome.get("delegated") or [])
                 for p in cert.parts if not p.empty and (p.outcome.get("delegated") or [])]
    if failed:
        satisfied = False
        notes.append(f"{failed} 的切片 passed=false —— 证书为**真**，但整条策略"
                     "**未被满足**")
    elif delegated:
        satisfied = False
        names = [d["name"] for _, ds in delegated for d in ds
                 if isinstance(d, dict) and d.get("name")]
        notes.append(f"{[r for r, _ in delegated]} 的切片里有 {len(names)} 条规则被"
                     f"**委托**（{names}）—— 多证明者层不替它下结论，须另行合取"
                     "ezkl 陪伴证明（L7），否则不构成『合规』")
    else:
        notes.append(f"三个角色的切片各证其段、全部 passed=true 且无委托规则"
                     f"（共 {proved} 份证明）")

    return ok, "; ".join(notes), satisfied
