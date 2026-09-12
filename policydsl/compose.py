"""组合证明（P1-6）—— ``Compose = (推理完整性 ∧ 策略合规)``。

## 问题

PoP 证明的是「响应 ``T`` 满足策略 ``π``」，但**谁来证明这条 ``T`` 是被那个模型
算出来的**？在真实部署里，agent 的响应由某个 LLM 产生，而「LLM 真的跑过、且吐出
的是这条响应」是**另一个**证明义务 —— zkAgent 那一侧的事。两份证明各自成立，
并不能推出「模型跑过 **且** 输出满足策略」：它们之间没有任何联系，除非把
「说的是同一条 ``T``」变成可机检的事实。

## 组合义务

``Compose = (推理完整性 ∧ 策略合规)``。本模块把两份证明合成一张
:class:`CompositeCertificate`，并给出验证方要跑的**全部**检查。

**键分离**是组合成立的关键：两份证明必须来自**不同的程序**（不同的 vkey）。
否则同一个程序既能出推理证明又能出策略证明，「这份证明属于哪一半」就无从判断 ——
``pop-types::job_domain`` 在两个 guest 入口各断言一次，把这件事钉在电路里。

## 验证方跑什么（``verify_composite``）

1. **形状**：恰好两个 part，``kind`` 一为 ``policy`` 一为 ``inference``，无多余项；
2. **证明文件**：字节哈希 == part 声明的 ``proof_sha256``（换文件即失败）；
3. **证明有效性**：跑 ``pop-verify``（免证明器快路径）或 ``pop-script --verify``；
4. **键分离**：两个 part 的 vkey **必须不同**；给了 ``expected_vkeys`` 时还要
   与期望值逐一相等；
5. **域绑定**：策略 part 的 ``mode == "public"``（合规结论要求能判语义规则）、
   推理 part 的 ``mode == "infer"`` 且 ``domain == "pop-infer-v1"``；
6. **同一条 T**：composite 声明、两份证明各自的 ``response_binding``、以及由
   **送达的 T′ 与 nonce 现场重算**的值，四者全部相等；
7. **模型与输入**：推理 part 的 ``model_hash`` 与 ``input_binding`` 与
   :mod:`policydsl.infer` 现场重算的值相等 —— 即「被证明的模型就是**这份代码里
   那个**模型、被证明的输入就是**由 T′ 导出**的那个输入」；
8. **合规结论**：策略 part 的 ``passed`` **且** ``delegated`` 为空。

第 8 条是刻意的保守：``delegated`` 非空意味着策略里有规则**没被这份证明判定**
（P2-9 的语义规则），那时 ``合规`` 的结论要由 ``verify_cert.py`` 合取陪伴证明后
才给出。组合层**不替它下结论** —— 否则组合证书会变成「把没判的规则当判过了」
的新通道，正是 P0-1 的形态。

## 边界（如实标注）

* 推理那一半在当前仓库里是**代理**（deterministic MLP，见 :mod:`policydsl.infer`），
  不是 zkAgent。组合逻辑本身与「谁出这一半证明」无关：换上真实 prover 只需改
  ``pop-infer`` guest 与 ``expected_vkeys``，本模块不动。见计划 D1、§P1-6。
* 本模块**不判**「模型好不好」、也**不判**策略写得对不对 —— 与 L7 的第 ② 条
  不保证同源。
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from policydsl import infer
from policydsl import verifier as V

REPO = Path(__file__).resolve().parent.parent
POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"
POP_VERIFY = REPO / "circuits" / "target" / "release" / "pop-verify"

#: composite.json 的格式版本。
COMPOSITE_VERSION = "v1"

#: 两个 part 的 kind。顺序无关，但**缺一不可**。
KIND_POLICY = "policy"
KIND_INFERENCE = "inference"
KINDS = (KIND_POLICY, KIND_INFERENCE)

#: kind → ``pop-script --job`` 的旗标。**两个名字不同**（`inference` vs `infer`），
#: 别把 kind 当旗标用 —— 直接传会被 pop-script 拒绝（`--job must be 'policy' or 'infer'`）。
#: 这个映射是**唯一**的转换点。
JOB_FOR_KIND = {KIND_POLICY: "policy", KIND_INFERENCE: "infer"}

#: 组合义务的陈述（进 composite，供人读；也是「这份证书声称什么」的原文）。
OBLIGATION = "推理完整性 ∧ 策略合规"


def sha256_file(path: Path) -> str:
    """对文件字节求 SHA-256（小写十六进制）。"""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _outcome_of(proof_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """取验证结果里的 outcome，**只剥 `name`**。

    刻意**不**用 ``verifier.outcome_without_meta``：那个函数连 ``mode`` 一起剥掉，
    因为在**证书载荷**里 ``mode`` 是冗余的展示字段（运行模式已在载荷顶层
    ``payload["mode"]``）。但组合证书记录的 outcome 是承诺本体，``mode`` 在这里
    是**载荷字段** —— 它区分 `public`/`private`/`infer` 三域，正是组合层要判的东西
    （见 :func:`build_composite` 与 :func:`verify_composite` 的第 5 步）。
    用前者会让这两处永远读到 `None`。
    """
    outcome = proof_result.get("outcome")
    if not isinstance(outcome, dict):
        return None
    return {k: v for k, v in outcome.items() if k != "name"}


@dataclass
class Part:
    """组合证书里的一「半」：一份证明 + 它的公开值与身份。

    刻意**不**冻结：测试与工具常要拿一份已验证的 part 改一个字段来构造反例
    （「换模型」「换绑定」），冻结只会逼调用方手搓整个结构体。
    """

    kind: str            # KIND_POLICY | KIND_INFERENCE
    name: str            # 展示名
    proof_file: str      # 相对 composite.json 所在目录的路径
    proof_sha256: str    # 证明文件字节的哈希（换文件即失败）
    vkey_hash: str       # 该证明所用程序的 vkey 哈希
    proof_mode: str      # core / compressed / groth16 / plonk（如实记录）
    outcome: Dict[str, Any]  # 证明公开值解出的 outcome（含 name 之外的展示字段）

    def to_json(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "proof_file": self.proof_file,
            "proof_sha256": self.proof_sha256,
            "vkey_hash": self.vkey_hash,
            "proof_mode": self.proof_mode,
            "outcome": self.outcome,
        }

    @staticmethod
    def from_json(d: Dict[str, Any]) -> "Part":
        return Part(
            kind=d["kind"], name=d.get("name", d["kind"]),
            proof_file=d["proof_file"], proof_sha256=d["proof_sha256"],
            vkey_hash=d["vkey_hash"], proof_mode=d.get("proof_mode", ""),
            outcome=d.get("outcome") or {},
        )


@dataclass
class CompositeCertificate:
    """两张证明 + 组合义务声明。``parts`` 恰好是那两个 kind。"""

    nonce: bytes
    response_binding: str
    parts: List[Part] = field(default_factory=list)
    policy_hash: Optional[str] = None
    obligation: str = OBLIGATION
    version: str = COMPOSITE_VERSION

    def to_json(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "kind": "composite",
            "obligation": self.obligation,
            "domain_separation": {
                "policy_vkey": self.part(KIND_POLICY).vkey_hash if self.part(KIND_POLICY) else None,
                "inference_vkey": (self.part(KIND_INFERENCE).vkey_hash
                                   if self.part(KIND_INFERENCE) else None),
                "note": "两个 vkey 必须不同：同一个程序既能出策略证明又能出推理证明时，"
                        "『这份证明属于哪一半』无从判断。",
            },
            "nonce_hex": self.nonce.hex(),
            "response_binding": self.response_binding,
            "policy_hash": self.policy_hash,
            "parts": [p.to_json() for p in self.parts],
        }

    @staticmethod
    def from_json(d: Dict[str, Any]) -> "CompositeCertificate":
        return CompositeCertificate(
            nonce=bytes.fromhex(d.get("nonce_hex") or ""),
            response_binding=d.get("response_binding") or "",
            parts=[Part.from_json(p) for p in d.get("parts") or []],
            policy_hash=d.get("policy_hash"),
            obligation=d.get("obligation") or OBLIGATION,
            version=d.get("version") or COMPOSITE_VERSION,
        )

    def part(self, kind: str) -> Optional[Part]:
        """按 kind 取 part；没有则 None（**不做默认值**：缺失必须被看见）。"""
        for p in self.parts:
            if p.kind == kind:
                return p
        return None


# --------------------------------------------------------------------------- #
# 出证方：从一份已保存的证明读出 part
# --------------------------------------------------------------------------- #

def _run(cmd: Sequence[str], env_extra: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    """跑一条外部命令。实现已挪到 :func:`policydsl.verifier.run_cmd`（会话层共用）。"""
    return V.run_cmd(cmd, env_extra)


def _verify_one(proof: Path, job_kind: str,
                pop_verify: Path = POP_VERIFY,
                pop_script: Path = POP_SCRIPT) -> Dict[str, Any]:
    """验证一份证明，返回验证器输出的字典（``verified`` / ``vkey_hash`` / ``outcome``）。

    与 ``verify_session.py`` 同一条路：能走 ``pop-verify``（免构造证明器）就走，
    否则退回 ``pop-script --verify``。**注意 core 证明必须走后者** —— core 没有
    可供第三方核验的递归工件。

    实现已挪到 :func:`policydsl.verifier.verify_proof_file`（P2-10 的会话层要用
    同一条路，而 ``--out`` 那个坑不该有第二份拷贝）；这里保留函数名与签名，
    供本模块内外的既有调用方继续使用。
    """
    return V.verify_proof_file(proof, job_kind, pop_verify=pop_verify, pop_script=pop_script)


def part_from_proof(proof: Path, kind: str, name: str,
                    pop_verify: Path = POP_VERIFY,
                    pop_script: Path = POP_SCRIPT,
                    relative_to: Optional[Path] = None) -> Part:
    """验证一份证明并构造对应的 :class:`Part`。

    ``relative_to`` 给定时，``proof_file`` 存相对路径（让整份组合证书可以随
    工件目录一起搬走）。验证失败**不降级**：抛 ``ValueError``。
    """
    job_kind = JOB_FOR_KIND[kind]
    v = _verify_one(proof, job_kind, pop_verify, pop_script)
    if not v.get("verified"):
        raise ValueError(f"证明未通过验证（{proof}）")
    rel = Path(proof)
    if relative_to is not None:
        try:
            rel = Path(proof).resolve().relative_to(Path(relative_to).resolve())
        except ValueError:
            rel = Path(proof)
    return Part(
        kind=kind,
        name=name,
        proof_file=str(rel),
        proof_sha256=sha256_file(proof),
        vkey_hash=str(v.get("vkey_hash") or ""),
        proof_mode=str(v.get("proof_mode") or ""),
        outcome=_outcome_of(v) or {},
    )


def build_composite(policy_part: Part, inference_part: Part, nonce: bytes) -> CompositeCertificate:
    """把两半合成一张组合证书。

    顶层 ``response_binding`` 取两份证明**共同**的那一个值；不相等直接抛错 ——
    合成一张「两半绑的是不同响应」的证书是纯粹的制造垃圾。
    """
    b_pol = policy_part.outcome.get("response_binding")
    b_inf = inference_part.outcome.get("response_binding")
    if not b_pol or b_pol != b_inf:
        raise ValueError(
            "两份证明的 response_binding 不一致（或缺失）—— 它们绑的不是同一条响应，"
            f"不能组合：policy={b_pol!r} inference={b_inf!r}")
    if policy_part.outcome.get("mode") != "public":
        raise ValueError(
            "策略那一半必须是**公开模式**：组合义务里的『策略合规』要求语义规则"
            "（若有）也能被判定，而语义规则只支持公开模式（P2-9）。"
            f"得到 mode={policy_part.outcome.get('mode')!r}")
    return CompositeCertificate(
        nonce=nonce,
        response_binding=b_pol,
        parts=[policy_part, inference_part],
        policy_hash=policy_part.outcome.get("policy_hash"),
    )


def write_composite(cert: CompositeCertificate, out_path: Path) -> Path:
    """把组合证书写到 ``out_path``（父目录须已存在）。"""
    out_path = Path(out_path)
    out_path.write_text(json.dumps(cert.to_json(), ensure_ascii=False, indent=2),
                        encoding="utf-8")
    return out_path


def read_composite(path: Path) -> CompositeCertificate:
    """从文件读回组合证书。"""
    return CompositeCertificate.from_json(
        json.loads(Path(path).read_text(encoding="utf-8")))


# --------------------------------------------------------------------------- #
# 验证方
# --------------------------------------------------------------------------- #

def verify_composite(composite: CompositeCertificate, *, response: str,
                     base: Optional[Path] = None,
                     expected_vkeys: Optional[Dict[str, str]] = None,
                     policy_pack: Optional[Path] = None,
                     verify_proofs: bool = True,
                     pop_verify: Path = POP_VERIFY,
                     pop_script: Path = POP_SCRIPT) -> Tuple[bool, str, bool]:
    """验证一张组合证书。返回 ``(ok, detail, satisfied)``。

    ``ok``  = 「这张组合证书是真的」：两份证明都有效、绑到同一条 T、且来自不同程序；
    ``satisfied`` = 「组合义务成立」，即**策略那一半确实合规**。二者分开的理由与
    ``verify_cert.py`` 的 ``RESULT`` / ``合规`` 两行完全相同：一张如实记录违规的
    组合证书同样是**真**证书。

    ``verify_proofs=False`` 跳过密码学验证（只跑绑定检查），用于离线预检与快测 ——
    此时 detail 会**如实注明**「证明有效性未核」，不会让调用方误以为跑全了。

    ``policy_pack`` 给定时，额外核「证书声明的 policy_hash == 现场重编译的哈希」。
    """
    base = Path(base) if base is not None else Path(".")
    notes: List[str] = []
    ok = True
    satisfied = True

    # ---- 1. 形状 ----
    kinds = [p.kind for p in composite.parts]
    if sorted(kinds) != sorted(KINDS) or len(kinds) != len(KINDS):
        return False, (f"parts 必须恰好是 {sorted(KINDS)} 各一份，得到 {kinds!r}"
                       " —— 缺一半或多一半都不构成组合"), False
    pol = composite.part(KIND_POLICY)
    inf = composite.part(KIND_INFERENCE)
    assert pol is not None and inf is not None

    # ---- 2. 证明文件字节哈希 ----
    files: Dict[str, Path] = {}
    for p in (pol, inf):
        f = (base / p.proof_file) if not Path(p.proof_file).is_absolute() else Path(p.proof_file)
        if not f.exists():
            return False, f"{p.kind}: 证明文件不存在：{f}", False
        got = sha256_file(f)
        if got != p.proof_sha256:
            return False, (f"{p.kind}: 证明文件哈希不符 —— 证书承诺 "
                           f"{V.short_hash(p.proof_sha256)}，实际 {V.short_hash(got)}"
                           "（**换证明**正是本检查要拦的攻击）"), False
        files[p.kind] = f
    notes.append("proof_sha256 两份均符")

    # ---- 3. 证明有效性（可选） + 4. 键分离 ----
    observed: Dict[str, Dict[str, Any]] = {}
    if verify_proofs:
        for p in (pol, inf):
            job_kind = JOB_FOR_KIND[p.kind]
            try:
                v = _verify_one(files[p.kind], job_kind, pop_verify, pop_script)
            except ValueError as e:
                return False, f"{p.kind}: {e}", False
            if not v.get("verified"):
                return False, f"{p.kind}: 证明未通过密码学验证", False
            if _outcome_of(v) != (p.outcome or None):
                return False, (f"{p.kind}: 证明公开值解出的 outcome 与证书记录的**不一致**"
                               " —— 证书转述的不是证明说的"), False
            if str(v.get("vkey_hash") or "") != p.vkey_hash:
                return False, (f"{p.kind}: vkey 哈希不符 —— 证书声明 "
                               f"{V.short_hash(p.vkey_hash)}，证明来自 "
                               f"{V.short_hash(str(v.get('vkey_hash') or ''))}"), False
            observed[p.kind] = v
        notes.append("两份证明均通过密码学验证")
    else:
        # 退到边车/meta 自报的 vkey（**不是**密码学绑定，须如实注明）
        for p in (pol, inf):
            m = _meta_vkey(files[p.kind])
            if m and m != p.vkey_hash:
                return False, (f"{p.kind}: 边车自报 vkey {V.short_hash(m)} 与证书声明的 "
                               f"{V.short_hash(p.vkey_hash)} 不符"), False
        notes.append("**证明有效性未核**（verify_proofs=False）")

    if pol.vkey_hash == inf.vkey_hash:
        return False, ("键分离失败：两份证明来自**同一个** vkey "
                       f"({V.short_hash(pol.vkey_hash)})。同一个程序既能出策略证明、"
                       "又能出推理证明时，『这份证明属于哪一半』无从判断，"
                       "组合义务也就无从谈起"), False
    notes.append(f"键分离：{V.short_hash(pol.vkey_hash)} ≠ {V.short_hash(inf.vkey_hash)}")

    if expected_vkeys:
        for kind, want in expected_vkeys.items():
            got = pol.vkey_hash if kind == KIND_POLICY else inf.vkey_hash
            if got != want:
                return False, (f"{kind}: vkey 不是期望的那一个 —— 期望 "
                               f"{V.short_hash(want)}，得到 {V.short_hash(got)}"), False
        notes.append("vkey 与期望值逐一相符")
    else:
        notes.append("**未提供期望 vkey**：只能核『两份证明用的是不同程序』，"
                     "不能核『它们是你信任的那两个程序』")

    # ---- 5. 域绑定 ----
    if pol.outcome.get("mode") != "public":
        return False, (f"策略那一半的 mode 是 {pol.outcome.get('mode')!r}，"
                       "组合义务要求公开模式（语义规则只支持公开模式）"), False
    if inf.outcome.get("mode") != "infer":
        return False, f"推理那一半的 mode 是 {inf.outcome.get('mode')!r}，应为 'infer'", False
    if inf.outcome.get("domain") != infer.DOMAIN.decode("ascii"):
        return False, (f"推理那一半的 domain 是 {inf.outcome.get('domain')!r}，"
                       f"应为 {infer.DOMAIN.decode('ascii')!r}"), False

    # ---- 6. 同一条 T ----
    recomputed = None
    try:
        from policydsl.commit import response_binding
        recomputed = response_binding(composite.nonce, response)
    except Exception as e:  # pragma: no cover - 只可能是调用方给的 nonce 类型不对
        return False, f"无法由送达响应重算 response_binding：{e}", False
    ok_b, detail_b = V.check_response_binding([
        ("composite", composite.response_binding),
        ("policy", pol.outcome.get("response_binding")),
        ("inference", inf.outcome.get("response_binding")),
        ("response", recomputed),
    ])
    if not ok_b:
        return False, ("两份证明绑的不是同一条送达响应（或绑定缺失）：" + detail_b), False
    notes.append("response_binding 四方一致（含由 T′ 现场重算）")

    # ---- 7. 模型与输入 ----
    if inf.outcome.get("model_hash") != infer.model_hash():
        return False, ("推理那一半的 model_hash 不是本仓库这份模型 —— 被证明的是"
                       "**别的**模型：证书称 "
                       f"{V.short_hash(str(inf.outcome.get('model_hash') or ''))}，"
                       f"现场重算 {V.short_hash(infer.model_hash())}"), False
    want_input = infer.input_binding(composite.nonce, infer.input_from_response(response))
    if inf.outcome.get("input_binding") != want_input:
        return False, ("推理那一半的 input_binding 与『由送达 T′ 导出的输入』不符 —— "
                       "被推理的不是这条响应：证书称 "
                       f"{V.short_hash(str(inf.outcome.get('input_binding') or ''))}，"
                       f"现场重算 {V.short_hash(want_input)}"), False
    notes.append("model_hash 与 input_binding 均与现场重算相符")

    # ---- 8. 合规结论 ----
    if composite.policy_hash and pol.outcome.get("policy_hash") != composite.policy_hash:
        return False, (f"策略那一半承诺的 policy_hash {V.short_hash(str(pol.outcome.get('policy_hash') or ''))} "
                       f"与证书顶层声明的 {V.short_hash(composite.policy_hash)} 不一致"), False
    if policy_pack is not None:
        try:
            from policydsl.compile import compile_policy
            from policydsl.serialize import spec_canonical_text
            spec = compile_policy(_load_policy(policy_pack))
            recompiled = hashlib.sha256(
                spec_canonical_text(spec).encode("utf-8")).hexdigest()
        except Exception as e:
            return False, f"策略包重编译失败：{e}", False
        if pol.outcome.get("policy_hash") != recompiled:
            return False, ("策略那一半承诺的 policy_hash 与**现场重编译策略包**所得的哈希"
                           "不符 —— 被证明的不是这个策略包"), False
        notes.append("policy_hash 与现场重编译相符")

    passed = bool(pol.outcome.get("passed"))
    delegated = pol.outcome.get("delegated") or []
    if not passed:
        satisfied = False
        notes.append("策略那一半 passed=false —— 组合证书为**真**，但策略**未被满足**")
    elif delegated:
        satisfied = False
        notes.append(f"策略那一半有 {len(delegated)} 条规则被**委托**（delegated 非空）"
                     " —— 组合层不替它下结论，须另行合取 ezkl 陪伴证明"
                     "（见 verify_cert.py 的『合规』行）")
    else:
        notes.append("策略那一半 passed=true 且无委托规则")

    return ok, "; ".join(notes), satisfied


def _meta_vkey(proof: Path) -> Optional[str]:
    """从 ``<proof>.meta.json`` 读自报的 vkey 哈希（只用于非密码学的一致性检查）。"""
    try:
        m = json.loads(Path(f"{proof}.meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    v = m.get("vkey_hash")
    return v if isinstance(v, str) and v else None


def _load_policy(path: Path):
    """从 JSON 载入策略包（与 ``issue_cert.load_policy`` 同口径，避免循环导入）。"""
    from policydsl.model import Policy, Rule
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r.get("name", f"r{i}"), params=r.get("params", {}))
             for i, r in enumerate(d["rules"])]
    return Policy(d["id"], d.get("version", "0.1.0"), rules=rules)
