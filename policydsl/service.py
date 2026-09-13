"""证明服务：把出证能力服务化（``docs/dev-plan.md`` §5.2 第二步）。

**为什么必须拆成两段**：这条链上两个阶段的时间尺度差 4 个数量级。

======================  ==================  ==========================
阶段                    耗时                内存
======================  ==================  ==========================
宿主判定（参考评估器）    毫秒级              可忽略
SP1 core 证明            ~2.5 分钟           峰值 ~10.2 GiB（**固定地板**）
======================  ==================  ==========================

如果只有一个接口，客户端要等 2.5 分钟才能拿到一个「合规/不合规」——那等于没有
服务。所以：

- ``POST /v1/check`` —— **在线段**。用 Python 参考评估器当场判定并签一张
  **如实标注 ``unproven``** 的证书（P0-4 已有成现语义，这里不新造）。它**不需要
  证明器**，因此可以在小机器/边缘跑，也不需要 ``circuits/`` 编译产物；
- ``POST /v1/attest`` —— **离线段**。入队，返回 ``job_id``，由后台工作线程调
  ``pop-script`` 出真证明，证书因此带**真 vkey 哈希**。客户端轮询
  ``GET /v1/attest/{job}``。

**并发上限是硬事实，不是可调项**：~10.2 GiB 是 SP1 core 证明的固定地板，一台
12 GB 机器同时只能跑一个证明器。于是默认 ``concurrency=1``，多出来的请求**排队**
（而不是被接受下来最终 OOM）。见 :class:`ProofService` 的 ``max_queue``。

**两段不是「降级」关系**：``/v1/check`` 的证书在一开始就写明了它不是证明
（``proof_mode: unproven``、``vkey_hash: unproven``），因此没有任何「看起来验过了」
的空间；``/v1/attest`` 把同一条响应升级成真证明。两者的 ``challenge`` 块绑同一个
nonce 时，持 T′ 的一方能离线确认两段说的是同一条 T。

本模块**只用标准库**，HTTP 驱动在 ``scripts/proof_service.py``。
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import anchor, cert, challenge, commit, evaluate, keys, trace, verifier
from .compile import compile_policy
from .model import Policy, PolicyError, Rule, Transcript
from .serialize import build_vectors, vector_entry

#: 作业状态。``done`` / ``failed`` 是终态，其余是中间态。
STATE_QUEUED = "queued"
STATE_PROVING = "proving"
STATE_DONE = "done"
STATE_FAILED = "failed"

STATE_TERMINAL_STATES = (STATE_DONE, STATE_FAILED)


class ServiceError(RuntimeError):
    """服务层可预期的失败 —— 对 HTTP 驱动而言就是一次 4xx（而不是 500）。"""


class UnknownPolicy(ServiceError):
    """请求里点了一个没注册的策略。"""

    def __init__(self, policy_id: str, known: Sequence[str]):
        self.policy_id, self.known = policy_id, list(known)
        super().__init__(
            f"unknown policy_id {policy_id!r}；已注册的有 {', '.join(self.known) or '(none)'}")


class QueueFull(ServiceError):
    """队列已满。**拒绝**而不是无限收下 —— 见 :class:`ProofService`。"""


class JobNotFound(ServiceError):
    """点了一个不存在的 job_id。"""


class PolicyNotServiceable(ServiceError):
    """策略含本服务**出不了**证的那类约束 —— 当场拒，不出一张注定验不过的证书。

    当前唯一一类是 ``semantic_bound``（语义规则）：它由 ezkl 陪伴证明判定，而
    陪伴证明的生成在 ``scripts/issue_cert.py`` 那条命令行路径里。**服务里没有
    这一步**，于是出来的证书 ``outcome.delegated`` 非空却没有 ``semantic`` 块 ——
    ``verify_cert.py`` 会据此如实判 FAIL（P2-9 fail closed）。

    换句话说这不是能力缺失，而是**这张证书根本不该存在**：一张「语义规则没人判」
    的证书不构成完整证据。所以这里停手，并把话说清楚，而不是发一张看起来正常、
    验的时候才炸的产物。
    """

    def __init__(self, policy_id: str, rules: Sequence[str]):
        self.policy_id, self.rules = policy_id, list(rules)
        super().__init__(
            f"策略 {policy_id!r} 含 {len(self.rules)} 条服务出不了证的约束"
            f"（{', '.join(self.rules)}）—— 语义规则由 ezkl 陪伴证明判定，本服务不"
            f"生成陪伴证明，因此出的证书会因缺少 companion 而验不过（fail closed）。"
            f"要这类策略请用：python3 scripts/issue_cert.py --pack <pack> ...")


class VerdictMismatch(ServiceError):
    """参考评估器与规范违规列表对同一条响应给出了不同结论。

    这不是「服务坏了」，而是**两套推导打架** —— 两者都是链下 Python
    （:func:`policydsl.evaluate.check` 走 ``Rule.params``，
    :func:`policydsl.commit.canonical_violations` 走**编译后的约束**）。证书的
    ``outcome`` 只能是其中一种形状（必须是**电路的那种**），而 ``passed`` 是
    拿给调用方读的那个布尔值。两者不一致时无论出哪一张证书，都会有一半的读者
    被误导 —— 所以这里**停证**并把两份结论原样报出来。
    """


# --------------------------------------------------------------------------- #
# 策略注册表
# --------------------------------------------------------------------------- #

def load_policy(path: Path) -> Policy:
    """从 JSON 文件加载策略包。

    口径与 ``scripts/verify_cert.py`` / ``issue_cert.py`` 的 ``load_policy``
    **逐字段相同**（``description`` 不进 :class:`Policy`，``semantic`` 取缺省的
    ``"and"``）—— 刻意如此：``compile_policy`` 会把 ``policy.semantic`` 写进
    规范 JSON，而 ``policy_hash`` 是**验证方自己重编译一遍**来核对的
    （``verify_cert.py`` 的 ``policy_hash`` 卡）。两处若用了不同口径的加载器，
    出证方与服务方会就同一个策略包算出两个哈希，而那张证书在第三方手里验不过。
    """
    d = json.loads(path.read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r.get("name", f"r{i}"), params=r.get("params", {}))
             for i, r in enumerate(d["rules"])]
    return Policy(d["id"], d.get("version", "0.1.0"), rules=rules)


@dataclass(frozen=True)
class PackedPolicy:
    """注册表里的一项：策略本身 + 它的规范 JSON（``policy_hash`` 的来源）。"""

    policy: Policy
    spec: Dict[str, Any]
    path: Optional[Path] = None

    @property
    def policy_hash(self) -> str:
        return self.spec["sha256"]

    @property
    def unserviceable_rules(self) -> List[str]:
        """本服务出不了证的那几条约束名（见 :class:`PolicyNotServiceable`）。"""
        return [c["name"] for c in self.spec["constraints"]
                if c.get("kind") == "semantic_bound"]

    def summary(self) -> Dict[str, Any]:
        """``GET /v1/policies`` 里的一行。

        ``serviceable=False`` 直接写在注册表里，**不等到调用时才说** —— 一个
        注册了却调不动的策略，运维只能靠读代码发现。见
        :class:`PolicyNotServiceable`。
        """
        return {"id": self.policy.id, "version": self.policy.version,
                "policy_hash": self.policy_hash,
                "serviceable": not self.unserviceable_rules,
                "unserviceable_rules": self.unserviceable_rules,
                "rules": [{"name": r.name, "kind": r.kind} for r in self.policy.rules]}


def pack_policy(policy: Policy, path: Optional[Path] = None) -> PackedPolicy:
    """编译一份策略包（编译期就会 ``validate()``，非法参数在这里当场失败）。"""
    return PackedPolicy(policy=policy, spec=compile_policy(policy), path=path)


class PolicyRegistry:
    """把若干策略包按 ``policy.id`` 收进一张表。

    服务要求调用方**点名**用哪条策略，而不是「服务器替你挑一条」：同一个响应在
    不同策略下的结论天差地别，让服务器猜等于让证书上的 ``policy_hash`` 变成一个
    调用方没同意过的值。
    """

    def __init__(self, packs: Sequence[PackedPolicy] = ()):
        self._packs: Dict[str, PackedPolicy] = {}
        for p in packs:
            self.add(p)

    def add(self, packed: PackedPolicy) -> None:
        pid = packed.policy.id
        if pid in self._packs and self._packs[pid].policy_hash != packed.policy_hash:
            raise ServiceError(
                f"策略 id {pid!r} 被注册了两次且内容不同"
                f"（{self._packs[pid].policy_hash[:12]}… vs {packed.policy_hash[:12]}…）；"
                "同名不同内容会让「证书里的 policy_hash」指哪一份变成看运气")
        self._packs[pid] = packed

    def get(self, policy_id: str) -> PackedPolicy:
        try:
            return self._packs[policy_id]
        except KeyError:
            raise UnknownPolicy(policy_id, sorted(self._packs)) from None

    def ids(self) -> List[str]:
        return sorted(self._packs)

    def summaries(self) -> List[Dict[str, Any]]:
        return [self._packs[i].summary() for i in self.ids()]

    def __len__(self) -> int:
        return len(self._packs)


def registry_from_paths(paths: Sequence[Path], *, on_skip=None) -> PolicyRegistry:
    """按路径建注册表。坏包（JSON 不合法 / 参数非法）跳过并交给 ``on_skip``。

    服务不该因为策略目录里多了一个半成品文件就起不来 —— 但**也不能悄悄跳过**：
    少掉的策略会让 ``/v1/policies`` 与运维脑子里的那张表对不上。所以由调用方
    决定怎么把 ``on_skip(policy_id_or_path, exc)`` 说出去。
    """
    reg = PolicyRegistry()
    for path in paths:
        try:
            reg.add(pack_policy(load_policy(path), path))
        except (OSError, json.JSONDecodeError, KeyError, PolicyError, ValueError) as exc:
            if on_skip is None:
                raise
            on_skip(path, exc)
    return reg


# --------------------------------------------------------------------------- #
# 判定 / 出证
# --------------------------------------------------------------------------- #

def _transcript(response: str, receipts: Optional[Sequence[Any]]) -> Transcript:
    """把 HTTP 请求体里的 ``response`` / ``receipts`` 收成 :class:`Transcript`。

    ``receipts`` 是**工具网关签发**的回执（P1-5），不是调用方自填的「我调用过」。
    这里只做形状还原；链自不自洽由 ``evaluate`` / ``commit`` 各自 fail-closed 地判
    （空链合法 —— 一次工具都没调用是正常情形）。
    """
    return Transcript(response=response,
                      receipts=[trace.ToolReceipt.from_dict(r) for r in (receipts or [])])


def _require_serviceable(packed: PackedPolicy) -> None:
    """含语义规则的策略**当场拒**（见 :class:`PolicyNotServiceable`）。"""
    rules = packed.unserviceable_rules
    if rules:
        raise PolicyNotServiceable(packed.policy.id, rules)


def _in_circuit_spec(spec: Dict[str, Any]) -> Dict[str, Any]:
    """把 ``semantic_bound`` 约束摘掉后的规范 JSON（其余字段原样）。

    只影响 :func:`policydsl.commit.canonical_violations` 的入参。**不改**
    ``spec["sha256"]``：那个哈希是整份规范 JSON（含语义约束）的承诺，摘掉的
    只是「哪些约束要拿去问违规列表」这个局部问题。
    """
    return {**spec,
            "constraints": [c for c in spec["constraints"] if c.get("kind") != "semantic_bound"]}


def host_outcome(packed: PackedPolicy, response: str,
                 receipts: Optional[Sequence[Any]] = None, *,
                 nonce: bytes = b"") -> Dict[str, Any]:
    """宿主判定：产出**与电路公开值同形**的 ``outcome``（毫秒级，无需证明器）。

    ``outcome`` 的形状照抄 ``pop-script`` 写下的那一份（``results.json`` 去掉
    ``name``/``mode``）：``{passed, policy_hash, response_binding, trace_root,
    violations, delegated}``。这不只是为了好看 —— ``/v1/check`` 与 ``/v1/attest``
    出的是**同一条响应的证书**，两份 ``outcome`` 若不同形，升段之后读者会看到
    「违规条目换了写法」，而没有任何东西提示他两次说的是同一件事。

    两个字段的来源值得点名：

    - ``violations`` 用 :func:`policydsl.commit.canonical_violations` —— 它是
      ``pop-types::evaluate`` 的**精确镜像**（编号/证据字符串逐字符一致），也正是
      电路写进公开值的那一份。调用前把 ``semantic_bound`` 约束摘掉：那种约束
      电路**只登记、不判定**（它进的是 ``delegated``），而
      ``canonical_violations`` 只镜像「判得出违规」的那部分，遇到它直接
      ``NotImplementedError``。摘掉是**对的**而不是绕过 —— 电路也不会为它产出
      任何 violation；
    - ``passed`` 用 :func:`policydsl.evaluate.check`（参考评估器，dev-plan §5.2.2
      点名的那一个）。它是**另一套推导**（走 ``Rule.params`` 而不是编译后的约束），
      所以两套结论**必须一致**：不一致就停证（:class:`VerdictMismatch`）。
      这道交叉校验本来就是「链下 golden 实现」存在的理由，白拿。

    ``response_binding`` 用 :func:`policydsl.commit.response_binding` 现算 ——
    与电路同一个函数、同一段域分隔，因此 ``/v1/check`` 绑的 T 与 ``/v1/attest``
    绑的 T 在同一个 nonce 下算出同一个值（升段时这一点是可核对的）。
    """
    tx = _transcript(response, receipts)
    res = evaluate.check(packed.policy, tx)

    violations = commit.canonical_violations(_in_circuit_spec(packed.spec), response,
                                             list(tx.receipts))
    if bool(res.passed) != (not violations):
        raise VerdictMismatch(
            f"策略 {packed.policy.id!r} 对同一条响应有两个结论：\n"
            f"  参考评估器 (evaluate.check)      : passed={res.passed} "
            f"违规 {len(res.violations)} 条 "
            f"{[v.to_dict()['rule'] for v in res.violations]}\n"
            f"  规范违规列表 (canonical_violations): 违规 {len(violations)} 条 "
            f"{[v['rule'] for v in violations]}\n"
            "证书的 outcome 只能是后者的形状（它才是电路公开值的镜像），而 passed "
            "是给调用方读的布尔值 —— 两者打架时出哪一张证书都会误导一半读者。")

    return {
        "passed": bool(res.passed),
        "policy_hash": packed.policy_hash,
        "response_binding": commit.response_binding(nonce, response),
        "trace_root": trace.trace_root(list(tx.receipts)),
        "violations": violations,
        "delegated": [d.to_dict() for d in res.delegated],
    }


@dataclass
class Issued:
    """一张签好了的证书及其落盘位置。"""

    payload: Dict[str, Any]
    envelope: Dict[str, Any]
    digest: str
    out_dir: Path
    proof_mode: str
    vkey_hash: str
    proof_sha256: Optional[str] = None
    proof_path: Optional[Path] = None
    #: 回执链的旁证文件（调用方给了 ``receipts`` 时才有）。
    receipts_path: Optional[Path] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"cert_digest": self.digest, "proof_mode": self.proof_mode,
                "vkey_hash": self.vkey_hash,
                "proof_sha256": self.proof_sha256,
                "cert": self.envelope,
                "dir": str(self.out_dir)}


def _write_vectors(out_dir: Path, packed: PackedPolicy, response: str, nonce: bytes,
                   mode: str, receipts: Optional[Sequence[Any]] = None) -> Path:
    """写 ``vectors.json``。

    用 :func:`policydsl.serialize.vector_entry` / ``build_vectors`` 拼装，**不
    手抄字段名** —— 这里第一版就是手抄的，抄漏了 ``receipts``，电路于是按**空
    回执链**判定：证书的 ``trace_root`` 写着 ``genesis``，而验证方拿调用方给的
    回执一重算就 MISMATCH。这正是 ``vector_entry`` 想防的那种错（它的 docstring
    原文：「两条路若各拼一次向量，迟早会有一条拼错字段而静默退化成没带
    receipts 之类」）。**这条是 ``verify_cert.py`` 的 ``trace_binding`` 卡当场
    抓出来的**，见 ``tests/test_proof_service.py`` 里锁住它的用例。
    """
    spec = packed.spec
    extra: Dict[str, Any] = {"name": packed.policy.id, "nonce": list(nonce)}
    if receipts:
        extra["receipts"] = list(receipts)
    if mode == "private":
        # 私有模式的见证：掩码 / 脱敏文本 / 见证区间。掩码来自策略里的
        # pattern_block；没有 pattern 规则时为空表（不是错误）。
        patterns = [p for c in spec["constraints"] if c["kind"] == "pattern_block"
                    for p in c["patterns"]]
        mask = commit.mask_from_patterns(patterns, response) if patterns else []
        spans = commit.spec_spans(spec, response) if patterns else []
        extra.update({"private": True, "mask": mask,
                      "redacted": commit.redact(response, mask), "spans": spans})
    vectors = out_dir / "vectors.json"
    vectors.write_text(json.dumps(build_vectors([vector_entry(spec, response, **extra)]),
                                  indent=2, ensure_ascii=False), encoding="utf-8")
    return vectors


def run_pop(args: Sequence[str]) -> None:
    """调 ``pop-script`` 驱动（强制 ``SP1_PROVER=cpu``，与 ``issue_cert.py`` 同）。"""
    subprocess.run([str(verifier.POP_SCRIPT), *args],
                   env=dict(os.environ, SP1_PROVER="cpu"),
                   check=True, cwd=str(verifier.REPO))


def failure_reason(exc: BaseException) -> str:
    """把作业失败翻译成一句**运维能照着做**的话。

    为什么不能只写 ``f"{type(exc).__name__}: {exc}"``：真证明失败最常见的样子是
    ``CalledProcessError: Command '[...]' died with <Signals.SIGKILL: 9>`` ——
    它把整条命令行（含一个只存活几秒的临时路径）印出来，却**不说**原因。本机
    12 GB、SP1 core 证明的固定地板 ~10.15 GiB（``bench/results/proofs.md``），
    SIGKILL 几乎总是 OOM killer。说不出这一句，读到它的人会去翻 ``pop-script``
    的代码，而问题在内存。

    仍然是**如实**而不是断言：SIGKILL 也可能是别人 ``kill -9``，所以说「多半」
    并给出核实方法。
    """
    if (isinstance(exc, subprocess.CalledProcessError)
            and exc.returncode is not None and exc.returncode < 0):
        sig = -exc.returncode
        if sig == signal.SIGKILL:
            return (f"{type(exc).__name__}: 证明器被 SIGKILL 杀死（signal 9）—— "
                    f"多半是内存不足：SP1 core 证明的固定地板 ~10.15 GiB，"
                    f"见 bench/results/proofs.md。核实：dmesg | grep -i 'killed process'；"
                    f"缓解：出证时不要让别的进程占内存（`free -g` 看当时还剩多少），"
                    f"或换一台内存更大的机器 —— 调大 --concurrency 只会更快 OOM")
        return f"{type(exc).__name__}: 证明器被 signal {sig} 杀死（{exc}）"
    return f"{type(exc).__name__}: {exc}"


def sha256_file(path: Path) -> str:
    """文件字节的 SHA-256（证明工件绑定用，与 ``issue_cert.py`` 同口径）。"""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def issue_certificate(out_dir: Path, packed: PackedPolicy, response: str, nonce: bytes,
                      signer: Any, backend: anchor.AnchorBackend, *,
                      prove: bool, mode: str = "public", proof_mode: str = "core",
                      receipts: Optional[Sequence[Any]] = None,
                      lock: Optional[threading.Lock] = None) -> Issued:
    """出证（证明段与宿主段**共用**这一条路径）。

    ``prove=False`` 时只跑 ``pop-script --check``（拿电路的 outcome，不出证明），
    证书如实标注 ``unproven``；``prove=True`` 时加 ``--proof-out``，vkey 与
    ``proof_mode`` 取自 ``proof.bin.meta.json``（**不是**命令行回显）。

    为什么宿主段也要跑 ``pop-script --check`` 而不是直接用手算的 outcome：
    走同一条路径、同一个二进制，**两段的 outcome 才保证同形**；而且 ``--check``
    本身是毫秒级的，与真证明的成本无关。真正被省掉的是 ~2.5 分钟 + ~10.2 GiB
    的那一段。

    ``lock`` 串行化账本追加：文件账本是「读全表 → 算前驱哈希 → 追加」，
    两个线程同时做会各自读到同一份旧表、写出两条 ``seq`` 相同的记录。工作线程与
    在线段都会锚定，所以这把锁是必需的，不是保险。
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    vectors = _write_vectors(out_dir, packed, response, nonce, mode, receipts)
    results = out_dir / "results.json"
    proof = out_dir / "proof.bin"

    # 回执链的旁证：调用方给了回执就落盘，`verify_cert.py --receipts` 才有的可比。
    #
    # 少了它并不影响证书的**正确性**（链尾摘要已经在 outcome 里），但会让
    # `trace_binding` 卡只剩**一个**来源可比 —— 那张卡要求至少两个来源，于是
    # 一份本来可以核实的证书会如实报成「binding uncheckable」。旁证落盘把
    # 「核不了」变成「核过了」，而它几乎是免费的。
    receipts_path = None
    if receipts:
        receipts_path = out_dir / "receipts.json"
        receipts_path.write_text(json.dumps(
            [r.to_dict() if hasattr(r, "to_dict") else r for r in receipts], indent=2),
            encoding="utf-8")

    if prove:
        run_pop(["--vectors", str(vectors), "--out", str(results), "--proof-out", str(proof)])
        meta = json.loads(Path(f"{proof}.meta.json").read_text(encoding="utf-8"))
        vkey_hash = meta["vkey_hash"]
        # 模式取 pop-script 写下的边车元信息 —— 证书如实转述**实际产出的**那一档。
        proof_mode = meta.get("proof_mode") or proof_mode
        proof_sha = sha256_file(proof)
        pv_file = Path(f"{proof}.pv")
        pv_sha = sha256_file(pv_file) if pv_file.exists() else None
    else:
        run_pop(["--check", "--vectors", str(vectors), "--out", str(results)])
        vkey_hash, proof_sha, pv_sha = cert.VKEY_HASH_UNPROVEN, None, None
        # 诚实标注（P0-4）：没有证明工件 ⇒ 只能记「未证明」，
        # 绝不写成 core（那会声称一档并不存在的证据）。
        proof_mode = cert.PROOF_MODE_UNPROVEN

    # 电路写下的 outcome 是**权威**的（它就是公开值那份）；宿主段另有手算路径
    # （host_outcome），两者的一致性由 host_outcome 的交叉校验负责。
    got = json.loads(results.read_text(encoding="utf-8"))[0]
    outcome = {k: v for k, v in got.items() if k not in ("name", "mode")}

    payload = cert.build_payload(
        packed.policy.id, packed.policy.version, packed.spec, mode, outcome,
        vkey_hash, proof_sha, public_values_sha256=pv_sha,
        challenge=challenge.challenge_block(nonce, outcome.get("response_binding") or ""),
        proof_mode=proof_mode)
    envelope = cert.sign_payload(payload, signer)
    (out_dir / "cert.json").write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    (out_dir / "payload.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    # 公钥不是秘密：放在证书旁边，第三方缺省就读它。
    (out_dir / "key.json").write_text(json.dumps(
        {"keyid": signer.keyid, "public_hex": signer.public_hex}, indent=2), encoding="utf-8")

    digest = cert.cert_digest(payload)
    meta = {"policy": packed.policy.id, "mode": mode, "proved": bool(prove)}
    entry = _anchor(backend, digest, meta, lock=lock)
    (out_dir / "anchor.json").write_text(json.dumps(entry, indent=2), encoding="utf-8")

    return Issued(payload=payload, envelope=envelope, digest=digest, out_dir=out_dir,
                  proof_mode=proof_mode, vkey_hash=vkey_hash, proof_sha256=proof_sha,
                  proof_path=proof if prove else None, receipts_path=receipts_path)


def _anchor(backend: anchor.AnchorBackend, digest: str, meta: Dict[str, Any], *,
            lock: Optional[threading.Lock] = None) -> Dict[str, Any]:
    if lock is None:
        return backend.anchor(digest, meta)
    with lock:
        return backend.anchor(digest, meta)


# --------------------------------------------------------------------------- #
# 作业队列
# --------------------------------------------------------------------------- #

@dataclass
class Job:
    """一次出证作业。``state`` 只在 :class:`ProofService` 的锁下改写。"""

    job_id: str
    seq: int
    policy_id: str
    #: 提交者的 token **标签**（不是 secret）。开鉴权时用它判「这作业是不是你的」，
    #: 见 :meth:`ProofService.public_job`。关鉴权时是 ``"anonymous"``。
    owner: str = ""
    state: str = STATE_QUEUED
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    error: Optional[str] = None
    issued: Optional[Issued] = None
    nonce_hex: str = ""
    #: 证明段是否真的跑了 SP1（``False`` ⇒ 作业产物是 ``unproven``）。
    proved: bool = False

    @property
    def elapsed(self) -> Optional[float]:
        if self.started_at is None:
            return None
        return (self.finished_at or time.time()) - self.started_at

    def public(self, queue_position: Optional[int] = None) -> Dict[str, Any]:
        """``GET /v1/attest/{job}`` 的响应体。

        终态之外**不**带证书：轮询的人要能一眼看出「还没好」，而不是从一堆字段里
        猜哪个是空的。``proved=False`` 时 ``proof_mode`` 会如实是 ``unproven``——
        调用方不需要读我们的文档才知道这份产物没有证明。
        """
        out: Dict[str, Any] = {
            "job_id": self.job_id, "state": self.state, "policy_id": self.policy_id,
            "nonce": self.nonce_hex, "proved": self.proved,
            "elapsed": self.elapsed,
        }
        if self.owner:
            # 只有在真有人认领时才写这个字段：关鉴权时每条都是 anonymous，
            # 把它印在每一份响应里只会让读的人以为「服务在区分调用方」。
            out["submitted_by"] = self.owner
        if queue_position is not None:
            out["queue_position"] = queue_position
        if self.state == STATE_FAILED:
            out["error"] = self.error
        if self.issued is not None:
            out.update({"cert_digest": self.issued.digest,
                        "proof_mode": self.issued.proof_mode,
                        "vkey_hash": self.issued.vkey_hash,
                        "cert": self.issued.envelope,
                        "dir": str(self.issued.out_dir)})
            if self.issued.proof_path is not None:
                out["proof"] = str(self.issued.proof_path)
        return out


class ProofService:
    """策略注册表 + 出证作业队列 + 账本锚定。

    线程模型：``concurrency`` 个工作线程从一条 :class:`queue.Queue` 上取作业。
    ``concurrency`` 缺省 1 —— 这不是保守取值，而是 ~10.2 GiB 地板的直接后果
    （见模块 docstring）。它可调，但调高之前请先确认机器的物理内存。

    ``max_queue`` 是**等待中**的作业上限（不含正在证的那 ``concurrency`` 个）。
    满了之后 ``submit`` 抛 :class:`QueueFull`（HTTP 层翻成 429）。

    **为什么是拒绝而不是无限收下**：队列不消耗内存、无限收下是最容易写的实现，
    但它把「做不到」推迟到几十分钟后以 OOM 的形式爆发，而那时客户端手里的
    ``job_id`` 已经排了半天队。429 让调用方**当场**知道该退避还是换一台机器。
    """

    def __init__(self, registry: PolicyRegistry, out_dir: Path, *,
                 ledger: Optional[Path] = None, signer: Any = None,
                 concurrency: int = 1, max_queue: int = 8,
                 host_check: bool = False, mode: str = "public",
                 proof_mode: str = "core",
                 rpc_url: Optional[str] = None, contract: Optional[str] = None,
                 private_key: Optional[str] = None):
        if concurrency < 1:
            raise ServiceError("concurrency 至少是 1 —— 0 个工作线程的服务只会排队")
        self.registry = registry
        self.out_dir = Path(out_dir)
        self.ledger = Path(ledger) if ledger else self.out_dir / "ledger.jsonl"
        self.host_check = bool(host_check)
        self.mode = mode
        self.proof_mode = proof_mode
        self.concurrency = int(concurrency)
        self.max_queue = int(max_queue)

        self._lock = threading.Lock()
        self._jobs: Dict[str, Job] = {}
        self._seq = 0
        self._outstanding = 0
        self._q: "queue.Queue[Optional[tuple]]" = queue.Queue()
        self._workers: List[threading.Thread] = []
        self._stopped = False

        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.out_dir / "jobs").mkdir(exist_ok=True)
        (self.out_dir / "checks").mkdir(exist_ok=True)

        # 签名器与账本后端**整套服务共用一把**：每张证书的公钥都写在自己的
        # key.json 里，换钥意味着同一个 out_dir 里的证书出自两个签名者 ——
        # 验证方按证书旁的 key.json 验签是对的，但运维会以为「服务就一把钥」。
        self.signer = signer or keys.signer_from_env(None)
        self.backend = anchor.backend_from_env(self.ledger, rpc_url=rpc_url,
                                               contract=contract, private_key=private_key)
        # 账本锁：见 issue_certificate 的 lock 参数。
        self._ledger_lock = threading.Lock()

    # ---------------------------------------------------------------- 生命周期

    def start(self) -> "ProofService":
        if self._workers:
            return self
        for i in range(self.concurrency):
            t = threading.Thread(target=self._work, name=f"pop-prover-{i}", daemon=True)
            t.start()
            self._workers.append(t)
        return self

    def stop(self, drain: bool = True, timeout: Optional[float] = None) -> None:
        """停服务。``drain=True``（缺省）先把手上的活干完。

        ``drain=False`` 会让还没开工的作业停在 ``queued`` —— 那是**一句假话**
        （它们永远不会再被处理），所以缺省不这么干。
        """
        if not self._workers:
            return
        if drain:
            self._q.join()
        for _ in self._workers:
            self._q.put(None)
        for t in self._workers:
            t.join(timeout=timeout)
        self._workers = []
        self._stopped = True

    def __enter__(self) -> "ProofService":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # ---------------------------------------------------------------- 队列

    @property
    def capacity(self) -> int:
        """能同时被收下的作业数（正在证的 + 排队的）。"""
        return self.concurrency + self.max_queue

    def queue_depth(self) -> int:
        """排队的深度（含正在证的，与 ``capacity`` 同口径）。"""
        with self._lock:
            return self._outstanding

    def _reserve(self) -> None:
        with self._lock:
            if self._outstanding >= self.capacity:
                raise QueueFull(
                    f"队列已满：{self._outstanding}/{self.capacity} "
                    f"（concurrency={self.concurrency} + max_queue={self.max_queue}）；"
                    "稍后重试或换一台机器 —— 在 12 GB 上同时跑两个证明器是 OOM，"
                    "不是慢")
            self._outstanding += 1

    def submit(self, policy_id: str, response: str, nonce: bytes = b"",
               receipts: Optional[Sequence[Any]] = None, owner: str = "") -> Job:
        """入队一次出证。返回的 :class:`Job` 处于 ``queued``，**不等于**已开工。"""
        packed = self.registry.get(policy_id)          # 未注册的策略当场 4xx
        _require_serviceable(packed)
        self._reserve()
        job: Optional[Job] = None      # 下面 except 里要读 job_id，先给它一个绑定
        try:
            with self._lock:
                self._seq += 1
                job = Job(job_id=f"job-{uuid.uuid4().hex[:16]}", seq=self._seq,
                          policy_id=policy_id, owner=owner,
                          nonce_hex=challenge.nonce_hex(nonce),
                          proved=not self.host_check)
                self._jobs[job.job_id] = job
            self._q.put((job.job_id, packed, response, nonce, list(receipts or [])))
            return job
        except BaseException:
            # 没能真正入队就必须把名额还回去 —— 否则一次参数错误会永久吃掉一个
            # 队列位，服务会随着运行越排越满，且没有任何日志解释为什么。
            with self._lock:
                self._outstanding -= 1
                if job is not None:
                    self._jobs.pop(job.job_id, None)
            raise

    def get(self, job_id: str) -> Job:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            raise JobNotFound(f"no such job: {job_id}")
        return job

    def public_job(self, job_id: str, *, viewer: Optional[Any] = None) -> Dict[str, Any]:
        """``GET /v1/attest/{job}`` 的响应体（含 ``verify_hint``）。

        由服务而不是 :class:`Job` 组装：``verify_hint`` 需要账本路径与策略包路径，
        这两样是服务的知识，不是作业的。

        ``viewer`` 非空时判归属（``viewer.owns(job.owner)``，duck-typed 成
        :class:`policydsl.auth.Principal`）。**不是你的作业报的是
        :class:`JobNotFound`，不是「无权限」** —— 报 403 等于确认「这个 job_id
        存在」，那它就成了一个探测别家 job_id 的预言机。两种情况必须从外部
        完全看不出区别，所以连措辞都用同一个。
        """
        job = self.get(job_id)
        if viewer is not None and not viewer.owns(job.owner):
            raise JobNotFound(f"no such job: {job_id}")
        out = job.public(self.queue_position(job))
        if job.issued is not None:
            out["verify_hint"] = verify_hint(job.issued,
                                             self.registry.get(job.policy_id), self.ledger)
        return out

    def queue_position(self, job: Job) -> Optional[int]:
        """``job`` 前面还有几个**没开工**的。开工/结束之后没有意义（返回 ``None``）。"""
        with self._lock:
            if job.state != STATE_QUEUED:
                return None
            return sum(1 for j in self._jobs.values()
                       if j.seq < job.seq and j.state == STATE_QUEUED)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            counts: Dict[str, int] = {}
            for j in self._jobs.values():
                counts[j.state] = counts.get(j.state, 0) + 1
        return {"concurrency": self.concurrency, "max_queue": self.max_queue,
                "capacity": self.capacity, "outstanding": self.queue_depth(),
                "jobs": counts, "host_check": self.host_check,
                "proof_mode": cert.PROOF_MODE_UNPROVEN if self.host_check else self.proof_mode,
                "policies": self.registry.ids(), "out_dir": str(self.out_dir),
                "ledger": str(self.ledger)}

    # ---------------------------------------------------------------- 工作线程

    def _work(self) -> None:
        while True:
            item = self._q.get()
            try:
                if item is None:
                    return
                self._run_job(*item)
            finally:
                self._q.task_done()

    def _run_job(self, job_id: str, packed: PackedPolicy, response: str, nonce: bytes,
                 receipts: List[Any]) -> None:
        job = self.get(job_id)
        with self._lock:
            job.state = STATE_PROVING
            job.started_at = time.time()
        try:
            issued = issue_certificate(
                self.out_dir / "jobs" / job_id, packed, response, nonce, self.signer,
                self.backend, prove=not self.host_check, mode=self.mode,
                proof_mode=self.proof_mode, receipts=receipts, lock=self._ledger_lock)
            with self._lock:
                job.issued, job.state = issued, STATE_DONE
        except BaseException as exc:      # noqa: BLE001 —— 作业失败必须落进 job.error
            # 工作线程里漏出去的异常会**静默杀死线程**（其余作业继续跑，而这个
            # job 永远停在 proving）。所以这里兜住一切，把它写进作业记录。
            with self._lock:
                job.state, job.error = STATE_FAILED, failure_reason(exc)
                job.proved = False
            print(f"[proof-service] job {job_id} failed: {job.error}", file=sys.stderr)
        finally:
            with self._lock:
                job.finished_at = time.time()
                self._outstanding -= 1

    # ---------------------------------------------------------------- 在线段

    def check(self, policy_id: str, response: str, nonce: bytes = b"",
              receipts: Optional[Sequence[Any]] = None) -> Dict[str, Any]:
        """``POST /v1/check``：宿主判定 + 一张**如实标注 unproven** 的证书。

        不需要证明器、不需要 ``circuits/`` 编译产物、不占队列 —— 这是它可以
        毫秒级返回的原因，也是它可以在边缘跑的原因。

        **它仍然要签一张证书**（而不是回一个裸的 JSON 结论）。理由是证据链：
        出证方对这条结论负责（Ed25519 签名 + 账本锚定），调用方拿到的是一份
        可转交、可独立验证的产物，而不是一个只能自己相信的 HTTP 响应体。
        """
        packed = self.registry.get(policy_id)
        _require_serviceable(packed)
        # 先用手算（毫秒级）复核一遍电路会给出的结论：两套推导不一致时停证。
        # 这一步**不**依赖 pop-script，所以在线段仍然是毫秒级的。
        _ = host_outcome(packed, response, receipts, nonce=nonce)

        # 目录按「内容前缀 / 每次调用一个」分层，**不覆盖**同一条响应的上一次检查：
        # 每次调用都是一张**新签发的证书**（载荷里有 ts ⇒ 摘要不同 ⇒ 账本里也是
        # 另一条记录）。用内容哈希当目录名会把上一张证书的文件盖掉，而账本里
        # 那条锚定记录还在指向它 —— 磁盘上就出现了一个「有账无据」的摘要。
        store = self.out_dir / "checks" / _short_digest(response, nonce) / uuid.uuid4().hex[:8]
        issued = issue_certificate(store, packed, response, nonce, self.signer,
                                   self.backend, prove=False, mode=self.mode,
                                   receipts=receipts, lock=self._ledger_lock)
        out = issued.to_dict()
        out.update({"nonce": challenge.nonce_hex(nonce),
                    "outcome": issued.payload["outcome"],
                    "passed": issued.payload["outcome"]["passed"],
                    "proved": False,
                    "verify_hint": verify_hint(issued, packed, self.ledger)})
        return out


def verify_hint(issued: Issued, packed: PackedPolicy, ledger: Path) -> str:
    """一行可以直接粘进终端的 ``verify_cert.py`` 调用。

    它出现在响应体里而不是只写进日志 —— 「这份产物怎么独立验证」是证书的一部分
    语义，把它留在服务器日志里等于要求调用方来读我们的文档。

    有证明工件时带上 ``--proof``（没有它，``proof``/``trace_binding`` 那两张卡
    会如实跳过：证明没在手上，谁也核不了）；有回执旁证时带上 ``--receipts``。
    """
    parts = [f"python3 scripts/verify_cert.py --cert {issued.out_dir / 'cert.json'}",
             f"--pack {packed.path or '<pack>'}", f"--ledger {ledger}",
             f"--keyring {issued.out_dir / 'key.json'}"]
    if issued.proof_path is not None:
        parts.append(f"--proof {issued.proof_path}")
    if issued.receipts_path is not None:
        parts.append(f"--receipts {issued.receipts_path}")
    return " ".join(parts)


def _short_digest(response: str, nonce: bytes) -> str:
    """``checks/`` 下的目录名：响应 + nonce 的短哈希。

    用内容哈希而不是序号：这样同一条响应的历次检查会**落在同一个前缀下**，
    运维一眼能把它们收拢到一起；而每次调用各自一个子目录，谁也不会盖掉谁
    （每次调用都是一张新证书，见 :meth:`ProofService.check`）。
    """
    h = hashlib.sha256(nonce + b"\x00" + response.encode("utf-8")).hexdigest()
    return h[:16]
