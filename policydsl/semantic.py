"""语义规则（P2-9）：Python 侧的**契约口径**（只依赖标准库）。

本模块是语义规则在「链外参考层」的真相源。它不 import ezkl，也不 import torch
（``semantic.features`` 的模块级 import 是纯标准库，torch 只在真正构造网络时才延迟
导入）—— 于是「设置文件的口径」「模型指纹」「规则与响应的绑定」这些**必须能被
离线复算**的东西，在纯标准库环境里也核得了。

## 为什么需要这一层

语义规则有三条信任边界（`docs/design-semantic-rules.md`，也是 P2-9 §9.0 的三条），
任何一条不成立，这条规则就退化成「证明者的一句话声明」—— 也就是 P0-1 修掉的那个
漏洞换了个马甲。三条里**最难保证的是 ②**（特征必须由响应确定性派生且在图内），
而最容易**看起来做对了、实际没有**的是 ① 的落地形式：

| # | 边界 | 本模块负责的部分 |
|---|---|---|
| ① | 权重被承诺 | :func:`model_manifest` —— ONNX 的 sha256 进约束；ezkl 的 vk 唯一确定整张图 |
| ② | 特征图内派生 | 无（由 ``semantic/features.py` 的图结构保证） |
| ③ | 输入与响应绑定 | :func:`encode_ids` —— 验证方拿 T 重算 id，与公开实例逐位比对 |

## 设置文件的口径（**最不能靠直觉的一处**）

ezkl 的 ``settings.json`` 里有两个字段的取值**不是调优，而是正确性前提**：

- ``run_args.input_scale`` **必须是 0**（即 ``2^0 = 1``）。索引类算子（``Gather`` /
  ``OneHot``）吃的是**缩放后的原始整数**，不是去量化后的真值 —— 若 ezkl 自选一个
  缩放（实测 ``2^7``），字符 id ``1`` 会被当成 ``128`` 去查只有 193 行的投影表，
  直接越界 panic；而「先把 id 除以 ``2^scale`` 补偿一下」的直觉做法更糟：``Cast``
  按去量化真值截断，``1/128 → 0``，整段文本退化成全 PAD，电路**恒输出同一个分数**
  —— 不报错，静默失效。细节见 ``semantic/features.py`` 模块 docstring 的「定点语义」。
- ``run_args.logrows`` 必须装得下 ``num_rows``（``num_rows > 2^logrows`` 时 ezkl 在
  ``src/circuit/ops/region.rs:905`` 处 panic，报的是 ``Option::unwrap() on a None value``
  —— 与「行数超了」毫无字面关系）。

:func:`patch_settings` 施加这两条，:func:`check_settings` 反过来**验**它们。出证脚本
只允许从 :func:`patch_settings` 产出的设置文件出发，避免出现「忘了打补丁的设置」。

## 实测规模（12 GB 机器，L=64/DIM=64/无三元组）

| 阶段 | 耗时 | 体积 / 峰值内存 |
|---|---|---|
| gen_settings + compile | 1.1 s | num_rows = 131,250 |
| gen_srs(logrows=18) | 8.5 s | — |
| setup | 34.0 s | ``pk.ezkl`` 2.92 GB（峰值 5.24 GB） |
| prove | 75.2 s | proof 40 KB（峰值 **9.17 GB**） |
| verify | 1.4 s | — |

峰值 9.17 GB 在 12 GB 机器上**很紧**（故 setup 与 prove 必须分进程跑，否则内存叠加）。
这些数字登记在 ``bench/results/semantic.json``。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Sequence

__all__ = [
    "SemanticError", "SEMANTIC_VERSION", "SETTINGS_VERSION", "REQUIRED_INPUT_SCALE",
    "DEFAULT_LOGROWS", "required_logrows", "patch_settings", "check_settings",
    "settings_fingerprint", "model_dir", "model_manifest", "onnx_sha256",
    "encode_ids", "input_width", "check_bound_to_response", "ARTIFACT_NAMES",
    "hex_int", "read_instances", "check_settings_file", "verify_companion",
    "companion_entry", "threshold_holds", "SEMANTIC_SYSTEM_EZKL",
]


class SemanticError(ValueError):
    """语义规则的契约被违反（设置口径错、模型指纹不符、绑定对不上等）。"""


#: 语义规则的版本标签（进约束、进文档；语义一变就要改）。
SEMANTIC_VERSION = "pop-semantic-v1"

#: 设置文件口径的版本标签。改 :func:`patch_settings` 的行为必须同时改它 ——
#: 这样「旧设置文件」能被一眼认出来，而不是悄悄按新口径解释。
SETTINGS_VERSION = "pop-semantic-settings-v1"

#: ``run_args.input_scale`` 的**强制值**（= ``2^0``）。理由见模块 docstring。
REQUIRED_INPUT_SCALE = 0

#: ``logrows`` 的下限。实测 L=64/DIM=64 的图有 131,250 行，需要 ``2^18``；
#: 取 18 作为下限同时给「关掉三元组但换个大 VOCAB」留了余量。
DEFAULT_LOGROWS = 18

#: 承担语义约束的证明系统标识。**必须与 Rust 侧常量
#: ``pop_types::SEMANTIC_SYSTEM_EZKL`` 逐字符相同** —— 它进公开值，验证方按它
#: 分发到具体的验证器；两边写岔会让「有陪伴证明」被判成「系统不认识」。
SEMANTIC_SYSTEM_EZKL = "ezkl-halo2"

#: 落盘产物的文件名（``scripts/ezkl_prove.py`` 与测试共用，避免两边写岔）。
#:
#: 说明：ezkl 对扩展名不作要求，这里刻意用 ``.ezkl`` 而不是 ``.key`` ——
#: ``.gitignore`` 里的 ``*.key`` 是给 P0-3 的 Ed25519 私钥用的，而 ``vk.ezkl``
#: **必须入库**（它是验证方唯一的凭据）。用 ``.key`` 会被那条规则静默吞掉。
ARTIFACT_NAMES: Dict[str, str] = {
    "settings": "settings.json",
    "compiled": "model.compiled",
    "srs": "kzg.srs",
    "vk": "vk.ezkl",
    "pk": "pk.ezkl",
    "proof": "proof.json",
    "manifest": "MANIFEST.json",
}


def required_logrows(num_rows: int, minimum: int = DEFAULT_LOGROWS) -> int:
    """装得下 ``num_rows`` 行的最小 ``logrows``，且不小于 ``minimum``。

    ``logrows`` 是**行数的位宽**：``num_rows > 2^logrows`` 时 ezkl 会 panic
    （见模块 docstring）。所以这是硬约束，不是性能调参。
    """
    if num_rows < 0:
        raise SemanticError(f"num_rows 不能为负：{num_rows}")
    need = max(1, (int(num_rows) - 1).bit_length())    # ceil(log2(num_rows))
    return max(int(minimum), need)


def patch_settings(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """把「正确性前提」写进 ezkl 的设置字典（**原地改并返回同一个对象**）。

    施加两件事，两件都是硬约束而非调优：

    1. ``run_args.input_scale = 0``（``2^0 = 1``）—— 见模块 docstring；
    2. ``run_args.logrows >= required_logrows(cfg["num_rows"])`` —— 不足会 panic。

    只**抬高** ``logrows``、从不压低：调用方若显式给了更大的值，那是它知道自己
    在做什么（例如留余量给更大的图）。
    """
    if not isinstance(cfg, dict):
        raise SemanticError(f"settings 必须是 dict，得到 {type(cfg).__name__}")
    run_args = cfg.setdefault("run_args", {})
    if not isinstance(run_args, dict):
        raise SemanticError("settings['run_args'] 必须是 dict")

    run_args["input_scale"] = REQUIRED_INPUT_SCALE

    num_rows = cfg.get("num_rows", 0)
    try:
        num_rows = int(num_rows)
    except (TypeError, ValueError) as exc:
        raise SemanticError(f"settings['num_rows'] 不是整数：{num_rows!r}") from exc
    need = required_logrows(num_rows)
    have = run_args.get("logrows", 0) or 0
    run_args["logrows"] = max(int(have), need)
    return cfg


def check_settings(cfg: Dict[str, Any]) -> None:
    """反过来**验**设置文件的口径；不合规抛 :class:`SemanticError`。

    出证脚本在 ``setup`` 前调它，验证方在核验时也调它 —— 后者的意义是：一个被
    掉包成「``input_scale = 7``」的设置文件会让语义规则静默失效（恒真），
    这种失效**不会**让证明验证失败，所以必须在协议层显式挡住。
    """
    if not isinstance(cfg, dict):
        raise SemanticError(f"settings 必须是 dict，得到 {type(cfg).__name__}")
    run_args = cfg.get("run_args") or {}
    scale = run_args.get("input_scale", None)
    if scale != REQUIRED_INPUT_SCALE:
        raise SemanticError(
            f"settings.run_args.input_scale = {scale!r}，必须为 {REQUIRED_INPUT_SCALE}"
            f"（=2^0=1）。索引算子吃的是缩放后的整数，别的取值会让全文退化成同一个"
            f"输入（静默失效），或直接越界 panic。见 policydsl/semantic.py 模块 docstring。")
    num_rows = int(cfg.get("num_rows", 0) or 0)
    logrows = int(run_args.get("logrows", 0) or 0)
    if num_rows and (1 << logrows) < num_rows:
        raise SemanticError(
            f"logrows={logrows} 装不下 num_rows={num_rows}（2^{logrows} < {num_rows}）；"
            f"至少需要 logrows={required_logrows(num_rows)}")


def settings_fingerprint(cfg: Dict[str, Any]) -> str:
    """设置文件的稳定指纹（进产物清单，便于发现口径被悄悄改了）。"""
    blob = json.dumps(cfg, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# 模型指纹（信任边界 ① 的落地形式）
# --------------------------------------------------------------------------- #

def model_dir() -> Path:
    """``semantic/`` 目录（模型与产物的家）。"""
    return Path(__file__).resolve().parents[1] / "semantic"


def onnx_sha256(path: Path | str | None = None) -> str:
    """``model.onnx`` 的 sha256（**现算**，不读 ``MODEL.sha256``）。

    现算是刻意的：约束里的 ``onnx_sha256`` 必须是对**文件字节**的承诺，而不是对
    另一个文本文件的转述 —— 后者可以被一起掉包。
    """
    p = Path(path) if path is not None else model_dir() / "model.onnx"
    if not p.exists():
        raise SemanticError(f"{p} 不存在 —— 先跑 python3 -m semantic.train 生成模型")
    return hashlib.sha256(p.read_bytes()).hexdigest()


def model_manifest(directory: Path | str | None = None) -> Dict[str, Any]:
    """模型指纹清单：进约束、进产物、进测试。

    返回 ``onnx_sha256`` / ``head_sha256`` / ``feature_version`` / ``dims`` /
    ``max_chars`` / ``onnx_bytes``，并**当场核对** ``MODEL.sha256`` 与文件是否一致
    （不一致说明模型被换过或导出漂移了 —— 这是必须炸掉的情况）。

    ``semantic/`` 是模型侧，本函数只读它的落盘产物，不 import torch。
    """
    d = Path(directory) if directory is not None else model_dir()
    onnx_p = d / "model.onnx"
    head_p = d / "head.weights.json"
    rep_p = d / "training_report.json"
    sha_p = d / "MODEL.sha256"

    for p in (onnx_p, head_p, rep_p, sha_p):
        if not p.exists():
            raise SemanticError(f"{p} 不存在 —— 先跑 python3 -m semantic.train")

    got = onnx_sha256(onnx_p)
    want = sha_p.read_text(encoding="utf-8").strip()
    if got != want:
        raise SemanticError(
            f"model.onnx 的 sha256 与 MODEL.sha256 不符：\n  文件 {got}\n  记录 {want}\n"
            f"（模型被换过，或 ONNX 导出不再逐字节确定）")

    report = json.loads(rep_p.read_text(encoding="utf-8"))
    dims = report.get("dims") or {}
    return {
        "onnx_sha256": got,
        "onnx_bytes": onnx_p.stat().st_size,
        "head_sha256": hashlib.sha256(head_p.read_bytes()).hexdigest(),
        "feature_version": report.get("feature_version"),
        "semantic_version": SEMANTIC_VERSION,
        "max_chars": dims.get("max_chars"),
        "dim": dims.get("dim"),
        "hidden": dims.get("hidden"),
        "vocab": dims.get("vocab"),
        "num_rows": report.get("circuit_rows"),
    }


# --------------------------------------------------------------------------- #
# 输入绑定（信任边界 ③）
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# 陪伴证明的读取与核验（P2-9 §9.5 的「组合与绑定」）
# --------------------------------------------------------------------------- #

def hex_int(h: str) -> int:
    """ezkl 的公开值是**32 字节小端**十六进制串。

    实测：id ``41``（字符 ``H``）写成 ``29`` 打头的串，小端读回 41；分数 ``128``
    写成 ``80`` 打头，小端读回 128。按十进制解析（得到天文数字）或按**大端**解析
    （得到另一个数）都**不会报错**，只会静默算错 —— 所以口径只此一处，调用方
    一律走这里。
    """
    return int.from_bytes(bytes.fromhex(str(h)), "little")


def read_instances(proof_path: Path | str) -> List[int]:
    """读 ezkl 证明里的公开实例：前 :func:`input_width` 个是输入，其后是输出。

    形状兼容两种（实测是二维 ``[[v0, v1, ...]]``，batch 维一条）：换 ezkl 版本时
    batch 维被省掉的话不会静默错位。
    """
    d = json.loads(Path(proof_path).read_text(encoding="utf-8"))
    raw = d.get("instances")
    if not isinstance(raw, list) or not raw:
        raise SemanticError(f"{proof_path} 里没有 instances —— 不是 ezkl 证明文件？")
    if isinstance(raw[0], list):
        raw = raw[0]
    return [hex_int(v) for v in raw]


def check_settings_file(path: Path | str) -> Dict[str, Any]:
    """:func:`check_settings` 的文件版（读 + 验，供验证方调用）。"""
    cfg = json.loads(Path(path).read_text(encoding="utf-8"))
    check_settings(cfg)
    return cfg


def threshold_holds(score_bp: int, threshold_bp: int, direction: str) -> bool:
    """把「分数 vs 阈值」的判定收敛到一处（与 Rust 侧的 ``BoundDirection`` 同名同义）。

    ``le``: ``score_bp <= threshold_bp``；``ge``: ``score_bp >= threshold_bp``。
    未知方向**抛错**而不是当作通过 —— 小开关被默认掉是这类协议里最安静的一种错。
    """
    if direction == "le":
        return score_bp <= threshold_bp
    if direction == "ge":
        return score_bp >= threshold_bp
    raise SemanticError(f"未知的 direction {direction!r}（只接受 'le' / 'ge'）")


def score_bp_of_instances(instances: Sequence[int], scale: int) -> int:
    """公开实例里的输出（**已解量化**的那个整数）换算成万分点。

    ``instances[input_width()]`` 就是 sigmoid 之后的 P(有害) 乘上 ``scale``；除以
    ``scale`` 再乘 10000 得到万分点。分数与阈值都来自证明本身，所以这一步是
    确定性的、不需要谁出证（见 :func:`verify_companion` 的说明）。
    """
    w = input_width()
    if len(instances) <= w:
        raise SemanticError(f"公开实例只有 {len(instances)} 个，取不到第 {w} 个输出")
    return int(round(instances[w] / scale * 10000))


def read_score_bp(proof_path: Path | str,
                  artifacts_dir: Path | str | None = None) -> int:
    """从一份陪伴证明里读出 P(有害)（万分点）—— **出证方自检**用。

    验证方走的是 :func:`verify_companion`（它顺带把证明绑到响应上）；这个函数只
    服务于出证方「我这一份证明到底算出了几分」的那一问 —— 出证方在看到分数之前
    不应该把证书当作已判定完成。``scale`` 取自 settings，不写死。
    """
    d = Path(artifacts_dir) if artifacts_dir is not None else model_dir() / "artifacts"
    cfg = json.loads((d / ARTIFACT_NAMES["settings"]).read_text(encoding="utf-8"))
    scale = 2 ** int(cfg["model_output_scales"][0])
    return score_bp_of_instances(read_instances(proof_path), scale)


def _fail(why: str) -> Tuple[bool, str, bool]:
    """「没验成」的统一出口：``ok=False``、``satisfied=False``。见
    :func:`verify_companion` 的返回值说明 —— 这里表达的是**没验**，
    不是「验了但没过」。"""
    return False, why, False


def verify_companion(dep: Dict[str, Any], companion: Dict[str, Any], response: str,
                     artifacts_dir: Path | str | None = None,
                     *, verify_proof: bool = True) -> Tuple[bool, str, bool]:
    """核验一条陪伴证明是否**确实承担**了 ``dep`` 这条被委托的约束。

    ``dep`` 是证明公开值里 ``delegated[i]`` 那一项（**电路算出来的**），
    ``companion`` 是证书 ``semantic.companions[i]`` 那一项（**出证方写的**）。
    这个函数做的就是「把出证方写的东西，逐字段钉在电路说的话上」——
    三项指纹必须全等，然后才轮到 ezkl 自己验证明。

    逐步（任何一步失败即返回 ``(False, 原因)``，绝不「跳过继续」）：

    1. ``system`` 一致（否则不知道该用哪个验证器 —— 不认识就拒绝）；
    2. ``model_vkey`` ↔ ``vk_sha256``、``onnx_sha256``、``threshold_bp``、
       ``direction`` 全等 —— 这一条挡的是「拿**另一个模型/另一个阈值**的证明来凑」；
    3. 证明文件的 sha256 == ``companion["proof_sha256"]``（证书承诺的那一份）；
    4. ezkl 验证明（``vk`` + ``settings`` + ``srs``，都从 ``artifacts_dir`` 取）；
    5. 公开实例的**输入部分** == ``encode(T′)`` —— 把证明绑到**送达的**响应上
       （信任边界 ③，与 SP1 侧的 ``response_binding`` 是两条独立的路，都要走）；
    6. 公开实例的**输出**换算成万分点后满足 ``direction``/``threshold_bp``。

    **第 6 步是在链下做的，这不影响健全性**：分数与阈值都是公开值里被证明过的
    数字，比较是二者的确定性函数 —— 验证方不需要为之出证，只需要**不要信任**
    任何一方转述的中间值，而这里用的两个数都直接来自证明本身。

    ## 返回值：``(ok, detail, satisfied)`` 三件事，**不要混为一谈**

    这个函数的调用方（``verify_cert.py``）是**一致性**检查器：它回答的是
    「这张证书自称的东西，是不是被证明支持的」，而**不是**「策略通过了」——
    仓库里 `--expect violate` 的演示证书同样是**真证书**，必须验得过
    （``RESULT: PASS`` 而 ``passed=false``）。所以：

    - ``ok``：**这份陪伴证明是真的、且绑在这条响应上**（第 1–5 步）。
      假的证明、换过的模型、错位的阈值、另一条响应的证明 —— 一律 False。
      这**才是**判定项。
    - ``satisfied``：语义规则**是否满足**（第 6 步）。它是「证书内容」的一部分，
      不是「证书真伪」的一部分。把它混进 ``ok`` 会让一张如实记录了违规的证书
      被判成「伪造」，那会让这个工具在最需要它的时候（审计违规）给不出正确结论。
    - ``detail``：给人看的诊断，包含分数与阈值判定的结果。

    唯一**必须** fail-closed 的情形是「压根拿不到判定」：没有陪伴证明、缺材料、
    ezkl 跑不起来 —— 那种时候 ``ok=False``，因为它意味着**没验**，而不是
    「验了但没过」。
    """
    d = Path(artifacts_dir) if artifacts_dir is not None else model_dir() / "artifacts"

    if dep.get("system") != SEMANTIC_SYSTEM_EZKL:
        return _fail(f"不认识的委托系统 {dep.get('system')!r}（只会核 "
                     f"{SEMANTIC_SYSTEM_EZKL}）—— 验证器不认识就拒绝")
    if companion.get("system") != dep.get("system"):
        return _fail(f"system 不符：证书 {companion.get('system')!r} vs "
                     f"证明 {dep.get('system')!r}")

    # ---- 2) 指纹与阈值逐字段相等（「三者一致」） ----
    pairs = (("vk_sha256", "model_vkey"), ("onnx_sha256", "onnx_sha256"),
             ("threshold_bp", "threshold_bp"), ("direction", "direction"))
    for ck, dk in pairs:
        if companion.get(ck) != dep.get(dk):
            return _fail(f"{ck} 与证明公开值里的 {dk} 不符："
                         f"证书 {companion.get(ck)!r} vs 证明 {dep.get(dk)!r}")

    # ---- 3) 证明文件本身 ----
    pf = companion.get("proof_file")
    if not isinstance(pf, str) or not pf:
        return _fail("证书没有指明陪伴证明文件（semantic.companions[].proof_file）")
    # 只取 basename：证书不得借路径逃逸到 artifacts_dir 之外去读任意文件。
    proof_path = d / Path(pf).name
    if not proof_path.exists():
        return _fail(f"找不到陪伴证明 {proof_path}")
    got_sha = hashlib.sha256(proof_path.read_bytes()).hexdigest()
    if got_sha != companion.get("proof_sha256"):
        return _fail(f"陪伴证明的 sha256 与证书承诺的不符：\n  文件 {got_sha}\n"
                     f"  证书 {companion.get('proof_sha256')}")

    # ---- 4) ezkl 验证明 ----
    #
    # srs 只在**真的要跑** ezkl 验证器时才必需：它是验证器算配对的参数表，本函数
    # 其余几步一个字节都不用它。把它列成无条件必需品会让「只核绑定、不跑验证器」
    # 的调用方（单测、离线审计）被 32 MB 的可选工件卡住，而那种卡顿只会诱使人们
    # 去删掉这条检查 —— 不如把条件写清楚。
    vk, settings, srs = (d / ARTIFACT_NAMES["vk"], d / ARTIFACT_NAMES["settings"],
                         d / ARTIFACT_NAMES["srs"])
    for p in (vk, settings, *((srs,) if verify_proof else ())):
        if not p.exists():
            return _fail(f"缺少 {p}（陪伴证明的验证材料）")
    # vk 的哈希必须等于被委托约束承诺的那个 —— 否则「同一个模型」只是一句话。
    got_vk = hashlib.sha256(vk.read_bytes()).hexdigest()
    if got_vk != dep.get("model_vkey"):
        return _fail(f"验证钥匙与约束承诺的不符：\n  本地 {got_vk}\n"
                     f"  承诺 {dep.get('model_vkey')}")
    # 设置文件的口径必须正确（input_scale=1 / logrows 够大）。理由见模块 docstring：
    # 一个 input_scale 不对的设置文件会让语义规则**静默失效**，而证明照样验证通过。
    try:
        check_settings_file(settings)
    except SemanticError as exc:
        return _fail(f"设置文件口径不合规：{exc}")

    if verify_proof:
        try:
            import ezkl
        except Exception as exc:  # pragma: no cover - 取决于环境
            return _fail(f"验证陪伴证明需要 ezkl，但导入失败：{exc}\n"
                         f"（语义规则的陪伴证明**必须**用 ezkl 验证器核 —— "
                         f"缺了它就只能相信出证方转述的分数，那是 P0-1 的形态）")
        ok = ezkl.verify(proof_path=str(proof_path), settings_path=str(settings),
                         vk_path=str(vk), srs_path=str(srs))
        if not ok:
            return _fail("ezkl 验证明失败")

    # ---- 5) 公开实例与送达响应绑定 ----
    w = input_width()
    instances = read_instances(proof_path)
    if len(instances) < w + 1:
        return _fail(f"公开实例只有 {len(instances)} 个，放不下 {w} 个输入 + 1 个输出")
    try:
        check_bound_to_response(instances, response, w)
    except SemanticError as exc:
        return _fail(str(exc))

    # ---- 6) 阈值判定 ----
    cfg = json.loads(Path(settings).read_text(encoding="utf-8"))
    scale = 2 ** int(cfg["model_output_scales"][0])
    score_bp = score_bp_of_instances(instances, scale)
    hits = threshold_holds(score_bp, int(dep["threshold_bp"]), str(dep["direction"]))
    base = (f"score={score_bp} bp {dep['direction']} {dep['threshold_bp']} bp；"
            f"输入 == encode(T′) ✓；vk/onnx/阈值与公开值逐字段相符 ✓")
    if not hits:
        # **证明是真的，规则没过** —— `ok` 仍为 True（这是一张可信的证据，
        # 只是它记录的是违规）。把 satisfaction 交给调用方写在「合规」一栏里。
        return True, f"{base} — ⚠ 语义规则**未满足**", False
    return True, base, True


def companion_entry(rule_name: str, proof_path: Path | str, artifacts_dir: Path | str,
                    dep: Dict[str, Any]) -> Dict[str, Any]:
    """构造证书里 ``semantic.companions[]`` 的一项（出证方用）。

    只记**指纹与文件名**，不内嵌 40 KB 的证明体：证明是独立工件，证书承诺它的
    sha256（与 ``binding.proof_sha256`` 对 SP1 证明的做法一致）。
    """
    d = Path(artifacts_dir)
    proof_path = Path(proof_path)
    return {
        "rule": rule_name,
        "system": SEMANTIC_SYSTEM_EZKL,
        "vk_sha256": hashlib.sha256((d / ARTIFACT_NAMES["vk"]).read_bytes()).hexdigest(),
        "onnx_sha256": dep["onnx_sha256"],
        "threshold_bp": dep["threshold_bp"],
        "direction": dep["direction"],
        # 只存文件名：验证方在 artifacts_dir 下按 basename 找，杜绝路径逃逸。
        "proof_file": proof_path.name,
        "proof_sha256": hashlib.sha256(proof_path.read_bytes()).hexdigest(),
    }


def input_width() -> int:
    """公开实例里**输入部分的长度**（= 图上限 ``MAX_CHARS``）。

    注意它**恒等于** ``MAX_CHARS``，与响应实际多长无关 —— :func:`encode_ids` 总会
    右补 PAD 到定长。所以「实例里前几个是输入」这句话里的「几个」是个常数，读
    ``len(encode(T))`` 去推它虽然碰巧也对，但会把「定长补位」这件事藏起来。
    """
    from semantic import features as F

    return int(F.MAX_CHARS)


def encode_ids(text: str, max_chars: int | None = None) -> List[int]:
    """拿响应 ``T`` 重算字符 id 序列 —— 验证方核对公开实例时调它。

    实现直接转发给 ``semantic.features.encode``（全仓库唯一的编码真相源），
    刻意**不在这里复制一份**：两份编码实现必然漂移，而漂移的表现是「验证方算出的
    id 与证明方喂进去的不一致」，那种 bug 极难定位。
    """
    from semantic import features as F     # 模块级 import 是纯标准库，torch 延迟加载

    if max_chars is None:
        return list(F.encode(text))
    return list(F.encode(text, max_chars=max_chars))


def check_bound_to_response(instances: Sequence[float], text: str,
                            max_chars: int | None = None) -> None:
    """核对 ezkl 公开实例里的**输入部分**是否就是 ``encode(T)``（信任边界 ③）。

    ``instances`` 是 ezkl 见证/证明里的 ``instances``（定点整数，``input_scale = 1``
    时**就是** id 本身）。只核前 ``max_chars`` 个；其余是输出（分数），由调用方核。

    不匹配抛 :class:`SemanticError` —— 这正是「换一个响应去复用别人的证明」要挡的。
    """
    want = encode_ids(text, max_chars)
    n = len(want)
    if len(instances) < n:
        raise SemanticError(
            f"公开实例只有 {len(instances)} 个，放不下 {n} 个字符 id —— 证明与模型不匹配")
    got = [int(round(float(v))) for v in instances[:n]]
    if got != want:
        first = next((i for i in range(n) if got[i] != want[i]), None)
        raise SemanticError(
            f"公开实例的输入部分与 encode(T) 不符（首处差异在下标 {first}："
            f"实例 {got[first] if first is not None else None} vs "
            f"期望 {want[first] if first is not None else None}）——"
            f"语义规则的输入必须与响应绑定（信任边界 ③）")
