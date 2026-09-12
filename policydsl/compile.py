"""把 Policy 编译成可序列化的 ConstraintSpec（prover 侧契约）。

ConstraintSpec 是 SP1 程序（W4+）实际消费的数据结构。Python 层同时保留一份
参考评估实现（``evaluate.py``），这样电路内的判定逻辑可以与这份编译器输出
做交叉校验（cross-check）。

ConstraintSpec 结构::

    {
      "spec_version": "v1",
      "policy_id": "...", "policy_version": "...", "semantic": "and",
      "constraints": [
        {"kind": "keyword_block", "name": "...", "keywords": ["a", "b", ...]},
        {"kind": "length_bound",  "name": "...", "min": 1, "max": 2000},
        {"kind": "pattern_block", "name": "...", "patterns": [...], "nfa": {...}},
        ...
      ],
      "sha256": "..."   # 稳定字段的哈希，用于来源绑定（provenance binding）
    }
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

from . import nfa
from .model import Policy, PolicyError, Rule

SPEC_VERSION = "v1"


#: 参与规范哈希的「契约主体」字段（不含随序列化方式变化的元信息，如 sha256 自身）。
STABLE_KEYS = ("spec_version", "policy_id", "policy_version", "semantic", "constraints")


def canonical_spec_bytes(spec: Dict[str, Any]) -> bytes:
    """把 ConstraintSpec 序列化为**规范 JSON 字节** —— 跨层唯一真相源。

    规范 = 键排序 + 紧凑分隔符 + UTF-8。Rust/SP1 侧把这段字节整段读入，
    **同时**用它派生 ``policy_hash`` 与解析要判定的约束，二者因此不可分离：
    证明者无法一边用空策略（恒通过）判定、一边声称哈希对应真实策略。

    ``ensure_ascii`` 保持默认 True（与 :func:`_canonical_hash` 一致），
    产出纯 ASCII，可安全地作为 UTF-8 文本跨进程/跨语言传递。
    """
    stable = {k: spec[k] for k in STABLE_KEYS}
    return json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_spec_text(spec: Dict[str, Any]) -> str:
    """:func:`canonical_spec_bytes` 的文本形式（写进 vectors.json 用）。

    因为规范字节是纯 ASCII，``decode("utf-8")`` 与再次 ``encode("utf-8")``
    是恒等变换 —— 电路侧算出的哈希因此与本模块的逐字节相同。
    """
    return canonical_spec_bytes(spec).decode("utf-8")


def _canonical_hash(obj: Dict[str, Any]) -> str:
    """对契约主体做「规范化哈希」：按键排序、紧凑分隔符后求 SHA-256。

    规范化（canonical）保证：只要语义内容相同，无论键的插入顺序如何，
    得到的哈希都一致 —— 这是证书中 policy_hash 可被独立重算的前提。
    """
    return hashlib.sha256(canonical_spec_bytes(obj)).hexdigest()


def _semantic_constraint(rule: "Rule") -> Dict[str, Any]:
    """把 ``semantic_bound`` 规则编译成约束，**固化模型指纹**（P2-9 §9.4）。

    模型指纹（``onnx_sha256`` / ``model_vkey``）在这里被**写进约束**，从而进入
    ``policy_hash``。这是信任边界 ① 的落地形式：策略一旦编译，它承诺的就是
    **某一个具体的图**；换一张图（哪怕只改一点权重）都会让 policy_hash 变，
    旧证明立刻对不上。

    两种情况：

    - 策略**显式写了**指纹：必须与仓库里的模型一致，否则编译期失败。这挡的是
      「用另一个模型去证这条策略」——不挡的话，攻击者只要拿一个「恒判安全」的
      模型出证，而验证方核的还是策略里那串哈希，两边各说各话。
    - 策略**没写**：从仓库里的模型现场解析并固化。作者不必手抄 sha256；代价是
      策略包本身不自足（换机器要先有同一份模型才能重编译），这一点如实记在
      ``docs/design-semantic-rules.md``。
    """
    from . import semantic as sem

    manifest = sem.model_manifest()
    for key, actual in (("onnx_sha256", manifest["onnx_sha256"]),
                        ("model_vkey", _model_vkey())):
        want = rule.params.get(key)
        if want is not None and want != actual:
            raise PolicyError(
                f"rule '{rule.name}': 策略里写死的 {key} 与仓库里的模型不一致\n"
                f"  策略 {want}\n  实际 {actual}\n"
                f"（这条检查挡的是「拿另一个模型去证这条策略」）")
    return {
        "kind": "semantic_bound",
        "name": rule.name,
        "model_vkey": rule.params.get("model_vkey") or _model_vkey(),
        "onnx_sha256": rule.params.get("onnx_sha256") or manifest["onnx_sha256"],
        "threshold_bp": int(rule.params["threshold_bp"]),
        "direction": rule.params["direction"],
    }


def _model_vkey() -> str:
    """ezkl 验证钥匙的指纹 = ``semantic/artifacts/vk.ezkl`` 的 sha256。

    少了它，约束只能承诺「模型是这一张」，承诺不了「证明是由这个电路出的」——
    而恰好是后者把整张图（含特征投影表）唯一确定了。
    """
    from . import semantic as sem

    p = sem.model_dir() / "artifacts" / sem.ARTIFACT_NAMES["vk"]
    if not p.exists():
        raise PolicyError(
            f"缺少 {p} —— 语义规则需要 ezkl 的验证钥匙指纹。"
            f"先跑 `python3 scripts/ezkl_prove.py setup` 生成它")
    return hashlib.sha256(p.read_bytes()).hexdigest()


def require_covering_length_bound(policy: Policy) -> None:
    """含语义规则的策略**必须**再含一条覆盖它的 ``length_bound``（P2-9 v1 边界）。

    为什么这是硬要求：特征图是**定长**的（``MAX_CHARS``）。超长响应若被静默
    截断，那么「第 ``MAX_CHARS`` 个字符之后的内容」就完全没被判定，而证明照样
    有效 —— 攻击者只要把有害内容放在尾部就能绕过语义规则。所以：

    - **截断被禁止**（``semantic.features.encode`` 超长直接报错）；
    - 于是策略必须自己声明长度上界 ``max <= MAX_CHARS``，把「合法输入的最大长度」
      与图的容量**对齐**。这样任意合法输入都必然被完整判定。

    缺了它，语义规则在**任何**超长响应上都判不了（encode 会报错），策略实际上
    是残缺的 —— 与其等到出证时才炸，不如编译期就说清楚。
    """
    from . import semantic as sem

    if not any(r.kind == "semantic_bound" for r in policy.rules):
        return
    width = sem.input_width()
    lens = [r for r in policy.rules if r.kind == "length_bound"]
    if not lens:
        raise PolicyError(
            f"含语义规则的策略必须同时含一条 length_bound，且 max <= {width}"
            f"（特征图是定长的；超长响应会被拒绝而不是截断，没有这条上界策略就"
            f"无法处理长响应）")
    if not any(int(r.params["max"]) <= width for r in lens):
        worst = min(int(r.params["max"]) for r in lens)
        raise PolicyError(
            f"语义规则要求至少一条 length_bound 的 max <= {width}（图的字符上限），"
            f"而策略里最小的 max 是 {worst} —— 超长响应会让语义规则判不了")


def compile_policy(policy: Policy) -> Dict[str, Any]:
    """把 Policy 编译为 ConstraintSpec 字典（含 sha256 绑定哈希）。

    流程：先校验策略 → 逐条规则映射为规范化的约束表示 → 计算稳定字段哈希。
    关键词/字段/工具名在编译期就做排序去重与小写化，保证跨层一致性。
    """
    policy.validate()
    require_covering_length_bound(policy)   # 语义规则的定长图边界（见该函数）
    constraints: list[Dict[str, Any]] = []
    for rule in policy.rules:
        if rule.kind == "keyword_block":
            # 关键词：排序去重 + 小写化，规避大小写/顺序差异导致的哈希漂移
            constraints.append({
                "kind": "keyword_block",
                "name": rule.name,
                "keywords": sorted({str(w).lower() for w in rule.params["keywords"]}),
            })
        elif rule.kind == "length_bound":
            # 长度边界：直接转 int（策略 JSON 里可能混入字符串形式的数字）
            constraints.append({
                "kind": "length_bound",
                "name": rule.name,
                "min": int(rule.params["min"]),
                "max": int(rule.params["max"]),
            })
        elif rule.kind == "pattern_block":
            # 把每条正则编译成可序列化的 NFA（跨层契约）。
            # 不支持的语法在编译期即快速失败，避免进入证明阶段才报错。
            pats = [str(p) for p in rule.params["patterns"]]
            specs = []
            for p in pats:
                try:
                    specs.append(nfa.compile_pattern(p))
                except nfa.RegexSyntaxError as exc:
                    raise PolicyError(
                        f"rule '{rule.name}': pattern {p!r} not supported by the "
                        f"NFA compiler ({exc})") from exc
            c = {
                "kind": "pattern_block",
                "name": rule.name,
                "patterns": pats,
                "nfa": {"compiled": specs},
            }
            # 只有显式声明 naive 才记录；缺省走 pike（电路内默认模式）
            if rule.params.get("match_mode") == "naive":
                c["mode"] = "naive"
            constraints.append(c)
        elif rule.kind == "format_check":
            # 格式校验：把声明格式透传给约束
            constraints.append({
                "kind": "format_check",
                "name": rule.name,
                "format": rule.params["format"],
            })
        elif rule.kind == "tool_arg_guard":
            # 工具参数防护：被禁字段排序去重；可选 tools 白名单也排序去重
            c = {
                "kind": "tool_arg_guard",
                "name": rule.name,
                "forbidden_fields": sorted(set(rule.params["forbidden_fields"])),
            }
            if rule.params.get("tools"):
                c["tools"] = sorted(set(rule.params["tools"]))
            constraints.append(c)
        elif rule.kind == "budget_bound":
            # 预算边界：记录上限值与计量单位
            constraints.append({
                "kind": "budget_bound",
                "name": rule.name,
                "budget": int(rule.params["budget"]),
                "unit": rule.params.get("unit", "calls"),
            })
        elif rule.kind == "semantic_bound":
            constraints.append(_semantic_constraint(rule))
        else:
            # 未知/未实现类型：打 stub 标记，说明参考评估器尚未实现
            constraints.append({
                "kind": rule.kind,
                "name": rule.name,
                "stub": True,
                "note": "not yet implemented in the reference evaluator",
            })

    # 稳定字段：参与哈希的「契约主体」，不含会随序列化方式变化的元信息
    stable = {
        "spec_version": SPEC_VERSION,
        "policy_id": policy.id,
        "policy_version": policy.version,
        "semantic": policy.semantic,
        "constraints": constraints,
    }
    spec = dict(stable)
    spec["sha256"] = _canonical_hash(stable)  # 绑定哈希：证书据此校验策略一致性
    return spec
