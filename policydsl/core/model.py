"""策略 DSL 的核心数据模型（Policy DSL core data model）。

本模块定义了 Proof-of-Policy 的策略领域模型：规则（Rule）、策略（Policy）、
违规（Violation）、判定结果（CheckResult），以及用于结构化评估的输入
（ToolReceipt / Transcript）。整个 Python 参考层都围绕这些数据结构展开。

工具轨迹以**网关签发的回执链**表示（P1-5）：``Transcript.receipts`` 的元素类型
是 :class:`policydsl.evidence.ToolReceipt` —— 这里不重复定义，只在需要时做
``TYPE_CHECKING`` 导入，免得两个模块互相 import。

规则类型（Rule kinds，阶段一范围）：
  keyword_block : 响应文本不得包含列出的任意关键词/短语
  length_bound  : 响应字符长度必须落在 [min, max] 区间内
  pattern_block : 响应文本不得匹配列出的任意正则模式
  format_check  : 响应必须能按声明的格式（json/int/float）解析
  tool_arg_guard: 工具调用的参数不得包含被禁止的字段
  budget_bound  : 累计调用/令牌预算必须满足上限
  semantic_bound: 语义规则（P2-9）—— 响应经**确定性特征图 + 训练好的 head**
                  算出的分数必须越过/低于阈值。**由 ezkl 承担证明**，SP1 电路
                  只登记委托（见 ``docs/design-semantic-rules.md``）
  normalized_keyword_block : keyword_block 的规范化版本（P2-9b）—— 先按约束里
                  **自带**的折叠表把响应折叠（同形异义字 → ASCII、删零宽字符、
                  全角 → 半角），再做同样的子串判定。折叠在电路内完成，见
                  ``policydsl/core/normalize.py``

Python 层是「参考语义」（reference semantics）：单测与 SP1 程序都以它为目标。
``compile()`` 把 Policy 编译成 ConstraintSpec（JSON），后者是与电路内 prover
之间的唯一契约。

内容类规则（keyword/pattern/length/format）判定自由文本 ``response``；
``tool_arg_guard`` / ``budget_bound`` 判定结构化 ``Transcript``
（P1-5 起其轨迹部分是**网关签发的回执链**，见 ``evaluate.check``）。
"""


from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

from policydsl.core import normalize  # 只用标准库，无循环导入风险（见 normalize 模块 docstring）

if TYPE_CHECKING:  # 只用于类型标注：避免 model ↔ trace 的循环导入
    from policydsl.evidence.trace import ToolReceipt


class PolicyError(ValueError):
    """策略包（policy pack）格式非法时抛出的异常。

    继承自 ValueError，便于上层统一捕获策略解析/校验阶段的错误。
    """


# ============================================================
# Rule 参数校验：每种 kind 一个函数，由下面的 _RULE_VALIDATORS 分派。
#
# 做法与 ``policydsl/proofs/multiparty.py`` 的 ``KIND_OWNER`` 相同 —— 一张显式的
# 模块级表 + 若干小函数，不引入注册框架。这么拆的好处有二：
#   * Rule.validate 是策略包的入口闸门（手写 Policy / 测试 / 脚本都走它），
#     可读性直接决定出错定位速度；
#   * 新增一种 kind 时只动「写一个函数 + 表里加一行」两处，不牵扯入口逻辑。
#
# **报错文案是诊断契约**（上层按 `PolicyError` 捕获并展示），所以每条 message
# 都与拆分前逐字一致，一个字都不改。
# ============================================================


def _validate_keyword_block(rule: "Rule") -> None:
    """关键词规则：keywords 必须是非空字符串列表。"""
    words = rule.params.get("keywords")
    if not isinstance(words, list) or not words:
        raise PolicyError(f"rule '{rule.name}': keyword_block needs non-empty 'keywords'")
    if not all(isinstance(w, str) for w in words):
        raise PolicyError(f"rule '{rule.name}': keywords must be strings")


def _validate_normalized_keyword_block(rule: "Rule") -> None:
    """规范化关键词规则（P2-9b）：keywords 与 keyword_block 同形，
    外加一个 fold 声明（预设名，或显式折叠表）。

    校验放在**这里**而不是只放在 compile 里：Rule.validate 是策略包的入口闸门，
    手写的 Policy（测试、脚本）也走它。折叠表非法 = 语义未定，必须编译期快速失败，
    绝不能带着一张「读不懂的表」出证。
    """
    words = rule.params.get("keywords")
    if not isinstance(words, list) or not words:
        raise PolicyError(
            f"rule '{rule.name}': normalized_keyword_block needs non-empty 'keywords'")
    if not all(isinstance(w, str) for w in words):
        raise PolicyError(f"rule '{rule.name}': keywords must be strings")
    if not all(words):
        raise PolicyError(
            f"rule '{rule.name}': keywords must be non-empty strings"
            f"（空串是任意文本的子串，该规则会恒真命中）")
    try:
        normalize.resolve_fold(rule.params.get("fold", normalize.DEFAULT_PRESET))
    except normalize.FoldError as exc:
        raise PolicyError(f"rule '{rule.name}': bad 'fold': {exc}") from exc


def _validate_length_bound(rule: "Rule") -> None:
    """长度规则：min/max 必须是整数，且 0 <= min <= max。"""
    lo, hi = rule.params.get("min"), rule.params.get("max")
    if not (isinstance(lo, int) and isinstance(hi, int) and 0 <= lo <= hi):
        raise PolicyError(f"rule '{rule.name}': length_bound needs ints 0 <= min <= max")


def _validate_pattern_block(rule: "Rule") -> None:
    """正则规则：patterns 必须非空；可选 match_mode 只能是 pike/naive。"""
    pats = rule.params.get("patterns")
    if not isinstance(pats, list) or not pats:
        raise PolicyError(f"rule '{rule.name}': pattern_block needs non-empty 'patterns'")
    mm = rule.params.get("match_mode")
    if mm is not None and mm not in ("pike", "naive"):
        raise PolicyError(
            f"rule '{rule.name}': match_mode must be 'pike' or 'naive', got {mm!r}")


def _validate_format_check(rule: "Rule") -> None:
    """格式规则：format 只能是 json/int/float 之一。"""
    fmt = rule.params.get("format")
    if fmt not in ("json", "int", "float"):
        raise PolicyError(
            f"rule '{rule.name}': format_check needs format in {{json,int,float}}, got {fmt!r}")


def _validate_tool_arg_guard(rule: "Rule") -> None:
    """工具参数规则：forbidden_fields 必须非空且全为字符串；
    可选的 tools 若存在必须是字符串列表（用于限定只约束哪些工具）。
    """
    fields = rule.params.get("forbidden_fields")
    if not isinstance(fields, list) or not fields or not all(
        isinstance(f, str) for f in fields
    ):
        raise PolicyError(
            f"rule '{rule.name}': tool_arg_guard needs non-empty 'forbidden_fields' strings")
    tools = rule.params.get("tools")
    if tools is not None and (
        not isinstance(tools, list) or not all(isinstance(t, str) for t in tools)
    ):
        raise PolicyError(f"rule '{rule.name}': optional 'tools' must be a list of str")


def _validate_budget_bound(rule: "Rule") -> None:
    """预算规则：budget 是非负整数；unit 只能是 calls/tokens。"""
    budget = rule.params.get("budget")
    unit = rule.params.get("unit", "calls")
    if not isinstance(budget, int) or budget < 0:
        raise PolicyError(f"rule '{rule.name}': budget_bound needs int budget >= 0")
    if unit not in ("calls", "tokens"):
        raise PolicyError(f"rule '{rule.name}': budget_bound unit must be 'calls' or 'tokens'")


def _validate_semantic_bound(rule: "Rule") -> None:
    """语义规则：阈值（万分点）+ 方向必填；模型指纹可选。

    指纹**可选**是刻意的：多数策略作者只想说「有害概率不得超过 5%」，
    而不想手抄一串 sha256。缺省时由 compile 从仓库里的模型现场解析
    （`policydsl.proofs.model_manifest`）并**固化进约束** —— 一旦固化，
    模型再变就会导致 policy_hash 变、证明对不上。显式给出时则要求它与
    实际模型一致，否则编译期直接失败（「用另一个模型去证」必须报错）。
    """
    thr = rule.params.get("threshold_bp")
    if not isinstance(thr, int) or isinstance(thr, bool) or not (0 <= thr <= 10000):
        raise PolicyError(
            f"rule '{rule.name}': semantic_bound needs int 'threshold_bp' in [0,10000]"
            f"（万分点刻度，与 ezkl 公开实例同刻度），got {thr!r}")
    direction = rule.params.get("direction")
    if direction not in ("le", "ge"):
        raise PolicyError(
            f"rule '{rule.name}': semantic_bound needs 'direction' in {{'le','ge'}}, "
            f"got {direction!r}（le: 分数 <= 阈值；ge: 分数 >= 阈值）")
    for key in ("onnx_sha256", "model_vkey"):
        v = rule.params.get(key)
        if v is not None and not (isinstance(v, str) and v):
            raise PolicyError(
                f"rule '{rule.name}': optional '{key}' must be a non-empty string")


# kind → 校验函数。新增 kind 时在这张表里加一行
# （另需同步 evaluate.check / compile.compile_constraints，
#  tests/test_rule_kinds.py 会盯着这三处是否漂移）。
_RULE_VALIDATORS: Dict[str, Callable[["Rule"], None]] = {
    "keyword_block":            _validate_keyword_block,
    "normalized_keyword_block": _validate_normalized_keyword_block,
    "length_bound":             _validate_length_bound,
    "pattern_block":            _validate_pattern_block,
    "format_check":             _validate_format_check,
    "tool_arg_guard":           _validate_tool_arg_guard,
    "budget_bound":             _validate_budget_bound,
    "semantic_bound":           _validate_semantic_bound,
}


@dataclass
class Rule:
    """单条规则：由类型 kind、名字 name、参数字典 params 三部分组成。

    kind 决定规则的语义；params 携带该类型所需的参数（如关键词列表、
    长度上下界、正则列表等）。规则本身不包含判定逻辑，判定由
    ``evaluate.check``（参考层）与 SP1 程序（电路内）各自实现。
    """

    kind: str
    name: str
    params: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        """校验本规则的参数是否合法，非法则抛出 PolicyError。

        每种 kind 有各自的合法参数约束，逐类型分派到上面的 ``_validate_*``，
        做到「编译期快速失败」，避免非法策略进入后续编译/证明流程。
        """
        # 未知规则类型直接拒绝，防止拼写错误悄悄变成「无操作」。
        #
        # `isinstance(kind, str)` 这个前置判断不能省：策略包的 kind 来自 JSON
        # （Policy.from_dict 只查包的**形状**、不查字段类型，原样透传），而
        # JSON 的值可以是数组/对象。不可哈希的 kind 若直接喂给 dict.get 会抛
        # TypeError 绕过 PolicyError，让「畸形策略包」从可诊断的校验错误变成
        # 未捕获的崩溃 —— 逐值比较的写法没有这个问题，改用查表后必须显式防住。
        kind = self.kind
        validator = _RULE_VALIDATORS.get(kind) if isinstance(kind, str) else None
        if validator is None:
            raise PolicyError(f"rule '{self.name}': unknown kind '{self.kind}'")
        validator(self)

    def to_dict(self) -> Dict[str, Any]:
        """把规则序列化为可 JSON 化的字典。"""
        return {"kind": self.kind, "name": self.name, "params": self.params}


def _require_pack_shape(data: Any) -> None:
    """「这份 JSON 根本不像策略包」——一律报 :class:`PolicyError`，绝不漏内建异常。

    与 :meth:`Policy.validate` 分工：``validate`` 诊断的是**包格式对、内容有问题**
    （未知 kind、参数越界）；这里拦的是**连包都算不上**的四种形状。二者都用
    ``PolicyError``，于是「加载 + 校验」两段对所有调用方是**一个**异常类型 ——
    这正是把加载收敛成 :meth:`Policy.from_dict` 之后才可能做到的。

    为什么必须显式拦而不是「让它自己炸」。这些形状原先各自漏出内建异常：

    ==================  ==========================  ===================================
    形状                原先漏出的                  后果
    ==================  ==========================  ===================================
    顶层不是对象        ``TypeError``/``AttributeError``   ``[1,2,3]`` → ``'list' object has no attribute 'get'``
    缺 ``id``           ``KeyError: 'id'``          CLI 里无人接住 → 未捕获 traceback
    ``rules`` 不是数组  ``AttributeError``/``TypeError``  ``"oops"`` → 逐字符取 ``.get``
    规则项不是对象      ``AttributeError``          ``5`` → ``'int' object has no attribute 'get'``
    ==================  ==========================  ===================================

    四条的后果是同一条：**调用方的 ``except PolicyError`` 接不住**，于是一个
    「用户把包写错了」的诊断问题，表现成「工具崩了」（``policydsl -m compile``
    退出码 1 + 一坨 traceback，而不是退出码 2 + 一行 ``error: …``）。这是实测
    发现的 —— 见 ``docs/dev-plan.md`` §5.7.12 与验收快照的第 3 面。

    文案里**不带文件路径**：路径属于调用方（``_load_policy`` 那一层已经知道自己在读
    哪个文件），这里只描述包的形状，免得两处各拼一次路径、拼出两种写法。
    """
    if not isinstance(data, dict):
        raise PolicyError(
            f"policy pack must be a JSON object, got {type(data).__name__}")
    if "id" not in data:
        raise PolicyError("policy pack missing 'id'")
    if not isinstance(data["rules"], list):
        raise PolicyError(
            f"policy pack 'rules' must be a list, got {type(data['rules']).__name__}")
    for i, r in enumerate(data["rules"]):
        if not isinstance(r, dict):
            raise PolicyError(
                f"policy pack rule #{i} must be a JSON object, got {type(r).__name__}")


@dataclass
class Policy:
    """一个策略包：由若干规则组成，按语义组合判定。

    semantic 目前只支持 "and"（全部规则都要通过）；后续可扩展 or/优先级等。
    """

    id: str
    version: str
    description: str = ""
    rules: List[Rule] = field(default_factory=list)
    semantic: str = "and"  # "and"：每一条规则都必须通过

    def validate(self) -> None:
        """校验策略包本身及其全部规则。"""
        if not self.id or not self.version:
            raise PolicyError("policy needs 'id' and 'version'")
        if self.semantic != "and":
            raise PolicyError(f"unsupported semantic '{self.semantic}' (only 'and' for now)")
        for r in self.rules:
            r.validate()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Policy:
        """从**已解析**的策略包 JSON 建 :class:`Policy` —— 全仓唯一出处。

        「把策略包 JSON 读成 Policy」这个动作一度被抄成 **11 份**（R7）。它们长得
        很像，但**像不等于同**：规则名的兜底串一份写 ``f"r{i}"``、另一份写
        ``f"rule-{i}"``；``semantic`` / ``description`` 有的带、有的丢；``rules``
        有的用 ``data["rules"]``、有的用 ``data.get("rules", [])``。后果不是报错，
        是**同一个包被两份加载器编译出两个 ``policy_hash``** —— 出证方算一个、
        验证方算另一个，两边都自洽，证书在第三方手里才验不过。这与 R4 的驱动路径、
        R5 的工件摘要是同一类事故。

        **分层很干脆：形状在这里拦，内容交给下游。** 形状不对（顶层不是对象、缺
        ``id``、``rules`` 不是数组、规则项不是对象）由 :func:`_require_pack_shape`
        当场报 ``PolicyError``；内容不对（未知 kind、参数越界）留给 :meth:`validate`
        —— 它把 ``PolicyError`` 的文案写成了诊断契约（``tests/test_rule_kinds.py``
        专门钉着「畸形的 kind 必须是 ``PolicyError``，不能漏成 ``TypeError``」）。
        两段报的是同一个类型，所以调用方一个 ``except PolicyError`` 就接得住全部。

        * ``data["id"]`` —— **缺了当场报错**，不兜底成 ``""``。``id`` 是必填位置字段，
          没有它连对象都构造不出来；兜底会把「忘了写 id 的包」与「id 写成空串的包」
          压成同一件事，而后者 :meth:`validate` 能说清楚。
        * ``data["rules"]`` —— **缺了当场报错**，而不是 ``.get("rules", [])``。
          理由与 ``id`` 不同、值得写下来：``rules`` 缺键若静默当成 ``[]``，得到的
          是一条**合法的空策略**（``validate`` 允许空规则表），于是「一个什么都没
          声明的包」会被编译成「没有任何规则的约束」并出证 —— 那是 fail-open，
          下游**诊断不出来**，所以只能在这里拦。
        * ``r.get("kind", "")`` —— 与上两条相反，**缺 kind 不在这里炸**，留给
          :meth:`Rule.validate` 报 ``PolicyError: rule '…': unknown kind ''``。
          ``""`` 不是合法 kind，所以这不是 fail-open，只是把报错挪到说得更清楚的那一层
          —— 而它报的仍是 ``PolicyError``，调用方看不出区别。

        另两处：规则名兜底取 ``f"rule-{i}"``（与 ``policydsl.__main__`` 一致）——
        7 个随包发行的策略里每条规则都显式写了 ``name``，两种兜底**都没被走到**
        （见 ``docs/dev-plan.md`` §5.7.7）；``description`` 取包内声明，这是 R7 的
        **一处已声明归一**（11 份里 8 份丢成 ``''``）：这个字段存在就是为了承载包作者
        的声明，而 :class:`Policy` 的缺省值本就是 ``''``，**只有显式不传的加载器**
        才得到它 —— 丢是信息丢失，不是省略。``semantic`` 进 ``policy_hash``，
        11 份本来就一致。

        申报与对拍见 ``tests/test_loader_parity.py``（快照
        ``tests/loader_parity_baseline.json`` 采于收敛之前，**不重采**）。
        """
        _require_pack_shape(data)
        rules = [
            Rule(kind=r.get("kind", ""), name=r.get("name", f"rule-{i}"),
                 params=r.get("params", {}))
            for i, r in enumerate(data["rules"])
        ]
        return cls(id=data["id"], version=data.get("version", "0.1.0"),
                   description=data.get("description", ""), rules=rules,
                   semantic=data.get("semantic", "and"))


@dataclass
class Violation:
    """一次违规：记录触发了哪条规则，以及违规的证据。

    evidence 按 evidence_kind 不同携带不同内容：
    - keyword : 命中的关键词列表
    - length  : {"len", "min", "max"}
    - pattern : 命中的正则模式串
    - format  : {"format", "len"}
    - tool_arg: {"tool", "field"}
    - budget  : {"unit", "total", "budget"}
    """

    rule: Rule
    evidence_kind: str        # "keyword" | "length" | "pattern" | ...
    evidence: Any = None      # 命中项 / 边界 / 命中的模式等

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的字典（用于证书/验证产物）。"""
        return {
            "rule": self.rule.name,
            "kind": self.rule.kind,
            "evidence_kind": self.evidence_kind,
            "evidence": self.evidence,
        }


@dataclass
class DelegatedConstraint:
    """一条**被委托**给外部证明系统的约束（P2-9 的 ``semantic_bound``）。

    逐字段对应 ``pop_types::DelegatedConstraint``（Rust 侧）—— 两侧**必须同形**，
    否则「链下 golden 结论」与「电路公开值」就无法逐字段比对，而那正是
    ``tests/`` 里交叉校验的前提。

    语义：「这条约束**没有**被本次判定覆盖；需要另行合取一条陪伴证明（ezkl），
    其 ``model_vkey`` / ``onnx_sha256`` / ``threshold_bp`` / ``direction`` 必须与
    这里逐字段相等。」``passed`` 只反映电路/参考层**判得了**的那部分。
    """

    name: str
    system: str                # 当前恒为 "ezkl-halo2"，见 pop_types::SEMANTIC_SYSTEM_EZKL
    model_vkey: str
    onnx_sha256: str
    threshold_bp: int
    direction: str             # "le" | "ge"

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的字典（形状与 Rust 侧的 serde 输出一致）。"""
        return {
            "name": self.name,
            "system": self.system,
            "model_vkey": self.model_vkey,
            "onnx_sha256": self.onnx_sha256,
            "threshold_bp": self.threshold_bp,
            "direction": self.direction,
        }


@dataclass
class CheckResult:
    """一次判定结果：是否通过，以及（若不通过）违规列表与备注。

    passed 为 True 当且仅当 violations 为空（语义为 "and"）。

    **``delegated`` 非空时 ``passed`` 的含义要读准**：它只表示「本次判定覆盖到的
    那些约束都通过了」，而不是「策略被满足了」。见 :class:`DelegatedConstraint`。
    """

    passed: bool
    violations: List[Violation] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    delegated: List[DelegatedConstraint] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的字典。"""
        return {
            "passed": self.passed,
            "violations": [v.to_dict() for v in self.violations],
            "notes": self.notes,
            "delegated": [d.to_dict() for d in self.delegated],
        }


@dataclass
class Transcript:
    """用于参考评估的结构化输入。

    内容类规则（keyword/pattern/length/format）判定 ``response``；
    ``tool_arg_guard`` 判定 ``receipts`` 里各条回执的参数；``budget_bound``
    按 ``unit`` 判定回执条数（``calls``）或**按固定空白规则自算**的 token 数
    （``tokens``，见 :func:`policydsl.evidence.token_count`）。

    **P1-5**：原来的 ``tool_calls``/``token_count`` 两个字段已被移除 —— 它们是
    「证明者自填」的，判出来的结论没有任何东西拴着。回执必须由工具网关签发
    （:class:`policydsl.evidence.ToolGateway`）。
    """

    response: Optional[str] = None
    receipts: List["ToolReceipt"] = field(default_factory=list)
