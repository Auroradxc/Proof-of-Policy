"""把 ConstraintSpec 打包成 SP1 驱动消费的 vectors 条目。

**历史注记（P0-1）**：本模块此前导出 ``spec_to_rust_constraints``，把约束转换成
serde「外部标签枚举」（``{"KeywordBlock": {...}}``）的 JSON。该设计有一个
**健全性漏洞**：电路侧收到的约束列表与证书里声称的 ``policy_hash`` 没有
任何共同来源 —— 证明者可以用空策略（恒通过）判定，再在证书里填上真实策略的
哈希，而验证方只做字符串比对，全部检查都会通过。

现在改为**传递规范 JSON 字节**（``spec_canonical``）：电路侧从这**同一段字节**
里同时派生 ``policy_hash`` 与解析要判定的约束。`pop-types::SpecConstraint` 用
serde 内部标签（``"kind"``）直接吃这份形状，因此不存在「两套序列化」的映射，
也就不存在映射带来的可分离性。

唯一真相源由 :func:`policydsl.compile.canonical_spec_bytes` 定义。
"""

from __future__ import annotations

from typing import Any, Dict, List

from .compile import canonical_spec_text


def spec_canonical_text(spec: Dict[str, Any]) -> str:
    """返回策略的规范 JSON 文本（写进 vectors 条目的 ``spec_canonical`` 字段）。

    这是 :func:`policydsl.compile.canonical_spec_text` 的再导出，保留在此模块
    是为了让所有 vectors 构造点从同一个地方取契约文本。
    """
    return canonical_spec_text(spec)


def vector_entry(spec: Dict[str, Any], response: str, **extra: Any) -> Dict[str, Any]:
    """构造一个 vectors 条目：``{name?, spec_canonical, response, ...}``。

    把「契约文本从哪来」收敛到一处，避免调用点各自拼装而写错字段名。
    """
    return {"spec_canonical": spec_canonical_text(spec), "response": response, **extra}


def build_vectors(entries: List[Dict]) -> Dict:
    """把 [{name, response, spec_canonical, ...}] 列表包装成 vectors 文件字典。"""
    return {"vectors": entries}
