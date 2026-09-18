"""按 ``--model`` 规格构造**真实**的 LangChain 聊天模型。

规格形如 ``openai:gpt-4o-mini`` / ``anthropic:claude-sonnet-5``；裸名
（``gpt-4o-mini``）按 openai 处理 —— OpenAI 兼容端点是最常见的那种。

为什么单独一个模块
------------------
证书层与模型无关（证书绑的是**一条具体的响应 T**，换模型只动适配器层），
但「换模型」这一步本身有三个真模型一上来就会踩的口子，都在这里堵：

1. **缺依赖**：没装 ``langchain_openai`` 时给一句能照着做的提示，
   而不是让 ``ImportError`` 从三层调用栈底下冒出来；
2. **缺 key**：同上 —— ``OPENAI_API_KEY`` / ``ANTHROPIC_API_KEY`` 没配时
   直接说是哪一个没配（并指出 ``OPENAI_API_BASE`` / ``OPENAI_BASE_URL``
   可指向自备端点），而不是等 SDK 在第一次请求时抛一个不含上下文的
   ValidationError；
3. **缺省必须是 fake**：CI 与 ``demo_all.sh`` 不能依赖网络与 key，
   所以本模块**只在显式给了 ``--model`` 时**才被调用（见
   ``scripts/demo/demo_e2e.py``）。「没传参数」与「传了参数但构造失败」是
   两件不同的事：前者走离线桩，后者**报错**，绝不静默退回桩 ——
   静默退回会让一份「真模型演示」的产物其实来自写死的字符串。

``ANTHROPIC_AUTH_TOKEN`` / ``ANTHROPIC_BASE_URL`` 是 Claude Code 自己的凭据，
本模块**刻意不认**：演示的真模型调用应该用使用者显式配的 key。
"""

from __future__ import annotations

import os
from typing import Any, Mapping, Optional, Tuple

#: 认识的两家。其余一律报错 —— 猜一个 provider 比拒绝更糟。
PROVIDERS = ("openai", "anthropic")

#: 各家认的环境变量（key、可选的自备端点）。
_ENV_KEY = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}
#: 自备端点的**候选变量名，按优先级排列** —— 顺序即真实请求的优先级。
#:
#: ``openai`` 有两个名字，这不是冗余：``OPENAI_API_BASE`` 是 ``langchain_openai``
#: 自己认的（它的 ``base_url_env``），``OPENAI_BASE_URL`` 是底层 ``openai`` SDK
#: 认的（LC 没解析出 base_url 时才轮到 SDK 去读）。**实测**（构造真客户端后读它
#: 真正会用的 ``base_url``）：两个都设时用 ``OPENAI_API_BASE``，只设一个时用那个，
#: 都不设则打官方端点。
#:
#: 为什么必须两个都认：只认一个的话，用另一个配置自备端点时 ``describe()`` 会
#: **静默不报端点** —— 而那行摘要存在的全部意义就是让读产物的人不必猜这次生成
#: 打到了哪里。
_ENV_BASE = {"openai": ("OPENAI_API_BASE", "OPENAI_BASE_URL"),
             "anthropic": ("ANTHROPIC_BASE_URL",)}
#: 安装提示里的包名
_PKG = {"openai": "langchain-openai", "anthropic": "langchain-anthropic"}


class ModelSpecError(RuntimeError):
    """``--model`` 规格不认识、依赖没装、或 key 没配 —— 一律给得出下一步。"""


def parse_spec(spec: str) -> Tuple[str, str]:
    """把 ``--model`` 规格拆成 ``(provider, model_name)``。

    裸名按 openai 处理（``"gpt-4o-mini"`` → ``("openai", "gpt-4o-mini")``）；
    显式写法是 ``"provider:model"``。空模型名、未知 provider 都抛
    :class:`ModelSpecError`。
    """
    text = (spec or "").strip()
    if not text:
        raise ModelSpecError("--model 是空的；给个规格，如 openai:gpt-4o-mini")
    provider, sep, name = text.partition(":")
    if not sep:
        provider, name = "openai", text  # 裸名 → openai（兼容端点最常见）
    provider = provider.strip().lower()
    name = name.strip()
    if provider not in PROVIDERS:
        raise ModelSpecError(
            f"不认识的 provider '{provider}'；支持 {', '.join(PROVIDERS)}"
            f"（裸名按 openai 处理），例如 openai:gpt-4o-mini")
    if not name:
        raise ModelSpecError(f"provider '{provider}' 后面没写模型名，如 {provider}:<model>")
    return provider, name


def effective_base(provider: str, env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """这个 provider 真正会生效的自备端点（没配就是 ``None``）。

    按 :data:`_ENV_BASE` 里的顺序取**第一个设了的** —— 那个顺序是实测出来的真实
    优先级，不是猜的（见该常量的注释）。``env`` 只为测试可注入，缺省读进程环境。
    """
    source = os.environ if env is None else env
    for var in _ENV_BASE[provider]:
        value = source.get(var)
        if value:
            return value
    return None


def describe(spec: str) -> str:
    """给终端一行摘要用的规格描述（不改规格本身，只做规范化）。

    带上**真正生效**的自备端点：这行字的作用就是让读产物（或看终端）的人不必去
    猜这次生成打到了哪里 —— 报一个不生效的端点，比不报更糟。
    """
    provider, name = parse_spec(spec)
    base = effective_base(provider)
    return f"{provider}:{name}" + (f" @ {base}" if base else "")


def _require_env(provider: str) -> None:
    """key 没配就当场说清楚 —— 别等 SDK 在第一次请求时抛。"""
    var = _ENV_KEY[provider]
    if not os.environ.get(var):
        hint = ""
        if provider == "openai":
            names = " / ".join(_ENV_BASE[provider])
            hint = (f"（要接自备端点，另设 {names}；"
                    "自建/本地端点也要给一个占位 key）")
        raise ModelSpecError(
            f"用 {provider}: 需要环境变量 {var}，当前没配{hint}。"
            f"不想用真模型就别传 --model —— 缺省是离线桩，不需要 key。")


def build_chat_model(spec: str, *, streaming: bool = True,
                     temperature: float = 0.0, **kwargs: Any) -> Any:
    """按规格构造一个真实的 LangChain ``BaseChatModel``。

    ``streaming=True`` 让 provider 侧也走增量返回（``stream_usage`` 之类各家
    自便）—— 回调层的 ``on_llm_new_token`` 靠的是 ``BaseChatModel.stream()``
    自己逐个 chunk 派发，与这个开关无关；这里开着只是别让传输层先攒成一坨。

    抛出的一律是 :class:`ModelSpecError`（消息里带下一步该做什么）。
    """
    provider, name = parse_spec(spec)
    _require_env(provider)

    if provider == "openai":
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as exc:  # pragma: no cover - 取决于环境
            raise ModelSpecError(
                f"没装 {_PKG[provider]}：pip install {_PKG[provider]}"
                f"（或跑 bash scripts/ops/install_frameworks.sh）") from exc
        return ChatOpenAI(model=name, temperature=temperature,
                          streaming=streaming, **kwargs)

    try:
        from langchain_anthropic import ChatAnthropic
    except ImportError as exc:  # pragma: no cover - 取决于环境
        raise ModelSpecError(
            f"没装 {_PKG[provider]}：pip install {_PKG[provider]}"
            f"（或跑 bash scripts/ops/install_frameworks.sh）") from exc
    return ChatAnthropic(model=name, temperature=temperature,
                         streaming=streaming, **kwargs)
