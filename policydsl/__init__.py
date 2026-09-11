"""zk-policy · Proof-of-Policy 的 DSL 工具链。

链外（Python，仅标准库）层：编写策略、把策略编译成 ConstraintSpec JSON、
对响应做参考评估。``circuits/`` 里的 Rust/SP1 层在 zkVM 内证明编译后的约束。
"""

__version__ = "0.1.0"

# 从各子模块 re-export 常用符号，方便 `from policydsl import Policy` 等用法
from .model import (  # noqa: F401
    Policy, Rule, Transcript, Violation, CheckResult, PolicyError,
)
from .compile import compile_policy, SPEC_VERSION  # noqa: F401
from .evaluate import check  # noqa: F401
from .trace import ToolGateway, ToolReceipt, verify_chain  # noqa: F401

__all__ = [
    "Policy", "Rule", "Transcript", "Violation", "CheckResult",
    "PolicyError",
    "compile_policy", "SPEC_VERSION", "check",
    "ToolGateway", "ToolReceipt", "verify_chain",
]
