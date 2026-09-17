"""zk-policy · Proof-of-Policy 的 DSL 工具链。

链外（Python，仅标准库）层：编写策略、把策略编译成 ConstraintSpec JSON、
对响应做参考评估。``circuits/`` 里的 Rust/SP1 层在 zkVM 内证明编译后的约束。

实现按职责分六个子包，各自有一个只写文档字符串的 ``__init__.py``
（**不 re-export**，避免两条 import 路径）：

- :mod:`policydsl.core`      策略 DSL 与 golden 判定
- :mod:`policydsl.privacy`   私有模式原语（承诺 / 挑战）
- :mod:`policydsl.evidence`  证书、密钥、回执链、锚定、核验
- :mod:`policydsl.proofs`    出证编排（组合 / 会话 / 多证明者 / 语义 / ezkl）
- :mod:`policydsl.adapters`  框架适配（**唯一**允许带可选第三方依赖的子包）
- :mod:`policydsl.runtime`   常驻出证服务

子包之间只走绝对导入（``from policydsl.core.model import Rule``）。**本模块的
门面是稳定的**：``from policydsl import Policy`` 这类用法不随内部搬家而变。
"""

__version__ = "0.1.0"

# 从各子包 re-export 常用符号，方便 `from policydsl import Policy` 等用法
from policydsl.core.model import (  # noqa: F401
    Policy, Rule, Transcript, Violation, CheckResult, PolicyError,
    DelegatedConstraint,
)
from policydsl.core.compile import (  # noqa: F401
    compile_policy, SPEC_VERSION, require_covering_length_bound,
)
from policydsl.core.evaluate import check  # noqa: F401
from policydsl.evidence.trace import (  # noqa: F401
    ToolGateway, ToolReceipt, ToolSeal, verify_chain, verify_seal,
)

__all__ = [
    "Policy", "Rule", "Transcript", "Violation", "CheckResult",
    "PolicyError", "DelegatedConstraint",
    "compile_policy", "SPEC_VERSION", "require_covering_length_bound", "check",
    "ToolGateway", "ToolReceipt", "ToolSeal", "verify_chain", "verify_seal",
]
