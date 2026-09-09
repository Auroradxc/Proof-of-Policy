"""zk-policy · Proof-of-Policy DSL toolchain.

Off-circuit (Python, stdlib-only) layer: author policies, compile them to a
ConstraintSpec JSON, and reference-evaluate responses. The Rust/SP1 layer in
``circuits/`` proves the compiled constraints inside a zkVM.
"""

__version__ = "0.1.0"

from .model import (  # noqa: F401
    Policy, Rule, ToolCall, Transcript, Violation, CheckResult, PolicyError,
)
from .compile import compile_policy, SPEC_VERSION  # noqa: F401
from .evaluate import check  # noqa: F401

__all__ = [
    "Policy", "Rule", "ToolCall", "Transcript", "Violation", "CheckResult",
    "PolicyError",
    "compile_policy", "SPEC_VERSION", "check",
]
