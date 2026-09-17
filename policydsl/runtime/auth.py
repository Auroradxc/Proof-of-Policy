"""证明服务的鉴权与限流（``docs/dev-plan.md`` §5.2 的可选加固第一步）。

为什么单独一个模块、而不是塞进 ``scripts/proof_service.py``：这里判断的三件事
——「这个 token 对不对」「这个调用方读不读得了这个作业」「他还剩多少配额」——
都是**不需要 socket 就能测干净**的逻辑。塞进 handler 就只能靠起服务器、发真请求
来验证，而这几条恰恰是最该被穷举测的（错的鉴权不是「少一个功能」，是「看起来
有」）。``scripts/`` 那层只负责把这里的结论翻成状态码。

四条设计取舍，都是**明写**的：

1. **没配 token ≠ 放行，但也不假装有鉴权**。没配 token 时服务照常能起（本机演示
   不该被逼着先造密钥），但 ``/v1/health`` 里如实写 ``auth: "none"``、启动横幅
   打 ``⚠``。想在生产上强制要求，用 ``--require-auth`` —— 它在没配 token 时
   **拒绝启动**，而不是启动之后默默放行每一个人。

2. **认证失败返 401 并带 ``WWW-Authenticate: Bearer``**；而**作业不属于你，返
   404 而不是 403**。403 等于告诉调用方「这个 job_id 存在，只是不给你看」——
   那它就成了一个探测别家 job_id 的预言机。404 让「不存在」与「不是你的」在
   外部**不可区分**。

3. **比较用 ``hmac.compare_digest``，且不提前退出**。提前 ``return`` 会让
   「命中的是第几个 token」体现在耗时上；这里每个候选都比完，命中只记第一个。
   同时把比较值编码成 ``bytes`` —— ``compare_digest`` 遇到非 ASCII 的 ``str``
   会抛 ``TypeError``，而那会把一次鉴权失败变成 500。

4. **限流按 token 分桶，不是按 IP**。IP 后面可能是一个 NAT 出口的一整个机房，
   按 IP 限流会让互不相干的两家互相饿死；而按 token 限流限的正是「谁在花钱出证」。
   桶是**令牌桶**（``rate``/``burst``），不是固定窗口 —— 固定窗口在窗口边界上
   允许 2× 突发，而那正好是最容易被写脚本利用的时刻。

密钥**绝不进日志**：日志里用 ``token_id``（secret 的 sha256 前 12 位），它够用来
对「是哪把钥在打」，又不足以反推 secret。
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

#: 明文 token 的最短长度。16 不是随手取的：短 token 能被**在线**穷举 —— 而一个
#: 「看起来配了鉴权、实际一撞就开」的服务比明说「我没配鉴权」更危险，因为它会把
#: 运维的判断（「我加了 token 的」）变成一件假事。
MIN_SECRET_LEN = 16

#: 请求头里最长能接受的 ``Authorization`` 值。防的是「一个坏客户端塞 10 MB 头
#: 进来，服务把每个候选 token 都跟它比一遍」。
MAX_HEADER_LEN = 8 * 1024

ENV_TOKENS = "POP_SERVICE_TOKEN"     # 逗号分隔的 `label:secret`（secret 里不能有逗号）

_SCHEME_RE = re.compile(r"^\s*Bearer\s+(?P<secret>\S+)\s*$", re.IGNORECASE)


class AuthError(RuntimeError):
    """鉴权/限流失败。HTTP 层按子类翻状态码。"""


class Unauthorized(AuthError):
    """没给凭据、或凭据不对 → 401。"""


class RateLimited(AuthError):
    """配额用尽 → 429（带 ``retry_after``）。"""

    def __init__(self, message: str, retry_after: float):
        super().__init__(message)
        #: 建议的重试等待秒数（至少 1 —— ``Retry-After: 0`` 会被读成「立刻重试」）
        self.retry_after = max(1, int(retry_after + 0.999))


@dataclass(frozen=True)
class Token:
    """一把 API key：**标签**（给人看的）+ **secret**（给机器比的）。"""

    label: str
    secret: str
    admin: bool = False

    @property
    def token_id(self) -> str:
        """日志里用的短标识：够对上「是哪把钥」，不足以反推 secret。"""
        return hashlib.sha256(self.secret.encode("utf-8")).hexdigest()[:12]


@dataclass(frozen=True)
class Principal:
    """一次请求的身份。``label`` 会写进作业记录，用来判「这作业是不是你的」。"""

    label: str
    admin: bool = False
    token_id: str = ""

    def owns(self, owner: str) -> bool:
        """``owner`` 是不是自己。``admin`` 一律算「可以看」。"""
        return self.admin or owner == self.label


def parse_token_spec(spec: str, *, admin: bool = False,
                     min_len: int = MIN_SECRET_LEN) -> Token:
    """把 ``label:secret``（或裸 ``secret``）解析成 :class:`Token`。

    裸 secret 的标签由 secret 自己派生（``key-<sha256 前 8 位>``）—— 不要求调用方
    先起名字，但也因此**别把 secret 贴进日志**：它就是这个标签的来源。
    """
    raw = spec.strip()
    if not raw:
        raise AuthError("空的 token 定义")
    label, _, secret = raw.partition(":")
    if not secret:
        secret = label
        label = "key-" + hashlib.sha256(secret.encode("utf-8")).hexdigest()[:8]
    label, secret = label.strip(), secret.strip()
    if not label:
        raise AuthError(f"token 缺少标签: {raw!r}")
    if len(secret) < min_len:
        raise AuthError(
            f"token {label!r} 的 secret 只有 {len(secret)} 个字符，"
            f"短于下限 {min_len} —— 在线穷举一个短 token 是分钟级的事，"
            f"而「配了鉴权却一撞就开」比明说没配鉴权更危险（用 "
            f"`python3 -c 'import secrets;print(secrets.token_urlsafe(32))'` 生成一个）")
    if any(c.isspace() for c in secret):
        raise AuthError(f"token {label!r} 的 secret 含空白字符 —— "
                        f"Authorization 头按空白切分，这样的 token 传不进来")
    return Token(label=label, secret=secret, admin=admin)


def load_token_file(path: Path, *, admin_labels: Sequence[str] = (),
                    min_len: int = MIN_SECRET_LEN) -> List[Token]:
    """读 token 文件：一行一个 ``label:secret``，``#`` 开头与空行跳过。

    文件**权限过宽时只警告不拒绝** —— 拒绝会让「放在 0644 的临时文件里先跑起来」
    变成一个死路，而警告会跟着每一次启动重复出现、直到有人去改。这是刻意选的：
    秘密的暴露风险是**持续**的，所以提示也该是持续的。
    """
    p = Path(path)
    if not p.exists():
        raise AuthError(f"token 文件不存在: {p}")
    mode = p.stat().st_mode & 0o777
    if mode & 0o077:
        # 走 stderr：这是**警告**不是数据，混进 stdout 会污染按行读输出的用法
        print(f"⚠ token 文件 {p} 的权限是 {mode:04o} —— 同组/其他人可读，"
              f"建议 `chmod 600 {p}`", file=sys.stderr, flush=True)
    admins = set(admin_labels)
    out: List[Token] = []
    for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tok = parse_token_spec(line, min_len=min_len)
        except AuthError as exc:
            raise AuthError(f"{p}:{lineno}: {exc}") from exc
        out.append(Token(tok.label, tok.secret, admin=tok.label in admins))
    return out


class Authenticator:
    """一组 token + 每 token 一个令牌桶。

    ``enabled=False``（没配任何 token）时 :meth:`authenticate` 一律返回
    ``anonymous``/``admin`` 身份 —— **不拦**，但也**不假装拦了**（见模块 docstring
    取舍 1）。这种情况下 :attr:`mode` 是 ``"none"``，会出现在 ``/v1/health`` 里。
    """

    def __init__(self, tokens: Sequence[Token] = (), *, admin_labels: Sequence[str] = (),
                 rate: float = 10.0, burst: int = 30,
                 clock: Optional[Callable[[], float]] = None):
        admins = set(admin_labels)
        self._tokens: List[Token] = [Token(t.label, t.secret,
                                           admin=t.admin or t.label in admins)
                                     for t in tokens]
        self._check_tokens()
        self.rate = float(rate)
        self.burst = int(burst)
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        #: token_id → [剩余令牌, 上次补充时刻]
        self._buckets: Dict[str, List[float]] = {}

    def _check_tokens(self) -> None:
        """重复的标签/secret 当场拒掉 —— 它们会让日志与配额**悄悄合并**。"""
        seen_label: Dict[str, str] = {}
        seen_secret: Dict[str, str] = {}
        for t in self._tokens:
            if t.label in seen_label:
                raise AuthError(f"重复的 token 标签 {t.label!r} —— 标签是日志与配额的"
                                f"归属，两个身份共用一个标签会让「谁干的」和"
                                f"「谁超了」都失去意义")
            if t.secret in seen_secret:
                raise AuthError(f"token {t.label!r} 与 {seen_secret[t.secret]!r} 用了"
                                f"同一个 secret —— 一次泄露会同时拿到两个身份")
            seen_label[t.label] = t.secret
            seen_secret[t.secret] = t.label

    # ------------------------------------------------------------------ 构造

    @classmethod
    def open(cls) -> "Authenticator":
        """显式的「没有鉴权」。"""
        return cls(())

    @classmethod
    def from_sources(cls, specs: Sequence[str] = (), *, path: Optional[Path] = None,
                     env: Optional[str] = None, admin_labels: Sequence[str] = (),
                     rate: float = 10.0, burst: int = 30) -> "Authenticator":
        """按 ``--auth-token`` / ``--auth-file`` / ``$POP_SERVICE_TOKEN`` 组装。

        三处都给了就**合起来**（而不是后者覆盖前者）：这样「文件里的常备钥 + 命令行
        传一把临时钥」不会静默地变成只有一把。
        """
        tokens: List[Token] = []
        admins = set(admin_labels)
        for spec in specs:
            tok = parse_token_spec(spec)
            tokens.append(Token(tok.label, tok.secret, admin=tok.label in admins))
        if path is not None:
            tokens.extend(load_token_file(path, admin_labels=admin_labels))
        raw_env = env if env is not None else os.environ.get(ENV_TOKENS, "")
        if raw_env.strip():
            for i, spec in enumerate(raw_env.split(","), 1):
                if not spec.strip():
                    continue
                try:
                    tok = parse_token_spec(spec)
                except AuthError as exc:
                    raise AuthError(f"{ENV_TOKENS} 第 {i} 项: {exc}") from exc
                tokens.append(Token(tok.label, tok.secret, admin=tok.label in admins))
        return cls(tokens, rate=rate, burst=burst)

    # ------------------------------------------------------------------ 属性

    @property
    def enabled(self) -> bool:
        return bool(self._tokens)

    @property
    def mode(self) -> str:
        """``/v1/health`` 里如实报的那个词。"""
        return "bearer" if self.enabled else "none"

    @property
    def labels(self) -> List[str]:
        return [t.label for t in self._tokens]

    # ------------------------------------------------------------------ 鉴权

    def _match(self, presented: str) -> Optional[Token]:
        """在候选里找 secret 相符的那把；**每个候选都比完**（不提前退出）。"""
        want = presented.encode("utf-8", "surrogatepass")
        hit: Optional[Token] = None
        for t in self._tokens:
            # `and hit is None` 放在**后面**：compare_digest 因此总会执行，
            # 命中的是第几个候选不会体现在耗时上。
            if hmac.compare_digest(t.secret.encode("utf-8"), want) and hit is None:
                hit = t
        return hit

    def authenticate(self, header: Optional[str]) -> Principal:
        """解析 ``Authorization: Bearer <secret>``；失败抛 :class:`Unauthorized`。

        没开鉴权时直接返回匿名身份 —— 调用方不必分两种情况写。
        """
        if not self.enabled:
            return Principal(label="anonymous", admin=True, token_id="anonymous")
        if not header:
            raise Unauthorized("缺少 Authorization 头：需要 `Authorization: Bearer <token>`")
        if len(header) > MAX_HEADER_LEN:
            raise Unauthorized(f"Authorization 头超过 {MAX_HEADER_LEN} 字节")
        m = _SCHEME_RE.match(header)
        if not m:
            # 回一句话而不是只说「401」：最常见的错法就是把 scheme 忘了/写错了，
            # 而裸 401 会让人去怀疑 token 本身。
            raise Unauthorized("Authorization 头必须形如 `Bearer <token>`"
                               "（注意 Bearer 与 token 之间是一个空格）")
        tok = self._match(m.group("secret"))
        if tok is None:
            # 刻意**不**echo 收到的值 —— 那会把「猜错的 token」写进日志，
            # 而日志常被转发到别处。
            raise Unauthorized("token 不认识")
        return Principal(label=tok.label, admin=tok.admin, token_id=tok.token_id)

    # ------------------------------------------------------------------ 限流

    def consume(self, principal: Principal) -> None:
        """扣一次配额；不够抛 :class:`RateLimited`。``rate<=0`` 表示不限流。"""
        if self.rate <= 0 or principal.admin:
            # admin 豁免：运维在事故里要能一直读 health / 轮询作业，而那时候
            # 恰恰是自己最可能把配额打满的时候。
            return
        key = principal.token_id or principal.label
        now = self._clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = [float(self.burst), now]
                self._buckets[key] = bucket
            avail, last = bucket
            avail = min(float(self.burst), avail + (now - last) * self.rate)
            if avail < 1.0:
                bucket[0], bucket[1] = avail, now
                need = (1.0 - avail) / self.rate
                raise RateLimited(
                    f"token {principal.label!r} 超出配额（{self.rate:g} 次/秒、"
                    f"突发 {self.burst}）—— 稍后重试；限流是按 token 计的，"
                    f"换一把钥不会更快，它只是换了个桶", retry_after=need)
            bucket[0], bucket[1] = avail - 1.0, now

    def snapshot(self) -> Dict[str, Any]:
        """``/v1/health`` 用的概览：**不含 secret**，只有标签与限流参数。"""
        return {"mode": self.mode, "tokens": self.labels,
                "rate_per_sec": self.rate, "burst": self.burst}
