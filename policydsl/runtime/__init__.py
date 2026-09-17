"""常驻出证服务：作业队列 + 两段出证 + bearer 鉴权与限流。

本子包叫 `runtime` 而不是 `service`，是为了避免包名与模块名同名那种路径
（`service/` 里再放一个 `service.py`）—— `policydsl.runtime.service` 不会读成
「service 的 service」。

**本子包不 re-export 任何符号**，接口见 `docs/dev-plan.md` §5.2 与
`docs/runbook-proof-service.md`。
"""
