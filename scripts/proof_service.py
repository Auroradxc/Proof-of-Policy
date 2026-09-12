#!/usr/bin/env python3
"""证明服务的 HTTP 驱动（``docs/dev-plan.md`` §5.2 第二步）。

接口（三段，见 dev-plan §5.2.2）：

    POST /v1/check          {policy_id, response, nonce?, receipts?}
                            → 毫秒级：宿主判定 + unproven 证书（含 challenge nonce）
    POST /v1/attest         {policy_id, response, nonce?, receipts?}
                            → 入队，立即返回 job_id 与 queue_position
    GET  /v1/attest/{job}   → queued | proving | done | failed
    GET  /v1/health         → 并发上限 / 队列深度 / 策略数（运维看的）
    GET  /v1/policies       → 已注册的策略（含 serviceable 标注）

库在 ``policydsl/service.py``，本文件只做 HTTP。**依赖只用标准库
``http.server``（零新依赖）** —— 这是刻意的：这一步要演示的是**证据链**，不是
web 框架；引入 FastAPI/uvicorn 会把注意力从证据挪到框架上。

    python3 scripts/proof_service.py --host-check          # 秒级演示（出 unproven 证书）
    SP1_PROVER=cpu python3 scripts/proof_service.py        # 真实证明（~2.5 分钟/次，需 ~10.2 GiB）

⚠️ **无鉴权**：默认只绑 ``127.0.0.1``，且**没有任何身份校验** —— 谁能连上谁就能
出证、就能读别人的作业。要放到网络上必须先自行加一层（反向代理 + mTLS/OIDC），
或者把它放在只对本机/内网开放的端口上。这一点写进 ``docs/runbook-proof-service.md``，
不是「以后再说」。
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from policydsl import challenge, keys, service
from policydsl.service import ProofService, ServiceError

#: 请求体上限。这是**防御**而不是配额：``http.server`` 会把 ``Content-Length``
#: 说明的字节全读进内存，没有上限时一个坏掉的（或恶意的）客户端就能把服务打爆。
#: 响应本身也受策略里的 length_bound 约束，1 MiB 远大于任何真实用例。
MAX_BODY = 1024 * 1024


def _json_response(handler: BaseHTTPRequestHandler, code: int, payload: Dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _error(handler: BaseHTTPRequestHandler, code: int, message: str) -> None:
    _json_response(handler, code, {"error": message})


class Handler(BaseHTTPRequestHandler):
    """把 HTTP 动词/路径翻成 :class:`ProofService` 调用。

    ``service`` 放在类属性上由 ``make_server`` 注入 —— ``http.server`` 每个
    连接新建一个 handler 实例，实例属性传不进去。
    """

    service: ProofService
    server_version = "pop-proof-service/1.0"

    # ------------------------------------------------------------ 工具

    def log_message(self, fmt: str, *args: Any) -> None:
        """把访问日志写到 stderr，并带上方法/路径（缺省只有裸的请求行）。"""
        sys.stderr.write("[proof-service] %s %s\n" % (self.address_string(), fmt % args))

    def _read_json(self) -> Optional[Dict[str, Any]]:
        """读并解析请求体。任何问题都**当场回**，返回 None 表示已经回复过了。"""
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            _error(self, 411, "需要一个带 Content-Length 的 JSON 请求体")
            return None
        try:
            length = int(raw_len)
        except ValueError:
            _error(self, 400, f"Content-Length 不是整数: {raw_len!r}")
            return None
        if length < 0 or length > MAX_BODY:
            _error(self, 413, f"请求体 {length} 字节超出上限 {MAX_BODY}")
            return None
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            _error(self, 400, f"请求体不是合法 JSON: {exc}")
            return None
        if not isinstance(body, dict):
            _error(self, 400, "请求体必须是一个 JSON 对象")
            return None
        return body

    def _request(self, body: Dict[str, Any]) -> Optional[Tuple[str, str, list]]:
        """从请求体里取 ``(policy_id, response, receipts)``，缺啥报啥。"""
        pid = body.get("policy_id")
        if not isinstance(pid, str) or not pid:
            _error(self, 400, "缺少 policy_id（要**点名**用哪条策略，见 GET /v1/policies）")
            return None
        response = body.get("response")
        if not isinstance(response, str):
            _error(self, 400, "缺少 response（字符串）")
            return None
        receipts = body.get("receipts") or []
        if not isinstance(receipts, list):
            _error(self, 400, "receipts 必须是数组（工具网关签发的回执，P1-5）")
            return None
        return pid, response, receipts

    def _nonce(self, body: Dict[str, Any]) -> bytes:
        """解析 ``nonce``：缺省现场生成一个。

        缺省生成而不是拒绝，是为了让调用方**单独**调 ``/v1/attest`` 也能用；
        但两段式的正确用法是「把 ``/v1/check`` 回给你的 nonce 原样传过来」——
        那样两张证书绑的才是同一条 T，升级才有意义。
        """
        raw = body.get("nonce")
        if raw is None or raw == "":
            return challenge.new_nonce()
        try:
            return challenge.parse_nonce(str(raw))
        except ValueError as exc:
            raise ServiceError(f"nonce 解析失败: {exc}") from exc

    # ------------------------------------------------------------ 路由

    def do_GET(self) -> None:                       # noqa: N802 —— BaseHTTPRequestHandler 的约定
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        try:
            if path == "/v1/health":
                _json_response(self, 200, {"status": "ok", "policies": len(self.service.registry),
                                           **self.service.snapshot()})
            elif path == "/v1/policies":
                _json_response(self, 200, {"policies": self.service.registry.summaries()})
            elif path.startswith("/v1/attest/"):
                job_id = path[len("/v1/attest/"):]
                if not job_id:
                    _error(self, 400, "缺少 job_id：GET /v1/attest/{job}")
                    return
                _json_response(self, 200, self.service.public_job(job_id))
            else:
                _error(self, 404, f"没有这条路径: {self.path}")
        except (service.UnknownPolicy, service.JobNotFound) as exc:
            # 「这个东西不存在」是 404；「你给的东西不合法」才是 400。把点错 job_id
            # 报成 400 会让调用方去查自己的请求体，而问题在路径上。
            _error(self, 404, str(exc))
        except ServiceError as exc:
            _error(self, 400, str(exc))
        except Exception as exc:                     # noqa: BLE001 —— 兜底，别让线程静默死
            _error(self, 500, f"{type(exc).__name__}: {exc}")

    def do_POST(self) -> None:                      # noqa: N802
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        try:
            body = self._read_json()
            if body is None:
                return
            if path == "/v1/check":
                req = self._request(body)
                if req is None:
                    return
                pid, response, receipts = req
                out = self.service.check(pid, response, self._nonce(body), receipts)
                _json_response(self, 200, out)
            elif path == "/v1/attest":
                req = self._request(body)
                if req is None:
                    return
                pid, response, receipts = req
                job = self.service.submit(pid, response, self._nonce(body), receipts)
                _json_response(self, 202, job.public(self.service.queue_position(job)))
            else:
                _error(self, 404, f"没有这条路径: {self.path}")
        except service.QueueFull as exc:
            # 429 而不是 503：调用方该做的是**退避重试**，而 503 通常被读成
            # 「服务坏了」。队列满恰恰说明服务是好的，只是不想把活儿收下之后 OOM。
            self.send_response(429)
            body_out = json.dumps({"error": str(exc)}, ensure_ascii=False).encode("utf-8")
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Retry-After", "30")
            self.send_header("Content-Length", str(len(body_out)))
            self.end_headers()
            self.wfile.write(body_out)
        except service.UnknownPolicy as exc:
            _error(self, 404, str(exc))
        except (service.PolicyNotServiceable, ServiceError) as exc:
            _error(self, 400, str(exc))
        except Exception as exc:                     # noqa: BLE001
            _error(self, 500, f"{type(exc).__name__}: {exc}")


def make_server(svc: ProofService, host: str, port: int) -> ThreadingHTTPServer:
    """建 HTTP 服务器。

    ``ThreadingHTTPServer``：``/v1/check`` 是毫秒级的、可以被并发调；真正的串行
    点在证明队列里（:class:`ProofService` 的 ``concurrency``），不在 HTTP 层。
    起单线程的 ``HTTPServer`` 会让一个正在轮询的客户端把别人的 check 也堵住。
    """
    handler = type("BoundHandler", (Handler,), {"service": svc})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    return httpd


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Proof-of-Policy 证明服务（宿主判定 + 出证队列）")
    ap.add_argument("--pack", type=Path, action="append", default=None,
                    help="策略包 JSON（可重复）。缺省扫描 policy_packs/*.json")
    ap.add_argument("--out-dir", type=Path,
                    default=REPO / "scripts" / "examples" / "out" / "service",
                    help="作业/证书/账本的落盘根目录")
    ap.add_argument("--ledger", type=Path, default=None,
                    help="锚定账本（缺省 <out-dir>/ledger.jsonl）")
    ap.add_argument("--host", default="127.0.0.1",
                    help="绑定地址。**默认只绑本机** —— 服务无鉴权，见模块 docstring")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--concurrency", type=int, default=1,
                    help="证明器线程数。缺省 1 是硬约束：SP1 core 证明峰值 ~10.2 GiB，"
                         "12 GB 机器上同时跑两个是 OOM，不是慢")
    ap.add_argument("--max-queue", type=int, default=8,
                    help="等待中的作业上限（不含正在证的），超出返 429")
    ap.add_argument("--host-check", action="store_true",
                    help="**只做宿主校验**：作业跑 pop-script --check 并如实标注 "
                         "proof_mode=unproven，几秒完成。用来验队列机制本身")
    ap.add_argument("--mode", choices=["public", "private"], default="public")
    ap.add_argument("--proof-mode", choices=["core", "compressed", "groth16", "plonk"],
                    default="core")
    ap.add_argument("--key", type=Path, default=None,
                    help="Ed25519 私钥（缺省读 $POP_SIGNING_KEY，都没有则在 "
                         ".pop-keys/signing.key 生成一把新的）")
    ap.add_argument("--rpc", default=None, help="EVM RPC：证书摘要同时登记上链")
    ap.add_argument("--contract", default=None, help="已部署的 Anchor 合约地址")
    ap.add_argument("--private-key", default=None, help="上链提交私钥")
    return ap


def main() -> int:
    args = build_parser().parse_args()

    paths = args.pack or sorted((REPO / "policy_packs").glob("*.json"))
    if not paths:
        print("没有可注册的策略包（--pack 或 policy_packs/*.json）", file=sys.stderr)
        return 2

    def _skip(path: Path, exc: BaseException) -> None:
        # 坏包跳过但**说出来**：静默少一条策略会让 GET /v1/policies 与运维
        # 脑子里的那张表对不上，而那是排查问题时唯一的对照物。
        print(f"⚠ 跳过策略包 {path}: {type(exc).__name__}: {exc}", file=sys.stderr)

    registry = service.registry_from_paths(paths, on_skip=_skip)
    if len(registry) == 0:
        print("所有策略包都注册失败 —— 拒不启动（一个没有策略的服务只会回 404）",
              file=sys.stderr)
        return 2

    svc = ProofService(
        registry, args.out_dir, ledger=args.ledger,
        signer=keys.signer_from_env(args.key),
        concurrency=args.concurrency, max_queue=args.max_queue,
        host_check=args.host_check, mode=args.mode, proof_mode=args.proof_mode,
        rpc_url=args.rpc, contract=args.contract, private_key=args.private_key)
    httpd = make_server(svc, args.host, args.port)
    actual_host, actual_port = httpd.server_address[0], httpd.server_address[1]
    svc.start()

    print(f"proof service on http://{actual_host}:{actual_port}")
    print(f"  策略      : {', '.join(registry.ids())}")
    for row in registry.summaries():
        if not row["serviceable"]:
            print(f"    ⚠ {row['id']} 不可出证（{', '.join(row['unserviceable_rules'])}）"
                  f"—— 调用会被拒，见 ProofService 的 PolicyNotServiceable")
    print(f"  out-dir   : {args.out_dir}")
    print(f"  账本      : {svc.ledger}")
    print(f"  并发      : {args.concurrency} 证明器 + 队列 {args.max_queue}"
          + ("   （--host-check：作业只做宿主校验，标注 unproven）"
             if args.host_check else "   （真实证明：~2.5 分钟/次，峰值 ~10.2 GiB）"))
    print(f"  签名者    : {svc.signer.keyid}")
    print("  ⚠ 无鉴权 —— 默认只绑 127.0.0.1；放到网络上必须先加一层，"
          "见 docs/runbook-proof-service.md")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n收到中断，等服务把手上的作业做完…")
    finally:
        httpd.shutdown()
        # drain=True：不把还没开工的作业留在 queued —— 那等于给它们判了一个
        # 永远不会执行的刑，而 GET /v1/attest/{job} 会一直回答 queued。
        svc.stop(drain=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
