"""一个**极小的** OpenAI 兼容流式端点（stdlib ``http.server``），供离线测试用。

为什么要有它
------------
``--model openai:…`` 那条路真正值得验的不是「模型会说话」，而是**真实的
传输层 + 真实的 ``langchain_openai`` 客户端**接进 ``PoPCallbackHandler`` 之后，
真早停是不是还能把流掐断。用假模型验不了这一段（``GenericFakeChatModel``
根本不走 HTTP）。而拿真 API key 去验，CI 跑不了、还会花掉使用者的额度。

于是这里实现**协议本身**：``POST /v1/chat/completions`` + ``text/event-stream``，
让真的 ``ChatOpenAI`` 客户端对着 ``http://127.0.0.1:<port>/v1`` 说话。
验的是客户端与回调层的代码，不是某家 provider 的脾气。

最要紧的一件事是 :attr:`StubServer.sent_chunks`：它数的是**服务器真的写出去
了**几个分片。客户端因 ``EarlyStop`` 提前断开连接之后，服务器再写就会
``BrokenPipeError`` —— 所以 ``sent_chunks < len(chunks)`` 是「流在**传输层**
真的被切断了」的证据，而不是「我们这边不再往列表里 append 了」这种自己说自己
的话。这两件事的差别，正是 #97 要修的。
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List, Tuple

DEFAULT_MODEL = "stub-model"
#: 分片之间的间隔。**不是为了模拟网速**，是为了让「服务器写第 N+1 片」与
#: 「客户端读完第 N 片后断开」这两件事有个确定的先后：没有间隔时服务器会把
#: 整条流塞进内核缓冲区，客户端断不断开它都写完了，于是 ``sent_chunks``
#: 量不出「传输层真的被切断」—— 会有测试通过而理由落空的假象。
DEFAULT_DELAY = 0.05


def _chunk_payload(model: str, text: str, finish: str = None) -> dict:
    """OpenAI ``chat.completion.chunk`` 的最小合法形状。"""
    delta = {"content": text} if text is not None else {}
    return {"id": "chatcmpl-stub", "object": "chat.completion.chunk",
            "created": 0, "model": model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}


class StubServer:
    """在后台线程里跑一个 OpenAI 兼容端点，并把每条响应切成给定分片流出去。

    ``raise_on_broken_pipe=False``：客户端提前断开是**预期**行为（早停），
    不该让服务器线程把它当故障报出来。
    """

    def __init__(self, chunks: List[str] = None, model: str = DEFAULT_MODEL,
                 delay: float = DEFAULT_DELAY, router=None):
        #: 固定分片；给了 ``router`` 就按请求另算（见下）。
        self.chunks = list(chunks or [])
        #: ``router(body: dict) -> List[str]``：按请求决定回什么分片。
        #: 演示/端到端要用的就是这个 —— 「问什么答什么」的桩才配得上
        #: 「干净那条干净、违规那条违规」这种按提示词分岔的脚本。
        self.router = router
        self.model = model
        self.delay = delay
        self.requests: List[dict] = []
        #: 服务器**真的写出去**的分片数（客户端断开后写失败的那些不计）
        self.sent_chunks = 0
        self.finished = threading.Event()
        self._httpd = None
        self._thread = None

    # ---- 生命周期 ----

    def start(self) -> "StubServer":
        stub = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):  # 静音：测试输出不需要 HTTP 日志
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    body = json.loads(raw or b"{}")
                except ValueError:
                    body = {}
                stub.requests.append(body)
                if not body.get("stream"):
                    # 本项目只验流式那条路；非流式直接说不支持，免得测试
                    # 悄悄跑到另一条分支上还以为验过了。
                    self.send_error(400, "stub only implements stream=true")
                    return
                self._stream(body)

            def _stream(self, body):
                chunks = (stub.router(body) if stub.router is not None else stub.chunks)
                payloads = [_chunk_payload(stub.model, c) for c in chunks]
                payloads.append(_chunk_payload(stub.model, None, finish="stop"))
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    for i, p in enumerate(payloads):
                        if i:
                            time.sleep(stub.delay)
                        self.wfile.write(f"data: {json.dumps(p)}\n\n".encode())
                        self.wfile.flush()
                        stub.sent_chunks += 1
                    self.wfile.write(b"data: [DONE]\n\n")
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    # 客户端在流中途断开了 —— 早停时就是这条路径
                    self.close_connection = True
                finally:
                    stub.finished.set()

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    @property
    def base_url(self) -> str:
        """喂给 ``ChatOpenAI(base_url=…)`` 的地址（含 ``/v1``）。"""
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}/v1"

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> "StubServer":
        # 走 ``with StubServer(...) as server`` 时就地起服务：调用方不必
        # 记得先 ``.start()``（忘了的话 ``base_url`` 会在读 ``None`` 上炸掉，
        # 报的错跟「桩没起来」毫无关系）。
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def start(chunks: List[str] = None, model: str = DEFAULT_MODEL,
          delay: float = DEFAULT_DELAY, router=None) -> Tuple[StubServer, str]:
    """起一个桩，返回 ``(server, base_url)``。用完记得 ``server.stop()``。"""
    s = StubServer(chunks, model, delay=delay, router=router).start()
    return s, s.base_url


def echo_router(clean_chunks: List[str], leak_marker: str = "Repeat the following line"):
    """一个「问什么答什么」的桩路由（手动验 ``--model`` 时用）。

    收到含 ``leak_marker`` 的提示词就**照念**其中引用的那一行（分片切开），
    其余一律回 ``clean_chunks``。这模拟的是最坏也最常见的一种服从：
    模型老老实实把使用者给的那行含密钥的文本回显出来。
    """
    def route(body: dict) -> List[str]:
        text = " ".join(str(m.get("content", "")) for m in body.get("messages", []))
        if leak_marker in text:
            tail = text.split(leak_marker, 1)[1].strip().lstrip(":\n ").strip()
            # 切成几片，好让早停停在流的**中间**（停在最后一片证明不了掐断）
            cut = max(1, len(tail) // 3)
            return [tail[:cut], tail[cut:2 * cut], tail[2 * cut:]]

        return clean_chunks

    return route
