"""tests/test_mcp.py 使用的最小 MCP 服务器（stdio）。

保留两个工具是为了分别命中守护的两条路径：``search_kb`` 用于参数侧（可用
``token`` 触发禁用字段），``dump_config`` 用于结果侧（返回值中含密钥）。
真实服务器无法用 fake 替代——它才验证得了协议握手、子进程传输等真实环节。

也可直接运行，手动对一个真实 MCP 服务器试 Proof-of-Policy 守护：
    python3 tests/mcp_echo_server.py
"""

from mcp.server import MCPServer

server = MCPServer("pop-echo")


# 供参数侧测试调用：token 是策略中的禁用字段，用于触发 no_secret_args
@server.tool()
def search_kb(query: str, token: str = "") -> str:
    """Search the knowledge base (echoes the query)."""
    return f"ok:{query}"


# 供结果侧测试调用：返回值里带一个伪造密钥，用于触发 no_secret
@server.tool()
def dump_config() -> str:
    """Return the service configuration (contains a credential)."""
    return "service=kb api_key=sk-abcdefghijklmnopqrstuvwxyz"


if __name__ == "__main__":
    server.run("stdio")
