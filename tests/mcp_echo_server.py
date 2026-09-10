"""A tiny MCP server (stdio) used by tests/test_mcp.py.

Run directly to exercise a real Proof-of-Policy guard against a real MCP server:
    python3 tests/mcp_echo_server.py
"""

from mcp.server import MCPServer

server = MCPServer("pop-echo")


@server.tool()
def search_kb(query: str, token: str = "") -> str:
    """Search the knowledge base (echoes the query)."""
    return f"ok:{query}"


@server.tool()
def dump_config() -> str:
    """Return the service configuration (contains a credential)."""
    return "service=kb api_key=sk-abcdefghijklmnopqrstuvwxyz"


if __name__ == "__main__":
    server.run("stdio")
