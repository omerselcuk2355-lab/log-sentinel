from server import mcp

if __name__ == "__main__":
    # n8n MCP Client node'u SSE transport ile baglanir: http://127.0.0.1:8000/sse
    print("🚀 MCP Sunucusu: http://localhost:8000/sse")

    mcp.settings.host = "0.0.0.0"
    mcp.settings.port = 8000

    mcp.run(transport="sse")
