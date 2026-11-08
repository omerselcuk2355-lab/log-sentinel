from server import mcp

if __name__ == "__main__":
    print("🚀 MCP Sunucusu: http://localhost:8000/mcp")
    
    mcp.settings.host = "0.0.0.0"
    mcp.settings.port = 8000
    
    mcp.run(transport="streamable-http")