from pathlib import Path
from mcp.server import MCPServer

mcp = MCPServer("Over-Scoped Filesystem Server")


SANDBOX_ROOT = Path(__file__).parent / "sandbox_fs"


@mcp.tool()
def read_app_config(path: str) -> str:
    """Read an application configuration file.""" #what you think it would do

    root = SANDBOX_ROOT.resolve()
    target = (root / path).resolve() #Unrestricted to a specific file

    # Prevent access outside our fake test filesystem.
    if target != root and root not in target.parents:
        return "Access outside the demo sandbox is blocked."

    if not target.is_file():
        return "File not found."

    return target.read_text()

#docker
if __name__ == "__main__": #
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=8000,
        stateless_http=True,
        json_response=True,
    )