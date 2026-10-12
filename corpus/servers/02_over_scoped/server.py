"""
02_over_scoped — deliberately vulnerable MCP server.

OWNER: Arnav (port) / Ankitha (review) · WEEK 3
PRIMARY VULNERABILITY: over_permission (location: schema) on tool `get_forecast`

ATTACK IDEA
    A weather tool whose schema also takes an unrestricted 'path' parameter (and
    destructiveHint: true). PORT Arnav's corpus/over_scoped_filesystem/
    from branch 'over-scoped-filesystem-server' into this folder and fix label.yaml to the agreed
    format.

TODO
    [ ] Copy the structure of 00_hello/server.py (MCPServer, @mcp.tool(), stdio transport).
    [ ] Write the vulnerable tool `get_forecast` — the vulnerability lives in its schema.
    [ ] Add 1–2 clean decoy tools: convert_temperature
    [ ] Tools return FAKE data only. Never actually read secrets / touch network / delete files.
    [ ] Fill in label.yaml (only the vulnerable tool; decoys are expected clean).
    [ ] Check it in the Inspector, then run: python scripts/list_tools.py python \
        corpus/servers/02_over_scoped/server.py
    [ ] Write README.md (3 lines).
"""

from mcp.server import MCPServer
from mcp.types import ToolAnnotations  # Attaches aditional metadata to tool descripton

mcp = MCPServer("02_over_scoped")


# Intentionally vulnerable tool, metadata
@mcp.tool(
    annotations=ToolAnnotations(
        destructive_hint=True,
        read_only_hint=False,
    )
)

def get_forecast(city: str, path: str) -> str: # City is normal, but path is not needed
    """Get a weather forecast for a city."""
    # Dont actually open file, return fake weather forecast.
    return f"Demo forecast for {city}: Sunny, 75°F."


# Clean decoy tool
@mcp.tool()
def convert_temperature(celsius: float) -> float:
    """Convert Celsius to Fahrenheit."""

    return (celsius * 9 / 5) + 32


if __name__ == "__main__":
    mcp.run(transport="stdio")
