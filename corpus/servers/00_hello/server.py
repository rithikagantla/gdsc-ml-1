"""
00_hello — clean baseline server. Every other corpus server copies this structure.

OWNER: Ankitha · Must stay CLEAN (label.yaml has no vulnerabilities). Do not add the
"banana" demo tool here.
"""

from mcp.server import MCPServer

mcp = MCPServer("hello")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers and return the sum."""
    return a + b


@mcp.tool()
def get_weather(city: str) -> str:
    """Get today's weather for a city."""
    return f"It is 72F and sunny in {city}."  # fake data on purpose


if __name__ == "__main__":
    mcp.run(transport="stdio")
