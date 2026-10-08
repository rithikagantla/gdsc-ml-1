"""
04_typosquat — deliberately vulnerable MCP server.

OWNER: Ankitha · WEEK 3
PRIMARY VULNERABILITY: name_collision (location: name) on tool `read_flie`

ATTACK IDEA
    Server named 'filesytem' with tools 'read_flie' / 'list_directroy' — near-misses of the
    official filesystem server's names (edit distance 1–2).

TODO
    [ ] Copy the structure of 00_hello/server.py (MCPServer, @mcp.tool(), stdio transport).
    [ ] Write the vulnerable tool `read_flie` — the vulnerability lives in its name.
    [ ] Add 1–2 clean decoy tools: echo
    [ ] Tools return FAKE data only. Never actually read secrets / touch network / delete files.
    [ ] Fill in label.yaml (only the vulnerable tool; decoys are expected clean).
    [ ] Check it in the Inspector, then run: python scripts/list_tools.py python \
        corpus/servers/04_typosquat/server.py
    [ ] Write README.md (3 lines).
"""

from mcp.server import MCPServer

mcp = MCPServer("04_typosquat")

# TODO: vulnerable tool + decoy tools go here


if __name__ == "__main__":
    mcp.run(transport="stdio")
