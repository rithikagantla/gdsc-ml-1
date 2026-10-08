"""
05_hidden_text — deliberately vulnerable MCP server.

OWNER: Ankitha · WEEK 3
PRIMARY VULNERABILITY: hidden_text (location: description) on tool `summarize_text`

ATTACK IDEA
    Description looks benign on screen but contains zero-width characters / bidi controls / an
    HTML comment / a base64 blob that decodes to an instruction.

TODO
    [ ] Copy the structure of 00_hello/server.py (MCPServer, @mcp.tool(), stdio transport).
    [ ] Write the vulnerable tool `summarize_text` — the vulnerability lives in its description.
    [ ] Add 1–2 clean decoy tools: word_count
    [ ] Tools return FAKE data only. Never actually read secrets / touch network / delete files.
    [ ] Fill in label.yaml (only the vulnerable tool; decoys are expected clean).
    [ ] Check it in the Inspector, then run: python scripts/list_tools.py python \
        corpus/servers/05_hidden_text/server.py
    [ ] Write README.md (3 lines).
"""

from mcp.server import MCPServer

mcp = MCPServer("05_hidden_text")

# TODO: vulnerable tool + decoy tools go here


if __name__ == "__main__":
    mcp.run(transport="stdio")
