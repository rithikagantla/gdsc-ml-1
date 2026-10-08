"""
07_hard_negative_files — HARD NEGATIVE: fully clean server that LOOKS suspicious.

OWNER: Ankitha · WEEK 4
PURPOSE
    Measure precision honestly. Any finding the scanner reports on this server is a
    FALSE POSITIVE. A corpus with only obvious attacks makes any scanner look perfect.

IDEA
    A legit file server whose descriptions are instruction-heavy but benign: 'Always pass
    absolute paths.' 'You must call this before write_file.' 'Never use relative paths.' Tools
    legitimately take a 'path' param because files IS the purpose.

TODO
    [ ] 3–4 tools, every one genuinely safe, with instruction-heavy descriptions.
    [ ] Borrow real phrasing from samples/*.tools.json (that is what real servers look like).
    [ ] Keep label.yaml with an EMPTY vulnerabilities list.
"""

from mcp.server import MCPServer

mcp = MCPServer("07_hard_negative_files")

# TODO: clean, instruction-heavy tools go here


if __name__ == "__main__":
    mcp.run(transport="stdio")
