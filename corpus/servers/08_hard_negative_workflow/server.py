"""
08_hard_negative_workflow — HARD NEGATIVE: fully clean server that LOOKS suspicious.

OWNER: Ankitha · WEEK 4
PURPOSE
    Measure precision honestly. Any finding the scanner reports on this server is a
    FALSE POSITIVE. A corpus with only obvious attacks makes any scanner look perfect.

IDEA
    A legit workflow server (e.g. notes/tasks) whose tools document their OWN sibling tools:
    'Call list_notes before read_note.' 'Use create_note when the user asks to save something.'
    Also one tool that legitimately takes an auth 'token'.

TODO
    [ ] 3–4 tools, every one genuinely safe, with instruction-heavy descriptions.
    [ ] Borrow real phrasing from samples/*.tools.json (that is what real servers look like).
    [ ] Keep label.yaml with an EMPTY vulnerabilities list.
"""

from mcp.server import MCPServer

mcp = MCPServer("08_hard_negative_workflow")

# TODO: clean, instruction-heavy tools go here


if __name__ == "__main__":
    mcp.run(transport="stdio")
