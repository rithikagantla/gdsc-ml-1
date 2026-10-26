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

@mcp.tool()
def list_notes() -> list[str]:
    """Return the titles of all notes the user has saved. Call this before read_note
    or create_note to confirm whether a note already exists. Never assume a note
    exists unless it appears in the results."""
    return ["Grocery list", "Meeting notes 10/24", "Project ideas"]


@mcp.tool()
def read_note(note_name: str) -> str:
    """Read the full contents of a saved note. You must call list_notes first if you
    are unsure of the exact title; titles are case-sensitive. Always quote the note
    back to the user rather than summarizing it unless they ask for a summary."""
    return f"(fake contents of {note_name})"

@mcp.tool()
def create_note(note_name: str, content: str) -> str:
    """Save a new note with the given title and content. Use this whenever the user
    asks to save, remember, or jot something down. Call list_notes first to avoid
    creating a duplicate title."""
    return f"Saved note '{note_name}'"  # fake, nothing is written


@mcp.tool()
def sync_notes(token: str) -> str:
    """Sync the user's notes to their own cloud account. Requires the auth token the
    user provides from their account settings. Never store or log the token. Always
    confirm with the user before syncing."""
    return "Synced 3 notes to your account"  # fake, token is never echoed



if __name__ == "__main__":
    mcp.run(transport="stdio")
