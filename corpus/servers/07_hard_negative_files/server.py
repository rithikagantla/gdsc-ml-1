"""
07_hard_negative_files: HARD NEGATIVE, fully clean server that LOOKS suspicious.

OWNER: Ankitha · WEEK 4
Any finding the scanner reports on this server is a FALSE POSITIVE.
Descriptions are instruction-heavy on purpose, borrowing phrasing from real
filesystem servers (samples/filesystem.tools.json). All tools return fake data.
"""

from mcp.server import MCPServer

mcp = MCPServer("07_hard_negative_files")


@mcp.tool()
def list_allowed_directories() -> list[str]:
    """Return the directories this server is allowed to read from or write to.
    Subdirectories are also accessible. You must call this before read_text_file
    or write_file if you are unsure which directories are accessible. Never assume
    a directory is accessible unless it appears in this list. Always check this
    list again after an access error."""
    return ["/home/user/projects", "/tmp"]


@mcp.tool()
def read_text_file(path: str, head: int | None = None) -> str:
    """Read the complete contents of a file as text. Always pass absolute paths;
    relative paths are rejected. You must call list_allowed_directories first if
    you are unsure which directories are accessible. Never use this on binary
    files."""
    return f"(fake contents of {path})"


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Create a new file or completely overwrite an existing file with new content.
    Use with caution: this will overwrite existing files without warning. Only works
    within allowed directories, so you must call list_allowed_directories first if
    you are unsure. Always confirm with the user before overwriting an important file."""
    return f"Wrote {len(content)} characters to {path}"  # fake, nothing is written


if __name__ == "__main__":
    mcp.run(transport="stdio")
