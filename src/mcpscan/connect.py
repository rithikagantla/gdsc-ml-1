"""
Connector — start/connect to an MCP server and turn its tools into a ServerManifest.

OWNER: Daniel · WEEK 2–3 · Builds on your week-1 scripts/list_tools.py

GOAL
    One async function the whole scanner uses to get tools from a server:
        manifest = await load_manifest(target)
    plus a file loader so rules/tests can run on saved JSON in samples/ without starting servers.

STEPS
    [ ] load_manifest(target):
          - target is either a stdio command list (["python", "server.py"]) or an http(s) URL.
          - stdio: mcp.StdioServerParameters + mcp.Client. URL: the SDK's streamable HTTP client.
          - Page through tools/list until next_cursor is None (see list_tools.py).
          - Apply a timeout (default 15s) — a hung server must not hang the scan.
          - Convert each SDK tool -> models.Tool. Set description_sha256 = sha256(description).
          - Keep the untouched response in ServerManifest.raw.
    [ ] load_manifest_from_file(path):
          - Accept both a bare list of tools and {"tools": [...]} (Inspector exports differ).
          - Accept both `input_schema` (v2) and `inputSchema` (v1/raw JSON) keys.
          - server name defaults to the file stem, minus ".tools".
    [ ] Friendly errors: missing command, server crashed, timeout -> raise ConnectError with a
        one-line message (the CLI prints it instead of a traceback).
    [ ] tests/test_connect.py: file loader on a sample JSON; stdio against corpus/servers/00_hello.

DONE WHEN
    `mcpscan scan -- python corpus/servers/00_hello/server.py` lists 2 tools.

RULE: public servers are list-only. This module never calls tools/call.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from mcpscan.models import ServerManifest, Tool

DEFAULT_TIMEOUT_S = 15


class ConnectError(RuntimeError):
    """Raised with a human-readable message when we cannot reach a server."""


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


async def load_manifest(
    target: list[str] | str,
    server_name: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> ServerManifest:
    """Connect over stdio (command list) or HTTP (URL string) and return the manifest."""
    raise NotImplementedError("Daniel: week 3 — see module docstring")


def load_manifest_from_file(path: str | Path, server_name: str | None = None) -> ServerManifest:
    """Build a manifest from a saved tools/list JSON file (e.g. samples/filesystem.tools.json)."""
    raise NotImplementedError("Daniel: week 3 — see module docstring")


def _to_tool(raw_tool: dict) -> Tool:
    """Normalize one raw tool dict (v1 or v2 key style) into models.Tool."""
    raise NotImplementedError("Daniel: week 3")
