from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
from pathlib import Path

from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcpscan.models import ServerManifest, Tool

DEFAULT_TIMEOUT_S = 15


class ConnectError(RuntimeError):
    pass


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _to_tool(raw_tool: dict) -> Tool:
    if not isinstance(raw_tool, dict) or not isinstance(raw_tool.get("name"), str):
        raise ConnectError("a tool entry is missing a string 'name'")
    description = raw_tool.get("description") or ""
    schema = raw_tool.get("input_schema") or raw_tool.get("inputSchema") or {}
    return Tool(
        name=raw_tool["name"],
        description=description,
        input_schema=schema,
        annotations=raw_tool.get("annotations") or {},
        description_sha256=sha256_text(description),
    )


def load_manifest_from_file(path: str | Path, server_name: str | None = None) -> ServerManifest:
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConnectError(f"file not found: {path}") from None
    except json.JSONDecodeError:
        raise ConnectError(f"{path} is not valid JSON") from None
    tools = data.get("tools") if isinstance(data, dict) else data
    if not isinstance(tools, list):
        raise ConnectError(f"{path} must be a list of tools or an object with a 'tools' list")
    name = server_name or path.name.removesuffix(".json").removesuffix(".tools")
    return ServerManifest(
        server=name,
        tools=[_to_tool(t) for t in tools],
        raw=data if isinstance(data, dict) else {"tools": data},
    )


async def _fetch(target) -> tuple[str | None, list[dict]]:
    async with Client(target) as client:
        tools = []
        cursor = None
        while True:
            page = await client.list_tools(cursor=cursor)
            tools += [t.model_dump(mode="json") for t in page.tools]
            cursor = page.next_cursor
            if cursor is None:
                return getattr(client.server_info, "name", None), tools


def _error_message(exc: BaseException, command: str | None, errlog) -> str:
    while isinstance(exc, BaseExceptionGroup):
        exc = exc.exceptions[0]
    if isinstance(exc, FileNotFoundError) and command:
        return f"could not start server, command not found: {command}"
    errlog.seek(0)
    lines = [line.strip() for line in errlog.read().splitlines() if line.strip()]
    detail = lines[-1] if lines else str(exc) or type(exc).__name__
    return f"could not start or talk to server: {detail}"


async def load_manifest(
    target: list[str] | str,
    server_name: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> ServerManifest:
    if not target:
        raise ConnectError("no server command given")
    if isinstance(target, str) and not target.startswith(("http://", "https://")):
        raise ConnectError(f"not an http(s) URL: {target}")

    with tempfile.TemporaryFile("w+", errors="replace") as errlog:
        client_target = target
        command = None
        if isinstance(target, list):
            command = target[0]
            params = StdioServerParameters(command=command, args=target[1:])
            client_target = stdio_client(params, errlog=errlog)
        try:
            name, raw_tools = await asyncio.wait_for(_fetch(client_target), timeout)
        except TimeoutError:
            raise ConnectError(f"server did not respond within {timeout:g}s") from None
        except Exception as exc:
            raise ConnectError(_error_message(exc, command, errlog)) from None

    return ServerManifest(
        server=server_name or name or "server",
        tools=[_to_tool(t) for t in raw_tools],
        raw={"tools": raw_tools},
    )
